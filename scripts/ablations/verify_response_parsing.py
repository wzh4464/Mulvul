#!/usr/bin/env python3
"""
Run a tiny end-to-end check that our response parsing logic can recover the
intended classification labels from real LLM outputs.

Example:
    uv run python scripts/ablations/verify_response_parsing.py \\
        --llm-type openai --model-name gpt-4o-mini \\
        --max-samples 2 --temperature 0.0
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional

# Ensure src/ is importable when running as a script.
sys.path.insert(0, "src")

from evoprompt.data.cwe_categories import CWE_MAJOR_CATEGORIES, map_cwe_to_major
from evoprompt.llm.client import create_llm_client, load_env_vars
from evoprompt.utils.response_parsing import (
    extract_cwe_major,
    extract_vulnerability_label,
)


SIMPLE_CASES = [
    {
        "id": "toy-buffer-overflow",
        "code": (
            "void insecure_copy(const char *src) {\n"
            "    char buf[16];\n"
            "    strcpy(buf, src); // no bounds check\n"
            "}\n"
            "\n"
            "int main() {\n"
            "    char input[256];\n"
            "    gets(input);\n"
            "    insecure_copy(input);\n"
            "    return 0;\n"
            "}"
        ),
        "target": "1",
        "description": "Classic buffer overflow via gets/strcpy.",
        "cwe_codes": ["CWE-120"],
    },
    {
        "id": "toy-sql-injection",
        "code": (
            "def fetch_user(conn, username):\n"
            '    query = f"SELECT * FROM users WHERE name = \'{username}\'"\n'
            "    return conn.execute(query)\n"
        ),
        "target": "1",
        "description": "SQL injection by string concatenation.",
        "cwe_codes": ["CWE-89"],
    },
    {
        "id": "toy-safe-loop",
        "code": (
            "#include <stddef.h>\n"
            "int sum(const int *arr, size_t len) {\n"
            "    int total = 0;\n"
            "    for (size_t i = 0; i < len; ++i) {\n"
            "        total += arr[i];\n"
            "    }\n"
            "    return total;\n"
            "}"
        ),
        "target": "0",
        "description": "Deliberately benign reference implementation.",
        "cwe_codes": [],
    },
]

DEFAULT_PROMPT = (
    "You are a security engineer. Determine if the following code contains a "
    "security vulnerability. Reply with only one word: 'vulnerable' if there "
    "is a vulnerability or 'benign' if it is safe.\n\n"
    "Code snippet:\n"
    "{code}\n\n"
    "Answer:"
)

CWE_SUFFIX = (
    "\n\nNow output only the CWE major category that best matches the vulnerability "
    "from the following list, or 'Benign' if it is safe:\n"
    f"{', '.join(CWE_MAJOR_CATEGORIES)}\n"
    "Response:"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify response parsing against real LLM outputs.")
    parser.add_argument(
        "--sample-file",
        type=str,
        help="Optional JSONL file to load samples from (falls back to built-in toy cases).",
    )
    parser.add_argument(
        "--max-samples",
        type=int,
        default=3,
        help="Number of samples to evaluate (default: 3).",
    )
    parser.add_argument(
        "--llm-type",
        type=str,
        default=os.getenv("LLM_TYPE", "openai"),
        help="Client type passed to create_llm_client (default: openai).",
    )
    parser.add_argument(
        "--model-name",
        type=str,
        default=os.getenv("MODEL_NAME"),
        help="Override MODEL_NAME; otherwise uses env or client default.",
    )
    parser.add_argument(
        "--api-base",
        type=str,
        default=os.getenv("API_BASE_URL"),
        help="Override API base URL for the client.",
    )
    parser.add_argument(
        "--api-key",
        type=str,
        default=os.getenv("API_KEY"),
        help="API key (falls back to env/.env).",
    )
    parser.add_argument(
        "--temperature",
        type=float,
        default=0.0,
        help="Decoding temperature for the LLM request.",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=32,
        help="Max tokens to sample per response.",
    )
    parser.add_argument(
        "--use-cwe-major",
        action="store_true",
        help="Enable CWE major category mode instead of binary labels.",
    )
    parser.add_argument(
        "--prompt-file",
        type=str,
        help="Optional text file containing a custom prompt template with {code}.",
    )
    parser.add_argument(
        "--output-json",
        type=str,
        help="Write detailed per-sample results to this JSON file.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print raw responses for easier debugging.",
    )
    parser.add_argument(
        "--mock-response",
        type=str,
        help="Skip real LLM calls and reuse this canned response for every sample (debug only).",
    )
    return parser.parse_args()


def load_prompt_template(prompt_file: Optional[str], use_cwe_major: bool) -> str:
    if prompt_file:
        template = Path(prompt_file).read_text(encoding="utf-8")
    else:
        template = DEFAULT_PROMPT

    if use_cwe_major:
        template = template.strip() + CWE_SUFFIX

    if "{code}" not in template:
        raise ValueError("Prompt template must contain '{code}' placeholder.")

    return template


def load_cases_from_jsonl(path: str, limit: int) -> List[Dict]:
    cases: List[Dict] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            item = json.loads(line)
            code = (
                item.get("code")
                or item.get("func")
                or item.get("input")
                or item.get("source")
                or ""
            )
            target = str(item.get("target", item.get("label", 0)))
            cwe = item.get("cwe") or item.get("cwe_ids") or []
            if isinstance(cwe, str):
                cwe = [cwe]

            cases.append(
                {
                    "id": str(item.get("idx") or len(cases)),
                    "code": code.strip(),
                    "target": target,
                    "description": item.get("commit_message") or item.get("desc"),
                    "cwe_codes": cwe,
                }
            )
            if len(cases) >= limit:
                break

    return cases


def build_cases(args: argparse.Namespace) -> List[Dict]:
    if args.sample_file:
        return load_cases_from_jsonl(args.sample_file, args.max_samples)

    return SIMPLE_CASES[: args.max_samples]


def compute_expected_major(case: Dict) -> str:
    if case.get("expected_major"):
        return case["expected_major"]

    cwe_codes = case.get("cwe_codes") or []
    if not cwe_codes:
        return "Benign" if case.get("target") in {"0", 0} else "Other"

    major = map_cwe_to_major(cwe_codes)
    return major or "Other"


def main():
    args = parse_args()
    load_env_vars()

    prompt_template = load_prompt_template(args.prompt_file, args.use_cwe_major)
    cases = build_cases(args)

    if not cases:
        raise SystemExit("No cases loaded.")

    if args.mock_response is None:
        client = create_llm_client(
            llm_type=args.llm_type,
            model_name=args.model_name,
            api_base=args.api_base,
            api_key=args.api_key,
        )
    else:
        client = None

    total = len(cases)
    correct = 0
    results = []

    print(f"Running parsing harness on {total} sample(s)...")

    for idx, case in enumerate(cases, start=1):
        filled_prompt = prompt_template.replace("{code}", case["code"])

        if args.mock_response is not None:
            response = args.mock_response
        else:
            response = client.generate(
                filled_prompt,
                temperature=args.temperature,
                max_tokens=args.max_tokens,
            )

        if args.use_cwe_major:
            parsed_label = extract_cwe_major(response)
            expected = compute_expected_major(case)
        else:
            parsed_label = extract_vulnerability_label(response)
            expected = str(case.get("target", "0"))

        is_correct = str(parsed_label) == str(expected)
        correct += int(is_correct)

        if args.verbose:
            print("-" * 60)
            print(f"[{idx}/{total}] case={case['id']}")
            print(f"Prompt:\n{filled_prompt}\n")
            print(f"Raw response:\n{response}\n")

        print(
            f"[{idx}/{total}] case={case['id']} "
            f"expected={expected} parsed={parsed_label} "
            f"{'✅' if is_correct else '❌'}"
        )

        results.append(
            {
                "case_id": case["id"],
                "expected": expected,
                "parsed": parsed_label,
                "raw_response": response,
                "prompt": filled_prompt,
                "description": case.get("description"),
                "cwe_codes": case.get("cwe_codes"),
            }
        )

    accuracy = correct / total if total else 0.0
    print(f"\nFinal accuracy: {accuracy:.2%} ({correct}/{total})")

    if args.output_json:
        output_path = Path(args.output_json)
        output_path.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Saved detailed results to {output_path}")


if __name__ == "__main__":
    main()

