#!/usr/bin/env python3
"""Build a hierarchical knowledge base from PrimeVul training data for RAG."""

from __future__ import annotations

import argparse
import json
import random
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from mulvul.data.cwe_hierarchy import CWE_TO_MIDDLE, MIDDLE_TO_MAJOR

DEFAULT_MIN_CODE_LENGTH = 50
DEFAULT_MAX_CODE_LENGTH = 2000
DEFAULT_MAX_DESC_LENGTH = 200
DEFAULT_FALLBACK_MIDDLE = "Unknown"
DEFAULT_FALLBACK_MAJOR = "Unknown"


def select_primary_cwe(cwes: list) -> str:
    """Select the primary CWE from a multi-CWE list.

    Policy: use the first CWE in the list.  PrimeVul orders CWEs by
    specificity (most specific first), so ``cwes[0]`` is typically the
    most precise label.  Samples are indexed only under this primary CWE
    to avoid double-counting in per-CWE sampling.
    """
    if isinstance(cwes, list):
        return str(cwes[0])
    return str(cwes)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build hierarchical KB from training JSONL."
    )
    parser.add_argument("--train-file", required=True)
    parser.add_argument("--output", default="data/primevul/knowledge_base.json")
    parser.add_argument("--samples-per-cwe", type=int, default=5)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--min-code-length",
        type=int,
        default=DEFAULT_MIN_CODE_LENGTH,
        help=f"Skip samples with code shorter than this (default: {DEFAULT_MIN_CODE_LENGTH})",
    )
    parser.add_argument(
        "--max-code-length",
        type=int,
        default=DEFAULT_MAX_CODE_LENGTH,
        help=f"Truncate code to this length (default: {DEFAULT_MAX_CODE_LENGTH})",
    )
    parser.add_argument(
        "--max-desc-length",
        type=int,
        default=DEFAULT_MAX_DESC_LENGTH,
        help=f"Truncate descriptions to this length (default: {DEFAULT_MAX_DESC_LENGTH})",
    )
    parser.add_argument(
        "--fallback-middle",
        default=DEFAULT_FALLBACK_MIDDLE,
        help=f"Middle category for unmapped CWEs (default: {DEFAULT_FALLBACK_MIDDLE})",
    )
    parser.add_argument(
        "--fallback-major",
        default=DEFAULT_FALLBACK_MAJOR,
        help=f"Major category for unmapped middles (default: {DEFAULT_FALLBACK_MAJOR})",
    )
    args = parser.parse_args()

    random.seed(args.seed)

    cwe_pool: dict[str, list[dict]] = defaultdict(list)
    parse_errors = 0
    with open(args.train_file, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                parse_errors += 1
                continue
            if int(item.get("target", 0)) == 0:
                continue
            cwes = item.get("cwe", [])
            if not cwes:
                continue
            cwe = select_primary_cwe(cwes)
            code = item.get("func", "")
            if len(code) < args.min_code_length:
                continue
            cwe_pool[cwe].append(
                {
                    "code": code[: args.max_code_length],
                    "cwe": cwe,
                    "description": item.get("cve_desc", "")[: args.max_desc_length],
                }
            )

    by_major: dict[str, list[dict]] = defaultdict(list)
    by_middle: dict[str, list[dict]] = defaultdict(list)
    by_cwe: dict[str, list[dict]] = defaultdict(list)
    fallback_count = 0

    for cwe, samples in cwe_pool.items():
        selected = random.sample(samples, min(args.samples_per_cwe, len(samples)))
        mid = CWE_TO_MIDDLE.get(cwe, args.fallback_middle)
        maj = MIDDLE_TO_MAJOR.get(mid, args.fallback_major)
        if cwe not in CWE_TO_MIDDLE:
            fallback_count += 1
        for s in selected:
            s["middle"] = mid
            s["major"] = maj
            by_cwe[cwe].append(s)
            by_middle[mid].append(s)
            by_major[maj].append(s)

    kb = {
        "by_major": dict(by_major),
        "by_middle": dict(by_middle),
        "by_cwe": dict(by_cwe),
    }

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(kb, f, ensure_ascii=False)

    total = sum(len(v) for v in by_cwe.values())
    print(
        f"KB: {len(by_cwe)} CWEs, {len(by_middle)} middles, "
        f"{len(by_major)} majors, {total} total samples"
    )
    if parse_errors:
        print(f"Warning: {parse_errors} lines skipped due to JSON parse errors")
    if fallback_count:
        print(
            f"Warning: {fallback_count} CWEs not in hierarchy, "
            f"mapped to {args.fallback_middle}/{args.fallback_major}"
        )
    print(f"Saved to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
