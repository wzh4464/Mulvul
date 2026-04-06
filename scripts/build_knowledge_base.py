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


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build hierarchical KB from training JSONL."
    )
    parser.add_argument("--train-file", required=True)
    parser.add_argument("--output", default="data/primevul/knowledge_base.json")
    parser.add_argument("--samples-per-cwe", type=int, default=5)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--min-code-length", type=int, default=DEFAULT_MIN_CODE_LENGTH,
        help=f"Skip samples with code shorter than this (default: {DEFAULT_MIN_CODE_LENGTH})",
    )
    parser.add_argument(
        "--max-code-length", type=int, default=DEFAULT_MAX_CODE_LENGTH,
        help=f"Truncate code to this length (default: {DEFAULT_MAX_CODE_LENGTH})",
    )
    parser.add_argument(
        "--max-desc-length", type=int, default=DEFAULT_MAX_DESC_LENGTH,
        help=f"Truncate descriptions to this length (default: {DEFAULT_MAX_DESC_LENGTH})",
    )
    args = parser.parse_args()

    random.seed(args.seed)

    cwe_pool: dict[str, list[dict]] = defaultdict(list)
    with open(args.train_file, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            item = json.loads(line)
            if int(item.get("target", 0)) == 0:
                continue
            cwes = item.get("cwe", [])
            if not cwes:
                continue
            cwe = cwes[0] if isinstance(cwes, list) else cwes
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
        mid = CWE_TO_MIDDLE.get(cwe, "Other")
        maj = MIDDLE_TO_MAJOR.get(mid, "Logic")
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
    if fallback_count:
        print(f"Warning: {fallback_count} CWEs not in hierarchy, mapped to Other/Logic")
    print(f"Saved to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
