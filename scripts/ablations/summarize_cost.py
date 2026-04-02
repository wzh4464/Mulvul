#!/usr/bin/env python3
"""Summarize cost metrics from JSONL files.

Usage:
    uv run python scripts/ablations/summarize_cost.py outputs/cost/*.jsonl
"""

import json
import sys
from pathlib import Path
from typing import List, Dict
import statistics


def load_records(jsonl_files: List[Path]) -> Dict[str, List[Dict]]:
    """Load records grouped by method."""
    by_method = {}

    for filepath in jsonl_files:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    record = json.loads(line)
                    method = record.get("method", "unknown")
                    if method not in by_method:
                        by_method[method] = []
                    by_method[method].append(record)

    return by_method


def summarize_method(method: str, records: List[Dict]) -> str:
    """Generate summary for a method."""
    n = len(records)

    llm_calls = [r["llm_calls"] for r in records]
    retrieval_calls = [r["retrieval_calls"] for r in records]
    input_tokens = [r["input_tokens"] for r in records]
    output_tokens = [r["output_tokens"] for r in records]
    times = [r["time_ms"] for r in records]

    lines = [
        f"Method: {method}",
        f"  Samples: {n}",
        f"  Avg LLM calls: {statistics.mean(llm_calls):.2f}",
        f"  Avg retrieval calls: {statistics.mean(retrieval_calls):.2f}",
        f"  Avg input tokens: {statistics.mean(input_tokens):,.0f}",
        f"  Avg output tokens: {statistics.mean(output_tokens):,.0f}",
    ]

    if times:
        p50 = statistics.median(times)
        sorted_times = sorted(times)
        p90_idx = int(len(sorted_times) * 0.9)
        p90 = sorted_times[p90_idx] if p90_idx < len(sorted_times) else sorted_times[-1]
        lines.append(f"  Avg time: {statistics.mean(times):,.0f}ms (p50: {p50:,.0f}ms, p90: {p90:,.0f}ms)")

    return "\n".join(lines)


def main():
    if len(sys.argv) < 2:
        print("Usage: python summarize_cost.py <jsonl_files...>")
        sys.exit(1)

    files = [Path(f) for f in sys.argv[1:] if Path(f).exists()]
    if not files:
        print("No valid JSONL files found.")
        sys.exit(1)

    by_method = load_records(files)

    print("=" * 60)
    print("COST SUMMARY")
    print("=" * 60)

    for method, records in sorted(by_method.items()):
        print()
        print(summarize_method(method, records))

    print()
    print("=" * 60)


if __name__ == "__main__":
    main()
