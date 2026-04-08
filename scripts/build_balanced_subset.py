#!/usr/bin/env python3
"""Build the PrimeVul-Balanced-20 subset for ablation experiments.

Reads primevul_train.jsonl, keeps CWEs with >= 50 vulnerable samples,
samples 50 vulnerable per eligible CWE, adds 1000 benign samples,
shuffles, and writes to primevul_balanced_20.jsonl.
"""

from __future__ import annotations

import json
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, "src")

from mulvul.data.cwe_hierarchy import CWE_TO_MIDDLE, MIDDLE_TO_MAJOR

SEED = 42
VULN_PER_CWE = 50
MIN_SAMPLES = 50
BENIGN_COUNT = 1000

INPUT_PATH = Path("data/primevul/primevul/primevul_train.jsonl")
OUTPUT_PATH = Path("data/primevul/primevul_balanced_20.jsonl")


def main() -> None:
    # ---- Load all records ----
    records: list[dict] = []
    with INPUT_PATH.open() as f:
        for line in f:
            records.append(json.loads(line))

    # ---- Separate vulnerable and benign ----
    vuln_by_cwe: dict[str, list[dict]] = defaultdict(list)
    benign: list[dict] = []

    for rec in records:
        if rec["target"] == 1:
            # Use the first CWE in the list as the primary CWE
            primary_cwe = rec["cwe"][0] if rec["cwe"] else None
            if primary_cwe:
                vuln_by_cwe[primary_cwe].append(rec)
        else:
            benign.append(rec)

    # ---- Count and filter CWEs with >= 50 samples ----
    cwe_counts = {cwe: len(samples) for cwe, samples in vuln_by_cwe.items()}
    eligible_cwes = sorted(
        [cwe for cwe, count in cwe_counts.items() if count >= MIN_SAMPLES]
    )

    print(f"Total records: {len(records)}")
    print(f"Total vulnerable: {sum(cwe_counts.values())}")
    print(f"Total benign: {len(benign)}")
    print(f"Unique CWEs in vulnerable set: {len(cwe_counts)}")
    print(f"CWEs with >= {MIN_SAMPLES} samples: {len(eligible_cwes)}")
    print()

    # ---- Print CWE distribution ----
    print("Eligible CWEs:")
    for cwe in eligible_cwes:
        middle = CWE_TO_MIDDLE.get(cwe, "Unknown")
        major = MIDDLE_TO_MAJOR.get(middle, "Unknown")
        print(f"  {cwe:>8s}  ({cwe_counts[cwe]:>4d} samples)  ->  {middle:<25s}  ->  {major}")
    print()

    # ---- Sample 50 per eligible CWE ----
    rng = random.Random(SEED)
    selected: list[dict] = []

    for cwe in eligible_cwes:
        pool = vuln_by_cwe[cwe]
        sampled = rng.sample(pool, VULN_PER_CWE)
        selected.extend(sampled)

    # ---- Sample 1000 benign ----
    benign_sampled = rng.sample(benign, BENIGN_COUNT)
    selected.extend(benign_sampled)

    # ---- Shuffle ----
    rng.shuffle(selected)

    # ---- Write output ----
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_PATH.open("w") as f:
        for rec in selected:
            f.write(json.dumps(rec) + "\n")

    print(f"Written {len(selected)} samples to {OUTPUT_PATH}")

    # ---- Verify hierarchy coverage ----
    middle_set: set[str] = set()
    major_set: set[str] = set()
    cwe_set: set[str] = set()

    for rec in selected:
        if rec["target"] == 1:
            primary_cwe = rec["cwe"][0]
            cwe_set.add(primary_cwe)
            middle = CWE_TO_MIDDLE.get(primary_cwe, "Unknown")
            middle_set.add(middle)
            major = MIDDLE_TO_MAJOR.get(middle, "Unknown")
            major_set.add(major)

    major_set.add("Benign")  # benign samples contribute to major

    print()
    print("Hierarchy coverage in output:")
    print(f"  Majors ({len(major_set)}): {sorted(major_set)}")
    print(f"  Middles ({len(middle_set)}): {sorted(middle_set)}")
    print(f"  CWEs ({len(cwe_set)}): {sorted(cwe_set)}")

    # ---- Final stats ----
    vuln_count = sum(1 for r in selected if r["target"] == 1)
    benign_count = sum(1 for r in selected if r["target"] == 0)
    print()
    print(f"Final breakdown: {vuln_count} vulnerable + {benign_count} benign = {len(selected)} total")


if __name__ == "__main__":
    main()
