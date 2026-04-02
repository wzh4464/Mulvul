#!/usr/bin/env python3
"""Generate balanced CWE subset for pairing ablation."""

import json
import random
import sys
from pathlib import Path
from collections import Counter

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from evoprompt.data.dataset import PrimevulDataset


def generate_balanced_cwe_subset(
    dataset: PrimevulDataset,
    n_cwes: int = 35,
    seed: int = 42
) -> list:
    """Select balanced CWE subset covering different frequencies.

    Args:
        dataset: PrimevulDataset to extract CWE frequencies from
        n_cwes: Target number of CWEs in subset
        seed: Random seed for reproducibility

    Returns:
        List of selected CWE IDs
    """
    random.seed(seed)

    # Count CWE frequencies
    cwe_counts = Counter()
    for sample in dataset.get_samples():
        cwes = sample.metadata.get('cwe', [])
        for cwe in cwes:
            cwe_counts[cwe] += 1

    # Sort by frequency
    sorted_cwes = sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True)

    # Stratified selection
    high_freq = [c for c, n in sorted_cwes if n >= 100][:20]
    medium_freq = [c for c, n in sorted_cwes if 10 <= n < 100]
    long_tail = [c for c, n in sorted_cwes if n < 10]

    # Select proportionally
    subset = []
    subset.extend(random.sample(high_freq, min(14, len(high_freq))))
    subset.extend(random.sample(medium_freq, min(14, len(medium_freq))))
    subset.extend(random.sample(long_tail, min(7, len(long_tail))))

    return subset[:n_cwes]


def main():
    dataset = PrimevulDataset("data/primevul/primevul/dev.jsonl", "train")

    subset = generate_balanced_cwe_subset(dataset, n_cwes=35, seed=42)

    output = {
        "cwes": subset,
        "n_cwes": len(subset),
        "seed": 42,
        "description": "Balanced CWE subset for cross-model pairing ablation"
    }

    output_path = Path("configs/cwe_subset_pairing.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)

    print(f"Generated CWE subset with {len(subset)} CWEs")
    print(f"Saved to: {output_path}")


if __name__ == "__main__":
    main()
