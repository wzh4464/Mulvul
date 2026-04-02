#!/usr/bin/env python3
"""Run EvoPrompt tuning on the benchmark dataset stored in data/benchmark.json."""

import argparse
import json
import random
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Ensure the package imports resolve when executed from project root
sys.path.insert(0, "src")

from evoprompt.workflows import VulnerabilityDetectionWorkflow


def load_benchmark_entries(path: Path) -> List[Dict[str, Any]]:
    """Load benchmark entries from a JSON file."""
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)

    if isinstance(data, dict) and "data" in data:
        data = data["data"]

    if not isinstance(data, list):
        raise ValueError(f"Benchmark file must contain a list, got {type(data)}")

    return data


def split_entries(
    entries: List[Dict[str, Any]], ratio: float, seed: int
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Split entries into dev/test subsets using a reproducible shuffle."""
    if not entries:
        return [], []

    ratio = max(0.0, min(1.0, ratio))
    indices = list(range(len(entries)))
    rng = random.Random(seed)
    rng.shuffle(indices)

    dev_count = max(1, int(round(len(entries) * ratio)))
    dev_indices = indices[:dev_count]
    test_indices = indices[dev_count:]

    dev_subset = [entries[i] for i in dev_indices]
    test_subset = [entries[i] for i in test_indices] or [
        entries[i] for i in dev_indices
    ]
    return dev_subset, test_subset


def write_entries(entries: List[Dict[str, Any]], path: Path) -> None:
    """Persist a subset of benchmark entries as JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(entries, handle, ensure_ascii=False, indent=2)


def summarize(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute simple summary statistics for a split."""
    vulnerable = 0
    category_counts: Dict[str, int] = {}

    for item in entries:
        ground_truth = item.get("gt") or []
        if ground_truth:
            vulnerable += 1
            for issue in ground_truth:
                category = issue.get("category")
                if category:
                    category_counts[category] = category_counts.get(category, 0) + 1

    total = len(entries)
    return {
        "total": total,
        "vulnerable": vulnerable,
        "benign": total - vulnerable,
        "categories": category_counts,
    }


def build_config(
    dev_file: Path,
    test_file: Path,
    args: argparse.Namespace,
    timestamp: str,
) -> Dict[str, Any]:
    """Construct a workflow configuration dictionary."""
    experiment_id = args.experiment_id or f"benchmark_{timestamp}"
    config: Dict[str, Any] = {
        "experiment_id": experiment_id,
        "experiment_name": "Benchmark Dataset Prompt Tuning",
        "dataset": "benchmark",
        "dev_file": str(dev_file),
        "test_file": str(test_file),
        "algorithm": args.algorithm,
        "population_size": args.population,
        "max_generations": args.generations,
        "mutation_rate": args.mutation_rate,
        "crossover_probability": args.crossover,
        "sample_size": args.sample_size,
        "test_sample_size": args.test_sample_size,
        "llm_type": args.llm_type,
        "output_dir": str(args.output_dir),
        "use_cwe_major": not args.disable_cwe_major,
    }

    if args.initial_prompts:
        config["initial_prompts_file"] = str(args.initial_prompts)

    if args.algorithm == "ga":
        # Genetic algorithm expects crossover_rate terminology
        config["crossover_rate"] = args.crossover

    return config


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Tune prompts on the benchmark dataset"
    )
    parser.add_argument(
        "data_path",
        type=Path,
        help="Path to data/benchmark.json (or a similarly structured file)",
    )
    parser.add_argument(
        "--data-output-dir",
        type=Path,
        default=Path("data/vul_detection/benchmark"),
        help="Where to write the dev/test benchmark splits",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("outputs/benchmark"),
        help="Directory to store evolution artifacts",
    )
    parser.add_argument(
        "--dev-ratio",
        type=float,
        default=0.7,
        help="Fraction of data used for the dev/evolution split",
    )
    parser.add_argument(
        "--seed", type=int, default=42, help="Random seed for the split"
    )
    parser.add_argument(
        "--population",
        type=int,
        default=12,
        help="Population size for the evolutionary algorithm",
    )
    parser.add_argument(
        "--generations",
        type=int,
        default=8,
        help="Number of generations to evolve prompts",
    )
    parser.add_argument(
        "--mutation-rate",
        type=float,
        default=0.15,
        help="Mutation rate hyperparameter",
    )
    parser.add_argument(
        "--crossover",
        type=float,
        default=0.75,
        help="Crossover probability (DE) or rate (GA)",
    )
    parser.add_argument(
        "--algorithm",
        choices=["de", "ga"],
        default="de",
        help="Evolutionary algorithm to use",
    )
    parser.add_argument(
        "--llm-type",
        default="sven",
        help="LLM client type (matches create_llm_client options)",
    )
    parser.add_argument(
        "--sample-size",
        type=int,
        default=None,
        help="Limit the number of dev samples per evaluation (default: use all)",
    )
    parser.add_argument(
        "--test-sample-size",
        type=int,
        default=None,
        help="Limit the number of test samples when reporting (default: use all)",
    )
    parser.add_argument(
        "--initial-prompts",
        type=Path,
        default=None,
        help="Optional file containing initial prompts, one per line",
    )
    parser.add_argument(
        "--experiment-id",
        default=None,
        help="Set a custom experiment_id instead of auto-generating",
    )
    parser.add_argument(
        "--disable-cwe-major",
        action="store_true",
        help="Disable CWE major category supervision and fall back to binary labels",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    entries = load_benchmark_entries(args.data_path)
    dev_entries, test_entries = split_entries(entries, args.dev_ratio, args.seed)

    dev_file = args.data_output_dir / "dev.json"
    test_file = args.data_output_dir / "test.json"
    write_entries(dev_entries, dev_file)
    write_entries(test_entries, test_file)

    dev_stats = summarize(dev_entries)
    test_stats = summarize(test_entries)

    print("📊 Benchmark split summary:")
    print(
        f"   Dev:  {dev_stats['total']} samples | vulnerable {dev_stats['vulnerable']} | benign {dev_stats['benign']}"
    )
    print(
        f"   Test: {test_stats['total']} samples | vulnerable {test_stats['vulnerable']} | benign {test_stats['benign']}"
    )

    config = build_config(dev_file, test_file, args, timestamp)
    print("🧬 Starting benchmark tuning experiment...")
    print(f"   Experiment ID: {config['experiment_id']}")
    print(f"   Dev file:  {config['dev_file']}")
    print(f"   Test file: {config['test_file']}")

    workflow = VulnerabilityDetectionWorkflow(config)
    results = workflow.run_evolution()

    best_fitness = results.get("best_fitness")
    if best_fitness is not None:
        print(f"✅ Evolution completed. Best fitness: {best_fitness:.4f}")
    else:
        print("✅ Evolution completed.")

    best_prompt = results.get("best_prompt")
    if best_prompt:
        print("✨ Best prompt candidate:\n")
        print(best_prompt)


if __name__ == "__main__":
    main()
