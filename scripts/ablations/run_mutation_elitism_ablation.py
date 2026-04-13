#!/usr/bin/env python3
"""Ablation study: constrained mutation and elitism mechanisms.

Runs four experiment groups in parallel:
1. baseline: both enabled (constrained_mutation=True, elitism_threshold=0.5)
2. no_elitism: elitism disabled (elitism_threshold=1.1)
3. no_constrained: unconstrained mutation (constrained_mutation=False)
4. no_both: both disabled

Uses PrimeVul-Balanced-20 dataset with 5 evolution rounds.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

DATASET_PATH = PROJECT_ROOT / "data" / "primevul" / "primevul_balanced_20.jsonl"
DEFAULT_OUTPUT_BASE = PROJECT_ROOT / "outputs" / "ablations" / "mutation_elitism"


@dataclass
class AblationConfig:
    """Configuration for a single ablation experiment."""

    name: str
    elitism_threshold: float
    constrained_mutation: bool
    description: str


ABLATION_CONFIGS = [
    AblationConfig(
        name="baseline",
        elitism_threshold=0.5,
        constrained_mutation=True,
        description="Both enabled (default)",
    ),
    AblationConfig(
        name="no_elitism",
        elitism_threshold=1.1,  # No node can reach 1.1, effectively disabled
        constrained_mutation=True,
        description="Elitism disabled, constrained mutation enabled",
    ),
    AblationConfig(
        name="no_constrained",
        elitism_threshold=0.5,
        constrained_mutation=False,
        description="Elitism enabled, constrained mutation disabled",
    ),
    AblationConfig(
        name="no_both",
        elitism_threshold=1.1,
        constrained_mutation=False,
        description="Both disabled",
    ),
]


def run_single_experiment(
    config: AblationConfig,
    output_base: Path,
    rounds: int,
    samples_per_class: int,
    max_workers: int,
    llm_type: str | None,
) -> dict:
    """Run a single ablation experiment."""
    output_dir = output_base / config.name
    output_dir.mkdir(parents=True, exist_ok=True)

    # Clear any existing checkpoint to ensure fresh start
    checkpoint_path = output_dir / "checkpoint.json"
    if checkpoint_path.exists():
        checkpoint_path.unlink()
        print(f"[{config.name}] Cleared existing checkpoint")

    cmd = [
        sys.executable,
        str(PROJECT_ROOT / "scripts" / "run_mainline_evolution.py"),
        "--train-file", str(DATASET_PATH),
        "--output-dir", str(output_dir),
        "--rounds", str(rounds),
        "--samples-per-class", str(samples_per_class),
        "--max-workers", str(max_workers),
        "--elitism-threshold", str(config.elitism_threshold),
    ]

    if not config.constrained_mutation:
        cmd.append("--no-constrained-mutation")

    if llm_type:
        # Validate llm_type to prevent command injection
        if not isinstance(llm_type, str) or not llm_type.replace('-', '').replace('_', '').isalnum():
            raise ValueError(f"Invalid llm_type: {llm_type}. Must be alphanumeric with hyphens/underscores only.")
        cmd.extend(["--llm-type", llm_type])

    print(f"[{config.name}] Starting: {config.description}")
    print(f"[{config.name}] Command: {' '.join(cmd)}")

    start_time = datetime.now()

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=PROJECT_ROOT,
            env={**os.environ, "PYTHONPATH": str(PROJECT_ROOT / "src")},
        )

        elapsed = (datetime.now() - start_time).total_seconds()

        if result.returncode != 0:
            print(f"[{config.name}] FAILED after {elapsed:.1f}s")
            print(f"[{config.name}] stderr: {result.stderr[:500]}")
            return {
                "name": config.name,
                "status": "failed",
                "elapsed_seconds": elapsed,
                "error": result.stderr[:1000],
            }

        # Read summary from output file (stdout has diagnostic messages)
        summary_path = output_dir / "summary.json"
        try:
            with summary_path.open("r", encoding="utf-8") as f:
                summary = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"[{config.name}] Warning: could not read summary.json: {e}")
            summary = {"raw_output": result.stdout[:1000]}

        print(f"[{config.name}] COMPLETED in {elapsed:.1f}s")

        return {
            "name": config.name,
            "description": config.description,
            "status": "success",
            "elapsed_seconds": elapsed,
            "elitism_threshold": config.elitism_threshold,
            "constrained_mutation": config.constrained_mutation,
            "output_dir": str(output_dir),
            "summary": summary,
        }

    except Exception as e:
        elapsed = (datetime.now() - start_time).total_seconds()
        print(f"[{config.name}] ERROR: {e}")
        return {
            "name": config.name,
            "status": "error",
            "elapsed_seconds": elapsed,
            "error": str(e),
        }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run mutation/elitism ablation study (4 groups in parallel)"
    )
    parser.add_argument(
        "--output-base",
        type=Path,
        default=DEFAULT_OUTPUT_BASE,
        help="Base directory for ablation outputs",
    )
    parser.add_argument("--rounds", type=int, default=5, help="Evolution rounds")
    parser.add_argument(
        "--samples-per-class", type=int, default=30, help="Samples per class"
    )
    parser.add_argument(
        "--max-workers", type=int, default=4, help="Workers per experiment"
    )
    parser.add_argument(
        "--parallel-experiments",
        type=int,
        default=2,
        help="Number of experiments to run in parallel",
    )
    parser.add_argument("--llm-type", default=None, help="LLM type override")
    args = parser.parse_args()

    # Create output directory with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_base = args.output_base / timestamp
    output_base.mkdir(parents=True, exist_ok=True)

    print(f"Ablation study: mutation/elitism mechanisms")
    print(f"Dataset: {DATASET_PATH}")
    print(f"Output: {output_base}")
    print(f"Rounds: {args.rounds}, Samples/class: {args.samples_per_class}")
    print(f"Parallel experiments: {args.parallel_experiments}")
    print(f"Workers per experiment: {args.max_workers}")
    print()

    # Save experiment config
    config_path = output_base / "ablation_config.json"
    with config_path.open("w") as f:
        json.dump(
            {
                "timestamp": timestamp,
                "dataset": str(DATASET_PATH),
                "rounds": args.rounds,
                "samples_per_class": args.samples_per_class,
                "max_workers": args.max_workers,
                "parallel_experiments": args.parallel_experiments,
                "experiments": [
                    {
                        "name": c.name,
                        "description": c.description,
                        "elitism_threshold": c.elitism_threshold,
                        "constrained_mutation": c.constrained_mutation,
                    }
                    for c in ABLATION_CONFIGS
                ],
            },
            f,
            indent=2,
        )

    results = []
    start_all = datetime.now()

    with ProcessPoolExecutor(max_workers=args.parallel_experiments) as executor:
        futures = {
            executor.submit(
                run_single_experiment,
                config,
                output_base,
                args.rounds,
                args.samples_per_class,
                args.max_workers,
                args.llm_type,
            ): config
            for config in ABLATION_CONFIGS
        }

        for future in as_completed(futures):
            config = futures[future]
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                print(f"[{config.name}] Exception: {e}")
                results.append(
                    {
                        "name": config.name,
                        "status": "exception",
                        "error": str(e),
                    }
                )

    total_elapsed = (datetime.now() - start_all).total_seconds()

    # Save all results
    results_path = output_base / "ablation_results.json"
    with results_path.open("w") as f:
        json.dump(
            {
                "timestamp": timestamp,
                "total_elapsed_seconds": total_elapsed,
                "results": results,
            },
            f,
            indent=2,
            ensure_ascii=False,
        )

    # Print summary
    print()
    print("=" * 60)
    print("ABLATION STUDY COMPLETE")
    print("=" * 60)
    print(f"Total time: {total_elapsed:.1f}s")
    print()

    for r in sorted(results, key=lambda x: x["name"]):
        status = r.get("status", "unknown")
        elapsed = r.get("elapsed_seconds", 0)
        print(f"  {r['name']}: {status} ({elapsed:.1f}s)")

    print()
    print(f"Results saved to: {results_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
