#!/usr/bin/env python3
"""A/B test: evolution WITH memory vs WITHOUT memory on balanced-20 dataset.

Usage:
    uv run python scripts/ablations/run_memory_ab_test.py [--rounds N] [--samples-per-class N]

    # With local LLM:
    uv run python scripts/ablations/run_memory_ab_test.py --rounds 5 --llm-type gemma4-31b-it-8bit-mlx \
        --api-base http://127.0.0.1:18082/v1 --api-key local-mlx
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from mulvul.mainline.workflows import (
    EvolutionWorkflowConfig,
    run_evolution_workflow,
)


def run_ab_test(
    rounds: int = 3,
    samples_per_class: int = 20,
    max_workers: int = 4,
    llm_type: str = None,
) -> dict:
    """Run A/B test comparing evolution with and without memory."""

    train_file = "data/primevul/primevul_balanced_20.jsonl"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_output_dir = Path("outputs/ablation_memory_ab")

    if llm_type:
        print(f"Using LLM: {llm_type}")

    results = {}

    # Arm A: WITH memory (control)
    print("=" * 60)
    print("ARM A: Evolution WITH memory")
    print("=" * 60)
    arm_a_dir = base_output_dir / f"{timestamp}_with_memory"
    arm_a_summary = run_evolution_workflow(
        EvolutionWorkflowConfig(
            train_file=train_file,
            output_dir=str(arm_a_dir),
            rounds=rounds,
            samples_per_class=samples_per_class,
            max_workers=max_workers,
            use_memory=True,
            llm_type=llm_type,
        )
    )
    results["with_memory"] = {
        "output_dir": str(arm_a_dir),
        "summary": arm_a_summary,
    }

    # Arm B: WITHOUT memory (treatment)
    print("=" * 60)
    print("ARM B: Evolution WITHOUT memory")
    print("=" * 60)
    arm_b_dir = base_output_dir / f"{timestamp}_no_memory"
    arm_b_summary = run_evolution_workflow(
        EvolutionWorkflowConfig(
            train_file=train_file,
            output_dir=str(arm_b_dir),
            rounds=rounds,
            samples_per_class=samples_per_class,
            max_workers=max_workers,
            use_memory=False,
            llm_type=llm_type,
        )
    )
    results["without_memory"] = {
        "output_dir": str(arm_b_dir),
        "summary": arm_b_summary,
    }

    # Compare results
    print("\n" + "=" * 60)
    print("A/B TEST COMPARISON")
    print("=" * 60)

    def extract_f1(summary: dict) -> float:
        """Extract average F1 from summary."""
        return summary.get("avg_f1", 0.0)

    f1_with = extract_f1(arm_a_summary)
    f1_without = extract_f1(arm_b_summary)
    delta = f1_with - f1_without

    print(f"With memory:    Avg F1 = {f1_with:.4f}")
    print(f"Without memory: Avg F1 = {f1_without:.4f}")
    print(f"Delta (memory effect): {delta:+.4f}")

    if delta > 0.01:
        print("RESULT: Memory improves evolution (+)")
    elif delta < -0.01:
        print("RESULT: Memory hurts evolution (-)")
    else:
        print("RESULT: No significant difference")

    # Save comparison report
    comparison = {
        "timestamp": timestamp,
        "config": {
            "train_file": train_file,
            "rounds": rounds,
            "samples_per_class": samples_per_class,
        },
        "results": results,
        "comparison": {
            "f1_with_memory": f1_with,
            "f1_without_memory": f1_without,
            "delta": delta,
        },
    }
    report_path = base_output_dir / f"{timestamp}_comparison.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(comparison, f, indent=2, ensure_ascii=False)
    print(f"\nFull report: {report_path}")

    return comparison


def main() -> int:
    parser = argparse.ArgumentParser(
        description="A/B test: evolution WITH vs WITHOUT memory on balanced-20"
    )
    parser.add_argument("--rounds", type=int, default=3, help="Evolution rounds")
    parser.add_argument("--samples-per-class", type=int, default=20)
    parser.add_argument("--max-workers", type=int, default=4)
    parser.add_argument("--llm-type", type=str, default=None,
                        help="LLM model name (e.g., gemma4-31b-it-8bit-mlx)")
    parser.add_argument("--api-base", type=str, default=None,
                        help="API base URL (e.g., http://127.0.0.1:18082/v1)")
    parser.add_argument("--api-key", type=str, default=None,
                        help="API key")
    args = parser.parse_args()

    # Override environment variables BEFORE any imports that load .env
    if args.api_base:
        os.environ["API_BASE_URL"] = args.api_base
        os.environ["OPENAI_API_BASE"] = args.api_base
    if args.api_key:
        os.environ["API_KEY"] = args.api_key
        os.environ["OPENAI_API_KEY"] = args.api_key

    run_ab_test(
        rounds=args.rounds,
        samples_per_class=args.samples_per_class,
        max_workers=args.max_workers,
        llm_type=args.llm_type,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
