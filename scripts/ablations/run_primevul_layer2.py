#!/usr/bin/env python3
"""Layer-2 refinement run that reuses Layer-1 PrimeVul prompts."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

# Ensure src/ is importable when launched from the repo root.
sys.path.insert(0, "src")

from evoprompt.data.sampler import sample_primevul_1percent
from evoprompt.workflows import VulnerabilityDetectionWorkflow


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Refine PrimeVul prompts using Layer-1 top_prompts.txt."
    )
    parser.add_argument(
        "--top-prompts",
        type=Path,
        default=None,
        help="Path to Layer-1 top_prompts.txt (falls back to LAYER1_TOP_PROMPTS env).",
    )
    parser.add_argument(
        "--sample-dir",
        type=Path,
        default=None,
        help="Directory containing the 1%% PrimeVul sample (default: data/primevul_1percent_sample).",
    )
    parser.add_argument(
        "--primevul-dir",
        type=Path,
        default=Path("data/primevul/primevul"),
        help="Source PrimeVul dataset directory used when regenerating samples.",
    )
    parser.add_argument(
        "--max-concurrency",
        type=int,
        default=8,
        help="Maximum concurrent LLM calls during refinement.",
    )
    parser.add_argument(
        "--population-size",
        type=int,
        default=10,
        help="Population size for the differential evolution.",
    )
    parser.add_argument(
        "--generations",
        type=int,
        default=6,
        help="Number of refinement generations.",
    )
    parser.add_argument(
        "--mutation-rate",
        type=float,
        default=0.12,
        help="Mutation rate for the differential evolution.",
    )
    parser.add_argument(
        "--crossover-probability",
        type=float,
        default=0.7,
        help="Crossover probability for the differential evolution.",
    )
    parser.add_argument(
        "--experiment-id",
        default=None,
        help="Optional experiment identifier (defaults to primevul_layer2_<timestamp>).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("outputs/primevul_layer2"),
        help="Directory where refinement artifacts are stored.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Optional JSON config to merge on top of the generated defaults.",
    )
    return parser.parse_args()


def normalize_path_arg(path: Optional[Path]) -> Optional[Path]:
    """Normalize optional Path arguments, treating empty strings as None."""
    if path is None:
        return None
    path_str = str(path).strip()
    if not path_str:
        return None
    return Path(path_str)


def resolve_top_prompts(args: argparse.Namespace) -> Path:
    """Figure out where top_prompts.txt lives."""
    top_prompts = args.top_prompts
    if top_prompts is None or str(top_prompts).strip() == "":
        env_path = os.getenv("LAYER1_TOP_PROMPTS")
        if env_path:
            top_prompts = Path(env_path)

    if top_prompts is None:
        raise ValueError(
            "Layer-2 refinement requires the path to Layer-1 top_prompts.txt. "
            "Provide --top-prompts or set LAYER1_TOP_PROMPTS."
        )

    top_prompts = Path(top_prompts).expanduser().resolve()
    if not top_prompts.exists():
        raise FileNotFoundError(f"top_prompts file not found: {top_prompts}")
    return top_prompts


def ensure_sample_data(sample_dir: Path, primevul_dir: Path) -> None:
    """Ensure the 1% PrimeVul sample exists before running refinement."""
    dev_file = sample_dir / "dev.txt"
    train_file = sample_dir / "train.txt"

    if dev_file.exists() and train_file.exists():
        return

    print("Rebuilding 1% PrimeVul sample for refinement...")
    sample_primevul_1percent(
        primevul_dir=str(primevul_dir),
        output_dir=str(sample_dir),
        seed=42,
    )


def build_default_config(args: argparse.Namespace, top_prompts: Path) -> Dict[str, Any]:
    """Construct the default refinement configuration."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    experiment_id = args.experiment_id or f"primevul_layer2_{timestamp}"
    sample_dir = args.sample_dir or Path("data/primevul_1percent_sample")
    sample_dir = Path(sample_dir).expanduser().resolve()

    ensure_sample_data(sample_dir, args.primevul_dir.expanduser().resolve())

    config: Dict[str, Any] = {
        "experiment_id": experiment_id,
        "experiment_name": "PrimeVul Layer-2 Refinement",
        "dataset": "primevul_layered",
        "dev_file": str(sample_dir / "dev.txt"),
        "test_file": str(sample_dir / "train.txt"),
        "algorithm": "de",
        "population_size": args.population_size,
        "max_generations": args.generations,
        "mutation_rate": args.mutation_rate,
        "crossover_probability": args.crossover_probability,
        "initial_prompts_file": str(top_prompts),
        "output_dir": str(args.output_dir.expanduser().resolve()),
        "llm_type": "gpt-3.5-turbo",
        "max_concurrency": args.max_concurrency,
        "force_async": True,
        "batch_evaluation": True,
        "enable_batch_processing": True,
        "use_cwe_major": False,
        "sample_size": None,
        "test_sample_size": None,
        "track_every_evaluation": True,
        "save_intermediate_results": True,
    }
    return config


def merge_config(
    base_config: Dict[str, Any], config_path: Path | None
) -> Dict[str, Any]:
    """Merge user-provided config overrides, keeping required keys intact."""
    if not config_path:
        return base_config

    config_path = config_path.expanduser().resolve()
    with config_path.open("r", encoding="utf-8") as handle:
        overrides = json.load(handle)

    merged = {**base_config, **overrides}

    # Guardrails: ensure required fields are preserved.
    merged["initial_prompts_file"] = base_config["initial_prompts_file"]
    merged.setdefault("dataset", base_config["dataset"])
    merged.setdefault("use_cwe_major", False)
    return merged


def main() -> int:
    args = parse_args()
    args.sample_dir = normalize_path_arg(args.sample_dir)
    args.top_prompts = normalize_path_arg(args.top_prompts)
    args.config = normalize_path_arg(args.config)
    args.primevul_dir = normalize_path_arg(args.primevul_dir) or Path(
        "data/primevul/primevul"
    )

    try:
        top_prompts = resolve_top_prompts(args)
    except (ValueError, FileNotFoundError) as exc:
        print(f"❌ {exc}")
        return 1

    try:
        config = build_default_config(args, top_prompts)
        config = merge_config(config, args.config)
    except Exception as exc:
        print(f"❌ Failed to prepare refinement config: {exc}")
        return 1

    print("PrimeVul Layer-2 Refinement")
    print("=" * 56)
    print(f"Experiment ID      : {config['experiment_id']}")
    print(f"Initial prompts    : {config['initial_prompts_file']}")
    print(f"Dev/Test splits    : {config['dev_file']} | {config['test_file']}")
    print(f"Output directory   : {config['output_dir']}")
    print(
        f"Population / Gen   : {config['population_size']} / {config['max_generations']}"
    )
    print(f"Max concurrency    : {config.get('max_concurrency', 'N/A')}")
    print(
        f"Mutation / Cross   : {config.get('mutation_rate')} / {config.get('crossover_probability')}"
    )
    print(f"CWE major enabled? : {config.get('use_cwe_major', False)}")

    workflow = VulnerabilityDetectionWorkflow(config)
    workflow.run_evolution()

    print("\nLayer-2 refinement complete.")
    print(f"📂 Results stored under: {workflow.exp_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
