#!/usr/bin/env python3
"""First-class workflow: evolve the best prompt for each stage."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from mulvul.mainline.workflows import (  # noqa: E402
    EvolutionWorkflowConfig,
    run_evolution_workflow,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evolve the best prompt for each router/detector stage."
    )
    parser.add_argument("--train-file", required=True)
    parser.add_argument("--output-dir", default="./outputs/mainline/evolution")
    parser.add_argument("--kb-path", default=None)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--samples-per-class", type=int, default=50)
    parser.add_argument("--max-workers", type=int, default=8)
    parser.add_argument("--llm-type", default=None)
    parser.add_argument("--phase1-only", action="store_true",
                        help="Run only Phase 1 (tournament), skip cascade eval and evolution")
    parser.add_argument("--elitism-threshold", type=float, default=0.5,
                        help="Nodes with F1 >= threshold skip mutation. Set to 1.1 to disable.")
    parser.add_argument("--no-constrained-mutation", action="store_true",
                        help="Allow full prompt rewriting instead of constrained mutation")
    args = parser.parse_args()

    summary = run_evolution_workflow(
        EvolutionWorkflowConfig(
            train_file=args.train_file,
            output_dir=args.output_dir,
            kb_path=args.kb_path,
            rounds=args.rounds,
            samples_per_class=args.samples_per_class,
            max_workers=args.max_workers,
            llm_type=args.llm_type,
            phase1_only=args.phase1_only,
            elitism_threshold=args.elitism_threshold,
            constrained_mutation=not args.no_constrained_mutation,
        )
    )
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
