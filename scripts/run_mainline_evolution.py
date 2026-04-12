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
    parser.add_argument("--output-dir", default=None,
                        help="Output directory (default: auto-select based on --no-memory)")
    parser.add_argument("--kb-path", default=None)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--samples-per-class", type=int, default=50)
    parser.add_argument("--max-workers", type=int, default=8)
    parser.add_argument("--llm-type", default=None)
    parser.add_argument("--phase1-only", action="store_true",
                        help="Run only Phase 1 (tournament), skip cascade eval and evolution")
    parser.add_argument("--no-memory", action="store_true",
                        help="Disable evolution memory (for A/B testing)")
    args = parser.parse_args()

    # Auto-select output directory to prevent checkpoint contamination
    if args.output_dir is None:
        if args.no_memory:
            output_dir = "./outputs/mainline/evolution_no_memory"
        else:
            output_dir = "./outputs/mainline/evolution"
    else:
        output_dir = args.output_dir
        # Warn if using explicit output-dir with checkpoint that may have different memory setting
        checkpoint_path = Path(output_dir) / "checkpoint.json"
        if checkpoint_path.exists() and args.no_memory:
            print(
                f"WARNING: Checkpoint exists at {checkpoint_path}. "
                "Resuming with --no-memory may produce inconsistent results. "
                "Consider using a different --output-dir or deleting the checkpoint.",
                file=sys.stderr,
            )

    summary = run_evolution_workflow(
        EvolutionWorkflowConfig(
            train_file=args.train_file,
            output_dir=output_dir,
            kb_path=args.kb_path,
            rounds=args.rounds,
            samples_per_class=args.samples_per_class,
            max_workers=args.max_workers,
            llm_type=args.llm_type,
            phase1_only=args.phase1_only,
            use_memory=not args.no_memory,
        )
    )
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
