#!/usr/bin/env python3
"""First-class entry point for the mainline prompt-evolution workflow."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from mulvul.mainline.workflows import (
    EvolutionWorkflowConfig,
    run_evolution_workflow,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evolve the best prompt for each router/detector stage."
    )
    parser.add_argument("--train-file", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--samples-per-class", type=int, default=30)
    parser.add_argument("--max-workers", type=int, default=8)
    parser.add_argument("--llm-type", default=None)
    parser.add_argument("--population-size", type=int, default=5)
    parser.add_argument("--tournament-k", type=int, default=3)
    parser.add_argument("--migration-rate", type=float, default=0.2)
    parser.add_argument("--phase1-only", action="store_true",
                        help="Run only Phase 1 (tournament), skip cascade/evolution")
    parser.add_argument("--adaptive-hierarchy", action="store_true",
                        help="Build adaptive data-driven taxonomy from training data")
    parser.add_argument("--agentic", action="store_true",
                        help="Use agentic multi-turn detection with tool calling")
    args = parser.parse_args()

    taxonomy = None
    if args.adaptive_hierarchy:
        from mulvul.agents.adaptive_hierarchy import AdaptiveHierarchyBuilder
        builder = AdaptiveHierarchyBuilder()
        taxonomy = builder.build(args.train_file)
        print(
            f"Built adaptive hierarchy: depth={taxonomy.depth()}, "
            f"leaves={len(taxonomy.all_leaves())}"
        )

    config = EvolutionWorkflowConfig(
        train_file=args.train_file,
        output_dir=args.output_dir,
        rounds=args.rounds,
        samples_per_class=args.samples_per_class,
        max_workers=args.max_workers,
        llm_type=args.llm_type,
        population_size=args.population_size if hasattr(args, 'population_size') else 5,
        tournament_k=args.tournament_k if hasattr(args, 'tournament_k') else 3,
        migration_rate=args.migration_rate if hasattr(args, 'migration_rate') else 0.2,
        phase1_only=args.phase1_only,
        use_agentic=args.agentic,
    )
    summary = run_evolution_workflow(config, taxonomy=taxonomy)
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
