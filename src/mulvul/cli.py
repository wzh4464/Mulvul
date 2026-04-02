"""Command-line interface for the two first-class Mulvul workflows."""

from __future__ import annotations

import argparse
import sys

from .mainline.ablations import list_supported_ablations
from .mainline.workflows import (
    EvaluationWorkflowConfig,
    EvolutionWorkflowConfig,
    run_evaluation_workflow,
    run_evolution_workflow,
)


def create_parser() -> argparse.ArgumentParser:
    """Create the top-level argument parser."""

    parser = argparse.ArgumentParser(
        description=(
            "Mulvul mainline CLI: evolve stage prompts, then evaluate the "
            "frozen router-detector system."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    evolve = subparsers.add_parser(
        "evolve",
        help="Evolve the best prompt for each router/detector stage.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    evolve.add_argument("--train-file", required=True, help="Training JSONL file.")
    evolve.add_argument("--output-dir", default="./outputs/mainline/evolution")
    evolve.add_argument("--kb-path", default=None, help="Optional knowledge base.")
    evolve.add_argument("--rounds", type=int, default=3)
    evolve.add_argument("--samples-per-class", type=int, default=50)
    evolve.add_argument("--max-workers", type=int, default=8)
    evolve.add_argument("--llm-type", default=None)

    evaluate = subparsers.add_parser(
        "evaluate",
        help="Evaluate the frozen prompt bundle on vulnerability detection.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    evaluate.add_argument("--eval-file", required=True, help="Evaluation JSONL file.")
    evaluate.add_argument(
        "--prompts-path",
        required=True,
        help="Prompt artifact or prompt bundle produced by the evolution workflow.",
    )
    evaluate.add_argument("--output-dir", default="./outputs/mainline/evaluation")
    evaluate.add_argument("--kb-path", default=None, help="Optional knowledge base.")
    evaluate.add_argument("--max-samples", type=int, default=None)
    evaluate.add_argument("--max-workers", type=int, default=8)
    evaluate.add_argument("--balanced", action="store_true")
    evaluate.add_argument("--seed", type=int, default=42)
    evaluate.add_argument("--llm-type", default=None)
    evaluate.add_argument(
        "--ablation",
        action="append",
        default=[],
        choices=list_supported_ablations(),
        help="Add a named ablation on top of the mainline system.",
    )
    return parser


def main() -> int:
    """CLI entry point."""

    parser = create_parser()
    args = parser.parse_args()

    try:
        if args.command == "evolve":
            summary = run_evolution_workflow(
                EvolutionWorkflowConfig(
                    train_file=args.train_file,
                    output_dir=args.output_dir,
                    kb_path=args.kb_path,
                    rounds=args.rounds,
                    samples_per_class=args.samples_per_class,
                    max_workers=args.max_workers,
                    llm_type=args.llm_type,
                )
            )
        else:
            summary = run_evaluation_workflow(
                EvaluationWorkflowConfig(
                    eval_file=args.eval_file,
                    prompts_path=args.prompts_path,
                    output_dir=args.output_dir,
                    kb_path=args.kb_path,
                    max_samples=args.max_samples,
                    max_workers=args.max_workers,
                    balanced=args.balanced,
                    seed=args.seed,
                    llm_type=args.llm_type,
                    ablations=args.ablation,
                )
            )
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
