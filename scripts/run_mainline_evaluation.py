#!/usr/bin/env python3
"""First-class workflow: evaluate vulnerability detection with frozen prompts."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from evoprompt.mainline.ablations import list_supported_ablations  # noqa: E402
from evoprompt.mainline.workflows import (  # noqa: E402
    EvaluationWorkflowConfig,
    run_evaluation_workflow,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate the frozen router-detector system."
    )
    parser.add_argument("--eval-file", required=True)
    parser.add_argument("--prompts-path", required=True)
    parser.add_argument("--output-dir", default="./outputs/mainline/evaluation")
    parser.add_argument("--kb-path", default=None)
    parser.add_argument("--max-samples", type=int, default=None)
    parser.add_argument("--max-workers", type=int, default=8)
    parser.add_argument("--balanced", action="store_true")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--llm-type", default=None)
    parser.add_argument(
        "--ablation",
        action="append",
        default=[],
        choices=list_supported_ablations(),
    )
    args = parser.parse_args()

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
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
