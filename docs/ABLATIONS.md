# Ablations

Anything outside the two mainline workflows is an ablation or legacy experiment.

## Mainline Boundary

The only first-class workflows are:

1. `scripts/run_mainline_evolution.py`
2. `scripts/run_mainline_evaluation.py`

Everything else exists to compare against, extend, or stress that baseline.

## Supported Mainline Ablations

The frozen evaluation workflow currently exposes these named ablations:

- `rag`: inject retrieved evidence into stage prompts
- `parallel`: score same-stage candidates in parallel
- `topk-router`: route top-k candidates instead of greedy top-1

These are configured through `--ablation` on
`scripts/run_mainline_evaluation.py`.

## Legacy Script Area

`scripts/ablations/` contains older experiment runners and utilities. The
directory stays in the repository for comparison and reproduction, but it is
not the default interface to Mulvul.

The scripts there roughly fall into four groups:

- older end-to-end training and evaluation runners
- retrieval, multi-agent, and alternative detector experiments
- preprocessing and dataset conversion helpers
- debugging, verification, and plotting utilities

## NL-AST / comment4vul Preprocessing

The NL-AST preprocessing path is legacy ablation code.

Entry points:

- `scripts/ablations/preprocess_primevul_comment4vul.py`
- `scripts/ablations/test_preprocess_basic.py`

Prerequisites:

- Preferred: install the tree-sitter adapter
  - `uv add tree-sitter`
  - `uv run python -c "from mulvul.utils.parsertool_adapter import build_languages; build_languages()"`
- Historical fallback: provide the external `parserTool` dependency under the
  old `comment4vul/SymbolicRule` layout if you are reproducing that pipeline

This path is intentionally not documented beyond this summary because it is not
part of the mainline workflow.
