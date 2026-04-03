# CLAUDE.md

## Project Scope

Mulvul has exactly two first-class workflows:

1. Prompt evolution: evolve stage-specific prompts for the mainline cascade.
2. Frozen evaluation: load frozen prompts and measure end-to-end vulnerability detection.

Everything else is either an ablation or legacy code. That includes RAG, parallel
scoring, top-k routing, `scripts/ablations/`, and the older prompt systems under
`src/mulvul/prompts/` and non-mainline detectors. Do not relabel an ablation as
baseline just because it lives under `src/mulvul/mainline/`.

Large payload examples and JSON schemas live in `docs/mainline_contracts.md`.
`CLAUDE.md` is for defaults, invariants, and required validation only.

## Mainline Baseline Defaults

Mainline baseline means all of the following at once:

- Routing policy: `GreedyCascadePolicy`
- `top_k = 1` at major and middle stages
- No RAG
- No parallel scoring
- Evaluation uses frozen prompts only
- Evaluation input may be v1 artifact or v2 bundle, but runtime execution uses a normalized `PromptBundle`

`TopKCascadePolicy` is an ablation even though it lives in `src/mulvul/mainline/`.

## Non-negotiable Invariants

- `src/mulvul/data/cwe_hierarchy.py` is the only taxonomy source of truth for the executable mainline hierarchy.
- Only `MAJOR_TO_MIDDLE` and `MIDDLE_TO_CWE` are hand-maintained. `CWE_TO_MIDDLE` and `MIDDLE_TO_MAJOR` must be derived from them.
- `src/mulvul/agents/hierarchical_detector.py` and mainline runtime modules may consume taxonomy mappings, but must not redefine them.
- Evaluation may accept `prompt_artifact.json` or `prompt_bundle.json`, but execution always normalizes to `PromptBundle` before scoring.
- In v2 bundles, `node_id` is the stable machine-facing identifier; human-facing names belong in `display_name`.
- `Benign` terminates the cascade explicitly. Benign samples must serialize as `major="Benign", middle=null, cwe=null`.
- Changes to taxonomy, artifact schema, adapter behavior, or `ranking_v2` parsing require contract tests.
- In core training, routing, and evaluation logic, do not add broad catch-and-continue error handling. Boundary layers may use narrow exception handling for file I/O, network calls, JSON parsing, or endpoint fallback, but must preserve traceback and original context.

## Artifact Compatibility Rules

- Evolution emits both `prompt_artifact.json` and `prompt_bundle.json`.
- `prompt_artifact.json` is the v1 compatibility format. It is not a separate runtime.
- `prompt_bundle.json` is the v2 structured runtime format.
- Evaluation may load either format, but execution normalizes to `PromptBundle`.
- Schema examples and field-level contracts are documented in `docs/mainline_contracts.md`.

## Benign Semantics

- `Benign` is a terminal major-stage classification.
- If major routing returns `Benign`, the cascade stops immediately.
- For benign samples, `middle = null` and `cwe = null`.
- If a major node is accepted but no middle node is accepted, the final prediction stays at the major label and downstream fields remain `null`.
- If a middle node is accepted but no CWE node is accepted, the final prediction stays at the middle label and `cwe = null`.
- Evaluator middle and CWE metrics are computed only on non-benign samples.
- Binary metrics cover `Benign` vs `Vulnerable` separately from exact-label metrics.

## Required Tests by Change Type

- Taxonomy changes in `src/mulvul/data/cwe_hierarchy.py`:
  `uv run pytest tests/test_cwe_hierarchy.py`
- Runtime result-shape changes in `src/mulvul/mainline/system.py` or `src/mulvul/mainline/evaluator.py`:
  `uv run pytest tests/test_mainline_system.py tests/test_mainline_evaluator.py`
- Artifact or bundle changes in `src/mulvul/mainline/artifacts.py` or `src/mulvul/mainline/bundle.py`:
  `uv run pytest tests/test_mainline_artifact.py tests/test_mainline_bundle.py tests/test_mainline_system.py tests/test_mainline_workflows.py`
- Parser changes in `src/mulvul/mainline/scorer.py` or `ranking_v2` contract changes:
  `uv run pytest tests/test_mainline_scorer.py`
  If parser behavior changes materially, add or update golden-style parser cases in that test file.
- Policy changes in `src/mulvul/mainline/policy.py`:
  `uv run pytest tests/test_mainline_policy.py tests/test_mainline_system.py tests/test_mainline_evaluator.py`
- Workflow changes in `src/mulvul/mainline/workflows.py`:
  `uv run pytest tests/test_mainline_workflows.py tests/test_mainline_bundle.py tests/test_mainline_system.py tests/test_mainline_evaluator.py`

## Developer Commands

All Python commands run through `uv run`.

```bash
# Install dependencies
uv sync

# Mainline workflows
uv run python scripts/run_mainline_evolution.py --train-file <path> --output-dir <path>
uv run python scripts/run_mainline_evaluation.py --eval-file <path> --prompts-path <path>

# Tests
uv run pytest tests/
uv run pytest -m "not slow"
RUN_RESPONSE_PARSING_TESTS=1 uv run pytest tests/test_response_parsing.py

# Formatting and static checks
uv run black src tests
uv run isort src tests
uv run ruff check src
uv run mypy src
```
