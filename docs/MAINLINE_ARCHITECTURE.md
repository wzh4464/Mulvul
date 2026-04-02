# Mainline Architecture

Mulvul should be read as a repository with exactly two first-class workflows.

## Mainline 1: Prompt Evolution

Goal: evolve the best prompt for every router/detector stage.

Code path:
- `src/evoprompt/mainline/workflows.py`
- `src/evoprompt/agents/hierarchical_trainer.py`
- `scripts/run_mainline_evolution.py`

Output:
- `best_prompts.json`
- `prompt_artifact.json`
- round-level training summaries

Design rule:
- The training artifact is stage-specific.
- Each `major_*`, `middle_*`, and `cwe_*` prompt is preserved as a first-class unit.
- We do not collapse stage-specific prompts back into a single monolithic prompt.

## Mainline 2: Frozen Evaluation

Goal: load the evolved prompt bundle and evaluate end-to-end vulnerability detection.

Code path:
- `src/evoprompt/mainline/system.py`
- `src/evoprompt/mainline/workflows.py`
- `scripts/run_mainline_evaluation.py`

Design rule:
- The evaluation system must consume the same stage-level prompt artifact produced by the evolution workflow.
- Router prompts are evaluated as one-vs-rest scorers over major categories.
- Detector prompts are evaluated as one-vs-rest scorers over middle/CWE categories.
- The final path is selected from the scored cascade, not reconstructed from a different architecture.

## What Counts As An Ablation

Everything beyond the two workflows above is an ablation on top of the same baseline.

Current ablation examples:
- `rag`: retrieval evidence injected into stage prompts
- `parallel`: same-stage prompt scoring in parallel
- `topk-router`: route top-k majors/middles instead of greedy top-1

Existing code that should be treated as ablation or legacy material:
- `src/evoprompt/agents/mulvul.py`
- `src/evoprompt/agents/router_agent.py`
- `src/evoprompt/agents/detector_agent.py`
- `src/evoprompt/detectors/rag_three_layer_detector.py`
- `src/evoprompt/detectors/topk_three_layer_detector.py`
- `src/evoprompt/detectors/parallel_hierarchical_detector.py`
- `main.py`
- `scripts/ablations/train_three_layer.py`
- `scripts/ablations/run_full_pipeline.py`
- `scripts/ablations/run_mulvul_eval.py`
- `scripts/ablations/run_mulvul_cwe_eval.py`

These can stay in the repository, but they should no longer define the repository structure.
They are comparison points, not the default mental model.

## Practical Rule For Future Changes

Any new feature must answer one question first:

1. Does it improve stage-prompt evolution?
2. Does it improve frozen end-to-end evaluation?

If neither is true, it belongs under ablation or experiment code, not the mainline.
