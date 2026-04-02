# Mainline Architecture

Mulvul is organized around exactly two first-class workflows.

## 1. Prompt Evolution

Goal: evolve the best prompt for every router and detector stage.

Primary entry points:

- `scripts/run_mainline_evolution.py`
- `src/mulvul/mainline/workflows.py`
- `src/mulvul/agents/hierarchical_trainer.py`

Core output:

- `prompt_artifact.json`
- `best_prompts.json`
- round-level training summaries

Design constraints:

- training produces stage-specific prompts, not one collapsed prompt
- `major_*`, `middle_*`, and `cwe_*` prompts remain first-class artifacts
- downstream evaluation must consume the same artifact shape produced here

## 2. Frozen Evaluation

Goal: load the evolved prompt artifact and measure end-to-end vulnerability
detection performance.

Primary entry points:

- `scripts/run_mainline_evaluation.py`
- `src/mulvul/mainline/system.py`
- `src/mulvul/mainline/workflows.py`

Design constraints:

- evaluation consumes the stage-level artifact directly
- router stages score major categories one-vs-rest
- detector stages score middle/CWE candidates one-vs-rest
- the final path is selected from the scored cascade, not rebuilt through a
  different architecture

## Repository Rule

When adding or keeping code, ask:

1. Does it improve stage-prompt evolution?
2. Does it improve frozen end-to-end evaluation?

If neither answer is yes, it belongs under ablation code rather than the
mainline interface. See [ABLATIONS.md](ABLATIONS.md).
