# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Mulvul is a prompt evolution framework for vulnerability detection. It uses evolutionary algorithms to optimize LLM prompts that classify code vulnerabilities through a three-level hierarchical cascade: Major categories (5) -> Middle categories (14) -> specific CWE IDs (100+).

The project has exactly **two first-class workflows**:
1. **Prompt Evolution** — train stage-specific prompts for each router/detector level
2. **Frozen Evaluation** — load the evolved prompt artifact and measure end-to-end detection

Everything else (RAG, parallel scoring, top-k routing) is an ablation layered on top of this baseline.

## Build & Run

All Python commands use `uv run`. The project uses `uv` for environment management with `hatchling` as build backend.

```bash
# Install dependencies
uv sync

# Run mainline evolution (train prompts)
uv run python scripts/run_mainline_evolution.py \
  --train-file data/primevul/primevul/primevul_train.jsonl \
  --output-dir outputs/mainline/evolution

# Run mainline evaluation (test frozen prompts)
uv run python scripts/run_mainline_evaluation.py \
  --eval-file data/primevul/primevul/primevul_valid.jsonl \
  --prompts-path outputs/mainline/evolution/prompt_artifact.json

# With ablations
uv run python scripts/run_mainline_evaluation.py \
  --eval-file data/primevul/primevul/primevul_valid.jsonl \
  --prompts-path outputs/mainline/evolution/prompt_artifact.json \
  --ablation rag --ablation parallel

# CLI entry point (installed as `mulvul` command)
uv run mulvul evolve --train-file <path> --output-dir <path>
uv run mulvul evaluate --eval-file <path> --prompts-path <path>
```

## Tests

```bash
# Run all tests
uv run pytest tests/

# Run a single test file
uv run pytest tests/test_mainline_system.py

# Run a specific test
uv run pytest tests/test_mainline_system.py::TestMainlineDetectorSystem::test_detect

# Response parsing tests require opt-in (they hit a real LLM)
RUN_RESPONSE_PARSING_TESTS=1 uv run pytest tests/test_response_parsing.py

# Markers: slow, integration, unit, asyncio
uv run pytest -m "not slow"
```

## Lint & Type Check

```bash
uv run ruff check src/
uv run mypy src/
```

Formatting uses black (line-length 88) and isort (profile "black"). Flake8 ignores E203 and W503.

## API Configuration

LLM access is configured via `.env` file (loaded automatically by `mulvul.llm.client.load_env_vars()`):

```env
API_BASE_URL=https://api-inference.modelscope.cn/v1/
API_KEY=your-key-here
BACKUP_API_BASE_URL=https://newapi.aicohere.org/v1
MODEL_NAME=Qwen/Qwen3-Coder-480B-A35B-Instruct
```

The client auto-falls back to `BACKUP_API_BASE_URL` if the primary fails.

## Architecture

### Three-Level Hierarchy

Defined in `src/mulvul/data/cwe_hierarchy.py` and `src/mulvul/agents/hierarchical_detector.py`:

```
Major (5): Memory, Injection, Logic, Input, Crypto  (+Benign for classification)
  └─ Middle (14): Buffer Errors, Memory Management, Injection, Concurrency Issues, ...
       └─ CWE (100+): CWE-119, CWE-416, CWE-476, ...
```

Mappings: `MAJOR_TO_MIDDLE`, `MIDDLE_TO_CWE` (forward), `CWE_TO_MIDDLE`, `MIDDLE_TO_MAJOR` (reverse).

### Detection Cascade (`src/mulvul/mainline/system.py`)

`MainlineDetectorSystem` runs a router-detector cascade:
1. Score all 5+1 major detectors on the code sample
2. If top confidence < `decision_threshold`, return Benign
3. For top-k major candidates, score their child middle detectors
4. For top-k middle candidates, score their child CWE detectors
5. Build all candidate `DetectionPath`s (major * middle * cwe confidence), pick the best

Each detector is a `LevelDetector` that fills a prompt template with code, calls the LLM, and parses a confidence ranking from the response.

### Prompt Artifacts (`src/mulvul/mainline/artifacts.py`)

`PromptArtifact` stores stage-specific prompts keyed by prefix:
- `major_Memory`, `major_Injection`, ... (router prompts)
- `middle_Buffer Errors`, ... (middle prompts)
- `cwe_CWE-119`, ... (CWE prompts)

Serialized as `prompt_artifact.json`. Evolution produces it, evaluation consumes it.

### Key Module Roles

| Module | Purpose |
|---|---|
| `mainline/workflows.py` | Orchestrates the two workflows end-to-end |
| `mainline/system.py` | Frozen evaluation cascade (`MainlineDetectorSystem`) |
| `mainline/artifacts.py` | `PromptArtifact` load/save |
| `mainline/ablations.py` | Named ablation configs (rag, parallel, topk-router) |
| `agents/hierarchical_trainer.py` | `HierarchicalTrainer` — trains prompts per level with feedback |
| `agents/hierarchical_detector.py` | `LevelDetector` — single-level detector with hierarchy maps |
| `agents/hierarchical_sampler.py` | `HierarchicalSampler` — 1:1:1 balanced sampling by level |
| `llm/client.py` | `LLMClient` ABC, `SVENLLMClient`, `create_llm_client()` factory |
| `rag/retriever.py` | `MulVulRetriever` — code similarity retrieval (ablation only) |
| `data/cwe_hierarchy.py` | Canonical hierarchy mappings and helper functions |
| `cli.py` | CLI entry point with `evolve` and `evaluate` subcommands |

### Script Layout

- `scripts/run_mainline_evolution.py` and `scripts/run_mainline_evaluation.py` — the two mainline entry points
- `scripts/ablations/` — legacy experiments, demos, preprocessing, plotting (not the default interface)

## Design Rules

- When adding code, ask: does it improve stage-prompt evolution or frozen evaluation? If neither, it belongs under `scripts/ablations/`, not the mainline.
- Training produces **stage-specific** prompts (one per major/middle/CWE), not a single collapsed prompt.
- Evaluation consumes the exact `prompt_artifact.json` shape produced by evolution.
- Avoid `try/except` during development — let exceptions propagate with full tracebacks. Only add error handling for user-facing tolerance or graceful fallback.
