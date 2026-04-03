<p align="center">
  <img src="https://img.shields.io/badge/Mulvul-Prompt_Evolution_for_Vulnerability_Detection-0d1117?style=for-the-badge&labelColor=161b22" alt="Mulvul" />
</p>

<p align="center">
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.9+-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python 3.9+" /></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="MIT License" /></a>
  <a href="https://github.com/astral-sh/uv"><img src="https://img.shields.io/badge/pkg-uv-blueviolet?style=flat-square" alt="uv" /></a>
  <a href="https://github.com/wzh4464/Mulvul/issues"><img src="https://img.shields.io/badge/issues-GitHub-red?style=flat-square&logo=github" alt="Issues" /></a>
</p>

<p align="center">
  <b>Evolve LLM prompts. Detect real-world vulnerabilities. One cascade at a time.</b>
</p>

---

## What is Mulvul?

Mulvul uses **evolutionary algorithms** to optimize LLM prompts for source-code vulnerability detection. Instead of hand-tuning a single monolithic prompt, it evolves **stage-specific prompts** across a three-level taxonomy — then freezes the best ones and evaluates end-to-end detection performance.

```
              Code Sample
                  |
          [ Major Router ]          Memory | Injection | Logic | Input | Crypto | Benign
                  |
         [ Middle Detector ]        Buffer Errors | Memory Mgmt | Pointer Deref | ...
                  |
          [ CWE Classifier ]        CWE-119 | CWE-120 | CWE-416 | CWE-476 | ...
                  |
          Detection Result
```

The cascade scores candidates at each level, multiplies confidences across the path, and picks the most likely vulnerability — or classifies the sample as benign.

## Two Workflows, Nothing More

| # | Workflow | What it does | Entry point |
|:-:|:---------|:-------------|:------------|
| 1 | **Evolve** | Train the best prompt for every router and detector node | `scripts/run_mainline_evolution.py` |
| 2 | **Evaluate** | Freeze evolved prompts, measure detection accuracy | `scripts/run_mainline_evaluation.py` |

Everything else — RAG retrieval, parallel scoring, top-k routing — is an **ablation** layered on top.

## Quick Start

### Install

```bash
git clone https://github.com/wzh4464/Mulvul.git && cd Mulvul
uv sync
```

### Configure

Create a `.env` file:

```env
API_BASE_URL=https://api-inference.modelscope.cn/v1/
API_KEY=your-key-here
BACKUP_API_BASE_URL=https://newapi.aicohere.org/v1
MODEL_NAME=Qwen/Qwen3-Coder-480B-A35B-Instruct
```

Any OpenAI-compatible endpoint works. The client auto-falls back to `BACKUP_API_BASE_URL` if the primary fails.

### Run

```bash
# 1. Evolve prompts
uv run python scripts/run_mainline_evolution.py \
  --train-file data/primevul/primevul/primevul_train.jsonl \
  --output-dir outputs/mainline/evolution

# 2. Evaluate frozen prompts
uv run python scripts/run_mainline_evaluation.py \
  --eval-file data/primevul/primevul/primevul_valid.jsonl \
  --prompts-path outputs/mainline/evolution/prompt_artifact.json

# Or use the CLI
uv run mulvul evolve   --train-file <path> --output-dir <path>
uv run mulvul evaluate --eval-file <path> --prompts-path <path>
```

### Ablations

```bash
uv run python scripts/run_mainline_evaluation.py \
  --eval-file data/primevul/primevul/primevul_valid.jsonl \
  --prompts-path outputs/mainline/evolution/prompt_artifact.json \
  --ablation rag \
  --ablation parallel
```

Available ablations: `rag` (inject retrieved evidence), `parallel` (concurrent scoring), `topk-router` (explore top-k cascade paths).

## Taxonomy

<table>
<tr>
<th>Major (6)</th>
<th>Middle (13)</th>
<th>CWE (46 types)</th>
</tr>
<tr>
<td>

`Memory`<br>`Injection`<br>`Logic`<br>`Input`<br>`Crypto`<br>`Benign`

</td>
<td>

Buffer Errors, Memory Management,<br>
Pointer Dereference, Integer Errors,<br>
Injection, Concurrency Issues,<br>
Information Exposure, Resource Management,<br>
Access Control, Other,<br>
Path Traversal, Input Validation,<br>
Cryptography Issues

</td>
<td>

CWE-119, CWE-120, CWE-125,<br>
CWE-416, CWE-476, CWE-190,<br>
CWE-787, CWE-200, CWE-264,<br>
CWE-399, CWE-310, ...

</td>
</tr>
</table>

> Single source of truth: [`src/mulvul/data/cwe_hierarchy.py`](src/mulvul/data/cwe_hierarchy.py). Only `MAJOR_TO_MIDDLE` and `MIDDLE_TO_CWE` are hand-maintained; reverse maps are derived.

## Architecture

```
src/mulvul/
├── mainline/                 # First-class runtime
│   ├── bundle.py             # PromptBundle, TaxonomyGraph, NodeSpec (v2 format)
│   ├── artifacts.py          # PromptArtifact (v1 compatibility)
│   ├── scorer.py             # LLMNodeScorer — prompt rendering + ranking_v2 parsing
│   ├── policy.py             # GreedyCascadePolicy / TopKCascadePolicy
│   ├── system.py             # MainlineDetectorSystem — top-level detect()
│   ├── evaluator.py          # MainlineEvaluator — accuracy & F1 metrics
│   ├── workflows.py          # End-to-end workflow orchestration
│   └── ablations.py          # AblationConfig (rag, parallel, topk-router)
├── agents/                   # Training & sampling
│   ├── hierarchical_trainer.py
│   ├── hierarchical_detector.py
│   └── hierarchical_sampler.py
├── data/                     # Taxonomy & dataset loading
│   └── cwe_hierarchy.py      # The taxonomy source of truth
├── llm/                      # LLM client abstraction
│   └── client.py             # OpenAI-compatible, auto-fallback
├── rag/                      # Retrieval (ablation only)
│   └── retriever.py
└── cli.py                    # `mulvul evolve` / `mulvul evaluate`
```

### Prompt Artifact Flow

```
 Evolution                              Evaluation
 ─────────                              ──────────
 HierarchicalSampler                    Load v1 or v2
       │                                      │
 HierarchicalTrainer                    PromptBundleAdapter
   (N rounds × stage)                   (normalize → PromptBundle)
       │                                      │
  PromptArtifact (v1)  ──────────►    MainlineDetectorSystem
  PromptBundle   (v2)                    ├─ LLMNodeScorer
                                         ├─ CascadePolicy
                                         └─ detect(code) → result
                                              │
                                       MainlineEvaluator
                                         └─ accuracy, F1
```

## Datasets

| Dataset | Scale | Location |
|:--------|:------|:---------|
| **PrimeVul** | 24,000+ samples | `data/primevul/primevul/` |
| **SVEN** | 9 CWE types | `data/vul_detection/sven/` |

Expected JSONL format:

```json
{"func": "void f(char *src) { char buf[8]; strcpy(buf, src); }", "target": 1, "cwe": ["CWE-120"]}
{"func": "int add(int a, int b) { return a + b; }", "target": 0, "cwe": []}
```

## Development

```bash
# Tests
uv run pytest tests/                    # all
uv run pytest tests/test_mainline_system.py::TestMainlineDetectorSystem::test_detect  # one

# Formatting & linting
uv run black src tests
uv run isort src tests
uv run ruff check src
uv run mypy src
```

Detailed design invariants and contract specifications live in:
- [`CLAUDE.md`](CLAUDE.md) — defaults, invariants, required validation
- [`docs/mainline_contracts.md`](docs/mainline_contracts.md) — payload schemas and fail-fast rules
- [`docs/MAINLINE_ARCHITECTURE.md`](docs/MAINLINE_ARCHITECTURE.md) — workflow-level architecture

## License

[MIT](LICENSE)
