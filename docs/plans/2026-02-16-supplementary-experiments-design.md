# MulVul Supplementary Experiments Design

**Date:** 2026-02-16
**Status:** Approved
**Approach:** Integrated Extension (Approach 2)

## Overview

This design covers supplementary experiments for paper revision addressing reviewer concerns:
1. Fair GPT-4o+RAG single-pass baseline (Reviewer C #1)
2. Single-Agent+Tool+RAG baseline (Reviewer B, strengthens C)
3. Cross-Model Prompt Evolution pairing ablation (Reviewer C #3)
4. Clean pool size sensitivity (Reviewer R1)
5. Cost/latency/token accounting (Reviewer R1 + C #2)

**Key Decisions:**
- Use full PrimeVul dataset (71 CWEs)
- Use `CodeSimilarityRetriever` extended with SCALE-style contrastive retrieval
- Use `ParallelHierarchicalDetector` as the MulVul baseline equivalent

---

## Section 1: Contrastive Retriever Extension

### 1.1 KnowledgeBase Changes (`src/evoprompt/rag/knowledge_base.py`)

```python
@dataclass
class KnowledgeBase:
    # Existing fields...
    major_examples: Dict[str, List[CodeExample]]
    middle_examples: Dict[str, List[CodeExample]]
    cwe_examples: Dict[str, List[CodeExample]]

    # NEW: Clean/benign pool for contrastive retrieval
    clean_examples: List[CodeExample] = field(default_factory=list)
```

**Builder changes:**
- Add `add_clean_example(code, description)` method
- Add `build_clean_pool_from_dataset(dataset, max_samples)` to sample benign code from training data

### 1.2 Retriever Changes (`src/evoprompt/rag/retriever.py`)

```python
class CodeSimilarityRetriever:
    def __init__(
        self,
        knowledge_base: KnowledgeBase,
        contrastive: bool = False,  # NEW
        clean_pool_frac: float = 1.0,  # NEW: for sensitivity experiment
        debug: bool = False
    ):
        self.contrastive = contrastive
        self.clean_pool_frac = clean_pool_frac
        self._subsampled_clean_pool = None  # Lazily computed

    def retrieve_contrastive(
        self,
        query_code: str,
        vulnerable_top_k: int = 2,
        clean_top_k: int = 1
    ) -> RetrievalResult:
        """Retrieve both vulnerable AND clean examples for contrast."""
```

**Evidence formatting with IDs:**
```
[VUL-1] Category: Memory | CWE: CWE-119
Code: <vulnerable code>
Description: Buffer overflow due to unchecked memcpy

[CLEAN-1] Category: Benign
Code: <safe code>
Description: Properly bounds-checked buffer operation
```

---

## Section 2: Cost Tracking

### 2.1 New `CostTracker` class (`src/evoprompt/utils/cost_tracker.py`)

```python
@dataclass
class CostRecord:
    sample_id: str
    method: str
    llm_calls: int = 0
    retrieval_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    time_ms: float = 0.0
    llm_call_details: List[Dict] = field(default_factory=list)

class CostTracker:
    def __init__(self, output_path: Path):
        self.output_path = output_path
        self._current_sample: Optional[CostRecord] = None

    def start_sample(self, sample_id: str, method: str) -> None
    def log_llm_call(self, model: str, in_tokens: int, out_tokens: int, time_ms: float) -> None
    def log_retrieval_call(self, top_k: int, time_ms: float) -> None
    def end_sample(self) -> CostRecord
```

### 2.2 LLM Client Integration

Modify `AsyncLLMClient._query_single` and `OpenAICompatibleClient._make_request` to:
- Extract token usage from `response.usage` (OpenAI-compatible)
- Accept optional `cost_tracker` parameter
- Log calls when tracker provided

### 2.3 Summary Script (`scripts/ablations/summarize_cost.py`)

Output format:
```
Method: gpt4o_rag_singlepass
  Samples: 1907
  Avg LLM calls: 1.00
  Avg retrieval calls: 1.00
  Avg input tokens: 2,450
  Avg output tokens: 85
  Avg time: 1,250ms (p50: 1,100ms, p90: 2,100ms)
```

---

## Section 3: Baselines

### 3.1 Baseline A: GPT-4o + RAG Single-Pass

**Flag:** `--method gpt4o_rag_singlepass`

- Single LLM call per sample with contrastive RAG evidence
- Uses same retrieval budget as MulVul detector layer

**Prompt:**
```
You are a security code auditor. Follow the output format exactly.

Given the following C/C++ code and retrieved vulnerability knowledge evidence,
decide whether the code contains a vulnerability and identify the most likely CWE type.

Constraints:
- Use ONLY the retrieved evidence and the code. If evidence is insufficient, output "NONE".
- Do NOT guess. Prefer "NONE" when uncertain.
- Output must be JSON with keys: "cwe", "rationale", "evidence_ids"

[CODE]
{code_snippet}

[EVIDENCE]
{packed_evidence_with_ids}
```

### 3.2 Baseline B: Single-Agent + Tool + RAG (ReAct-style)

**Flag:** `--method single_agent_tool_rag`

- Agent can call `SEARCH(query, top_k)` tool up to N times (default 2)
- Final output in same JSON format

**Prompt:**
```
You are a security code auditor with access to a retrieval tool.

Task: Identify the most likely CWE type for the given code (or "NONE" if no vulnerability).

You may call the tool:
- SEARCH(query, top_k) - searches vulnerability knowledge base

Rules:
- At most 2 tool calls.
- Final answer must be JSON with keys: "cwe", "rationale", "evidence_ids"

Code:
{code_snippet}
```

---

## Section 4: Cross-Model Prompt Evolution Pairing Ablation

### 4.1 Configuration Flags

```python
--evo-generator-model {claude,gpt4o}  # Model for generating prompt mutations
--evo-executor-model {claude,gpt4o}   # Model for executing/evaluating prompts
--evo-cwe-subset PATH                 # JSON file with CWE subset
```

### 4.2 CWE Subset Selection

Create `configs/cwe_subset_pairing.json` with ~35 CWEs:
- 40% high-frequency (Memory: CWE-119, CWE-125, CWE-476)
- 40% medium-frequency (Logic: CWE-287, CWE-862)
- 20% long-tail (Crypto: CWE-327, CWE-330)

Deterministic selection with seed=42.

### 4.3 Pairings to Test

| Pairing | Generator | Executor |
|---------|-----------|----------|
| MulVul (current) | Claude | GPT-4o |
| Same-model ablation | GPT-4o | GPT-4o |

### 4.4 Output Structure

```
outputs/evo_prompts/
├── claude_to_gpt4o/
│   ├── evolution_log.jsonl
│   ├── best_prompts.json
│   └── metrics.json
├── gpt4o_to_gpt4o/
│   └── ...
└── subset_definition.json
```

---

## Section 5: Clean Pool Size Sensitivity

### 5.1 Configuration

```python
--clean-pool-frac {0.1,0.25,0.5,1.0}  # Fraction of clean pool to use
```

### 5.2 Deterministic Subsampling

```python
def _subsample_clean_pool(self, seed: int = 42) -> List[CodeExample]:
    """Deterministically subsample clean pool."""
    rng = random.Random(seed)
    n_samples = int(len(self.kb.clean_examples) * self.clean_pool_frac)
    return rng.sample(self.kb.clean_examples, n_samples)
```

### 5.3 Output Table

```
Fraction | Pool Size | Macro-F1 | Precision | FP Rate
---------|-----------|----------|-----------|--------
0.10     |       500 |   0.421  |    0.65   |  0.12
0.25     |     1,250 |   0.445  |    0.68   |  0.10
0.50     |     2,500 |   0.458  |    0.71   |  0.08
1.00     |     5,000 |   0.462  |    0.72   |  0.07
```

---

## Section 6: Output Artifacts

### 6.1 Method Flag

```python
--method {mulvul, gpt4o_rag_singlepass, single_agent_tool_rag,
          gpt4o_no_rag, clean_pool_sensitivity, pairing_ablation}
```

### 6.2 Output Directory Structure

```
outputs/supplementary_experiments/
├── cost/
│   ├── gpt4o_no_rag.jsonl
│   ├── gpt4o_rag_singlepass.jsonl
│   ├── single_agent_tool_rag.jsonl
│   └── mulvul.jsonl
├── metrics/
│   ├── baseline_comparison.json
│   ├── pairing_ablation.json
│   └── clean_pool_sensitivity.json
├── evo_prompts/
│   ├── claude_to_gpt4o/
│   └── gpt4o_to_gpt4o/
├── configs/
│   └── cwe_subset_pairing.json
├── cost_summary.txt
└── rebuttal_snippet.md
```

### 6.3 Example Commands

```bash
# Baseline A: GPT-4o + RAG single-pass
uv run python scripts/ablations/train_three_layer.py --method gpt4o_rag_singlepass --top-k 3

# Baseline B: Single-Agent + Tool + RAG
uv run python scripts/ablations/train_three_layer.py --method single_agent_tool_rag --max-tool-calls 2

# Cross-model pairing ablation
uv run python scripts/ablations/train_three_layer.py --method pairing_ablation \
    --evo-generator-model claude --evo-executor-model gpt4o \
    --evo-cwe-subset configs/cwe_subset_pairing.json

uv run python scripts/ablations/train_three_layer.py --method pairing_ablation \
    --evo-generator-model gpt4o --evo-executor-model gpt4o \
    --evo-cwe-subset configs/cwe_subset_pairing.json

# Clean pool sensitivity
uv run python scripts/ablations/train_three_layer.py --method clean_pool_sensitivity

# Generate cost summary
uv run python scripts/ablations/summarize_cost.py outputs/supplementary_experiments/cost/*.jsonl

# Generate rebuttal snippet
uv run python scripts/ablations/generate_rebuttal_snippet.py outputs/supplementary_experiments/
```

---

## Acceptance Criteria

- [ ] Contrastive retriever with clean pool support
- [ ] Cost tracking in LLM clients with JSONL output
- [ ] GPT-4o+RAG single-pass baseline working
- [ ] Single-Agent+Tool+RAG baseline working
- [ ] Cross-model pairing ablation with fixed CWE subset
- [ ] Clean pool sensitivity with deterministic subsampling
- [ ] Rebuttal snippet generator producing pasteable markdown
- [ ] All methods use same evaluation pipeline (Macro-F1 over full test set)
- [ ] One command per experiment documented
