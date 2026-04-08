# Three Evolutionary Improvements — Design Spec

## Overview

Three independent improvements to the cooperative coevolutionary prompt evolution system, each with its own worktree/branch, ablation experiment, and PR.

**Shared evaluation protocol:**
- Dataset: PrimeVul-Balanced-20 (20 CWEs with >= 50 samples, 50 per CWE + 1000 benign = 2000 samples)
- Metric: average F1 across all nodes after 5 generations of full evolution
- Baseline: current code (constrained mutation + elitism) on the same dataset
- Each improvement is evaluated independently against the same baseline

---

## Shared: PrimeVul-Balanced-20 Dataset

### Construction

Script: `scripts/build_balanced_subset.py`

1. From `primevul_train.jsonl`, select CWEs with >= 50 vulnerable samples (20 CWEs)
2. For each CWE, randomly sample exactly 50 vulnerable samples (seed=42)
3. Add 1000 randomly sampled benign samples
4. Total: 2000 samples (1000 vulnerable + 1000 benign)
5. Save as `data/primevul/primevul_balanced_20.jsonl`

### Coverage

| Major | Middle | CWEs | Samples |
|-------|--------|------|---------|
| Memory | Buffer Errors | CWE-119, CWE-125, CWE-787 | 150 |
| Memory | Memory Management | CWE-416, CWE-401, CWE-772, CWE-415 | 200 |
| Memory | Pointer Dereference | CWE-476 | 50 |
| Memory | Integer Errors | CWE-190, CWE-189, CWE-369 | 150 |
| Logic | Access Control | CWE-264, CWE-284 | 100 |
| Logic | Concurrency Issues | CWE-362 | 50 |
| Logic | Information Exposure | CWE-200 | 50 |
| Logic | Resource Management | CWE-399, CWE-835 | 100 |
| Input | Input Validation | CWE-20, CWE-703 | 100 |
| Crypto | Cryptography Issues | CWE-310 | 50 |

4 majors, 10 middles, 20 CWEs. Max candidates per middle = 5 (Memory Management). All within the "sweet spot" range.

---

## Improvement 1: Adaptive Hierarchy

**Branch:** `feat/adaptive-hierarchy`

### Problem

The fixed 3-level hierarchy (5 major → 13 middle → 46 CWE) has two failure modes:
- Too many candidates (Cryptography Issues: 8 CWEs → F1=0.175)
- Semantically overlapping siblings (CWE-119/120/121/122 all mean "buffer overflow")

### Design

New class `AdaptiveHierarchyBuilder` in `src/mulvul/agents/adaptive_hierarchy.py`:

1. **Input**: training data JSONL + CWE descriptions
2. **Embed CWE descriptions** using the scorer LLM (or a sentence-transformer) to get per-CWE vectors
3. **Agglomerative clustering** with distance threshold: CWEs closer than threshold merge into a group
4. **Constraint**: each group has 3-6 members (split if > 6, merge up if < 3)
5. **Output**: a `DynamicTaxonomy` object that replaces the static `MAJOR_TO_MIDDLE` / `MIDDLE_TO_CWE` mappings

The `CoevolutionaryTrainer._init_populations()` reads from `DynamicTaxonomy` instead of static maps.

### Key interfaces

```python
@dataclass
class DynamicTaxonomy:
    """Data-driven taxonomy replacing static hierarchy maps."""
    stages: List[str]                    # e.g., ["major", "group", "cwe"]
    parent_map: Dict[str, str]           # child_id → parent_id
    children_map: Dict[str, List[str]]   # parent_id → [child_ids]
    labels: Dict[str, str]              # node_id → display label

    def candidates_for(self, node_id: str) -> List[str]:
        """Return sibling candidates for a node."""

    def depth(self) -> int:
        """Number of cascade levels."""

class AdaptiveHierarchyBuilder:
    def build(self, data_path: str, cwe_descriptions: Dict[str, str]) -> DynamicTaxonomy:
        """Analyze data and build optimal hierarchy."""
```

### Ablation experiment

1. Baseline: static hierarchy on PrimeVul-Balanced-20, 5 generations → avg F1
2. Treatment: adaptive hierarchy on same data, 5 generations → avg F1
3. Report: per-node F1 comparison, candidate list sizes, hierarchy structure

---

## Improvement 2: Progressive Disclosure (Agentic Tool-Use)

**Branch:** `feat/progressive-disclosure`

### Problem

Current detection stuffs all context (code, evidence, candidates) into one prompt. The LLM processes irrelevant evidence and may be distracted by noisy AST details.

### Design

New class `AgenticDetector` in `src/mulvul/agents/agentic_detector.py`, replacing `LevelDetector` for detection:

1. **Initial prompt**: LLM sees only the code + candidate list + task instruction
2. **Available tools** (LLM can call 0-N of these):
   - `get_ast_summary(code)` → function signatures, dangerous API calls, control flow patterns
   - `retrieve_similar(code, candidate)` → top-3 similar code samples from RAG knowledge base
   - `lookup_cwe(cwe_id)` → CWE description, examples, common patterns
3. **LLM decides** which tools to call based on the code it sees
4. **Final output**: same `ranking_v2` JSON format

Implementation uses OpenAI-compatible function calling (tool_use). Falls back to single-prompt mode if the endpoint doesn't support tools.

### Key interfaces

```python
class AgenticDetector:
    """Multi-turn detector with progressive context disclosure."""

    def __init__(self, llm_client, tools: List[DetectionTool], max_turns: int = 3):
        ...

    def detect(self, code: str, candidates: List[str]) -> List[Tuple[str, float]]:
        """Run multi-turn detection with tool use."""

class DetectionTool(Protocol):
    name: str
    description: str
    def execute(self, **kwargs) -> str: ...

class ASTSummaryTool(DetectionTool): ...
class RAGRetrieveTool(DetectionTool): ...
class CWELookupTool(DetectionTool): ...
```

### Ablation experiment

1. Baseline: single-prompt `LevelDetector` on PrimeVul-Balanced-20 → avg F1
2. Treatment: `AgenticDetector` with 3 tools on same data → avg F1
3. Also report: avg tools called per sample, tool call distribution, latency overhead

---

## Improvement 3: Meta-LLM Evolution Memory

**Branch:** `feat/evolution-memory`

### Problem

Current meta-LLM mutations are stateless — each mutation starts from scratch. The meta-LLM doesn't know that "adding decision boundaries worked for CWE-189" or "rewriting role descriptions degraded Crypto".

### Design

New class `EvolutionMemory` in `src/mulvul/agents/evolution_memory.py`:

1. **Record experiences** after each mutation/crossover/migration:
   ```
   {"node": "cwe_CWE-189", "action": "mutation", "description": "Added candidate distinction rules between CWE-189/190/191", "f1_before": 0.162, "f1_after": 0.490, "delta": +0.328, "generation": 1}
   ```
2. **Store** in `evolution_memory.jsonl` (append-only, survives restarts)
3. **Retrieve** top-5 relevant experiences when mutating a node:
   - Same node's history (most relevant)
   - Same stage sibling experiences (transferable)
   - Global high-delta experiences (general lessons)
4. **Inject** into the mutation prompt as context:
   ```
   ## Lessons from previous evolution rounds:
   - [+0.33] CWE-189: Adding distinction rules between similar CWEs improved F1 significantly
   - [-0.28] major_Crypto: Completely rewriting the role description degraded performance — prefer additive changes
   - [+0.17] middle_Input Validation: Adding concrete code pattern examples improved classification
   ```

### Key interfaces

```python
@dataclass
class Experience:
    node: str
    action: str          # "mutation" | "crossover" | "migration"
    description: str     # natural language summary of what was changed
    f1_before: float
    f1_after: float
    delta: float
    generation: int

class EvolutionMemory:
    def __init__(self, path: Path): ...
    def record(self, exp: Experience) -> None: ...
    def retrieve(self, node: str, stage: str, top_k: int = 5) -> List[Experience]: ...
    def format_for_prompt(self, experiences: List[Experience]) -> str: ...
```

Integration: `CoevolutionaryTrainer._mutate_prompt()` calls `memory.retrieve()` and appends the formatted experiences to the mutation request.

### Experience description generation

After each mutation, the meta-LLM is asked to summarize what it changed in one sentence. This summary becomes the `description` field. Cost: one extra short LLM call per mutation (~10 tokens output).

### Ablation experiment

1. Baseline: stateless mutation on PrimeVul-Balanced-20 → avg F1 over 5 generations
2. Treatment: memory-augmented mutation → avg F1 over 5 generations
3. Also report: experience accumulation curve, retrieval hit rate, memory size over generations

---

## Execution Plan

### Phase 0: Build shared dataset (prerequisite)
- Script `scripts/build_balanced_subset.py`
- Run baseline experiment on PrimeVul-Balanced-20

### Phase 1: Parallel implementation (3 worktrees, 3 agents)
- `feat/adaptive-hierarchy` → PR
- `feat/progressive-disclosure` → PR
- `feat/evolution-memory` → PR

### Phase 2: Ablation experiments (can run in parallel after implementation)
- Each improvement runs 5-gen evolution on PrimeVul-Balanced-20
- Compare avg F1 against baseline

### Phase 3: Results & PR review
- Each PR includes ablation results in PR description
- Merge improvements that show significant avg F1 improvement
