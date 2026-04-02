# Unified Pipeline Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Merge 6 independent pipeline capabilities into a single CLI entry point (`main.py`) with `--mode` selection.

**Architecture:** main.py gains a `--mode` flag that selects the detection strategy. All modes share: data loading, sampling, checkpoint/recovery, result saving. Each mode plugs in a different `DetectionStrategy` that implements `evaluate(prompt, samples) -> predictions`. Evolution remains the outer loop wrapping any strategy.

**Tech Stack:** Python 3.11, sklearn, OpenAI-compatible LLM API, existing evoprompt modules

---

## Current State

```
main.py (Layer-1 flat classification)
  └── PromptEvolver (batch feedback → meta-LLM → new guidance)
      └── Single prompt → all 11 categories at once
```

## Target State

```
main.py --mode {flat,hierarchical,mulvul,baseline,coevolution}
  │
  ├── --mode flat        (current Pipeline 1: single prompt, 11 categories)
  ├── --mode hierarchical (Pipeline 4: Layer1→Layer2→Layer3 cascade)
  ├── --mode mulvul      (Pipeline 7: Router→Detectors→Aggregator)
  ├── --mode baseline    (Pipeline 6: zero-shot, no evolution)
  └── --mode coevolution (Pipeline 3: detection+meta agent collaboration)
  │
  ├── --enable-rag       (Pipeline 5/7: add RAG retrieval to any mode)
  └── --enable-meta      (Pipeline 5: error accumulation → meta-tuning)
```

## File Structure

| File | Responsibility | Status |
|------|---------------|--------|
| `main.py` | CLI, data loading, evolution loop, result saving | Modify |
| `src/evoprompt/strategies/__init__.py` | Strategy protocol + factory | Create |
| `src/evoprompt/strategies/flat.py` | Current 11-class flat classification | Create (extract from main.py) |
| `src/evoprompt/strategies/hierarchical.py` | 3-layer cascade wrapper | Create (wraps existing ThreeLayerDetector) |
| `src/evoprompt/strategies/mulvul.py` | Router→Detector→Aggregator wrapper | Create (wraps existing agents/) |
| `src/evoprompt/strategies/baseline.py` | Zero-shot single-pass | Create (wraps existing baselines/) |
| `src/evoprompt/strategies/coevolution.py` | Multi-agent collaborative | Create (wraps existing multiagent/) |
| `tests/test_strategies.py` | Strategy interface tests | Create |

## Key Design Decisions

1. **Strategy pattern, not modes scattered through main.py** — each mode is a self-contained class implementing a common protocol
2. **Evolution loop stays in main.py** — strategies only handle detection/prediction, not evolution
3. **Incremental**: Task 1 extracts the current logic into FlatStrategy without changing behavior. Subsequent tasks add new strategies one at a time.
4. **Each task is independently testable** — can merge after each task

---

### Task 1: Define Strategy Protocol and Extract FlatStrategy

**Files:**
- Create: `src/evoprompt/strategies/__init__.py`
- Create: `src/evoprompt/strategies/flat.py`
- Create: `tests/test_strategies.py`
- Modify: `main.py`

- [ ] **Step 1: Write the strategy protocol test**

```python
# tests/test_strategies.py
from evoprompt.strategies import DetectionStrategy

def test_strategy_protocol():
    """DetectionStrategy defines predict_batch and get_ground_truth."""
    assert hasattr(DetectionStrategy, 'predict_batch')
    assert hasattr(DetectionStrategy, 'get_ground_truth')
```

- [ ] **Step 2: Create strategy protocol**

```python
# src/evoprompt/strategies/__init__.py
from typing import Protocol, List, Dict, Any, Tuple
from evoprompt.data.dataset import Sample

class DetectionStrategy(Protocol):
    """Interface for all detection strategies."""

    def predict_batch(
        self, prompt: str, samples: List[Sample], batch_idx: int
    ) -> List[str]:
        """Return predicted category for each sample."""
        ...

    def get_ground_truth(self, sample: Sample) -> str:
        """Return ground truth category for a sample."""
        ...
```

- [ ] **Step 3: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_strategies.py -v`

- [ ] **Step 4: Write FlatStrategy test**

```python
# tests/test_strategies.py (append)
def test_flat_strategy_implements_protocol():
    """FlatStrategy implements DetectionStrategy."""
    from evoprompt.strategies.flat import FlatStrategy
    from unittest.mock import MagicMock
    client = MagicMock()
    strategy = FlatStrategy(client)
    assert hasattr(strategy, 'predict_batch')
    assert hasattr(strategy, 'get_ground_truth')
```

- [ ] **Step 5: Extract FlatStrategy from main.py**

Move `batch_predict()` logic and ground truth mapping from `PrimeVulLayer1Pipeline` into `src/evoprompt/strategies/flat.py`. Keep main.py calling `self.strategy.predict_batch()` and `self.strategy.get_ground_truth()`.

- [ ] **Step 6: Update main.py to use FlatStrategy**

```python
# In PrimeVulLayer1Pipeline.__init__():
from evoprompt.strategies.flat import FlatStrategy
self.strategy = FlatStrategy(self.llm_client)
```

Replace inline `batch_predict()` calls with `self.strategy.predict_batch()`.

- [ ] **Step 7: Run full test suite**

Run: `uv run python -m pytest tests/ --ignore=tests/test_gpt4o_rag_baseline.py --ignore=tests/test_rag_retriever_parallel.py -q --timeout=30`

- [ ] **Step 8: Run smoke test to verify no regression**

Run: `uv run python main.py --max-generations 1 --batch-size 8 --balance-mode layer1 --force-resample --experiment-id smoke_strategy_refactor`

- [ ] **Step 9: Commit**

```bash
git add src/evoprompt/strategies/ tests/test_strategies.py main.py
git commit -m "refactor: extract FlatStrategy from main.py pipeline"
```

---

### Task 2: Add HierarchicalStrategy (3-Layer Detection)

**Files:**
- Create: `src/evoprompt/strategies/hierarchical.py`
- Modify: `tests/test_strategies.py`
- Modify: `main.py` (add `--mode` arg)

- [ ] **Step 1: Write HierarchicalStrategy test**

```python
def test_hierarchical_strategy():
    from evoprompt.strategies.hierarchical import HierarchicalStrategy
    from unittest.mock import MagicMock
    client = MagicMock()
    strategy = HierarchicalStrategy(client)
    assert hasattr(strategy, 'predict_batch')
```

- [ ] **Step 2: Implement HierarchicalStrategy**

Wraps `ThreeLayerDetector` from `src/evoprompt/detectors/three_layer_detector.py`. Maps its 3-layer output to the 11-class label space.

- [ ] **Step 3: Add `--mode` CLI arg to main.py**

```python
parser.add_argument("--mode", choices=["flat", "hierarchical", "mulvul", "baseline", "coevolution"],
                   default="flat", help="Detection strategy")
```

Strategy factory in `__init__`:
```python
from evoprompt.strategies import create_strategy
self.strategy = create_strategy(config["mode"], self.llm_client, config)
```

- [ ] **Step 4: Test with `--mode hierarchical`**

- [ ] **Step 5: Commit**

---

### Task 3: Add MulVulStrategy (Router→Detectors→Aggregator)

**Files:**
- Create: `src/evoprompt/strategies/mulvul.py`
- Modify: `tests/test_strategies.py`

- [ ] **Step 1: Write test**
- [ ] **Step 2: Implement MulVulStrategy**

Wraps `MulVulDetector` from `src/evoprompt/agents/mulvul.py`. Uses `RouterAgent` → parallel `DetectorAgent` → `DecisionAggregator`.

- [ ] **Step 3: Test with `--mode mulvul`**
- [ ] **Step 4: Commit**

---

### Task 4: Add BaselineStrategy (Zero-Shot)

**Files:**
- Create: `src/evoprompt/strategies/baseline.py`
- Modify: `tests/test_strategies.py`

- [ ] **Step 1: Write test**
- [ ] **Step 2: Implement BaselineStrategy**

Single LLM call, no evolution. When `--mode baseline`, skip evolution loop entirely — just evaluate once and save results.

- [ ] **Step 3: Test with `--mode baseline`**
- [ ] **Step 4: Commit**

---

### Task 5: Add CoevolutionStrategy (Multi-Agent)

**Files:**
- Create: `src/evoprompt/strategies/coevolution.py`
- Modify: `tests/test_strategies.py`

- [ ] **Step 1: Write test**
- [ ] **Step 2: Implement CoevolutionStrategy**

Uses `MultiAgentCoordinator` with `DetectionAgent` + `MetaAgent`. Replaces `PromptEvolver` with collaborative evolution.

- [ ] **Step 3: Test with `--mode coevolution`**
- [ ] **Step 4: Commit**

---

### Task 6: Add `--enable-rag` Flag

**Files:**
- Modify: `src/evoprompt/strategies/flat.py` (and others)
- Modify: `main.py`

- [ ] **Step 1: Write test for RAG-augmented prediction**
- [ ] **Step 2: Add `--enable-rag` to CLI**
- [ ] **Step 3: Implement RAG injection**

When enabled, before each `predict_batch()`, retrieve contrastive examples from `MulVulRetriever` and prepend to prompt context.

- [ ] **Step 4: Test**
- [ ] **Step 5: Commit**

---

### Task 7: Add `--enable-meta` Flag (Error Accumulation + Meta-Tuning)

**Files:**
- Modify: `main.py`

- [ ] **Step 1: Write test for meta-learning trigger**
- [ ] **Step 2: Implement meta-learning wrapper**

Uses `ErrorAccumulator` to track confusion patterns. When `should_trigger_meta_learning()` returns True, calls `MetaLearningPromptTuner` to rewrite guidance targeting specific confusion pairs.

- [ ] **Step 3: Test**
- [ ] **Step 4: Commit**

---

### Task 8: Integration Smoke Tests

- [ ] **Step 1: Test each mode end-to-end**

```bash
# Flat (current behavior)
uv run python main.py --mode flat --max-generations 1 --batch-size 8 --force-resample --experiment-id smoke_flat

# Hierarchical
uv run python main.py --mode hierarchical --max-generations 1 --batch-size 8 --force-resample --experiment-id smoke_hier

# Baseline (no evolution)
uv run python main.py --mode baseline --batch-size 8 --force-resample --experiment-id smoke_baseline

# Coevolution
uv run python main.py --mode coevolution --max-generations 1 --batch-size 8 --force-resample --experiment-id smoke_coevo

# MulVul
uv run python main.py --mode mulvul --max-generations 1 --batch-size 8 --force-resample --experiment-id smoke_mulvul

# Flat + RAG
uv run python main.py --mode flat --enable-rag --max-generations 1 --batch-size 8 --force-resample --experiment-id smoke_flat_rag

# Flat + Meta-tuning
uv run python main.py --mode flat --enable-meta --max-generations 1 --batch-size 8 --force-resample --experiment-id smoke_flat_meta
```

- [ ] **Step 2: Compare results across modes**
- [ ] **Step 3: Final commit and push**
