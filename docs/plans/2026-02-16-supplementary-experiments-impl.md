# Supplementary Experiments Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement reviewer-requested supplementary experiments: GPT-4o+RAG baseline, Single-Agent+Tool+RAG baseline, cross-model pairing ablation, clean pool sensitivity, and cost tracking.

**Architecture:** Integrated extension of existing codebase - modify `KnowledgeBase` and `CodeSimilarityRetriever` for contrastive retrieval, add `CostTracker` utility, extend `train_three_layer.py` with new `--method` options.

**Tech Stack:** Python 3.11, asyncio, aiohttp, existing EvoPrompt infrastructure

---

## Task 1: Add Clean Pool to KnowledgeBase

**Files:**
- Modify: `src/evoprompt/rag/knowledge_base.py`
- Test: `tests/test_knowledge_base_clean_pool.py`

**Step 1: Write the failing test**

```python
# tests/test_knowledge_base_clean_pool.py
import pytest
from evoprompt.rag.knowledge_base import KnowledgeBase, CodeExample


def test_knowledge_base_has_clean_examples_field():
    """KnowledgeBase should have clean_examples field."""
    kb = KnowledgeBase()
    assert hasattr(kb, 'clean_examples')
    assert kb.clean_examples == []


def test_add_clean_example():
    """Should be able to add clean/benign examples."""
    kb = KnowledgeBase()
    example = CodeExample(
        code="int x = 5; return x;",
        category="Benign",
        description="Safe integer assignment"
    )
    kb.add_clean_example(example)
    assert len(kb.clean_examples) == 1
    assert kb.clean_examples[0].category == "Benign"


def test_clean_examples_in_statistics():
    """Statistics should include clean pool size."""
    kb = KnowledgeBase()
    kb.add_clean_example(CodeExample(
        code="safe code",
        category="Benign",
        description="Safe"
    ))
    stats = kb.statistics()
    assert "clean_examples" in stats
    assert stats["clean_examples"] == 1


def test_save_and_load_with_clean_examples():
    """Clean examples should be saved and loaded correctly."""
    import tempfile
    import os

    kb = KnowledgeBase()
    kb.add_clean_example(CodeExample(
        code="safe code here",
        category="Benign",
        description="Safe operation"
    ))

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_path = f.name

    try:
        kb.save(temp_path)
        loaded_kb = KnowledgeBase.load(temp_path)
        assert len(loaded_kb.clean_examples) == 1
        assert loaded_kb.clean_examples[0].code == "safe code here"
    finally:
        os.unlink(temp_path)
```

**Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_knowledge_base_clean_pool.py -v`
Expected: FAIL with "AttributeError: 'KnowledgeBase' object has no attribute 'clean_examples'"

**Step 3: Write minimal implementation**

Modify `src/evoprompt/rag/knowledge_base.py`:

```python
# Add to KnowledgeBase dataclass (after line 75):
    clean_examples: List[CodeExample] = field(default_factory=list)

# Add method after add_cwe_example (after line 95):
    def add_clean_example(self, example: CodeExample):
        """Add a clean/benign example for contrastive retrieval."""
        self.clean_examples.append(example)

# Modify statistics() method to include clean_examples:
    def statistics(self) -> Dict:
        """Get statistics about knowledge base."""
        return {
            "total_examples": len(self.get_all_examples()),
            "major_categories": len(self.major_examples),
            "middle_categories": len(self.middle_examples),
            "cwe_types": len(self.cwe_examples),
            "clean_examples": len(self.clean_examples),  # ADD THIS
            "examples_per_major": {
                cat: len(examples) for cat, examples in self.major_examples.items()
            },
            "examples_per_middle": {
                cat: len(examples) for cat, examples in self.middle_examples.items()
            },
            "examples_per_cwe": {
                cwe: len(examples) for cwe, examples in self.cwe_examples.items()
            },
        }

# Modify save() method to include clean_examples:
    def save(self, filepath: str):
        """Save knowledge base to file."""
        data = {
            "major_examples": {
                cat: [ex.to_dict() for ex in examples]
                for cat, examples in self.major_examples.items()
            },
            "middle_examples": {
                cat: [ex.to_dict() for ex in examples]
                for cat, examples in self.middle_examples.items()
            },
            "cwe_examples": {
                cwe: [ex.to_dict() for ex in examples]
                for cwe, examples in self.cwe_examples.items()
            },
            "clean_examples": [ex.to_dict() for ex in self.clean_examples],  # ADD THIS
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

# Modify load() method to include clean_examples:
    @classmethod
    def load(cls, filepath: str) -> "KnowledgeBase":
        """Load knowledge base from file."""
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        kb = cls()

        # Load major examples
        for cat, examples in data.get("major_examples", {}).items():
            kb.major_examples[cat] = [CodeExample.from_dict(ex) for ex in examples]

        # Load middle examples
        for cat, examples in data.get("middle_examples", {}).items():
            kb.middle_examples[cat] = [CodeExample.from_dict(ex) for ex in examples]

        # Load CWE examples
        for cwe, examples in data.get("cwe_examples", {}).items():
            kb.cwe_examples[cwe] = [CodeExample.from_dict(ex) for ex in examples]

        # Load clean examples (ADD THIS)
        for ex in data.get("clean_examples", []):
            kb.clean_examples.append(CodeExample.from_dict(ex))

        return kb
```

**Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_knowledge_base_clean_pool.py -v`
Expected: PASS (4 tests)

**Step 5: Commit**

```bash
git add tests/test_knowledge_base_clean_pool.py src/evoprompt/rag/knowledge_base.py
git commit -m "feat: add clean_examples field to KnowledgeBase for contrastive retrieval"
```

---

## Task 2: Add Clean Pool Builder Function

**Files:**
- Modify: `src/evoprompt/rag/knowledge_base.py`
- Test: `tests/test_knowledge_base_clean_pool.py`

**Step 1: Write the failing test**

Add to `tests/test_knowledge_base_clean_pool.py`:

```python
def test_build_clean_pool_from_dataset():
    """Should build clean pool from dataset benign samples."""
    from unittest.mock import MagicMock
    from evoprompt.rag.knowledge_base import build_clean_pool_from_dataset

    # Mock dataset with benign samples
    mock_dataset = MagicMock()
    mock_sample1 = MagicMock()
    mock_sample1.input_text = "int safe_func() { return 0; }"
    mock_sample1.target = "0"  # benign
    mock_sample1.metadata = {"idx": 1}

    mock_sample2 = MagicMock()
    mock_sample2.input_text = "void vuln() { strcpy(buf, input); }"
    mock_sample2.target = "1"  # vulnerable
    mock_sample2.metadata = {"idx": 2, "cwe": ["CWE-120"]}

    mock_sample3 = MagicMock()
    mock_sample3.input_text = "int another_safe() { return 1; }"
    mock_sample3.target = "0"  # benign
    mock_sample3.metadata = {"idx": 3}

    mock_dataset.get_samples.return_value = [mock_sample1, mock_sample2, mock_sample3]

    kb = KnowledgeBase()
    build_clean_pool_from_dataset(kb, mock_dataset, max_samples=10, seed=42)

    # Should only have benign samples
    assert len(kb.clean_examples) == 2
    assert all(ex.category == "Benign" for ex in kb.clean_examples)
```

**Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_knowledge_base_clean_pool.py::test_build_clean_pool_from_dataset -v`
Expected: FAIL with "ImportError: cannot import name 'build_clean_pool_from_dataset'"

**Step 3: Write minimal implementation**

Add to `src/evoprompt/rag/knowledge_base.py` (at end of file):

```python
def build_clean_pool_from_dataset(
    kb: KnowledgeBase,
    dataset,
    max_samples: int = 5000,
    seed: int = 42
) -> None:
    """Build clean/benign pool from dataset.

    Args:
        kb: KnowledgeBase to add clean examples to
        dataset: Dataset with samples (must have input_text, target, metadata)
        max_samples: Maximum number of clean samples to add
        seed: Random seed for reproducibility
    """
    import random
    rng = random.Random(seed)

    # Collect benign samples (target == "0" or target == 0)
    benign_samples = []
    for sample in dataset.get_samples():
        target = str(sample.target)
        if target == "0":
            benign_samples.append(sample)

    # Shuffle and limit
    rng.shuffle(benign_samples)
    selected = benign_samples[:max_samples]

    # Add to knowledge base
    for sample in selected:
        example = CodeExample(
            code=sample.input_text,
            category="Benign",
            description="Clean code sample from training set",
            metadata={"source_idx": sample.metadata.get("idx")}
        )
        kb.add_clean_example(example)
```

**Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_knowledge_base_clean_pool.py::test_build_clean_pool_from_dataset -v`
Expected: PASS

**Step 5: Commit**

```bash
git add src/evoprompt/rag/knowledge_base.py tests/test_knowledge_base_clean_pool.py
git commit -m "feat: add build_clean_pool_from_dataset function"
```

---

## Task 3: Add Contrastive Retrieval to CodeSimilarityRetriever

**Files:**
- Modify: `src/evoprompt/rag/retriever.py`
- Test: `tests/test_contrastive_retriever.py`

**Step 1: Write the failing test**

```python
# tests/test_contrastive_retriever.py
import pytest
from evoprompt.rag.knowledge_base import KnowledgeBase, CodeExample
from evoprompt.rag.retriever import CodeSimilarityRetriever


def test_retriever_accepts_contrastive_flag():
    """Retriever should accept contrastive parameter."""
    kb = KnowledgeBase()
    retriever = CodeSimilarityRetriever(kb, contrastive=True)
    assert retriever.contrastive is True


def test_retriever_accepts_clean_pool_frac():
    """Retriever should accept clean_pool_frac parameter."""
    kb = KnowledgeBase()
    retriever = CodeSimilarityRetriever(kb, clean_pool_frac=0.5)
    assert retriever.clean_pool_frac == 0.5


def test_retrieve_contrastive_returns_both_types():
    """retrieve_contrastive should return vulnerable and clean examples."""
    kb = KnowledgeBase()

    # Add vulnerable example
    kb.major_examples["Memory"] = [CodeExample(
        code="strcpy(buf, input);",
        category="Memory",
        description="Buffer overflow",
        cwe="CWE-120"
    )]

    # Add clean example
    kb.add_clean_example(CodeExample(
        code="strncpy(buf, input, sizeof(buf));",
        category="Benign",
        description="Safe copy"
    ))

    retriever = CodeSimilarityRetriever(kb, contrastive=True)
    result = retriever.retrieve_contrastive(
        "char buf[64]; strcpy(buf, user_input);",
        vulnerable_top_k=1,
        clean_top_k=1
    )

    assert len(result.examples) == 2
    # Check formatted text has IDs
    assert "[VUL-" in result.formatted_text
    assert "[CLEAN-" in result.formatted_text


def test_clean_pool_subsampling():
    """Should subsample clean pool based on fraction."""
    kb = KnowledgeBase()

    # Add 10 clean examples
    for i in range(10):
        kb.add_clean_example(CodeExample(
            code=f"safe_code_{i}",
            category="Benign",
            description=f"Safe {i}"
        ))

    retriever = CodeSimilarityRetriever(kb, clean_pool_frac=0.5, clean_pool_seed=42)

    # Should have ~5 examples in subsampled pool
    assert len(retriever._get_clean_pool()) == 5
```

**Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_contrastive_retriever.py -v`
Expected: FAIL with "TypeError: __init__() got an unexpected keyword argument 'contrastive'"

**Step 3: Write minimal implementation**

Modify `src/evoprompt/rag/retriever.py`:

```python
# Modify __init__ (around line 69):
class CodeSimilarityRetriever:
    """Retrieves similar code examples using simple text similarity."""

    def __init__(
        self,
        knowledge_base: KnowledgeBase,
        contrastive: bool = False,
        clean_pool_frac: float = 1.0,
        clean_pool_seed: int = 42,
        debug: bool = False
    ):
        """Initialize retriever.

        Args:
            knowledge_base: Knowledge base containing examples
            contrastive: Enable contrastive retrieval with clean examples
            clean_pool_frac: Fraction of clean pool to use (for sensitivity)
            clean_pool_seed: Random seed for clean pool subsampling
            debug: Enable debug output
        """
        self.kb = knowledge_base
        self.contrastive = contrastive
        self.clean_pool_frac = clean_pool_frac
        self.clean_pool_seed = clean_pool_seed
        self.debug = debug
        self._subsampled_clean_pool: Optional[List[CodeExample]] = None

    def _get_clean_pool(self) -> List[CodeExample]:
        """Get (possibly subsampled) clean pool."""
        if self._subsampled_clean_pool is not None:
            return self._subsampled_clean_pool

        if not self.kb.clean_examples or self.clean_pool_frac >= 1.0:
            self._subsampled_clean_pool = self.kb.clean_examples
        else:
            import random
            rng = random.Random(self.clean_pool_seed)
            n_samples = int(len(self.kb.clean_examples) * self.clean_pool_frac)
            self._subsampled_clean_pool = rng.sample(self.kb.clean_examples, n_samples)

        return self._subsampled_clean_pool

    def retrieve_contrastive(
        self,
        query_code: str,
        vulnerable_top_k: int = 2,
        clean_top_k: int = 1
    ) -> RetrievalResult:
        """Retrieve both vulnerable AND clean examples for contrast.

        Args:
            query_code: Code to find similar examples for
            vulnerable_top_k: Number of vulnerable examples
            clean_top_k: Number of clean examples

        Returns:
            RetrievalResult with formatted evidence including IDs
        """
        # Get vulnerable examples
        vuln_result = self.retrieve_for_major_category(query_code, vulnerable_top_k)

        # Get clean examples
        clean_pool = self._get_clean_pool()
        clean_result = self._retrieve_from_pool(query_code, clean_pool, clean_top_k)

        # Combine and format with IDs
        all_examples = vuln_result.examples + clean_result.examples
        all_scores = vuln_result.similarity_scores + clean_result.similarity_scores

        formatted = self._format_contrastive_examples(
            vuln_result.examples, clean_result.examples
        )

        debug_info = {
            "vulnerable_count": len(vuln_result.examples),
            "clean_count": len(clean_result.examples),
            "clean_pool_size": len(clean_pool),
            "clean_pool_frac": self.clean_pool_frac,
        }

        return RetrievalResult(
            examples=all_examples,
            formatted_text=formatted,
            similarity_scores=all_scores,
            debug_info=debug_info
        )

    def _format_contrastive_examples(
        self,
        vulnerable: List[CodeExample],
        clean: List[CodeExample]
    ) -> str:
        """Format examples with IDs for contrastive retrieval."""
        parts = ["Retrieved vulnerability knowledge:\n"]

        # Vulnerable examples
        for i, ex in enumerate(vulnerable, 1):
            parts.append(f"[VUL-{i}] Category: {ex.category}")
            if ex.cwe:
                parts.append(f" | CWE: {ex.cwe}")
            parts.append(f"\nCode: {ex.code}\nDescription: {ex.description}\n")

        # Clean examples
        for i, ex in enumerate(clean, 1):
            parts.append(f"[CLEAN-{i}] Category: {ex.category}")
            parts.append(f"\nCode: {ex.code}\nDescription: {ex.description}\n")

        return "\n".join(parts)
```

**Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_contrastive_retriever.py -v`
Expected: PASS (4 tests)

**Step 5: Commit**

```bash
git add src/evoprompt/rag/retriever.py tests/test_contrastive_retriever.py
git commit -m "feat: add contrastive retrieval with clean pool subsampling"
```

---

## Task 4: Create CostTracker Class

**Files:**
- Create: `src/evoprompt/utils/cost_tracker.py`
- Test: `tests/test_cost_tracker.py`

**Step 1: Write the failing test**

```python
# tests/test_cost_tracker.py
import pytest
import json
import tempfile
from pathlib import Path


def test_cost_tracker_creates_file():
    """CostTracker should create JSONL output file."""
    from evoprompt.utils.cost_tracker import CostTracker

    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "cost.jsonl"
        tracker = CostTracker(output_path)

        tracker.start_sample("sample_1", "test_method")
        tracker.log_llm_call("gpt-4o", 100, 50, 1000.0)
        tracker.end_sample()

        assert output_path.exists()

        with open(output_path) as f:
            record = json.loads(f.readline())

        assert record["sample_id"] == "sample_1"
        assert record["method"] == "test_method"
        assert record["llm_calls"] == 1
        assert record["input_tokens"] == 100
        assert record["output_tokens"] == 50


def test_cost_tracker_accumulates_calls():
    """Multiple LLM calls should accumulate."""
    from evoprompt.utils.cost_tracker import CostTracker

    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "cost.jsonl"
        tracker = CostTracker(output_path)

        tracker.start_sample("sample_1", "agent_method")
        tracker.log_llm_call("gpt-4o", 100, 50, 500.0)
        tracker.log_llm_call("gpt-4o", 150, 75, 600.0)
        tracker.log_retrieval_call(3, 50.0)
        record = tracker.end_sample()

        assert record.llm_calls == 2
        assert record.input_tokens == 250
        assert record.output_tokens == 125
        assert record.retrieval_calls == 1


def test_cost_tracker_records_time():
    """Total time should be tracked."""
    from evoprompt.utils.cost_tracker import CostTracker

    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "cost.jsonl"
        tracker = CostTracker(output_path)

        tracker.start_sample("sample_1", "test")
        tracker.log_llm_call("gpt-4o", 100, 50, 1000.0)
        record = tracker.end_sample()

        assert record.time_ms >= 0  # At least 0
```

**Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_cost_tracker.py -v`
Expected: FAIL with "ModuleNotFoundError: No module named 'evoprompt.utils.cost_tracker'"

**Step 3: Write minimal implementation**

Create `src/evoprompt/utils/cost_tracker.py`:

```python
"""Cost tracking for LLM and retrieval calls."""

import json
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class CostRecord:
    """Record of costs for a single sample."""
    sample_id: str
    method: str
    llm_calls: int = 0
    retrieval_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    time_ms: float = 0.0
    llm_call_details: List[Dict] = field(default_factory=list)
    retrieval_call_details: List[Dict] = field(default_factory=list)

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


class CostTracker:
    """Track costs for LLM and retrieval calls.

    Usage:
        tracker = CostTracker(Path("cost.jsonl"))
        tracker.start_sample("sample_1", "method_name")
        tracker.log_llm_call("gpt-4o", 100, 50, 1000.0)
        tracker.log_retrieval_call(3, 50.0)
        tracker.end_sample()
    """

    def __init__(self, output_path: Path):
        """Initialize cost tracker.

        Args:
            output_path: Path to JSONL output file
        """
        self.output_path = Path(output_path)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self._current: Optional[CostRecord] = None
        self._start_time: Optional[float] = None

    def start_sample(self, sample_id: str, method: str) -> None:
        """Begin tracking a new sample.

        Args:
            sample_id: Unique identifier for the sample
            method: Method name (e.g., "gpt4o_rag_singlepass")
        """
        self._current = CostRecord(sample_id=str(sample_id), method=method)
        self._start_time = time.perf_counter()

    def log_llm_call(
        self,
        model: str,
        in_tokens: int,
        out_tokens: int,
        time_ms: float
    ) -> None:
        """Log a single LLM call.

        Args:
            model: Model name
            in_tokens: Input/prompt tokens
            out_tokens: Output/completion tokens
            time_ms: Call duration in milliseconds
        """
        if self._current is None:
            raise RuntimeError("Must call start_sample() before log_llm_call()")

        self._current.llm_calls += 1
        self._current.input_tokens += in_tokens
        self._current.output_tokens += out_tokens
        self._current.llm_call_details.append({
            "model": model,
            "in_tokens": in_tokens,
            "out_tokens": out_tokens,
            "time_ms": time_ms
        })

    def log_retrieval_call(self, top_k: int, time_ms: float) -> None:
        """Log a retrieval operation.

        Args:
            top_k: Number of results retrieved
            time_ms: Retrieval duration in milliseconds
        """
        if self._current is None:
            raise RuntimeError("Must call start_sample() before log_retrieval_call()")

        self._current.retrieval_calls += 1
        self._current.retrieval_call_details.append({
            "top_k": top_k,
            "time_ms": time_ms
        })

    def end_sample(self) -> CostRecord:
        """Finalize current sample and write to file.

        Returns:
            The completed CostRecord
        """
        if self._current is None:
            raise RuntimeError("Must call start_sample() before end_sample()")

        # Calculate total time
        if self._start_time is not None:
            self._current.time_ms = (time.perf_counter() - self._start_time) * 1000

        # Write to JSONL
        with open(self.output_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(self._current.to_dict()) + "\n")

        record = self._current
        self._current = None
        self._start_time = None

        return record
```

**Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_cost_tracker.py -v`
Expected: PASS (3 tests)

**Step 5: Commit**

```bash
git add src/evoprompt/utils/cost_tracker.py tests/test_cost_tracker.py
git commit -m "feat: add CostTracker for LLM and retrieval call accounting"
```

---

## Task 5: Add Cost Summary Script

**Files:**
- Create: `scripts/ablations/summarize_cost.py`
- Test: Manual verification

**Step 1: Write the script**

Create `scripts/ablations/summarize_cost.py`:

```python
#!/usr/bin/env python3
"""Summarize cost metrics from JSONL files.

Usage:
    uv run python scripts/ablations/summarize_cost.py outputs/cost/*.jsonl
"""

import json
import sys
from pathlib import Path
from typing import List, Dict
import statistics


def load_records(jsonl_files: List[Path]) -> Dict[str, List[Dict]]:
    """Load records grouped by method."""
    by_method = {}

    for filepath in jsonl_files:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    record = json.loads(line)
                    method = record.get("method", "unknown")
                    if method not in by_method:
                        by_method[method] = []
                    by_method[method].append(record)

    return by_method


def summarize_method(method: str, records: List[Dict]) -> str:
    """Generate summary for a method."""
    n = len(records)

    llm_calls = [r["llm_calls"] for r in records]
    retrieval_calls = [r["retrieval_calls"] for r in records]
    input_tokens = [r["input_tokens"] for r in records]
    output_tokens = [r["output_tokens"] for r in records]
    times = [r["time_ms"] for r in records]

    lines = [
        f"Method: {method}",
        f"  Samples: {n}",
        f"  Avg LLM calls: {statistics.mean(llm_calls):.2f}",
        f"  Avg retrieval calls: {statistics.mean(retrieval_calls):.2f}",
        f"  Avg input tokens: {statistics.mean(input_tokens):,.0f}",
        f"  Avg output tokens: {statistics.mean(output_tokens):,.0f}",
    ]

    if times:
        p50 = statistics.median(times)
        sorted_times = sorted(times)
        p90_idx = int(len(sorted_times) * 0.9)
        p90 = sorted_times[p90_idx] if p90_idx < len(sorted_times) else sorted_times[-1]
        lines.append(f"  Avg time: {statistics.mean(times):,.0f}ms (p50: {p50:,.0f}ms, p90: {p90:,.0f}ms)")

    return "\n".join(lines)


def main():
    if len(sys.argv) < 2:
        print("Usage: python summarize_cost.py <jsonl_files...>")
        sys.exit(1)

    files = [Path(f) for f in sys.argv[1:] if Path(f).exists()]
    if not files:
        print("No valid JSONL files found.")
        sys.exit(1)

    by_method = load_records(files)

    print("=" * 60)
    print("COST SUMMARY")
    print("=" * 60)

    for method, records in sorted(by_method.items()):
        print()
        print(summarize_method(method, records))

    print()
    print("=" * 60)


if __name__ == "__main__":
    main()
```

**Step 2: Make executable and test manually**

```bash
chmod +x scripts/ablations/summarize_cost.py
```

**Step 3: Commit**

```bash
git add scripts/ablations/summarize_cost.py
git commit -m "feat: add cost summary script for experiment analysis"
```

---

## Task 6: Add GPT-4o + RAG Single-Pass Baseline

**Files:**
- Modify: `scripts/ablations/train_three_layer.py`
- Test: Integration test (manual)

**Step 1: Add argument parser options**

Add to argparse section in `scripts/ablations/train_three_layer.py`:

```python
# Add after existing arguments:
parser.add_argument('--method', type=str, default='mulvul',
                    choices=['mulvul', 'gpt4o_rag_singlepass', 'single_agent_tool_rag',
                             'gpt4o_no_rag', 'clean_pool_sensitivity', 'pairing_ablation'],
                    help='Evaluation method to run')
parser.add_argument('--top-k', type=int, default=3,
                    help='Number of retrieved examples')
parser.add_argument('--clean-top-k', type=int, default=1,
                    help='Number of clean examples for contrastive retrieval')
```

**Step 2: Add baseline prompt constant**

Add near top of file:

```python
GPT4O_RAG_PROMPT = """You are a security code auditor. Follow the output format exactly.

Given the following C/C++ code and retrieved vulnerability knowledge evidence, decide whether the code contains a vulnerability and identify the most likely CWE type.

Constraints:
- Use ONLY the retrieved evidence and the code. If evidence is insufficient, output "NONE".
- Do NOT guess. Prefer "NONE" when uncertain.
- Output must be JSON with keys: "cwe" (string "CWE-XXX" or "NONE"), "rationale" (1-3 sentences), "evidence_ids" (list of IDs used)

[CODE]
{code_snippet}

[EVIDENCE]
{packed_evidence_with_ids}"""
```

**Step 3: Add baseline implementation function**

```python
async def run_gpt4o_rag_singlepass(
    dataset,
    retriever,
    llm_client: AsyncLLMClient,
    cost_tracker,
    args
) -> List[Dict]:
    """Run GPT-4o + RAG single-pass baseline."""
    from evoprompt.utils.cost_tracker import CostTracker
    import re

    results = []
    samples = dataset.get_samples(args.eval_samples) if args.eval_samples else dataset.get_samples()

    print(f"   Running GPT-4o + RAG single-pass on {len(samples)} samples...")

    for i, sample in enumerate(samples):
        sample_id = sample.metadata.get('idx', i)
        cost_tracker.start_sample(sample_id, 'gpt4o_rag_singlepass')

        # Retrieve contrastive evidence
        import time
        retrieval_start = time.perf_counter()
        evidence = retriever.retrieve_contrastive(
            sample.input_text,
            vulnerable_top_k=args.top_k,
            clean_top_k=args.clean_top_k
        )
        retrieval_time = (time.perf_counter() - retrieval_start) * 1000
        cost_tracker.log_retrieval_call(args.top_k + args.clean_top_k, retrieval_time)

        # Single LLM call
        prompt = GPT4O_RAG_PROMPT.format(
            code_snippet=sample.input_text[:4000],  # Truncate if needed
            packed_evidence_with_ids=evidence.formatted_text
        )

        response = await llm_client.generate_async(prompt)

        # Parse response
        prediction = parse_baseline_response(response)
        prediction['ground_truth'] = sample.target
        prediction['ground_truth_cwe'] = sample.metadata.get('cwe', [])
        results.append(prediction)

        cost_tracker.end_sample()

        if (i + 1) % 100 == 0:
            print(f"   Processed {i + 1}/{len(samples)} samples")

    return results


def parse_baseline_response(response: str) -> Dict:
    """Parse JSON response from baseline models."""
    import json
    import re

    # Try to extract JSON from response
    try:
        # Look for JSON block
        json_match = re.search(r'\{[^{}]*\}', response, re.DOTALL)
        if json_match:
            data = json.loads(json_match.group())
            return {
                'cwe': data.get('cwe', 'NONE'),
                'rationale': data.get('rationale', ''),
                'evidence_ids': data.get('evidence_ids', []),
                'raw_response': response
            }
    except json.JSONDecodeError:
        pass

    # Fallback: extract CWE pattern
    cwe_match = re.search(r'CWE-\d+', response)
    if cwe_match:
        return {
            'cwe': cwe_match.group(),
            'rationale': response[:200],
            'evidence_ids': [],
            'raw_response': response
        }

    return {
        'cwe': 'NONE',
        'rationale': response[:200],
        'evidence_ids': [],
        'raw_response': response
    }
```

**Step 4: Add dispatch in main()**

In main() function, add method dispatch:

```python
# After dataset loading:
if args.method == 'gpt4o_rag_singlepass':
    from evoprompt.utils.cost_tracker import CostTracker

    cost_dir = Path(args.output_dir) / "cost"
    cost_dir.mkdir(parents=True, exist_ok=True)
    cost_tracker = CostTracker(cost_dir / "gpt4o_rag_singlepass.jsonl")

    # Setup retriever with contrastive mode
    retriever = CodeSimilarityRetriever(kb, contrastive=True)

    # Run baseline
    results = asyncio.run(run_gpt4o_rag_singlepass(
        eval_dataset, retriever, async_client, cost_tracker, args
    ))

    # Compute metrics
    metrics = compute_baseline_metrics(results)
    save_baseline_results(args.output_dir, 'gpt4o_rag_singlepass', results, metrics)

    return
```

**Step 5: Commit**

```bash
git add scripts/ablations/train_three_layer.py
git commit -m "feat: add GPT-4o + RAG single-pass baseline method"
```

---

## Task 7: Add Single-Agent + Tool + RAG Baseline

**Files:**
- Modify: `scripts/ablations/train_three_layer.py`

**Step 1: Add agent prompt constant**

```python
AGENT_TOOL_PROMPT = """You are a security code auditor with access to a retrieval tool.

Task: Identify the most likely CWE type for the given code (or "NONE" if no vulnerability).

You may call the tool:
- SEARCH(query, top_k) - searches vulnerability knowledge base, returns similar code examples

Rules:
- At most {max_tool_calls} tool calls.
- Use evidence to justify your answer.
- Final answer must be JSON with keys: "cwe", "rationale", "evidence_ids"

Code to analyze:
{code_snippet}

If you want to search, respond with: SEARCH("your query", top_k)
When ready to give final answer, respond with JSON."""
```

**Step 2: Add argument**

```python
parser.add_argument('--max-tool-calls', type=int, default=2,
                    help='Maximum tool calls for agent baseline')
```

**Step 3: Add implementation**

```python
async def run_single_agent_tool_rag(
    dataset,
    retriever,
    llm_client: AsyncLLMClient,
    cost_tracker,
    args
) -> List[Dict]:
    """Run Single-Agent + Tool + RAG baseline."""
    import re

    results = []
    samples = dataset.get_samples(args.eval_samples) if args.eval_samples else dataset.get_samples()

    print(f"   Running Single-Agent + Tool + RAG on {len(samples)} samples...")

    for i, sample in enumerate(samples):
        sample_id = sample.metadata.get('idx', i)
        cost_tracker.start_sample(sample_id, 'single_agent_tool_rag')

        # Initial prompt
        prompt = AGENT_TOOL_PROMPT.format(
            max_tool_calls=args.max_tool_calls,
            code_snippet=sample.input_text[:4000]
        )

        tool_calls_used = 0
        conversation = prompt
        accumulated_evidence = ""

        while tool_calls_used < args.max_tool_calls:
            response = await llm_client.generate_async(conversation)

            # Check for SEARCH tool call
            search_match = re.search(r'SEARCH\s*\(\s*["\']([^"\']+)["\'],?\s*(\d+)?\s*\)', response)

            if search_match:
                query = search_match.group(1)
                top_k = int(search_match.group(2)) if search_match.group(2) else 3

                # Execute retrieval
                import time
                retrieval_start = time.perf_counter()
                evidence = retriever.retrieve_contrastive(query, top_k, 1)
                retrieval_time = (time.perf_counter() - retrieval_start) * 1000
                cost_tracker.log_retrieval_call(top_k + 1, retrieval_time)

                accumulated_evidence += f"\n{evidence.formatted_text}"

                # Continue conversation
                conversation = f"{conversation}\n\nAssistant: {response}\n\n[TOOL RESULT]\n{evidence.formatted_text}\n\nNow provide your final JSON answer:"
                tool_calls_used += 1
            else:
                # Final answer (contains JSON or no SEARCH)
                break

        # Parse final response
        prediction = parse_baseline_response(response)
        prediction['ground_truth'] = sample.target
        prediction['ground_truth_cwe'] = sample.metadata.get('cwe', [])
        prediction['tool_calls_used'] = tool_calls_used
        results.append(prediction)

        cost_tracker.end_sample()

        if (i + 1) % 100 == 0:
            print(f"   Processed {i + 1}/{len(samples)} samples")

    return results
```

**Step 4: Add dispatch in main()**

```python
elif args.method == 'single_agent_tool_rag':
    from evoprompt.utils.cost_tracker import CostTracker

    cost_dir = Path(args.output_dir) / "cost"
    cost_dir.mkdir(parents=True, exist_ok=True)
    cost_tracker = CostTracker(cost_dir / "single_agent_tool_rag.jsonl")

    retriever = CodeSimilarityRetriever(kb, contrastive=True)

    results = asyncio.run(run_single_agent_tool_rag(
        eval_dataset, retriever, async_client, cost_tracker, args
    ))

    metrics = compute_baseline_metrics(results)
    save_baseline_results(args.output_dir, 'single_agent_tool_rag', results, metrics)

    return
```

**Step 5: Commit**

```bash
git add scripts/ablations/train_three_layer.py
git commit -m "feat: add Single-Agent + Tool + RAG baseline method"
```

---

## Task 8: Add Clean Pool Sensitivity Experiment

**Files:**
- Modify: `scripts/ablations/train_three_layer.py`

**Step 1: Add argument**

```python
parser.add_argument('--clean-pool-frac', type=float, default=1.0,
                    help='Fraction of clean pool to use (for sensitivity experiment)')
```

**Step 2: Add implementation**

```python
async def run_clean_pool_sensitivity(
    dataset,
    kb: KnowledgeBase,
    llm_client: AsyncLLMClient,
    args
) -> Dict:
    """Run clean pool sensitivity experiment."""
    from evoprompt.utils.cost_tracker import CostTracker

    fractions = [0.1, 0.25, 0.5, 1.0]
    results = {}

    print("\n" + "=" * 60)
    print("CLEAN POOL SENSITIVITY EXPERIMENT")
    print("=" * 60)

    for frac in fractions:
        print(f"\n🔬 Running with clean_pool_frac={frac}")

        cost_dir = Path(args.output_dir) / "cost"
        cost_dir.mkdir(parents=True, exist_ok=True)
        cost_tracker = CostTracker(cost_dir / f"mulvul_frac_{frac}.jsonl")

        retriever = CodeSimilarityRetriever(
            kb,
            contrastive=True,
            clean_pool_frac=frac,
            clean_pool_seed=42
        )

        pool_stats = {
            "total_clean": len(kb.clean_examples),
            "subsampled": len(retriever._get_clean_pool()),
            "fraction": frac
        }
        print(f"   Clean pool: {pool_stats['subsampled']}/{pool_stats['total_clean']}")

        # Run MulVul-style evaluation
        # (reuse existing evaluation logic with the modified retriever)
        # ... evaluation code ...

        results[frac] = {
            "clean_pool_size": pool_stats['subsampled'],
            "fraction": frac,
            # "macro_f1": metrics["macro_f1"],
            # "precision": metrics["precision"],
            # "fp_rate": metrics["fp_rate"],
        }

    # Print summary table
    print("\n" + "=" * 60)
    print("CLEAN POOL SENSITIVITY RESULTS")
    print("=" * 60)
    print("Fraction | Pool Size | Macro-F1 | Precision | FP Rate")
    print("-" * 60)
    for frac, data in sorted(results.items()):
        print(f"{frac:8.2f} | {data['clean_pool_size']:9d} | ... | ... | ...")

    return results
```

**Step 3: Add dispatch**

```python
elif args.method == 'clean_pool_sensitivity':
    results = asyncio.run(run_clean_pool_sensitivity(
        eval_dataset, kb, async_client, args
    ))

    # Save results
    with open(Path(args.output_dir) / "metrics" / "clean_pool_sensitivity.json", "w") as f:
        json.dump(results, f, indent=2)

    return
```

**Step 4: Commit**

```bash
git add scripts/ablations/train_three_layer.py
git commit -m "feat: add clean pool sensitivity experiment"
```

---

## Task 9: Add Cross-Model Pairing Ablation

**Files:**
- Modify: `scripts/ablations/train_three_layer.py`
- Create: `configs/cwe_subset_pairing.json`
- Create: `scripts/ablations/generate_cwe_subset.py`

**Step 1: Add arguments**

```python
parser.add_argument('--evo-generator-model', type=str, default='claude',
                    choices=['claude', 'gpt4o'],
                    help='Model for generating prompt mutations')
parser.add_argument('--evo-executor-model', type=str, default='gpt4o',
                    choices=['claude', 'gpt4o'],
                    help='Model for executing/evaluating prompts')
parser.add_argument('--evo-cwe-subset', type=str, default=None,
                    help='Path to JSON file with CWE subset for ablation')
```

**Step 2: Create CWE subset generator**

Create `scripts/ablations/generate_cwe_subset.py`:

```python
#!/usr/bin/env python3
"""Generate balanced CWE subset for pairing ablation."""

import json
import random
import sys
from pathlib import Path
from collections import Counter

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from evoprompt.data.dataset import PrimevulDataset


def generate_balanced_cwe_subset(
    dataset: PrimevulDataset,
    n_cwes: int = 35,
    seed: int = 42
) -> list:
    """Select balanced CWE subset covering different frequencies."""
    random.seed(seed)

    # Count CWE frequencies
    cwe_counts = Counter()
    for sample in dataset.get_samples():
        cwes = sample.metadata.get('cwe', [])
        for cwe in cwes:
            cwe_counts[cwe] += 1

    # Sort by frequency
    sorted_cwes = sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True)

    # Stratified selection
    high_freq = [c for c, n in sorted_cwes if n >= 100][:20]
    medium_freq = [c for c, n in sorted_cwes if 10 <= n < 100]
    long_tail = [c for c, n in sorted_cwes if n < 10]

    # Select proportionally
    subset = []
    subset.extend(random.sample(high_freq, min(14, len(high_freq))))
    subset.extend(random.sample(medium_freq, min(14, len(medium_freq))))
    subset.extend(random.sample(long_tail, min(7, len(long_tail))))

    return subset[:n_cwes]


def main():
    dataset = PrimevulDataset("data/primevul/primevul/dev.jsonl", "train")

    subset = generate_balanced_cwe_subset(dataset, n_cwes=35, seed=42)

    output = {
        "cwes": subset,
        "n_cwes": len(subset),
        "seed": 42,
        "description": "Balanced CWE subset for cross-model pairing ablation"
    }

    output_path = Path("configs/cwe_subset_pairing.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)

    print(f"Generated CWE subset with {len(subset)} CWEs")
    print(f"Saved to: {output_path}")


if __name__ == "__main__":
    main()
```

**Step 3: Add pairing ablation implementation**

```python
async def run_pairing_ablation(
    dataset,
    kb: KnowledgeBase,
    args
) -> Dict:
    """Run cross-model prompt evolution pairing ablation."""

    # Load CWE subset
    if args.evo_cwe_subset:
        with open(args.evo_cwe_subset) as f:
            cwe_config = json.load(f)
        cwe_subset = cwe_config["cwes"]
    else:
        cwe_subset = None

    pairing = f"{args.evo_generator_model}_to_{args.evo_executor_model}"
    print(f"\n🔬 Running pairing ablation: {pairing}")

    if cwe_subset:
        print(f"   CWE subset: {len(cwe_subset)} CWEs")
        # Filter dataset
        # dataset = dataset.filter_by_cwes(cwe_subset)

    # Create agents with specified models
    # generator = create_meta_agent(model_name=args.evo_generator_model)
    # executor = create_detection_agent(model_name=args.evo_executor_model)

    # Run evolution
    # ... evolution code ...

    # Save results
    output_dir = Path(args.output_dir) / "evo_prompts" / pairing
    output_dir.mkdir(parents=True, exist_ok=True)

    return {"pairing": pairing, "cwe_subset": cwe_subset}
```

**Step 4: Add dispatch**

```python
elif args.method == 'pairing_ablation':
    results = asyncio.run(run_pairing_ablation(eval_dataset, kb, args))
    return
```

**Step 5: Commit**

```bash
git add scripts/ablations/train_three_layer.py scripts/ablations/generate_cwe_subset.py
git commit -m "feat: add cross-model pairing ablation experiment"
```

---

## Task 10: Add Rebuttal Snippet Generator

**Files:**
- Create: `scripts/ablations/generate_rebuttal_snippet.py`

**Step 1: Create script**

```python
#!/usr/bin/env python3
"""Generate markdown snippet for OpenReview rebuttal."""

import json
import sys
from pathlib import Path


def load_all_results(output_dir: Path) -> dict:
    """Load all experiment results."""
    results = {}

    # Load baseline comparison
    baseline_path = output_dir / "metrics" / "baseline_comparison.json"
    if baseline_path.exists():
        with open(baseline_path) as f:
            results["baselines"] = json.load(f)

    # Load pairing ablation
    pairing_path = output_dir / "metrics" / "pairing_ablation.json"
    if pairing_path.exists():
        with open(pairing_path) as f:
            results["pairing"] = json.load(f)

    # Load clean pool sensitivity
    sensitivity_path = output_dir / "metrics" / "clean_pool_sensitivity.json"
    if sensitivity_path.exists():
        with open(sensitivity_path) as f:
            results["sensitivity"] = json.load(f)

    return results


def generate_snippet(results: dict) -> str:
    """Generate markdown snippet."""

    snippet = """## Supplementary Experiment Results

### Table R1: Baseline Comparison (Full PrimeVul Test Set)

| Method | Macro-F1 | Avg LLM Calls | Avg Retrieval | Avg Time (ms) |
|--------|----------|---------------|---------------|---------------|
| GPT-4o (no RAG) | - | 1.0 | 0.0 | - |
| GPT-4o + RAG (single-pass) | - | 1.0 | 1.0 | - |
| Single-Agent + Tool + RAG | - | - | - | - |
| **MulVul (Ours)** | **-** | - | - | - |

### Table R2: Cross-Model Pairing Ablation

| Generator → Executor | Macro-F1 | Evolution Cost (tokens) |
|---------------------|----------|------------------------|
| Claude → GPT-4o (MulVul) | - | - |
| GPT-4o → GPT-4o | - | - |

### Table R3: Clean Pool Size Sensitivity

| Clean Pool Fraction | Macro-F1 | Precision | FP Rate |
|--------------------|----------|-----------|---------|
| 10% | - | - | - |
| 25% | - | - | - |
| 50% | - | - | - |
| 100% | - | - | - |

---
*Results generated automatically. Update with actual values after running experiments.*
"""
    return snippet


def main():
    if len(sys.argv) < 2:
        print("Usage: python generate_rebuttal_snippet.py <output_dir>")
        sys.exit(1)

    output_dir = Path(sys.argv[1])
    results = load_all_results(output_dir)

    snippet = generate_snippet(results)

    # Save snippet
    snippet_path = output_dir / "rebuttal_snippet.md"
    with open(snippet_path, "w") as f:
        f.write(snippet)

    print(f"Rebuttal snippet saved to: {snippet_path}")
    print("\n" + "=" * 60)
    print(snippet)


if __name__ == "__main__":
    main()
```

**Step 2: Commit**

```bash
git add scripts/ablations/generate_rebuttal_snippet.py
git commit -m "feat: add rebuttal snippet generator for OpenReview"
```

---

## Task 11: Integration Test and Final Verification

**Step 1: Run all tests**

```bash
uv run pytest tests/test_knowledge_base_clean_pool.py tests/test_contrastive_retriever.py tests/test_cost_tracker.py -v
```

Expected: All tests PASS

**Step 2: Verify baseline command works**

```bash
# Test with small sample
uv run python scripts/ablations/train_three_layer.py --method gpt4o_rag_singlepass --eval-samples 5 --top-k 2
```

**Step 3: Generate CWE subset**

```bash
uv run python scripts/ablations/generate_cwe_subset.py
```

**Step 4: Final commit**

```bash
git add -A
git commit -m "feat: complete supplementary experiments implementation"
```

---

## Summary of Commands

```bash
# Run baselines
uv run python scripts/ablations/train_three_layer.py --method gpt4o_rag_singlepass --top-k 3
uv run python scripts/ablations/train_three_layer.py --method single_agent_tool_rag --max-tool-calls 2

# Cross-model pairing ablation
uv run python scripts/ablations/generate_cwe_subset.py
uv run python scripts/ablations/train_three_layer.py --method pairing_ablation \
    --evo-generator-model claude --evo-executor-model gpt4o \
    --evo-cwe-subset configs/cwe_subset_pairing.json

# Clean pool sensitivity
uv run python scripts/ablations/train_three_layer.py --method clean_pool_sensitivity

# Cost summary
uv run python scripts/ablations/summarize_cost.py outputs/supplementary_experiments/cost/*.jsonl

# Generate rebuttal
uv run python scripts/ablations/generate_rebuttal_snippet.py outputs/supplementary_experiments/
```
