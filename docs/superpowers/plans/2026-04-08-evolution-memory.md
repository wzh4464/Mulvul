# Evolution Memory Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the meta-LLM a persistent memory of what mutations worked/failed, so it can make better evolution decisions across generations.

**Architecture:** `EvolutionMemory` stores natural-language experience records (`node`, `action`, `description`, `f1_delta`). Before each mutation, top-5 relevant experiences are retrieved and injected into the meta-LLM prompt. After mutation, the meta-LLM summarizes what it changed in one sentence, and the F1 delta is recorded.

**Tech Stack:** Python 3.9+, JSONL storage, existing `CoevolutionaryTrainer`

**Worktree:** `../Mulvul-evolution-memory` on branch `feat/evolution-memory`

---

## File Structure

| File | Responsibility |
|---|---|
| `src/mulvul/agents/evolution_memory.py` | **Create.** `Experience` dataclass, `EvolutionMemory` (record/retrieve/format) |
| `tests/test_evolution_memory.py` | **Create.** Unit tests |
| `src/mulvul/agents/coevolutionary_trainer.py` | **Modify.** Integrate memory into `_mutate_prompt` and `_phase4_evolve` |

---

### Task 1: EvolutionMemory Core

**Files:**
- Create: `src/mulvul/agents/evolution_memory.py`
- Test: `tests/test_evolution_memory.py`

- [ ] **Step 1: Write failing tests**

```python
"""Tests for evolution memory system."""
from __future__ import annotations

import json
import pytest
from pathlib import Path


class TestExperience:
    def test_is_positive(self):
        from mulvul.agents.evolution_memory import Experience

        pos = Experience(node="cwe_CWE-189", action="mutation",
                         description="Added distinction rules", f1_before=0.16, f1_after=0.49,
                         delta=0.33, generation=1)
        neg = Experience(node="major_Crypto", action="mutation",
                         description="Rewrote role description", f1_before=0.69, f1_after=0.41,
                         delta=-0.28, generation=1)
        assert pos.is_positive
        assert not neg.is_positive

    def test_to_dict_roundtrip(self):
        from mulvul.agents.evolution_memory import Experience

        exp = Experience(node="cwe_CWE-89", action="crossover",
                         description="Merged SQL-focused prompts", f1_before=0.5, f1_after=0.8,
                         delta=0.3, generation=2)
        d = exp.to_dict()
        restored = Experience.from_dict(d)
        assert restored.node == exp.node
        assert restored.delta == exp.delta


class TestEvolutionMemory:
    def test_record_and_retrieve_same_node(self, tmp_path):
        from mulvul.agents.evolution_memory import EvolutionMemory, Experience

        mem = EvolutionMemory(tmp_path / "memory.jsonl")
        mem.record(Experience(
            node="cwe_CWE-189", action="mutation",
            description="Added CWE distinction rules",
            f1_before=0.16, f1_after=0.49, delta=0.33, generation=0,
        ))
        mem.record(Experience(
            node="cwe_CWE-190", action="mutation",
            description="Added overflow examples",
            f1_before=0.6, f1_after=0.7, delta=0.1, generation=0,
        ))

        results = mem.retrieve("cwe_CWE-189", stage="cwe", top_k=5)
        # Same node's experience should rank first
        assert results[0].node == "cwe_CWE-189"

    def test_retrieve_includes_sibling_experiences(self, tmp_path):
        from mulvul.agents.evolution_memory import EvolutionMemory, Experience

        mem = EvolutionMemory(tmp_path / "memory.jsonl")
        mem.record(Experience(
            node="cwe_CWE-190", action="mutation",
            description="Added integer overflow patterns",
            f1_before=0.5, f1_after=0.7, delta=0.2, generation=0,
        ))

        # Query for CWE-189 (same stage sibling) — should find CWE-190's experience
        results = mem.retrieve("cwe_CWE-189", stage="cwe", top_k=5)
        assert len(results) >= 1
        assert results[0].node == "cwe_CWE-190"

    def test_format_for_prompt(self, tmp_path):
        from mulvul.agents.evolution_memory import EvolutionMemory, Experience

        mem = EvolutionMemory(tmp_path / "memory.jsonl")
        mem.record(Experience(
            node="cwe_CWE-189", action="mutation",
            description="Added distinction rules between CWE-189/190",
            f1_before=0.16, f1_after=0.49, delta=0.33, generation=0,
        ))
        mem.record(Experience(
            node="major_Crypto", action="mutation",
            description="Completely rewrote role description",
            f1_before=0.69, f1_after=0.41, delta=-0.28, generation=1,
        ))

        text = mem.format_for_prompt(mem.retrieve("cwe_CWE-189", "cwe", top_k=5))
        assert "+0.33" in text
        assert "-0.28" in text
        assert "distinction rules" in text

    def test_persists_across_instances(self, tmp_path):
        from mulvul.agents.evolution_memory import EvolutionMemory, Experience

        path = tmp_path / "memory.jsonl"
        mem1 = EvolutionMemory(path)
        mem1.record(Experience(
            node="cwe_CWE-89", action="mutation",
            description="Test persistence", f1_before=0.5, f1_after=0.8,
            delta=0.3, generation=0,
        ))

        mem2 = EvolutionMemory(path)
        results = mem2.retrieve("cwe_CWE-89", "cwe", top_k=5)
        assert len(results) == 1
        assert results[0].description == "Test persistence"

    def test_empty_memory_returns_empty(self, tmp_path):
        from mulvul.agents.evolution_memory import EvolutionMemory

        mem = EvolutionMemory(tmp_path / "memory.jsonl")
        results = mem.retrieve("cwe_CWE-119", "cwe", top_k=5)
        assert results == []
```

- [ ] **Step 2: Run tests to verify fail**

Run: `uv run pytest tests/test_evolution_memory.py -v`

- [ ] **Step 3: Implement EvolutionMemory**

```python
"""Persistent natural-language memory for meta-LLM evolution decisions."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List


@dataclass
class Experience:
    """One evolution experience record."""

    node: str
    action: str          # "mutation" | "crossover" | "migration"
    description: str     # natural language: what was changed
    f1_before: float
    f1_after: float
    delta: float
    generation: int

    @property
    def is_positive(self) -> bool:
        return self.delta > 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Experience:
        return cls(**{k: data[k] for k in cls.__dataclass_fields__})


class EvolutionMemory:
    """Append-only JSONL memory with relevance-based retrieval.

    Experiences are stored as natural-language records and retrieved
    by relevance: same-node > same-stage > high-delta global.
    """

    def __init__(self, path: Path | str):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._experiences: List[Experience] = []
        self._load()

    def _load(self) -> None:
        if self._path.exists():
            with self._path.open() as f:
                for line in f:
                    if line.strip():
                        self._experiences.append(Experience.from_dict(json.loads(line)))

    def record(self, exp: Experience) -> None:
        """Append an experience to memory."""
        self._experiences.append(exp)
        with self._path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(exp.to_dict(), ensure_ascii=False) + "\n")

    def retrieve(self, node: str, stage: str, top_k: int = 5) -> List[Experience]:
        """Retrieve most relevant experiences for a node.

        Ranking: same node (score 3) > same stage (score 2) > global high-delta (score 1).
        Within each tier, sort by |delta| descending.
        """
        if not self._experiences:
            return []

        def _score(exp: Experience) -> tuple[int, float]:
            if exp.node == node:
                return (3, abs(exp.delta))
            if exp.node.split("_", 1)[0] == stage:
                return (2, abs(exp.delta))
            return (1, abs(exp.delta))

        ranked = sorted(self._experiences, key=_score, reverse=True)
        return ranked[:top_k]

    def format_for_prompt(self, experiences: List[Experience]) -> str:
        """Format experiences as a prompt section."""
        if not experiences:
            return ""
        lines = ["## Lessons from previous evolution rounds:"]
        for exp in experiences:
            sign = "+" if exp.delta >= 0 else ""
            lines.append(
                f"- [{sign}{exp.delta:.2f}] {exp.node}: {exp.description}"
            )
        return "\n".join(lines)
```

- [ ] **Step 4: Run tests, commit**

```bash
uv run pytest tests/test_evolution_memory.py -v
git add src/mulvul/agents/evolution_memory.py tests/test_evolution_memory.py
git commit -m "feat: add EvolutionMemory for cross-generation experience learning"
```

---

### Task 2: Integrate Memory into CoevolutionaryTrainer

**Files:**
- Modify: `src/mulvul/agents/coevolutionary_trainer.py`

- [ ] **Step 1: Add memory to trainer init**

In `__init__`, create `self.memory = EvolutionMemory(Path(output_dir) / "evolution_memory.jsonl")`.

- [ ] **Step 2: Inject memory into `_mutate_prompt`**

Before the mutation request, retrieve relevant experiences and append to the prompt:

```python
# In _mutate_prompt, before building mutation_request:
from .evolution_memory import EvolutionMemory

stage = node_key.split("_", 1)[0]
experiences = self.memory.retrieve(node_key, stage, top_k=5)
memory_context = self.memory.format_for_prompt(experiences)

# Append to mutation_request:
mutation_request = (
    f"Improve this vulnerability detection instruction for node '{node_key}'.\n\n"
    f"--- CURRENT INSTRUCTION ---\n{mutable.strip()}\n"
    f"--- END INSTRUCTION ---\n\n"
    f"Cascade errors attributed to this node:\n{error_summary}\n\n"
    + (f"{memory_context}\n\n" if memory_context else "")
    + "You may:\n"
    # ... rest unchanged
)
```

- [ ] **Step 3: Record experience after mutation in `_phase4_evolve`**

After mutation, when Phase 1 of the next generation scores the mutated node, compare F1 before/after and record the experience. This requires:

1. Before mutation, save `f1_before = pop.best().node_fitness`
2. After next Phase 1 scores the node, compute `f1_after`
3. Ask meta-LLM: "Summarize in one sentence what you changed in this prompt" (10 tokens)
4. Record `Experience(node, "mutation", summary, f1_before, f1_after, delta, gen)`

Implementation: track pending mutations in `self._pending_mutations: Dict[str, float]` (node_key → f1_before). After Phase 1 scoring, check pending mutations and record experiences.

- [ ] **Step 4: Run all tests**

```bash
uv run pytest tests/test_evolution_memory.py tests/test_coevolutionary_trainer.py -v
```

- [ ] **Step 5: Commit**

```bash
git add src/mulvul/agents/coevolutionary_trainer.py src/mulvul/agents/evolution_memory.py
git commit -m "feat: integrate evolution memory into mutation pipeline"
```

---

### Task 3: Ablation Experiment

- [ ] **Step 1: Run memory-augmented evolution**

```bash
uv run python scripts/run_mainline_evolution.py \
  --train-file data/primevul/primevul_balanced_20.jsonl \
  --output-dir outputs/ablation_evolution_memory \
  --rounds 5 --samples-per-class 30
```

- [ ] **Step 2: Compare against baseline**

```bash
# Compare avg F1 per generation: baseline vs memory-augmented
# Check evolution_memory.jsonl for experience quality
```

- [ ] **Step 3: Push PR with results**

```bash
git push -u origin feat/evolution-memory
gh pr create --title "feat: meta-LLM evolution memory" --body "..."
```
