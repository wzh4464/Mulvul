# Adaptive Hierarchy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the fixed 3-level taxonomy (5 major → 13 middle → 46 CWE) with a data-driven hierarchy that automatically merges overlapping CWEs and keeps candidate lists in the 3-6 sweet spot.

**Architecture:** `AdaptiveHierarchyBuilder` analyzes training data CWE co-occurrence and description similarity to build a `DynamicTaxonomy`. The trainer reads from `DynamicTaxonomy` instead of static `MAJOR_TO_MIDDLE`/`MIDDLE_TO_CWE` maps. Hierarchy depth and breadth adapt to the dataset.

**Tech Stack:** Python 3.9+, scikit-learn (AgglomerativeClustering), existing `CoevolutionaryTrainer`

**Worktree:** `../Mulvul-adaptive-hierarchy` on branch `feat/adaptive-hierarchy`

---

## File Structure

| File | Responsibility |
|---|---|
| `src/mulvul/agents/adaptive_hierarchy.py` | **Create.** `DynamicTaxonomy`, `AdaptiveHierarchyBuilder` |
| `tests/test_adaptive_hierarchy.py` | **Create.** Unit tests |
| `src/mulvul/agents/coevolutionary_trainer.py` | **Modify.** Accept `DynamicTaxonomy` in `_init_populations` |
| `scripts/run_mainline_evolution.py` | **Modify.** Add `--adaptive-hierarchy` flag |

---

### Task 1: DynamicTaxonomy Data Structure

**Files:**
- Create: `src/mulvul/agents/adaptive_hierarchy.py`
- Test: `tests/test_adaptive_hierarchy.py`

- [ ] **Step 1: Write failing tests**

```python
"""Tests for adaptive hierarchy construction."""
from __future__ import annotations

import pytest


class TestDynamicTaxonomy:
    def test_candidates_for_returns_siblings(self):
        from mulvul.agents.adaptive_hierarchy import DynamicTaxonomy

        tax = DynamicTaxonomy(
            stages=["group", "cwe"],
            parent_map={"CWE-119": "buffer", "CWE-120": "buffer", "CWE-476": "pointer"},
            children_map={"buffer": ["CWE-119", "CWE-120"], "pointer": ["CWE-476"]},
            labels={"CWE-119": "Buffer Overflow", "CWE-120": "Classic Overflow",
                    "CWE-476": "NULL Deref", "buffer": "Buffer Errors", "pointer": "Pointer Deref"},
        )
        cands = tax.candidates_for("CWE-119")
        assert "CWE-119" in cands
        assert "CWE-120" in cands
        assert "CWE-476" not in cands

    def test_candidates_includes_benign(self):
        from mulvul.agents.adaptive_hierarchy import DynamicTaxonomy

        tax = DynamicTaxonomy(
            stages=["group", "cwe"],
            parent_map={"CWE-119": "buffer", "CWE-120": "buffer"},
            children_map={"buffer": ["CWE-119", "CWE-120"]},
            labels={},
        )
        cands = tax.candidates_for("CWE-119")
        assert "Benign" in cands

    def test_depth(self):
        from mulvul.agents.adaptive_hierarchy import DynamicTaxonomy

        tax = DynamicTaxonomy(
            stages=["major", "group", "cwe"],
            parent_map={}, children_map={}, labels={},
        )
        assert tax.depth() == 3

    def test_root_nodes(self):
        from mulvul.agents.adaptive_hierarchy import DynamicTaxonomy

        tax = DynamicTaxonomy(
            stages=["group", "cwe"],
            parent_map={"CWE-119": "buffer", "CWE-120": "buffer", "buffer": None},
            children_map={"buffer": ["CWE-119", "CWE-120"]},
            labels={},
        )
        roots = tax.root_nodes()
        assert roots == ["buffer"]

    def test_all_leaves(self):
        from mulvul.agents.adaptive_hierarchy import DynamicTaxonomy

        tax = DynamicTaxonomy(
            stages=["group", "cwe"],
            parent_map={"CWE-119": "buffer", "CWE-120": "buffer"},
            children_map={"buffer": ["CWE-119", "CWE-120"]},
            labels={},
        )
        leaves = tax.all_leaves()
        assert set(leaves) == {"CWE-119", "CWE-120"}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_adaptive_hierarchy.py -v`

- [ ] **Step 3: Implement DynamicTaxonomy**

```python
"""Data-driven taxonomy for adaptive cascade hierarchy."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class DynamicTaxonomy:
    """A data-driven taxonomy that replaces static hierarchy maps.

    Unlike the fixed MAJOR_TO_MIDDLE/MIDDLE_TO_CWE, this structure
    supports arbitrary depth and is built from training data.
    """

    stages: List[str]
    parent_map: Dict[str, Optional[str]]
    children_map: Dict[str, List[str]]
    labels: Dict[str, str]

    def candidates_for(self, node_id: str) -> List[str]:
        """Return sibling candidates for a node (including itself and Benign)."""
        parent = self.parent_map.get(node_id)
        if parent is None:
            return [node_id, "Benign"]
        siblings = list(self.children_map.get(parent, []))
        if "Benign" not in siblings:
            siblings.append("Benign")
        return siblings

    def depth(self) -> int:
        return len(self.stages)

    def root_nodes(self) -> List[str]:
        """Return nodes with no parent (top of hierarchy)."""
        all_children = {c for kids in self.children_map.values() for c in kids}
        all_parents = set(self.children_map.keys())
        return [p for p in all_parents if self.parent_map.get(p) is None]

    def all_leaves(self) -> List[str]:
        """Return nodes with no children (bottom of hierarchy)."""
        parents = set(self.children_map.keys())
        all_nodes = set(self.parent_map.keys())
        return [n for n in all_nodes if n not in parents]

    def stage_of(self, node_id: str) -> str:
        """Determine which stage a node belongs to."""
        if node_id in self.children_map and node_id not in self.parent_map:
            return self.stages[0]
        depth = 0
        current = node_id
        while self.parent_map.get(current) is not None:
            depth += 1
            current = self.parent_map[current]
        idx = min(len(self.stages) - 1, len(self.stages) - 1 - 0 + depth)
        return self.stages[min(depth, len(self.stages) - 1)]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stages": self.stages,
            "parent_map": self.parent_map,
            "children_map": self.children_map,
            "labels": self.labels,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> DynamicTaxonomy:
        return cls(
            stages=data["stages"],
            parent_map=data["parent_map"],
            children_map=data["children_map"],
            labels=data["labels"],
        )
```

- [ ] **Step 4: Run tests, commit**

```bash
uv run pytest tests/test_adaptive_hierarchy.py -v
git add src/mulvul/agents/adaptive_hierarchy.py tests/test_adaptive_hierarchy.py
git commit -m "feat: add DynamicTaxonomy data structure"
```

---

### Task 2: AdaptiveHierarchyBuilder

**Files:**
- Modify: `src/mulvul/agents/adaptive_hierarchy.py`
- Test: `tests/test_adaptive_hierarchy.py`

- [ ] **Step 1: Write failing tests**

```python
class TestAdaptiveHierarchyBuilder:
    def test_build_groups_overlapping_cwes(self, tmp_path):
        from mulvul.agents.adaptive_hierarchy import AdaptiveHierarchyBuilder

        # Create minimal JSONL with 3 CWEs under same middle
        data_path = tmp_path / "train.jsonl"
        lines = []
        for cwe in ["CWE-119", "CWE-120", "CWE-125"]:
            for i in range(60):
                lines.append(json.dumps({"func": f"void f{i}(){{;}}", "target": 1, "cwe": [cwe]}))
        for i in range(100):
            lines.append(json.dumps({"func": f"int g{i}(){{return 0;}}", "target": 0, "cwe": []}))
        data_path.write_text("\n".join(lines))

        builder = AdaptiveHierarchyBuilder(max_candidates=6, min_candidates=2)
        tax = builder.build(str(data_path))

        # All 3 CWEs should be leaves
        leaves = tax.all_leaves()
        assert "CWE-119" in leaves
        assert "CWE-120" in leaves
        assert "CWE-125" in leaves
        # Each leaf should have <= max_candidates siblings
        for leaf in leaves:
            cands = tax.candidates_for(leaf)
            assert len(cands) <= 7  # max_candidates + Benign

    def test_build_respects_max_candidates(self, tmp_path):
        from mulvul.agents.adaptive_hierarchy import AdaptiveHierarchyBuilder

        # 10 CWEs all under same middle — should be split into subgroups
        data_path = tmp_path / "train.jsonl"
        lines = []
        for i in range(10):
            cwe = f"CWE-{100+i}"
            for j in range(60):
                lines.append(json.dumps({"func": f"void f{j}(){{;}}", "target": 1, "cwe": [cwe]}))
        for i in range(200):
            lines.append(json.dumps({"func": f"int g{i}(){{return 0;}}", "target": 0, "cwe": []}))
        data_path.write_text("\n".join(lines))

        builder = AdaptiveHierarchyBuilder(max_candidates=5, min_candidates=2)
        tax = builder.build(str(data_path))

        for leaf in tax.all_leaves():
            cands = tax.candidates_for(leaf)
            assert len(cands) <= 6  # max + Benign

    def test_build_filters_rare_cwes(self, tmp_path):
        from mulvul.agents.adaptive_hierarchy import AdaptiveHierarchyBuilder

        data_path = tmp_path / "train.jsonl"
        lines = []
        # CWE-119: 60 samples (kept)
        for i in range(60):
            lines.append(json.dumps({"func": f"void f{i}(){{;}}", "target": 1, "cwe": ["CWE-119"]}))
        # CWE-999: 3 samples (filtered)
        for i in range(3):
            lines.append(json.dumps({"func": f"void g{i}(){{;}}", "target": 1, "cwe": ["CWE-999"]}))
        for i in range(50):
            lines.append(json.dumps({"func": f"int h{i}(){{return 0;}}", "target": 0, "cwe": []}))
        data_path.write_text("\n".join(lines))

        builder = AdaptiveHierarchyBuilder(min_samples=10)
        tax = builder.build(str(data_path))

        leaves = tax.all_leaves()
        assert "CWE-119" in leaves
        assert "CWE-999" not in leaves
```

- [ ] **Step 2: Run tests to verify fail, then implement**

```python
import json
from collections import Counter, defaultdict

from mulvul.data.cwe_hierarchy import CWE_TO_MIDDLE, MIDDLE_TO_MAJOR, CWE_DESCRIPTIONS


class AdaptiveHierarchyBuilder:
    """Build a data-driven taxonomy from training data."""

    def __init__(
        self,
        max_candidates: int = 6,
        min_candidates: int = 2,
        min_samples: int = 10,
    ):
        self.max_candidates = max_candidates
        self.min_candidates = min_candidates
        self.min_samples = min_samples

    def build(self, data_path: str) -> DynamicTaxonomy:
        """Analyze training data and build optimal hierarchy."""
        # Count CWE occurrences
        cwe_counts = self._count_cwes(data_path)

        # Filter rare CWEs
        eligible = {cwe: cnt for cwe, cnt in cwe_counts.items() if cnt >= self.min_samples}

        # Group by existing middle category
        by_middle: dict[str, list[str]] = defaultdict(list)
        for cwe in eligible:
            mid = CWE_TO_MIDDLE.get(cwe, "Other")
            by_middle[mid].append(cwe)

        # Build hierarchy: split large groups, merge tiny ones
        parent_map: dict[str, str | None] = {}
        children_map: dict[str, list[str]] = {}
        labels: dict[str, str] = {}

        # Group middles by major
        by_major: dict[str, list[str]] = defaultdict(list)
        for mid in by_middle:
            maj = MIDDLE_TO_MAJOR.get(mid, "Other")
            by_major[maj].append(mid)

        # Build major level
        for maj, middles in by_major.items():
            parent_map[maj] = None
            children_map[maj] = list(middles)
            labels[maj] = maj

            for mid in middles:
                parent_map[mid] = maj
                labels[mid] = mid
                cwes = by_middle[mid]

                if len(cwes) <= self.max_candidates:
                    # Fits within limit — direct children
                    children_map[mid] = list(cwes)
                    for cwe in cwes:
                        parent_map[cwe] = mid
                        labels[cwe] = CWE_DESCRIPTIONS.get(cwe, cwe)
                else:
                    # Too many — split into subgroups
                    subgroups = self._split_into_subgroups(cwes)
                    children_map[mid] = []
                    for i, group in enumerate(subgroups):
                        group_id = f"{mid}_g{i}"
                        parent_map[group_id] = mid
                        children_map[mid].append(group_id)
                        children_map[group_id] = list(group)
                        labels[group_id] = f"{mid} group {i}"
                        for cwe in group:
                            parent_map[cwe] = group_id
                            labels[cwe] = CWE_DESCRIPTIONS.get(cwe, cwe)

        stages = ["major", "middle", "cwe"]
        return DynamicTaxonomy(stages=stages, parent_map=parent_map,
                               children_map=children_map, labels=labels)

    def _count_cwes(self, path: str) -> dict[str, int]:
        counts: dict[str, int] = Counter()
        with open(path) as f:
            for line in f:
                if not line.strip():
                    continue
                item = json.loads(line)
                if int(item.get("target", 0)) == 1:
                    cwes = item.get("cwe", [])
                    if cwes:
                        counts[cwes[0]] += 1
        return dict(counts)

    def _split_into_subgroups(self, cwes: list[str]) -> list[list[str]]:
        """Split a list of CWEs into subgroups of max_candidates size."""
        groups: list[list[str]] = []
        current: list[str] = []
        for cwe in sorted(cwes):
            current.append(cwe)
            if len(current) >= self.max_candidates:
                groups.append(current)
                current = []
        if current:
            if groups and len(current) < self.min_candidates:
                groups[-1].extend(current)
            else:
                groups.append(current)
        return groups
```

- [ ] **Step 3: Run tests, commit**

```bash
uv run pytest tests/test_adaptive_hierarchy.py -v
git add src/mulvul/agents/adaptive_hierarchy.py tests/test_adaptive_hierarchy.py
git commit -m "feat: add AdaptiveHierarchyBuilder for data-driven taxonomy"
```

---

### Task 3: Integrate with CoevolutionaryTrainer

**Files:**
- Modify: `src/mulvul/agents/coevolutionary_trainer.py`
- Modify: `scripts/run_mainline_evolution.py`

- [ ] **Step 1: Add `taxonomy` parameter to trainer**

In `CoevolutionaryTrainer.__init__`, add optional `taxonomy: DynamicTaxonomy | None = None` parameter. In `_init_populations`, if `taxonomy` is provided, use it instead of static maps.

- [ ] **Step 2: Add `--adaptive-hierarchy` flag to CLI**

In `scripts/run_mainline_evolution.py`, add flag. When set, run `AdaptiveHierarchyBuilder.build()` on the training file and pass the result to the trainer.

- [ ] **Step 3: Run existing tests to verify no regression**

```bash
uv run pytest tests/test_coevolutionary_trainer.py tests/test_adaptive_hierarchy.py -v
```

- [ ] **Step 4: Commit**

```bash
git add src/mulvul/agents/coevolutionary_trainer.py scripts/run_mainline_evolution.py
git commit -m "feat: integrate adaptive hierarchy into evolution workflow"
```

---

### Task 4: Ablation Experiment

- [ ] **Step 1: Run adaptive hierarchy evolution**

```bash
uv run python scripts/run_mainline_evolution.py \
  --train-file data/primevul/primevul_balanced_20.jsonl \
  --output-dir outputs/ablation_adaptive_hierarchy \
  --rounds 5 --samples-per-class 30 --adaptive-hierarchy
```

- [ ] **Step 2: Compare against baseline, push PR**

```bash
git push -u origin feat/adaptive-hierarchy
gh pr create --title "feat: adaptive hierarchy — data-driven taxonomy" --body "..."
```
