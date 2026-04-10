"""Tests for adaptive hierarchy — data-driven taxonomy construction."""

from __future__ import annotations

import json
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# DynamicTaxonomy unit tests
# ---------------------------------------------------------------------------


class TestDynamicTaxonomy:
    """Unit tests for the DynamicTaxonomy dataclass."""

    def _make_simple_taxonomy(self):
        """Build a small two-level taxonomy for testing.

        Structure:
            root
            ├── Memory
            │   ├── CWE-119
            │   └── CWE-416
            └── Logic
                └── CWE-362
        """
        from mulvul.agents.adaptive_hierarchy import DynamicTaxonomy

        return DynamicTaxonomy(
            stages=["major", "cwe"],
            parent_map={
                "Memory": None,
                "Logic": None,
                "CWE-119": "Memory",
                "CWE-416": "Memory",
                "CWE-362": "Logic",
            },
            children_map={
                "Memory": ["CWE-119", "CWE-416"],
                "Logic": ["CWE-362"],
            },
            labels={
                "Memory": "Memory",
                "Logic": "Logic",
                "CWE-119": "Buffer overflow",
                "CWE-416": "Use after free",
                "CWE-362": "Race condition",
            },
        )

    def _make_three_level_taxonomy(self):
        """Build a three-level (major/middle/cwe) taxonomy for testing.

        Structure:
            root
            ├── Memory
            │   ├── Buffer Errors
            │   │   ├── CWE-119
            │   │   └── CWE-787
            │   └── Memory Management
            │       └── CWE-416
            └── Logic
                └── Concurrency Issues
                    └── CWE-362
        """
        from mulvul.agents.adaptive_hierarchy import DynamicTaxonomy

        return DynamicTaxonomy(
            stages=["major", "middle", "cwe"],
            parent_map={
                "Memory": None,
                "Logic": None,
                "Buffer Errors": "Memory",
                "Memory Management": "Memory",
                "Concurrency Issues": "Logic",
                "CWE-119": "Buffer Errors",
                "CWE-787": "Buffer Errors",
                "CWE-416": "Memory Management",
                "CWE-362": "Concurrency Issues",
            },
            children_map={
                "Memory": ["Buffer Errors", "Memory Management"],
                "Logic": ["Concurrency Issues"],
                "Buffer Errors": ["CWE-119", "CWE-787"],
                "Memory Management": ["CWE-416"],
                "Concurrency Issues": ["CWE-362"],
            },
            labels={
                "Memory": "Memory",
                "Logic": "Logic",
                "Buffer Errors": "Buffer Errors",
                "Memory Management": "Memory Management",
                "Concurrency Issues": "Concurrency Issues",
                "CWE-119": "Buffer overflow",
                "CWE-787": "Out-of-bounds write",
                "CWE-416": "Use after free",
                "CWE-362": "Race condition",
            },
        )

    def test_candidates_for_returns_siblings_plus_benign(self):
        tax = self._make_simple_taxonomy()
        candidates = tax.candidates_for("CWE-119")
        assert "CWE-119" in candidates
        assert "CWE-416" in candidates
        assert "Benign" in candidates
        # CWE-362 is NOT a sibling of CWE-119
        assert "CWE-362" not in candidates

    def test_candidates_for_single_child(self):
        tax = self._make_simple_taxonomy()
        candidates = tax.candidates_for("CWE-362")
        assert "CWE-362" in candidates
        assert "Benign" in candidates
        # Single child means siblings list = [CWE-362]
        assert len(candidates) == 2

    def test_candidates_for_root_node(self):
        tax = self._make_simple_taxonomy()
        candidates = tax.candidates_for("Memory")
        # Root nodes are siblings of each other
        assert "Memory" in candidates
        assert "Logic" in candidates
        assert "Benign" in candidates

    def test_candidates_for_three_level_middle_node(self):
        tax = self._make_three_level_taxonomy()
        candidates = tax.candidates_for("Buffer Errors")
        assert "Buffer Errors" in candidates
        assert "Memory Management" in candidates
        assert "Benign" in candidates
        # Concurrency Issues is NOT a sibling (different parent)
        assert "Concurrency Issues" not in candidates

    def test_root_nodes(self):
        tax = self._make_simple_taxonomy()
        roots = tax.root_nodes()
        assert set(roots) == {"Memory", "Logic"}

    def test_all_leaves(self):
        tax = self._make_simple_taxonomy()
        leaves = tax.all_leaves()
        assert set(leaves) == {"CWE-119", "CWE-416", "CWE-362"}

    def test_all_leaves_three_level(self):
        tax = self._make_three_level_taxonomy()
        leaves = tax.all_leaves()
        assert set(leaves) == {"CWE-119", "CWE-787", "CWE-416", "CWE-362"}

    def test_depth(self):
        tax = self._make_simple_taxonomy()
        assert tax.depth() == 2

    def test_depth_three_level(self):
        tax = self._make_three_level_taxonomy()
        assert tax.depth() == 3

    def test_to_dict_and_from_dict_roundtrip(self):
        from mulvul.agents.adaptive_hierarchy import DynamicTaxonomy

        tax = self._make_three_level_taxonomy()
        data = tax.to_dict()
        restored = DynamicTaxonomy.from_dict(data)
        assert restored.stages == tax.stages
        assert restored.parent_map == tax.parent_map
        assert restored.children_map == tax.children_map
        assert restored.labels == tax.labels

    def test_to_dict_is_json_serializable(self):
        tax = self._make_three_level_taxonomy()
        data = tax.to_dict()
        serialized = json.dumps(data)
        assert isinstance(serialized, str)

    def test_candidates_for_unknown_node_raises(self):
        tax = self._make_simple_taxonomy()
        with pytest.raises(KeyError):
            tax.candidates_for("CWE-999")


# ---------------------------------------------------------------------------
# AdaptiveHierarchyBuilder unit tests
# ---------------------------------------------------------------------------


class TestAdaptiveHierarchyBuilder:
    """Unit tests for the AdaptiveHierarchyBuilder."""

    def _write_jsonl(self, path: Path, records: list[dict]) -> str:
        filepath = path / "test.jsonl"
        with open(filepath, "w") as f:
            for rec in records:
                f.write(json.dumps(rec) + "\n")
        return str(filepath)

    def _make_records(
        self, cwe_counts: dict[str, int], benign_count: int = 0
    ) -> list[dict]:
        """Generate minimal JSONL records with given CWE counts."""
        records = []
        idx = 0
        for cwe, count in cwe_counts.items():
            for _ in range(count):
                records.append(
                    {
                        "idx": idx,
                        "target": 1,
                        "cwe": [cwe],
                        "func": f"void f_{idx}() {{}}",
                    }
                )
                idx += 1
        for _ in range(benign_count):
            records.append(
                {
                    "idx": idx,
                    "target": 0,
                    "cwe": [],
                    "func": f"int safe_{idx}() {{ return 0; }}",
                }
            )
            idx += 1
        return records

    def test_build_groups_cwes_by_middle(self, tmp_path):
        from mulvul.agents.adaptive_hierarchy import AdaptiveHierarchyBuilder

        # CWE-119 and CWE-787 both map to Buffer Errors
        records = self._make_records({"CWE-119": 20, "CWE-787": 20}, benign_count=10)
        data_path = self._write_jsonl(tmp_path, records)

        builder = AdaptiveHierarchyBuilder(min_samples=5)
        tax = builder.build(data_path)

        # Both CWEs should be leaves
        leaves = tax.all_leaves()
        assert "CWE-119" in leaves
        assert "CWE-787" in leaves

        # They should share the same parent (a middle or subgroup node)
        assert tax.parent_map["CWE-119"] == tax.parent_map["CWE-787"]

    def test_build_filters_rare_cwes(self, tmp_path):
        from mulvul.agents.adaptive_hierarchy import AdaptiveHierarchyBuilder

        records = self._make_records(
            {"CWE-119": 20, "CWE-787": 20, "CWE-120": 3}, benign_count=10
        )
        data_path = self._write_jsonl(tmp_path, records)

        builder = AdaptiveHierarchyBuilder(min_samples=10)
        tax = builder.build(data_path)

        leaves = tax.all_leaves()
        assert "CWE-119" in leaves
        assert "CWE-787" in leaves
        # CWE-120 has only 3 samples < min_samples=10 -> filtered
        assert "CWE-120" not in leaves

    def test_build_splits_large_groups(self, tmp_path):
        from mulvul.agents.adaptive_hierarchy import AdaptiveHierarchyBuilder

        # Buffer Errors has 8 CWEs in the canonical taxonomy:
        # CWE-119, CWE-120, CWE-121, CWE-122, CWE-125, CWE-131, CWE-787, CWE-805
        buffer_cwes = {
            "CWE-119": 15,
            "CWE-120": 15,
            "CWE-121": 15,
            "CWE-122": 15,
            "CWE-125": 15,
            "CWE-131": 15,
            "CWE-787": 15,
            "CWE-805": 15,
        }
        records = self._make_records(buffer_cwes, benign_count=10)
        data_path = self._write_jsonl(tmp_path, records)

        builder = AdaptiveHierarchyBuilder(max_candidates=4, min_samples=10)
        tax = builder.build(data_path)

        leaves = tax.all_leaves()
        for cwe in buffer_cwes:
            assert cwe in leaves

        # With 8 CWEs and max_candidates=4, the middle group should be split.
        # Each leaf CWE should have at most max_candidates-1 siblings (+ Benign).
        for cwe in buffer_cwes:
            candidates = tax.candidates_for(cwe)
            # candidates = siblings + Benign; siblings <= max_candidates
            sibling_count = len(candidates) - 1  # subtract Benign
            assert sibling_count <= 4, (
                f"{cwe} has {sibling_count} siblings, expected <= 4"
            )

    def test_build_preserves_major_middle_structure(self, tmp_path):
        from mulvul.agents.adaptive_hierarchy import AdaptiveHierarchyBuilder

        # CWE-119 -> Buffer Errors -> Memory
        # CWE-362 -> Concurrency Issues -> Logic
        records = self._make_records({"CWE-119": 20, "CWE-362": 20}, benign_count=10)
        data_path = self._write_jsonl(tmp_path, records)

        builder = AdaptiveHierarchyBuilder(min_samples=10)
        tax = builder.build(data_path)

        roots = tax.root_nodes()
        assert "Memory" in roots
        assert "Logic" in roots
        assert len(tax.stages) == 3  # major/middle/cwe

    def test_build_min_candidates_floor(self, tmp_path):
        from mulvul.agents.adaptive_hierarchy import AdaptiveHierarchyBuilder

        # Single CWE in a middle group should still work
        records = self._make_records({"CWE-476": 20}, benign_count=10)
        data_path = self._write_jsonl(tmp_path, records)

        builder = AdaptiveHierarchyBuilder(min_samples=10, min_candidates=2)
        tax = builder.build(data_path)

        leaves = tax.all_leaves()
        assert "CWE-476" in leaves
        candidates = tax.candidates_for("CWE-476")
        assert "Benign" in candidates


# ---------------------------------------------------------------------------
# Integration test with PrimeVul-Balanced-20
# ---------------------------------------------------------------------------


class TestTrainerWithTaxonomy:
    """Test that CoevolutionaryTrainer uses DynamicTaxonomy when provided."""

    def test_init_populations_from_taxonomy(self, tmp_path):
        from mulvul.agents.adaptive_hierarchy import DynamicTaxonomy
        from mulvul.agents.coevolutionary_trainer import CoevolutionaryTrainer

        tax = DynamicTaxonomy(
            stages=["major", "middle", "cwe"],
            parent_map={
                "Memory": None,
                "Logic": None,
                "Buffer Errors": "Memory",
                "Concurrency Issues": "Logic",
                "CWE-119": "Buffer Errors",
                "CWE-787": "Buffer Errors",
                "CWE-362": "Concurrency Issues",
            },
            children_map={
                "Memory": ["Buffer Errors"],
                "Logic": ["Concurrency Issues"],
                "Buffer Errors": ["CWE-119", "CWE-787"],
                "Concurrency Issues": ["CWE-362"],
            },
            labels={
                "Memory": "Memory",
                "Logic": "Logic",
                "Buffer Errors": "Buffer Errors",
                "Concurrency Issues": "Concurrency Issues",
                "CWE-119": "Buffer overflow",
                "CWE-787": "Out-of-bounds write",
                "CWE-362": "Race condition",
            },
        )

        class StubLLM:
            def generate(self, prompt, **kw):
                return '{"predictions":[{"category":"Memory","confidence":0.9}]}'

        trainer = CoevolutionaryTrainer(
            llm_client=StubLLM(),
            output_dir=str(tmp_path),
            taxonomy=tax,
        )
        trainer._init_populations(population_size=2)

        # Major populations
        assert "major_Logic" in trainer.populations
        assert "major_Memory" in trainer.populations

        # Middle populations
        assert "middle_Buffer Errors" in trainer.populations
        assert "middle_Concurrency Issues" in trainer.populations

        # CWE populations
        assert "cwe_CWE-119" in trainer.populations
        assert "cwe_CWE-787" in trainer.populations
        assert "cwe_CWE-362" in trainer.populations

        # Each population should have 2 individuals
        for key, pop in trainer.populations.items():
            assert pop.size == 2, f"{key} has {pop.size} individuals, expected 2"

    def test_taxonomy_candidates_used_in_seed_prompts(self, tmp_path):
        from mulvul.agents.adaptive_hierarchy import DynamicTaxonomy
        from mulvul.agents.coevolutionary_trainer import CoevolutionaryTrainer

        tax = DynamicTaxonomy(
            stages=["major", "cwe"],
            parent_map={
                "Memory": None,
                "CWE-119": "Memory",
                "CWE-416": "Memory",
            },
            children_map={
                "Memory": ["CWE-119", "CWE-416"],
            },
            labels={
                "Memory": "Memory",
                "CWE-119": "Buffer overflow",
                "CWE-416": "Use after free",
            },
        )

        class StubLLM:
            def generate(self, prompt, **kw):
                return '{"predictions":[]}'

        trainer = CoevolutionaryTrainer(
            llm_client=StubLLM(),
            output_dir=str(tmp_path),
            taxonomy=tax,
        )
        trainer._init_populations(population_size=1)

        # CWE-119's seed prompt should mention its sibling CWE-416
        cwe119_prompt = trainer.populations["cwe_CWE-119"].individuals[0].prompt
        assert "CWE-416" in cwe119_prompt
        assert "CWE-119" in cwe119_prompt
        assert "Benign" in cwe119_prompt


class TestBuilderOnPrimeVulBalanced20:
    """Integration test using the real PrimeVul-Balanced-20 dataset."""

    DATA_PATH = "data/primevul/primevul_balanced_20.jsonl"

    @pytest.fixture
    def data_file(self):
        path = Path(__file__).parent.parent / self.DATA_PATH
        if not path.exists():
            pytest.skip(f"Dataset not found: {path}")
        return str(path)

    def test_build_on_primevul_balanced_20(self, data_file):
        from mulvul.agents.adaptive_hierarchy import AdaptiveHierarchyBuilder

        builder = AdaptiveHierarchyBuilder(
            max_candidates=6, min_candidates=2, min_samples=10
        )
        tax = builder.build(data_file)

        # The dataset has 20 CWEs, all with 50 samples each
        leaves = tax.all_leaves()
        assert len(leaves) == 20

        roots = tax.root_nodes()
        assert len(roots) >= 2  # at least Memory and Logic

        # Every leaf should have candidates_for returning siblings + Benign
        for leaf in leaves:
            candidates = tax.candidates_for(leaf)
            assert "Benign" in candidates
            assert leaf in candidates
            sibling_count = len(candidates) - 1  # subtract Benign
            assert sibling_count >= 1
            assert sibling_count <= 6  # max_candidates

        # Roundtrip serialization
        from mulvul.agents.adaptive_hierarchy import DynamicTaxonomy

        data = tax.to_dict()
        restored = DynamicTaxonomy.from_dict(data)
        assert restored.all_leaves() == tax.all_leaves()

    def test_depth_is_three(self, data_file):
        from mulvul.agents.adaptive_hierarchy import AdaptiveHierarchyBuilder

        builder = AdaptiveHierarchyBuilder(min_samples=10)
        tax = builder.build(data_file)
        assert tax.depth() == 3
