"""Tests for evolution memory — experience tracking and retrieval."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from mulvul.agents.evolution_memory import EvolutionMemory, Experience


class TestExperience:
    def test_is_positive_for_positive_delta(self):
        exp = Experience(
            node="cwe_CWE-189",
            action="mutation",
            description="Added distinction rules",
            f1_before=0.50,
            f1_after=0.83,
            delta=0.33,
            generation=0,
        )
        assert exp.is_positive is True

    def test_is_positive_for_negative_delta(self):
        exp = Experience(
            node="major_Crypto",
            action="crossover",
            description="Completely rewrote role description",
            f1_before=0.80,
            f1_after=0.52,
            delta=-0.28,
            generation=1,
        )
        assert exp.is_positive is False

    def test_is_positive_for_zero_delta(self):
        exp = Experience(
            node="middle_Buffer Errors",
            action="mutation",
            description="No change",
            f1_before=0.60,
            f1_after=0.60,
            delta=0.0,
            generation=2,
        )
        assert exp.is_positive is False

    def test_to_dict_from_dict_roundtrip(self):
        exp = Experience(
            node="cwe_CWE-189",
            action="mutation",
            description="Added distinction rules between CWE-189/190",
            f1_before=0.50,
            f1_after=0.83,
            delta=0.33,
            generation=3,
        )
        d = exp.to_dict()
        restored = Experience.from_dict(d)
        assert restored.node == exp.node
        assert restored.action == exp.action
        assert restored.description == exp.description
        assert restored.f1_before == exp.f1_before
        assert restored.f1_after == exp.f1_after
        assert restored.delta == exp.delta
        assert restored.generation == exp.generation

    def test_to_dict_keys(self):
        exp = Experience(
            node="major_Memory",
            action="migration",
            description="Migrated from Injection",
            f1_before=0.40,
            f1_after=0.55,
            delta=0.15,
            generation=0,
        )
        d = exp.to_dict()
        assert set(d.keys()) == {
            "node", "action", "description",
            "f1_before", "f1_after", "delta", "generation",
        }


class TestEvolutionMemory:
    def test_record_and_retrieve_same_node(self, tmp_path: Path):
        mem = EvolutionMemory(tmp_path / "mem.jsonl", include_seeds=False)
        exp = Experience(
            node="cwe_CWE-189",
            action="mutation",
            description="Added distinction rules",
            f1_before=0.50,
            f1_after=0.83,
            delta=0.33,
            generation=0,
        )
        mem.record(exp)
        results = mem.retrieve("cwe_CWE-189", "cwe", top_k=5)
        assert len(results) == 1
        assert results[0].node == "cwe_CWE-189"
        assert results[0].delta == 0.33

    def test_retrieve_includes_sibling_experiences(self, tmp_path: Path):
        mem = EvolutionMemory(tmp_path / "mem.jsonl", include_seeds=False)
        # Same node
        mem.record(Experience(
            node="cwe_CWE-189", action="mutation",
            description="Targeted fix", f1_before=0.50, f1_after=0.83,
            delta=0.33, generation=0,
        ))
        # Same stage, different node (sibling)
        mem.record(Experience(
            node="cwe_CWE-190", action="mutation",
            description="Sibling fix", f1_before=0.40, f1_after=0.60,
            delta=0.20, generation=0,
        ))
        # Different stage entirely
        mem.record(Experience(
            node="major_Memory", action="crossover",
            description="Major tweak", f1_before=0.60, f1_after=0.55,
            delta=-0.05, generation=0,
        ))

        results = mem.retrieve("cwe_CWE-189", "cwe", top_k=5)
        assert len(results) == 3
        # Same-node first (score 3), then same-stage (score 2), then global (score 1)
        assert results[0].node == "cwe_CWE-189"
        assert results[1].node == "cwe_CWE-190"
        assert results[2].node == "major_Memory"

    def test_retrieve_ranking_by_abs_delta_within_tier(self, tmp_path: Path):
        mem = EvolutionMemory(tmp_path / "mem.jsonl", include_seeds=False)
        mem.record(Experience(
            node="cwe_CWE-189", action="mutation",
            description="Small improvement", f1_before=0.50, f1_after=0.55,
            delta=0.05, generation=0,
        ))
        mem.record(Experience(
            node="cwe_CWE-189", action="mutation",
            description="Big improvement", f1_before=0.50, f1_after=0.83,
            delta=0.33, generation=1,
        ))
        results = mem.retrieve("cwe_CWE-189", "cwe", top_k=5)
        assert len(results) == 2
        # Within same-node tier, sort by |delta| descending
        assert results[0].delta == 0.33
        assert results[1].delta == 0.05

    def test_retrieve_top_k_limits_results(self, tmp_path: Path):
        mem = EvolutionMemory(tmp_path / "mem.jsonl", include_seeds=False)
        for i in range(10):
            mem.record(Experience(
                node="cwe_CWE-189", action="mutation",
                description=f"Change {i}", f1_before=0.50, f1_after=0.50 + i * 0.01,
                delta=i * 0.01, generation=i,
            ))
        results = mem.retrieve("cwe_CWE-189", "cwe", top_k=3)
        assert len(results) == 3

    def test_format_for_prompt_contains_delta_signs(self, tmp_path: Path):
        mem = EvolutionMemory(tmp_path / "mem.jsonl", include_seeds=False)
        mem.record(Experience(
            node="cwe_CWE-189", action="mutation",
            description="Added distinction rules between CWE-189/190",
            f1_before=0.50, f1_after=0.83, delta=0.33, generation=0,
        ))
        mem.record(Experience(
            node="major_Crypto", action="crossover",
            description="Completely rewrote role description",
            f1_before=0.80, f1_after=0.52, delta=-0.28, generation=1,
        ))
        experiences = mem.retrieve("cwe_CWE-189", "cwe", top_k=5)
        text = mem.format_for_prompt(experiences)
        assert "## Lessons from previous evolution rounds:" in text
        assert "+0.33" in text
        assert "-0.28" in text
        assert "cwe_CWE-189" in text
        assert "major_Crypto" in text
        assert "Added distinction rules" in text
        assert "Completely rewrote role description" in text

    def test_format_for_prompt_empty_list(self, tmp_path: Path):
        mem = EvolutionMemory(tmp_path / "mem.jsonl", include_seeds=False)
        text = mem.format_for_prompt([])
        assert text == ""

    def test_empty_memory_returns_empty_list(self, tmp_path: Path):
        mem = EvolutionMemory(tmp_path / "mem.jsonl", include_seeds=False)
        results = mem.retrieve("cwe_CWE-189", "cwe", top_k=5)
        assert results == []

    def test_persistence_across_instances(self, tmp_path: Path):
        path = tmp_path / "mem.jsonl"
        mem1 = EvolutionMemory(path, include_seeds=False)
        mem1.record(Experience(
            node="cwe_CWE-189", action="mutation",
            description="First session fix", f1_before=0.50, f1_after=0.83,
            delta=0.33, generation=0,
        ))
        mem1.record(Experience(
            node="major_Memory", action="crossover",
            description="Second record", f1_before=0.60, f1_after=0.70,
            delta=0.10, generation=1,
        ))

        # New instance loads previous records
        mem2 = EvolutionMemory(path, include_seeds=False)
        results = mem2.retrieve("cwe_CWE-189", "cwe", top_k=5)
        assert len(results) == 2
        assert any(r.node == "cwe_CWE-189" for r in results)
        assert any(r.node == "major_Memory" for r in results)

    def test_jsonl_format_on_disk(self, tmp_path: Path):
        path = tmp_path / "mem.jsonl"
        mem = EvolutionMemory(path, include_seeds=False)
        mem.record(Experience(
            node="cwe_CWE-189", action="mutation",
            description="Test", f1_before=0.5, f1_after=0.8,
            delta=0.3, generation=0,
        ))
        lines = path.read_text().strip().split("\n")
        assert len(lines) == 1
        data = json.loads(lines[0])
        assert data["node"] == "cwe_CWE-189"
        assert data["delta"] == 0.3
