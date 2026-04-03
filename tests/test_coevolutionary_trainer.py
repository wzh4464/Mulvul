"""Tests for cooperative coevolutionary trainer components."""
from __future__ import annotations

import json
from pathlib import Path

import pytest


class TestEvolutionLog:
    def test_emit_writes_json_line_immediately(self, tmp_path):
        from mulvul.agents.coevolutionary_trainer import EvolutionLog
        log_path = tmp_path / "evolution.jsonl"
        log = EvolutionLog(log_path)
        log.emit("generation_start", {"generation": 0, "population_size": 5})
        lines = log_path.read_text().strip().split("\n")
        assert len(lines) == 1
        event = json.loads(lines[0])
        assert event["event"] == "generation_start"
        assert event["data"]["generation"] == 0
        assert "timestamp" in event
        log.close()

    def test_emit_multiple_events_appended(self, tmp_path):
        from mulvul.agents.coevolutionary_trainer import EvolutionLog
        log_path = tmp_path / "evolution.jsonl"
        log = EvolutionLog(log_path)
        log.emit("gen_start", {"gen": 0})
        log.emit("tournament_done", {"node": "major_Memory", "best_f1": 0.85})
        log.emit("gen_end", {"gen": 0, "e2e_accuracy": 0.72})
        lines = log_path.read_text().strip().split("\n")
        assert len(lines) == 3
        assert json.loads(lines[1])["event"] == "tournament_done"
        log.close()

    def test_recent_returns_tail(self, tmp_path):
        from mulvul.agents.coevolutionary_trainer import EvolutionLog
        log_path = tmp_path / "evolution.jsonl"
        log = EvolutionLog(log_path)
        for i in range(20):
            log.emit("tick", {"i": i})
        recent = log.recent(5)
        assert len(recent) == 5
        assert recent[0]["data"]["i"] == 15
        log.close()

    def test_summary_returns_latest_per_event_type(self, tmp_path):
        from mulvul.agents.coevolutionary_trainer import EvolutionLog
        log_path = tmp_path / "evolution.jsonl"
        log = EvolutionLog(log_path)
        log.emit("gen_end", {"gen": 0, "e2e": 0.60})
        log.emit("gen_end", {"gen": 1, "e2e": 0.72})
        log.emit("tournament_done", {"node": "major_Memory", "best_f1": 0.85})
        summary = log.summary()
        assert summary["gen_end"]["data"]["gen"] == 1
        assert "tournament_done" in summary
        log.close()


class TestPromptIndividual:
    def test_combined_fitness_weights(self):
        from mulvul.agents.coevolutionary_trainer import PromptIndividual
        ind = PromptIndividual(prompt="test", node_fitness=1.0, cascade_fitness=0.5)
        assert abs(ind.combined_fitness - 0.70) < 1e-6

    def test_default_origin_is_seed(self):
        from mulvul.agents.coevolutionary_trainer import PromptIndividual
        ind = PromptIndividual(prompt="x")
        assert ind.origin == "seed"


class TestNodePopulation:
    def _make_pop(self):
        from mulvul.agents.coevolutionary_trainer import NodePopulation, PromptIndividual
        individuals = [
            PromptIndividual(prompt=f"p{i}", node_fitness=f, cascade_fitness=f * 0.9)
            for i, f in enumerate([0.6, 0.9, 0.5, 0.8, 0.7])
        ]
        return NodePopulation(node_key="major_Memory", stage="major", individuals=individuals)

    def test_best_returns_highest_combined(self):
        pop = self._make_pop()
        best = pop.best()
        assert best.prompt == "p1"

    def test_tournament_select_returns_individual(self):
        from mulvul.agents.coevolutionary_trainer import PromptIndividual
        pop = self._make_pop()
        selected = pop.tournament_select(k=3, rng_seed=42)
        assert isinstance(selected, PromptIndividual)
        assert selected in pop.individuals

    def test_worst_returns_lowest_combined(self):
        pop = self._make_pop()
        worst = pop.worst()
        assert worst.prompt == "p2"

    def test_size(self):
        pop = self._make_pop()
        assert pop.size == 5


class TestErrorAttribution:
    def test_major_error(self):
        from mulvul.agents.coevolutionary_trainer import attribute_cascade_error
        assert attribute_cascade_error(
            true_major="Memory", pred_major="Injection",
            true_middle="Buffer Errors", pred_middle="Injection",
            true_cwe="CWE-120", pred_cwe="CWE-89",
        ) == "major"

    def test_middle_error(self):
        from mulvul.agents.coevolutionary_trainer import attribute_cascade_error
        assert attribute_cascade_error(
            true_major="Memory", pred_major="Memory",
            true_middle="Buffer Errors", pred_middle="Memory Management",
            true_cwe="CWE-120", pred_cwe="CWE-416",
        ) == "middle"

    def test_cwe_error(self):
        from mulvul.agents.coevolutionary_trainer import attribute_cascade_error
        assert attribute_cascade_error(
            true_major="Memory", pred_major="Memory",
            true_middle="Buffer Errors", pred_middle="Buffer Errors",
            true_cwe="CWE-120", pred_cwe="CWE-119",
        ) == "cwe"

    def test_no_error_returns_none(self):
        from mulvul.agents.coevolutionary_trainer import attribute_cascade_error
        assert attribute_cascade_error(
            true_major="Memory", pred_major="Memory",
            true_middle="Buffer Errors", pred_middle="Buffer Errors",
            true_cwe="CWE-120", pred_cwe="CWE-120",
        ) is None

    def test_benign_true_major_error(self):
        from mulvul.agents.coevolutionary_trainer import attribute_cascade_error
        assert attribute_cascade_error(
            true_major="Benign", pred_major="Memory",
            true_middle=None, pred_middle="Buffer Errors",
            true_cwe=None, pred_cwe="CWE-120",
        ) == "major"
