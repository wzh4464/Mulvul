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

    def test_population_alias_maps_to_individuals(self):
        pop = self._make_pop()
        assert pop.population is pop.individuals

        replacement = pop.individuals[:2]
        pop.population = replacement
        assert pop.individuals == replacement


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


from mulvul.agents.coevolutionary_trainer import CoevolutionaryTrainer


class StubLLMClient:
    """Returns predictable ranking_v2 responses for testing."""

    def generate(self, prompt: str, **kwargs) -> str:
        if "specializing in Memory" in prompt:
            return '{"predictions":[{"category":"Memory","confidence":0.91}]}'
        if "specializing in Injection" in prompt:
            return '{"predictions":[{"category":"Benign","confidence":0.80}]}'
        if "Buffer Errors" in prompt:
            return '{"predictions":[{"category":"Buffer Errors","confidence":0.84}]}'
        if "CWE-120" in prompt:
            return '{"predictions":[{"cwe":"CWE-120","confidence":0.88}]}'
        return '{"predictions":[{"category":"Benign","confidence":0.70}]}'

    def batch_generate(self, prompts, **kwargs):
        return [self.generate(p) for p in prompts]


class StubSampler:
    """Minimal sampler returning fixed samples."""

    def get_all_majors(self):
        return ["Memory"]

    def get_all_middles(self):
        return ["Buffer Errors"]

    def get_all_cwes(self, min_samples=0):
        return ["CWE-120"]

    def sample_for_major(self, target, n):
        from mulvul.agents.hierarchical_sampler import TrainingSample
        return [
            TrainingSample(code="void f(){char b[8];strcpy(b,x);}", label="target",
                           cwe="CWE-120", middle="Buffer Errors", major="Memory"),
            TrainingSample(code="int add(int a,int b){return a+b;}", label="benign",
                           cwe="Benign", middle="Benign", major="Benign"),
        ]

    def sample_for_middle(self, target, n):
        return self.sample_for_major(target, n)

    def sample_for_cwe(self, target, n):
        return self.sample_for_major(target, n)


class TestCoevolutionaryTrainer:
    def test_train_all_levels_returns_best_prompts(self, tmp_path):
        trainer = CoevolutionaryTrainer(
            llm_client=StubLLMClient(),
            sampler=StubSampler(),
            output_dir=str(tmp_path),
        )
        best_prompts = trainer.train_all_levels(
            n_rounds=2, n_samples_per_class=2, population_size=3,
        )
        assert isinstance(best_prompts, dict)
        assert "major_Memory" in best_prompts
        assert "middle_Buffer Errors" in best_prompts
        assert "cwe_CWE-120" in best_prompts

    def test_evolution_log_file_created(self, tmp_path):
        trainer = CoevolutionaryTrainer(
            llm_client=StubLLMClient(),
            sampler=StubSampler(),
            output_dir=str(tmp_path),
        )
        trainer.train_all_levels(n_rounds=1, n_samples_per_class=2, population_size=2)
        log_path = tmp_path / "evolution.jsonl"
        assert log_path.exists()
        lines = log_path.read_text().strip().split("\n")
        assert len(lines) >= 3

    def test_best_scores_populated(self, tmp_path):
        trainer = CoevolutionaryTrainer(
            llm_client=StubLLMClient(),
            sampler=StubSampler(),
            output_dir=str(tmp_path),
        )
        trainer.train_all_levels(n_rounds=1, n_samples_per_class=2, population_size=2)
        assert len(trainer.best_scores) > 0
        assert all(isinstance(v, float) for v in trainer.best_scores.values())

    def test_save_best_prompts(self, tmp_path):
        trainer = CoevolutionaryTrainer(
            llm_client=StubLLMClient(),
            sampler=StubSampler(),
            output_dir=str(tmp_path),
        )
        trainer.train_all_levels(n_rounds=1, n_samples_per_class=2, population_size=2)
        trainer.save_best_prompts()
        saved = json.loads((tmp_path / "best_prompts.json").read_text())
        assert "prompts" in saved
        assert "scores" in saved


class TestEvolutionLogIntegration:
    def test_full_run_produces_expected_event_sequence(self, tmp_path):
        trainer = CoevolutionaryTrainer(
            llm_client=StubLLMClient(),
            sampler=StubSampler(),
            output_dir=str(tmp_path),
        )
        trainer.train_all_levels(n_rounds=2, n_samples_per_class=2, population_size=3)

        log_path = tmp_path / "evolution.jsonl"
        events = [json.loads(line) for line in log_path.read_text().strip().split("\n")]

        event_types = [e["event"] for e in events]
        assert "generation_start" in event_types
        assert "tournament_done" in event_types
        assert "cascade_eval_done" in event_types
        assert "generation_end" in event_types

        # Verify cascade_eval_done has the expected fields
        cascade_events = [e for e in events if e["event"] == "cascade_eval_done"]
        assert len(cascade_events) == 2  # one per generation
        for ce in cascade_events:
            assert "e2e_accuracy" in ce["data"]
            assert "error_count" in ce["data"]
            assert "error_distribution" in ce["data"]

        # Verify generation_end has diversity info
        gen_ends = [e for e in events if e["event"] == "generation_end"]
        for ge in gen_ends:
            assert "population_diversity" in ge["data"]
            assert "best_fitness" in ge["data"]


class TestErrorRouting:
    """Verify that error attribution routes to the correct population."""

    def test_false_positive_routes_to_predicted_node(self):
        from mulvul.agents.coevolutionary_trainer import CoevolutionaryTrainer, NodePopulation, PromptIndividual

        trainer = CoevolutionaryTrainer.__new__(CoevolutionaryTrainer)
        trainer.populations = {
            "major_Memory": NodePopulation(node_key="major_Memory", stage="major",
                individuals=[PromptIndividual(prompt="p")]),
        }
        # Benign sample wrongly predicted as Memory -> charge major_Memory
        err = {"stage": "major", "true_major": "Benign", "pred_major": "Memory",
               "true_middle": None, "pred_middle": "Buffer Errors",
               "true_cwe": None, "pred_cwe": "CWE-120"}
        assert trainer._route_error_to_node(err) == "major_Memory"

    def test_false_negative_routes_to_true_node(self):
        from mulvul.agents.coevolutionary_trainer import CoevolutionaryTrainer, NodePopulation, PromptIndividual

        trainer = CoevolutionaryTrainer.__new__(CoevolutionaryTrainer)
        trainer.populations = {
            "major_Memory": NodePopulation(node_key="major_Memory", stage="major",
                individuals=[PromptIndividual(prompt="p")]),
        }
        # Memory sample wrongly predicted as Injection -> charge major_Memory (failed to attract)
        err = {"stage": "major", "true_major": "Memory", "pred_major": "Injection",
               "true_middle": "Buffer Errors", "pred_middle": "Injection",
               "true_cwe": "CWE-120", "pred_cwe": "CWE-89"}
        assert trainer._route_error_to_node(err) == "major_Memory"

    def test_nonexistent_population_returns_none(self):
        from mulvul.agents.coevolutionary_trainer import CoevolutionaryTrainer, NodePopulation, PromptIndividual

        trainer = CoevolutionaryTrainer.__new__(CoevolutionaryTrainer)
        trainer.populations = {}
        err = {"stage": "major", "true_major": "Benign", "pred_major": "Memory",
               "true_middle": None, "pred_middle": None,
               "true_cwe": None, "pred_cwe": None}
        assert trainer._route_error_to_node(err) is None


class TestConstrainedMutation:
    def test_split_prompt_finds_evidence_marker(self):
        from mulvul.agents.coevolutionary_trainer import CoevolutionaryTrainer

        trainer = CoevolutionaryTrainer.__new__(CoevolutionaryTrainer)
        prompt = (
            "You are a security expert.\n"
            "Classify into: Memory, Injection, Benign.\n\n"
            "## Evidence:\n{evidence}\n\n"
            "## Code:\n```\n{code}\n```\n\n"
            '## Output (JSON):\n{{"predictions":[]}}'
        )
        mutable, protected = trainer._split_prompt(prompt)
        assert "security expert" in mutable
        assert "{evidence}" in protected
        assert "{code}" in protected
        assert "predictions" in protected
        assert "{evidence}" not in mutable

    def test_split_prompt_returns_empty_mutable_if_no_marker(self):
        from mulvul.agents.coevolutionary_trainer import CoevolutionaryTrainer

        trainer = CoevolutionaryTrainer.__new__(CoevolutionaryTrainer)
        mutable, protected = trainer._split_prompt("no markers here")
        assert mutable == ""
        assert protected == "no markers here"

    def test_split_prompt_fallback_to_evidence_placeholder(self):
        from mulvul.agents.coevolutionary_trainer import CoevolutionaryTrainer

        trainer = CoevolutionaryTrainer.__new__(CoevolutionaryTrainer)
        prompt = "Role description.\n\n{evidence}\n\n{code}"
        mutable, protected = trainer._split_prompt(prompt)
        assert "Role description" in mutable
        assert "{evidence}" in protected

    def test_mutate_preserves_protected_region(self, tmp_path):
        """Verify that mutation output still contains {code} and {evidence}."""
        from mulvul.agents.coevolutionary_trainer import (
            CoevolutionaryTrainer,
            EvolutionLog,
        )
        from mulvul.agents.evolution_memory import EvolutionMemory

        class FakeMeta:
            def generate(self, prompt, **kw):
                return "Improved: You are an expert at finding buffer overflows."

        trainer = CoevolutionaryTrainer.__new__(CoevolutionaryTrainer)
        trainer.meta_llm = FakeMeta()
        trainer.log = EvolutionLog(tmp_path / "test.jsonl")
        trainer.memory = EvolutionMemory(tmp_path / "mem.jsonl")

        original = (
            "You are a security expert.\n"
            "Classify into: Memory, Benign.\n\n"
            "## Evidence:\n{evidence}\n\n"
            "## Code:\n```\n{code}\n```\n\n"
            '## Output (JSON):\n{{"predictions":[]}}'
        )
        errors = [{"stage": "major", "true_major": "Memory", "pred_major": "Benign"}]

        result = trainer._mutate_prompt(original, errors, "major_Memory")

        assert "{evidence}" in result
        assert "{code}" in result
        assert "predictions" in result
        assert "buffer overflow" in result.lower()
        trainer.log.close()

    def test_mutate_returns_original_when_no_errors(self, tmp_path):
        from mulvul.agents.coevolutionary_trainer import (
            CoevolutionaryTrainer,
            EvolutionLog,
        )

        trainer = CoevolutionaryTrainer.__new__(CoevolutionaryTrainer)
        trainer.log = EvolutionLog(tmp_path / "test.jsonl")

        original = "Some prompt\n\n## Evidence:\n{evidence}\n\n## Code:\n{code}"
        result = trainer._mutate_prompt(original, [], "major_Memory")
        assert result == original
        trainer.log.close()

    def test_mutate_returns_original_when_no_split_point(self, tmp_path):
        from mulvul.agents.coevolutionary_trainer import (
            CoevolutionaryTrainer,
            EvolutionLog,
        )

        class FakeMeta:
            def generate(self, prompt, **kw):
                return "Improved prompt without structure."

        trainer = CoevolutionaryTrainer.__new__(CoevolutionaryTrainer)
        trainer.meta_llm = FakeMeta()
        trainer.log = EvolutionLog(tmp_path / "test.jsonl")

        original = "No markers in this prompt"
        errors = [{"stage": "major", "true_major": "Memory", "pred_major": "Benign"}]
        result = trainer._mutate_prompt(original, errors, "major_Memory")
        assert result == original
        trainer.log.close()

    def test_mutate_returns_original_on_short_llm_response(self, tmp_path):
        from mulvul.agents.coevolutionary_trainer import (
            CoevolutionaryTrainer,
            EvolutionLog,
        )
        from mulvul.agents.evolution_memory import EvolutionMemory

        class FakeMeta:
            def generate(self, prompt, **kw):
                return "Too short"

        trainer = CoevolutionaryTrainer.__new__(CoevolutionaryTrainer)
        trainer.meta_llm = FakeMeta()
        trainer.log = EvolutionLog(tmp_path / "test.jsonl")
        trainer.memory = EvolutionMemory(tmp_path / "mem.jsonl")

        original = "You are an expert.\n\n## Evidence:\n{evidence}\n\n## Code:\n{code}"
        errors = [{"stage": "major", "true_major": "Memory", "pred_major": "Benign"}]
        result = trainer._mutate_prompt(original, errors, "major_Memory")
        assert result == original
        trainer.log.close()

    def test_crossover_preserves_protected_region(self, tmp_path):
        from mulvul.agents.coevolutionary_trainer import (
            CoevolutionaryTrainer,
            EvolutionLog,
        )

        class FakeMeta:
            def generate(self, prompt, **kw):
                return "Merged: Expert at both memory and injection issues."

        trainer = CoevolutionaryTrainer.__new__(CoevolutionaryTrainer)
        trainer.meta_llm = FakeMeta()
        trainer.log = EvolutionLog(tmp_path / "test.jsonl")

        protected_part = "## Evidence:\n{evidence}\n\n## Code:\n```\n{code}\n```"
        prompt_a = "Expert in memory.\n\n" + protected_part
        prompt_b = "Expert in injection.\n\n" + protected_part

        result = trainer._crossover_prompts(prompt_a, prompt_b, "major_Memory")

        assert "{evidence}" in result
        assert "{code}" in result
        assert "Merged" in result
        trainer.log.close()

    def test_crossover_returns_prompt_a_when_no_split(self, tmp_path):
        from mulvul.agents.coevolutionary_trainer import (
            CoevolutionaryTrainer,
            EvolutionLog,
        )

        class FakeMeta:
            def generate(self, prompt, **kw):
                return "Should not be used."

        trainer = CoevolutionaryTrainer.__new__(CoevolutionaryTrainer)
        trainer.meta_llm = FakeMeta()
        trainer.log = EvolutionLog(tmp_path / "test.jsonl")

        prompt_a = "No markers in A"
        prompt_b = "No markers in B"

        result = trainer._crossover_prompts(prompt_a, prompt_b, "major_Memory")
        assert result == prompt_a
        trainer.log.close()

    def test_mutate_does_not_send_protected_region_to_llm(self, tmp_path):
        """Verify the meta-LLM never sees the protected region content."""
        from mulvul.agents.coevolutionary_trainer import (
            CoevolutionaryTrainer,
            EvolutionLog,
        )
        from mulvul.agents.evolution_memory import EvolutionMemory

        captured_prompts = []

        class CapturingMeta:
            def generate(self, prompt, **kw):
                captured_prompts.append(prompt)
                return "Improved instruction with better decision boundaries."

        trainer = CoevolutionaryTrainer.__new__(CoevolutionaryTrainer)
        trainer.meta_llm = CapturingMeta()
        trainer.log = EvolutionLog(tmp_path / "test.jsonl")
        trainer.memory = EvolutionMemory(tmp_path / "mem.jsonl")

        original = (
            "You are a security expert.\n"
            "Classify into: Memory, Benign.\n\n"
            "## Evidence:\n{evidence}\n\n"
            "## Code:\n```\n{code}\n```\n\n"
            '## Output (JSON):\n{{"predictions":[]}}'
        )
        errors = [{"stage": "major", "true_major": "Memory", "pred_major": "Benign"}]
        trainer._mutate_prompt(original, errors, "major_Memory")

        assert len(captured_prompts) == 1
        llm_input = captured_prompts[0]
        # The protected footer sections should not appear in the LLM input
        assert "## Evidence:" not in llm_input
        assert "## Code:" not in llm_input
        assert "## Output (JSON):" not in llm_input
        # The mutable header content should be present
        assert "security expert" in llm_input
        trainer.log.close()


class TestCheckpointResuming:
    def test_checkpoint_created_after_generation(self, tmp_path):
        trainer = CoevolutionaryTrainer(
            llm_client=StubLLMClient(),
            sampler=StubSampler(),
            output_dir=str(tmp_path),
        )
        trainer.train_all_levels(n_rounds=1, n_samples_per_class=2, population_size=2)
        assert (tmp_path / "checkpoint.json").exists()
        ckpt = json.loads((tmp_path / "checkpoint.json").read_text())
        assert ckpt["next_generation"] == 1
        assert "populations" in ckpt
        assert "best_prompts" in ckpt

    def test_resume_from_checkpoint_skips_completed_generations(self, tmp_path):
        # Run 1 generation
        trainer1 = CoevolutionaryTrainer(
            llm_client=StubLLMClient(),
            sampler=StubSampler(),
            output_dir=str(tmp_path),
        )
        trainer1.train_all_levels(n_rounds=1, n_samples_per_class=2, population_size=2)
        prompts_after_gen1 = dict(trainer1.best_prompts)

        # Resume and run 1 more generation (total 2)
        trainer2 = CoevolutionaryTrainer(
            llm_client=StubLLMClient(),
            sampler=StubSampler(),
            output_dir=str(tmp_path),
        )
        trainer2.train_all_levels(n_rounds=2, n_samples_per_class=2, population_size=2)

        # Should have the same keys
        assert set(trainer2.best_prompts.keys()) == set(prompts_after_gen1.keys())

        # Log should contain checkpoint_restored event
        log_lines = (tmp_path / "evolution.jsonl").read_text().strip().split("\n")
        events = [json.loads(line)["event"] for line in log_lines]
        assert "checkpoint_restored" in events

    def test_no_checkpoint_starts_fresh(self, tmp_path):
        trainer = CoevolutionaryTrainer(
            llm_client=StubLLMClient(),
            sampler=StubSampler(),
            output_dir=str(tmp_path),
        )
        trainer.train_all_levels(n_rounds=1, n_samples_per_class=2, population_size=2)
        log_lines = (tmp_path / "evolution.jsonl").read_text().strip().split("\n")
        events = [json.loads(line)["event"] for line in log_lines]
        assert "checkpoint_restored" not in events
