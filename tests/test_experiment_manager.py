"""Tests for ExperimentManager and ArtifactStore."""
from __future__ import annotations

import json
import pytest
from pathlib import Path

from evoprompt.core.experiment import (
    ExperimentConfig,
    ExperimentManager,
    ArtifactStore,
)


class TestExperimentConfig:
    """Tests for ExperimentConfig."""

    def test_config_defaults(self):
        config = ExperimentConfig(name="test-exp")
        assert config.name == "test-exp"
        assert config.population_size == 20
        assert config.max_generations == 10

    def test_config_custom(self):
        config = ExperimentConfig(
            name="custom",
            population_size=50,
            max_generations=20,
            model_name="gpt-4",
            extra={"custom_key": "value"},
        )
        assert config.population_size == 50
        assert config.extra["custom_key"] == "value"

    def test_config_dict_roundtrip(self):
        config = ExperimentConfig(
            name="roundtrip",
            population_size=30,
            model_name="test-model",
        )
        d = config.to_dict()
        restored = ExperimentConfig.from_dict(d)
        assert restored.name == config.name
        assert restored.population_size == config.population_size
        assert restored.model_name == config.model_name

    def test_config_json_roundtrip(self, tmp_path):
        config = ExperimentConfig(
            name="json-test",
            max_generations=5,
        )
        path = tmp_path / "config.json"
        config.save(path)
        loaded = ExperimentConfig.load(path)
        assert loaded.name == "json-test"
        assert loaded.max_generations == 5


class TestExperimentManager:
    """Tests for ExperimentManager."""

    def test_experiment_dir_creation(self, tmp_path):
        config = ExperimentConfig(name="test-exp")
        mgr = ExperimentManager(
            config=config, base_dir=tmp_path
        )
        assert mgr.experiment_dir.exists()
        assert (mgr.experiment_dir / "prompts").exists()
        assert (mgr.experiment_dir / "metrics").exists()
        assert (mgr.experiment_dir / "checkpoints").exists()

    def test_save_and_load_config(self, tmp_path):
        config = ExperimentConfig(
            name="save-test", population_size=15
        )
        mgr = ExperimentManager(
            config=config, base_dir=tmp_path
        )
        mgr.save_config()
        loaded = ExperimentConfig.load(
            mgr.experiment_dir / "config.json"
        )
        assert loaded.name == "save-test"
        assert loaded.population_size == 15

    def test_save_prompt_snapshot(self, tmp_path):
        config = ExperimentConfig(name="prompt-test")
        mgr = ExperimentManager(
            config=config, base_dir=tmp_path
        )
        mgr.save_prompt_snapshot(
            {"prompt": "test {input}"}, label="gen_0"
        )
        prompt_file = (
            mgr.experiment_dir / "prompts" / "gen_0.json"
        )
        assert prompt_file.exists()

    def test_load_prompt_snapshot(self, tmp_path):
        config = ExperimentConfig(name="load-prompt")
        mgr = ExperimentManager(
            config=config, base_dir=tmp_path
        )
        data = {"prompt": "hello {input}", "fitness": 0.9}
        mgr.save_prompt_snapshot(data, label="best")
        loaded = mgr.load_prompt_snapshot("best")
        assert loaded["prompt"] == "hello {input}"
        assert loaded["fitness"] == 0.9

    def test_save_metrics(self, tmp_path):
        config = ExperimentConfig(name="metrics-test")
        mgr = ExperimentManager(
            config=config, base_dir=tmp_path
        )
        mgr.save_metrics(
            {"accuracy": 0.85, "f1": 0.80},
            label="gen_0",
        )
        metrics_file = (
            mgr.experiment_dir / "metrics" / "gen_0.json"
        )
        assert metrics_file.exists()
        with open(metrics_file) as f:
            data = json.load(f)
        assert data["accuracy"] == 0.85

    def test_checkpoint_save_load(self, tmp_path):
        config = ExperimentConfig(name="ckpt-test")
        mgr = ExperimentManager(
            config=config, base_dir=tmp_path
        )
        state = {
            "generation": 5,
            "best_fitness": 0.92,
            "population": ["p1", "p2"],
        }
        mgr.save_checkpoint(state, label="gen_5")
        loaded = mgr.load_checkpoint("gen_5")
        assert loaded["generation"] == 5
        assert loaded["best_fitness"] == 0.92

    def test_log_event_appends(self, tmp_path):
        config = ExperimentConfig(name="log-test")
        mgr = ExperimentManager(
            config=config, base_dir=tmp_path
        )
        mgr.log_event("Started evolution")
        mgr.log_event("Generation 1 complete")
        log_file = mgr.experiment_dir / "events.jsonl"
        assert log_file.exists()
        lines = log_file.read_text().strip().split("\n")
        assert len(lines) == 2
        event0 = json.loads(lines[0])
        assert event0["message"] == "Started evolution"

    def test_finalize_writes_summary(self, tmp_path):
        config = ExperimentConfig(name="final-test")
        mgr = ExperimentManager(
            config=config, base_dir=tmp_path
        )
        mgr.save_metrics({"accuracy": 0.85}, label="final")
        mgr.finalize(
            summary={"best_fitness": 0.92, "generations": 10}
        )
        summary_file = (
            mgr.experiment_dir / "experiment_summary.json"
        )
        assert summary_file.exists()
        with open(summary_file) as f:
            data = json.load(f)
        assert data["best_fitness"] == 0.92

    def test_list_experiments(self, tmp_path):
        for name in ["exp1", "exp2", "exp3"]:
            config = ExperimentConfig(name=name)
            ExperimentManager(
                config=config, base_dir=tmp_path
            )
        experiments = ExperimentManager.list_experiments(
            tmp_path
        )
        assert len(experiments) == 3

    def test_no_overwrite_existing_experiment(self, tmp_path):
        config1 = ExperimentConfig(name="unique")
        mgr1 = ExperimentManager(
            config=config1, base_dir=tmp_path
        )
        config2 = ExperimentConfig(name="unique")
        mgr2 = ExperimentManager(
            config=config2, base_dir=tmp_path
        )
        # Should create different directories
        assert mgr1.experiment_dir != mgr2.experiment_dir


class TestArtifactStore:
    """Tests for ArtifactStore."""

    def test_artifact_store_prompt_versioning(self, tmp_path):
        store = ArtifactStore(base_dir=tmp_path)
        store.store_prompt(
            {"text": "prompt v1"}, generation=0
        )
        store.store_prompt(
            {"text": "prompt v2"}, generation=1
        )
        loaded = store.load_prompt(generation=1)
        assert loaded["text"] == "prompt v2"

    def test_artifact_store_metrics_versioning(self, tmp_path):
        store = ArtifactStore(base_dir=tmp_path)
        store.store_metrics(
            {"accuracy": 0.8}, generation=0
        )
        store.store_metrics(
            {"accuracy": 0.9}, generation=1
        )
        loaded = store.load_metrics(generation=1)
        assert loaded["accuracy"] == 0.9

    def test_artifact_store_evolution_history(self, tmp_path):
        store = ArtifactStore(base_dir=tmp_path)
        for gen in range(3):
            store.store_prompt(
                {"text": f"gen_{gen}"}, generation=gen
            )
        history = store.get_evolution_history()
        assert len(history) == 3
        assert history[0]["text"] == "gen_0"
        assert history[2]["text"] == "gen_2"
