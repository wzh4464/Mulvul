"""Experiment and artifact management.

Provides ExperimentConfig, ExperimentManager, and ArtifactStore
for unified experiment lifecycle with config archival, checkpoint,
and prompt/metrics versioning.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class ExperimentConfig:
    """Configuration for an experiment run."""

    name: str = ""
    population_size: int = 20
    max_generations: int = 10
    mutation_rate: float = 0.1
    model_name: str = ""
    dataset: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "population_size": self.population_size,
            "max_generations": self.max_generations,
            "mutation_rate": self.mutation_rate,
            "model_name": self.model_name,
            "dataset": self.dataset,
            "extra": self.extra,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ExperimentConfig":
        return cls(
            name=data.get("name", ""),
            population_size=data.get("population_size", 20),
            max_generations=data.get("max_generations", 10),
            mutation_rate=data.get("mutation_rate", 0.1),
            model_name=data.get("model_name", ""),
            dataset=data.get("dataset", ""),
            extra=data.get("extra", {}),
        )

    def save(self, path: Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load(cls, path: Path) -> "ExperimentConfig":
        with open(path) as f:
            return cls.from_dict(json.load(f))


class ExperimentManager:
    """Manages experiment lifecycle."""

    def __init__(
        self,
        config: ExperimentConfig,
        base_dir: Path,
    ):
        self.config = config
        self.base_dir = Path(base_dir)
        self.experiment_dir = self._create_experiment_dir()
        self._setup_subdirs()

    def _create_experiment_dir(self) -> Path:
        """Create a unique experiment directory."""
        base_name = self.config.name or "experiment"
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")
        dir_name = f"{base_name}_{timestamp}"
        exp_dir = self.base_dir / dir_name
        exp_dir.mkdir(parents=True, exist_ok=True)
        return exp_dir

    def _setup_subdirs(self) -> None:
        for subdir in ["prompts", "metrics", "checkpoints"]:
            (self.experiment_dir / subdir).mkdir(exist_ok=True)

    def save_config(self) -> None:
        self.config.save(self.experiment_dir / "config.json")

    def save_prompt_snapshot(
        self, data: Dict[str, Any], label: str
    ) -> None:
        path = self.experiment_dir / "prompts" / f"{label}.json"
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    def load_prompt_snapshot(self, label: str) -> Dict[str, Any]:
        path = self.experiment_dir / "prompts" / f"{label}.json"
        with open(path) as f:
            return json.load(f)

    def save_metrics(
        self, metrics: Dict[str, Any], label: str
    ) -> None:
        path = self.experiment_dir / "metrics" / f"{label}.json"
        with open(path, "w") as f:
            json.dump(metrics, f, indent=2)

    def save_checkpoint(
        self, state: Dict[str, Any], label: str
    ) -> None:
        path = self.experiment_dir / "checkpoints" / f"{label}.json"
        with open(path, "w") as f:
            json.dump(state, f, indent=2)

    def load_checkpoint(self, label: str) -> Dict[str, Any]:
        path = self.experiment_dir / "checkpoints" / f"{label}.json"
        with open(path) as f:
            return json.load(f)

    def log_event(self, message: str) -> None:
        log_file = self.experiment_dir / "events.jsonl"
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "message": message,
        }
        with open(log_file, "a") as f:
            f.write(json.dumps(event) + "\n")

    def finalize(self, summary: Dict[str, Any]) -> None:
        path = self.experiment_dir / "experiment_summary.json"
        with open(path, "w") as f:
            json.dump(summary, f, indent=2)

    @staticmethod
    def list_experiments(base_dir: Path) -> List[str]:
        base_dir = Path(base_dir)
        return sorted(
            d.name for d in base_dir.iterdir() if d.is_dir()
        )


class ArtifactStore:
    """Stores and retrieves versioned prompts and metrics."""

    def __init__(self, base_dir: Path):
        self.base_dir = Path(base_dir)
        self.prompts_dir = self.base_dir / "prompts"
        self.metrics_dir = self.base_dir / "metrics"
        self.prompts_dir.mkdir(parents=True, exist_ok=True)
        self.metrics_dir.mkdir(parents=True, exist_ok=True)

    def store_prompt(
        self, data: Dict[str, Any], generation: int
    ) -> None:
        path = self.prompts_dir / f"gen_{generation}.json"
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    def load_prompt(self, generation: int) -> Dict[str, Any]:
        path = self.prompts_dir / f"gen_{generation}.json"
        with open(path) as f:
            return json.load(f)

    def store_metrics(
        self, data: Dict[str, Any], generation: int
    ) -> None:
        path = self.metrics_dir / f"gen_{generation}.json"
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    def load_metrics(self, generation: int) -> Dict[str, Any]:
        path = self.metrics_dir / f"gen_{generation}.json"
        with open(path) as f:
            return json.load(f)

    def get_evolution_history(self) -> List[Dict[str, Any]]:
        files = sorted(self.prompts_dir.glob("gen_*.json"))
        history = []
        for f in files:
            with open(f) as fh:
                history.append(json.load(fh))
        return history
