"""Baseline management for deterministic evaluation snapshots.

Provides tools to create, save, load, and compare evaluation baselines
for tracking prompt quality over time.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List


@dataclass
class BaselineConfig:
    """Configuration for baseline evaluation.

    Attributes:
        sample_count: Number of samples for baseline evaluation.
        seed: Random seed for reproducibility.
        dataset_split: Which dataset split to use (e.g. "dev", "test").
    """

    sample_count: int = 50
    seed: int = 42
    dataset_split: str = "dev"


@dataclass
class BaselineSnapshot:
    """A snapshot of evaluation results for a specific prompt.

    Attributes:
        prompt_text: The prompt text that was evaluated.
        prompt_hash: Hash of the prompt for identity tracking.
        metrics: Dictionary of metric names to values.
        sample_ids: IDs of samples used in evaluation.
        predictions: Model predictions for each sample.
        ground_truths: Ground truth labels for each sample.
        timestamp: ISO-format timestamp of when the snapshot was created.
    """

    prompt_text: str
    prompt_hash: str
    metrics: Dict[str, float]
    sample_ids: List[str]
    predictions: List[str]
    ground_truths: List[str]
    timestamp: str = field(
        default_factory=lambda: datetime.utcnow().isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize snapshot to a dictionary."""
        return {
            "prompt_text": self.prompt_text,
            "prompt_hash": self.prompt_hash,
            "metrics": self.metrics,
            "sample_ids": self.sample_ids,
            "predictions": self.predictions,
            "ground_truths": self.ground_truths,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> BaselineSnapshot:
        """Deserialize snapshot from a dictionary."""
        return cls(
            prompt_text=data["prompt_text"],
            prompt_hash=data["prompt_hash"],
            metrics=data["metrics"],
            sample_ids=data["sample_ids"],
            predictions=data["predictions"],
            ground_truths=data["ground_truths"],
            timestamp=data.get("timestamp", ""),
        )

    def save(self, path: Path) -> None:
        """Save snapshot to a JSON file.

        Args:
            path: File path to save the snapshot to.
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load(cls, path: Path) -> BaselineSnapshot:
        """Load snapshot from a JSON file.

        Args:
            path: File path to load the snapshot from.

        Returns:
            Deserialized BaselineSnapshot instance.
        """
        with open(path) as f:
            return cls.from_dict(json.load(f))


@dataclass
class ComparisonResult:
    """Result of comparing current metrics to a baseline.

    Attributes:
        has_regression: Whether any metric regressed beyond threshold.
        metric_deltas: Dictionary of metric name to delta values
            (current - baseline).
        regression_details: Details for metrics that regressed.
    """

    has_regression: bool
    metric_deltas: Dict[str, float]
    regression_details: Dict[str, str] = field(default_factory=dict)

    def summary(self) -> str:
        """Generate a human-readable summary of the comparison."""
        lines = []
        for metric, delta in self.metric_deltas.items():
            if delta > 0:
                direction = "improved"
            elif delta < 0:
                direction = "regressed"
            else:
                direction = "unchanged"
            lines.append(f"  {metric}: {delta:+.4f} ({direction})")
        status = "REGRESSION DETECTED" if self.has_regression else "OK"
        return f"Comparison: {status}\n" + "\n".join(lines)


class BaselineManager:
    """Manages baseline snapshots for deterministic evaluation."""

    @staticmethod
    def compute_prompt_hash(prompt: str) -> str:
        """Compute a short hash of a prompt for identity tracking.

        Args:
            prompt: The prompt text to hash.

        Returns:
            First 16 characters of the SHA-256 hex digest.
        """
        return hashlib.sha256(prompt.encode()).hexdigest()[:16]

    @staticmethod
    def compare(
        current: BaselineSnapshot,
        baseline: BaselineSnapshot,
        regression_threshold: float = 0.0,
    ) -> ComparisonResult:
        """Compare current snapshot metrics against a baseline.

        Args:
            current: The current evaluation snapshot.
            baseline: The baseline snapshot to compare against.
            regression_threshold: Minimum drop (absolute) to count as
                a regression. Drops smaller than this are tolerated.

        Returns:
            ComparisonResult with delta information and regression
            detection.
        """
        deltas: Dict[str, float] = {}
        regressions: Dict[str, str] = {}
        has_regression = False

        all_metrics = set(current.metrics.keys()) | set(
            baseline.metrics.keys()
        )
        for metric in all_metrics:
            current_val = current.metrics.get(metric, 0.0)
            baseline_val = baseline.metrics.get(metric, 0.0)
            delta = current_val - baseline_val
            deltas[metric] = delta
            if delta < -regression_threshold:
                has_regression = True
                regressions[metric] = (
                    f"{metric}: {baseline_val:.4f} -> {current_val:.4f} "
                    f"(delta={delta:+.4f}, "
                    f"threshold={regression_threshold})"
                )

        return ComparisonResult(
            has_regression=has_regression,
            metric_deltas=deltas,
            regression_details=regressions,
        )
