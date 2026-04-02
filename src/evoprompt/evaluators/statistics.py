"""Statistics collection for vulnerability detection evaluation.

Collects detailed statistics about:
- Overall accuracy and F1 scores
- Per-category error rates
- Misclassification patterns (confusion matrix)
- False positive/negative rates per CWE type
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple
from collections import defaultdict
import json


@dataclass
class DetectionStatistics:
    """Statistics for a single evaluation run.

    Attributes:
        total_samples: Total number of samples evaluated
        correct: Number of correct predictions
        accuracy: Overall accuracy
        true_positives: Number of true positives
        false_positives: Number of false positives
        true_negatives: Number of true negatives
        false_negatives: Number of false negatives
        precision: Precision score
        recall: Recall score
        f1_score: F1 score
        category_stats: Per-category statistics
        confusion_matrix: Confusion matrix (predicted -> actual -> count)
    """

    total_samples: int = 0
    correct: int = 0
    accuracy: float = 0.0

    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0

    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0

    # Per-category statistics: category -> {correct, total, accuracy, ...}
    category_stats: Dict[str, Dict] = field(default_factory=dict)

    # Confusion matrix: predicted_label -> actual_label -> count
    confusion_matrix: Dict[str, Dict[str, int]] = field(default_factory=lambda: defaultdict(lambda: defaultdict(int)))

    # Misclassification patterns
    misclassifications: List[Dict] = field(default_factory=list)

    def compute_metrics(self):
        """Compute derived metrics from counts."""
        if self.total_samples > 0:
            self.accuracy = self.correct / self.total_samples

        if self.true_positives + self.false_positives > 0:
            self.precision = self.true_positives / (self.true_positives + self.false_positives)
        else:
            self.precision = 0.0

        if self.true_positives + self.false_negatives > 0:
            self.recall = self.true_positives / (self.true_positives + self.false_negatives)
        else:
            self.recall = 0.0

        if self.precision + self.recall > 0:
            self.f1_score = 2 * (self.precision * self.recall) / (self.precision + self.recall)
        else:
            self.f1_score = 0.0

    def add_prediction(
        self,
        predicted: str,
        actual: str,
        category: Optional[str] = None,
        sample_id: Optional[str] = None,
    ):
        """Add a single prediction result.

        Args:
            predicted: Predicted label ("vulnerable" or "benign")
            actual: Actual label
            category: Optional category/CWE type
            sample_id: Optional sample identifier
        """
        self.total_samples += 1

        # Normalize labels
        pred_norm = predicted.lower().strip()
        actual_norm = actual.lower().strip()

        # Binary classification
        is_correct = pred_norm == actual_norm
        if is_correct:
            self.correct += 1

        # Update confusion matrix
        self.confusion_matrix[pred_norm][actual_norm] += 1

        # Update TP/FP/TN/FN
        if actual_norm == "vulnerable":
            if pred_norm == "vulnerable":
                self.true_positives += 1
            else:
                self.false_negatives += 1
                # Record misclassification
                self.misclassifications.append({
                    "type": "false_negative",
                    "predicted": pred_norm,
                    "actual": actual_norm,
                    "category": category,
                    "sample_id": sample_id,
                })
        else:  # actual is benign
            if pred_norm == "benign":
                self.true_negatives += 1
            else:
                self.false_positives += 1
                # Record misclassification
                self.misclassifications.append({
                    "type": "false_positive",
                    "predicted": pred_norm,
                    "actual": actual_norm,
                    "category": category,
                    "sample_id": sample_id,
                })

        # Update per-category statistics
        if category:
            if category not in self.category_stats:
                self.category_stats[category] = {
                    "total": 0,
                    "correct": 0,
                    "tp": 0,
                    "fp": 0,
                    "tn": 0,
                    "fn": 0,
                }

            stats = self.category_stats[category]
            stats["total"] += 1
            if is_correct:
                stats["correct"] += 1

            # Update category-specific TP/FP/TN/FN
            if actual_norm == "vulnerable":
                if pred_norm == "vulnerable":
                    stats["tp"] += 1
                else:
                    stats["fn"] += 1
            else:
                if pred_norm == "benign":
                    stats["tn"] += 1
                else:
                    stats["fp"] += 1

    def get_summary(self) -> Dict:
        """Get a summary of statistics as a dictionary."""
        self.compute_metrics()

        summary = {
            "total_samples": self.total_samples,
            "correct": self.correct,
            "accuracy": round(self.accuracy, 4),
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1_score": round(self.f1_score, 4),
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "true_negatives": self.true_negatives,
            "false_negatives": self.false_negatives,
        }

        # Add per-category stats
        if self.category_stats:
            category_summary = {}
            for cat, stats in self.category_stats.items():
                cat_acc = stats["correct"] / stats["total"] if stats["total"] > 0 else 0
                category_summary[cat] = {
                    "total": stats["total"],
                    "correct": stats["correct"],
                    "accuracy": round(cat_acc, 4),
                    "tp": stats["tp"],
                    "fp": stats["fp"],
                    "fn": stats["fn"],
                    "error_rate": round(1 - cat_acc, 4),
                }
            summary["category_stats"] = category_summary

        # Add confusion matrix
        summary["confusion_matrix"] = {
            pred: dict(actual_counts)
            for pred, actual_counts in self.confusion_matrix.items()
        }

        # Add misclassification patterns
        if self.misclassifications:
            summary["total_misclassifications"] = len(self.misclassifications)
            summary["false_negatives_count"] = sum(1 for m in self.misclassifications if m["type"] == "false_negative")
            summary["false_positives_count"] = sum(1 for m in self.misclassifications if m["type"] == "false_positive")

        return summary


@dataclass
class BatchStatistics:
    """Statistics for a batch of evaluations.

    Used in batch-based evolution to track performance across batches.
    """

    batch_id: int
    batch_size: int
    statistics: DetectionStatistics = field(default_factory=DetectionStatistics)
    metadata: Dict = field(default_factory=dict)

    def get_summary(self) -> Dict:
        """Get batch summary."""
        summary = {
            "batch_id": self.batch_id,
            "batch_size": self.batch_size,
            "statistics": self.statistics.get_summary(),
            "metadata": self.metadata,
        }
        return summary


class StatisticsCollector:
    """Collects and aggregates statistics across multiple evaluations.

    This is used during evolution to track:
    - Historical performance trends
    - Category-specific error patterns
    - Improvement over generations
    """

    def __init__(self):
        self.generation_stats: Dict[int, DetectionStatistics] = {}
        self.batch_stats: List[BatchStatistics] = []
        self.overall_stats: DetectionStatistics = DetectionStatistics()

    def add_generation_stats(self, generation: int, stats: DetectionStatistics):
        """Add statistics for a generation."""
        self.generation_stats[generation] = stats

    def add_batch_stats(self, batch_stats: BatchStatistics):
        """Add statistics for a batch."""
        self.batch_stats.append(batch_stats)

    def get_generation_summary(self, generation: int) -> Optional[Dict]:
        """Get summary for a specific generation."""
        if generation in self.generation_stats:
            return self.generation_stats[generation].get_summary()
        return None

    def get_historical_trend(self) -> List[Dict]:
        """Get historical trend of key metrics across generations."""
        trend = []
        for gen in sorted(self.generation_stats.keys()):
            stats = self.generation_stats[gen]
            stats.compute_metrics()
            trend.append({
                "generation": gen,
                "accuracy": stats.accuracy,
                "f1_score": stats.f1_score,
                "precision": stats.precision,
                "recall": stats.recall,
            })
        return trend

    def get_category_error_patterns(self) -> Dict[str, List[float]]:
        """Get error rate trends for each category across generations."""
        patterns = defaultdict(list)

        for gen in sorted(self.generation_stats.keys()):
            stats = self.generation_stats[gen]
            for cat, cat_stats in stats.category_stats.items():
                error_rate = 1 - (cat_stats["correct"] / cat_stats["total"] if cat_stats["total"] > 0 else 0)
                patterns[cat].append(error_rate)

        return dict(patterns)

    def get_improvement_suggestions(self) -> List[str]:
        """Analyze statistics and suggest areas for improvement.

        Returns a list of human-readable suggestions based on error patterns.
        """
        suggestions = []

        if not self.generation_stats:
            return suggestions

        # Get latest generation stats
        latest_gen = max(self.generation_stats.keys())
        latest_stats = self.generation_stats[latest_gen]
        latest_stats.compute_metrics()

        # Check overall metrics
        if latest_stats.accuracy < 0.7:
            suggestions.append("Overall accuracy is low. Consider refining the prompt structure.")

        if latest_stats.precision < latest_stats.recall:
            suggestions.append("High false positive rate. Make the prompt more specific to reduce over-detection.")
        elif latest_stats.recall < latest_stats.precision:
            suggestions.append("High false negative rate. Make the prompt more sensitive to vulnerabilities.")

        # Check category-specific issues
        for cat, cat_stats in latest_stats.category_stats.items():
            cat_acc = cat_stats["correct"] / cat_stats["total"] if cat_stats["total"] > 0 else 0
            if cat_acc < 0.6:
                suggestions.append(f"Category '{cat}' has low accuracy ({cat_acc:.2%}). Focus on improving detection for this category.")

            # Check for bias
            if cat_stats["fp"] > cat_stats["fn"] * 2:
                suggestions.append(f"Category '{cat}' has high false positives. Tighten detection criteria.")
            elif cat_stats["fn"] > cat_stats["fp"] * 2:
                suggestions.append(f"Category '{cat}' has high false negatives. Broaden detection criteria.")

        return suggestions

    def export_to_json(self, filepath: str):
        """Export all statistics to JSON file."""
        data = {
            "generation_stats": {
                gen: stats.get_summary()
                for gen, stats in self.generation_stats.items()
            },
            "batch_stats": [
                batch.get_summary() for batch in self.batch_stats
            ],
            "overall_stats": self.overall_stats.get_summary(),
            "historical_trend": self.get_historical_trend(),
            "category_error_patterns": self.get_category_error_patterns(),
            "improvement_suggestions": self.get_improvement_suggestions(),
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
