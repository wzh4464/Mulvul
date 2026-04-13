"""Evaluation contracts for the v2 mainline runtime."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Mapping, Protocol, Sequence

from .bundle import PromptBundle
from .policy import InferencePolicy, InferenceResult
from .scorer import NodeScorer

NodeCounter = dict[str, float]


@dataclass
class NodeMetrics:
    """Node-level evaluation summary."""

    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0
    target_accept_rate: float = 0.0
    hard_negative_reject_rate: float = 0.0
    benign_reject_rate: float = 0.0
    hard_negative_benign_reject_rate: float = 0.0
    abstain_rate: float = 0.0
    error_rate: float = 0.0
    node_precision: float = 0.0
    node_recall: float = 0.0
    node_f1: float = 0.0


@dataclass
class EvaluationSample:
    """Single labeled evaluation example."""

    sample_id: str
    code: str
    major_label: str | None
    middle_label: str | None
    cwe_label: str | None
    final_label: str
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass
class EvaluationResult:
    """Structured evaluator output."""

    node_metrics: dict[str, NodeMetrics]
    route_metrics: dict[str, float]
    end_to_end_metrics: dict[str, float]
    cost_metrics: dict[str, float]
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass
class _EvaluationAccumulator:
    route_counts: defaultdict[str, float]
    path_margins: list[float]
    node_counters: defaultdict[str, NodeCounter]
    final_pairs: list[tuple[str, str]]
    major_pairs: list[tuple[str, str]]
    middle_pairs: list[tuple[str, str]]
    cwe_pairs: list[tuple[str, str]]
    binary_pairs: list[tuple[str, str]]
    nodes_scored_total: float
    major_top_k: int
    middle_top_k: int


class Evaluator(Protocol):
    """Evaluator contract."""

    def evaluate(
        self,
        bundle: PromptBundle,
        scorer: NodeScorer,
        policy: InferencePolicy,
        dataset: Sequence[EvaluationSample],
    ) -> EvaluationResult:
        """Evaluate a bundle end-to-end."""


class MainlineEvaluator:
    """Minimal evaluator for v2 mainline bundles."""

    def _new_accumulator(self, policy: InferencePolicy) -> _EvaluationAccumulator:
        return _EvaluationAccumulator(
            route_counts=defaultdict(float),
            path_margins=[],
            node_counters=defaultdict(self._new_node_counter),
            final_pairs=[],
            major_pairs=[],
            middle_pairs=[],
            cwe_pairs=[],
            binary_pairs=[],
            nodes_scored_total=0.0,
            major_top_k=max(1, getattr(policy, "major_top_k", 1)),
            middle_top_k=max(1, getattr(policy, "middle_top_k", 1)),
        )

    def evaluate(
        self,
        bundle: PromptBundle,
        scorer: NodeScorer,
        policy: InferencePolicy,
        dataset: Sequence[EvaluationSample],
    ) -> EvaluationResult:
        accumulator = self._new_accumulator(policy)
        for sample in dataset:
            inference = policy.run(bundle, scorer, sample.code)
            self._record_prediction_pairs(bundle, sample, inference, accumulator)
            self._record_route_metrics(bundle, sample, inference, accumulator)
            self._record_node_metrics(bundle, sample, inference, accumulator)
        return self._build_result(dataset, accumulator)

    def _record_prediction_pairs(
        self,
        bundle: PromptBundle,
        sample: EvaluationSample,
        inference: InferenceResult,
        accumulator: _EvaluationAccumulator,
    ) -> None:
        accumulator.final_pairs.append((sample.final_label, inference.prediction))
        accumulator.nodes_scored_total += inference.nodes_scored

        pred_major, pred_middle, pred_cwe = self._extract_predicted_labels(
            inference,
            benign_label=bundle.taxonomy.benign_label,
        )
        accumulator.major_pairs.append(
            (
                sample.major_label or bundle.taxonomy.benign_label,
                pred_major,
            )
        )
        if sample.final_label != bundle.taxonomy.benign_label:
            accumulator.middle_pairs.append(
                (sample.middle_label or "Unknown", pred_middle or "Unknown")
            )
            accumulator.cwe_pairs.append(
                (sample.cwe_label or "Unknown", pred_cwe or "Unknown")
            )

        accumulator.binary_pairs.append(
            (
                (
                    "Vulnerable"
                    if sample.final_label != bundle.taxonomy.benign_label
                    else bundle.taxonomy.benign_label
                ),
                (
                    "Vulnerable"
                    if inference.prediction != bundle.taxonomy.benign_label
                    else bundle.taxonomy.benign_label
                ),
            )
        )

    def _record_route_metrics(
        self,
        bundle: PromptBundle,
        sample: EvaluationSample,
        inference: InferenceResult,
        accumulator: _EvaluationAccumulator,
    ) -> None:
        if sample.major_label:
            major_ranked = [
                result.target_label for result in inference.stage_results["major"]
            ]
            if major_ranked[:1] and major_ranked[0] == sample.major_label:
                accumulator.route_counts["major_route_recall_at_1"] += 1
            if sample.major_label in major_ranked[: accumulator.major_top_k]:
                accumulator.route_counts["major_route_recall_at_k"] += 1

        if sample.middle_label:
            middle_ranked = [
                result.target_label for result in inference.stage_results["middle"]
            ]
            if middle_ranked[:1] and middle_ranked[0] == sample.middle_label:
                accumulator.route_counts["middle_route_recall_at_1"] += 1
            if sample.middle_label in middle_ranked[: accumulator.middle_top_k]:
                accumulator.route_counts["middle_route_recall_at_k"] += 1

        if sample.final_label != bundle.taxonomy.benign_label and inference.candidate_paths:
            accumulator.route_counts["path_coverage"] += 1

        if len(inference.candidate_paths) >= 2:
            accumulator.path_margins.append(
                inference.candidate_paths[0].score
                - inference.candidate_paths[1].score
            )
        elif len(inference.candidate_paths) == 1:
            accumulator.path_margins.append(inference.candidate_paths[0].score)

    def _record_node_metrics(
        self,
        bundle: PromptBundle,
        sample: EvaluationSample,
        inference: InferenceResult,
        accumulator: _EvaluationAccumulator,
    ) -> None:
        sample_labels = {
            "major": sample.major_label,
            "middle": sample.middle_label,
            "cwe": sample.cwe_label,
        }
        for stage_results in inference.stage_results.values():
            for result in stage_results:
                node_label = sample_labels[result.stage]
                counters = accumulator.node_counters[result.node_id]
                counters["total"] += 1

                if sample.final_label == bundle.taxonomy.benign_label:
                    sample_kind = "benign"
                elif node_label == result.target_label:
                    sample_kind = "target"
                else:
                    sample_kind = "hard_negative"

                if sample_kind == "target":
                    counters["target_total"] += 1
                    if result.decision == "accept":
                        counters["target_accept"] += 1
                        counters["tp"] += 1
                    else:
                        counters["fn"] += 1
                else:
                    if sample_kind == "hard_negative":
                        counters["hard_negative_total"] += 1
                    else:
                        counters["benign_total"] += 1

                    if result.decision == "accept":
                        counters["fp"] += 1
                    else:
                        counters["tn"] += 1
                        if sample_kind == "hard_negative":
                            counters["hard_negative_reject"] += 1
                        else:
                            counters["benign_reject"] += 1

                if result.decision == "abstain":
                    counters["abstain"] += 1
                elif result.decision == "error":
                    counters["error"] += 1

    def _build_result(
        self,
        dataset: Sequence[EvaluationSample],
        accumulator: _EvaluationAccumulator,
    ) -> EvaluationResult:
        total_samples = max(len(dataset), 1)
        node_metrics = {
            node_id: self._finalize_node_metrics(counters)
            for node_id, counters in accumulator.node_counters.items()
        }
        route_metrics = {
            "major_route_recall_at_1": accumulator.route_counts["major_route_recall_at_1"]
            / total_samples,
            "major_route_recall_at_k": accumulator.route_counts["major_route_recall_at_k"]
            / total_samples,
            "middle_route_recall_at_1": accumulator.route_counts["middle_route_recall_at_1"]
            / total_samples,
            "middle_route_recall_at_k": accumulator.route_counts["middle_route_recall_at_k"]
            / total_samples,
            "path_coverage": accumulator.route_counts["path_coverage"] / total_samples,
            "top1_top2_margin_mean": (
                sum(accumulator.path_margins) / len(accumulator.path_margins)
                if accumulator.path_margins
                else 0.0
            ),
        }
        end_to_end_metrics = {
            "final_exact_match": self._accuracy(accumulator.final_pairs),
            "major_accuracy": self._accuracy(accumulator.major_pairs),
            "middle_accuracy": self._accuracy(accumulator.middle_pairs),
            "cwe_accuracy": self._accuracy(accumulator.cwe_pairs),
            "vuln_vs_benign_f1": self._binary_f1(
                accumulator.binary_pairs,
                positive="Vulnerable",
            ),
            "macro_f1": self._macro_f1(accumulator.final_pairs),
        }
        cost_metrics = {
            "avg_nodes_scored_per_sample": accumulator.nodes_scored_total / total_samples,
            "avg_tokens_per_sample": 0.0,
            "avg_cost_per_sample": 0.0,
        }
        return EvaluationResult(
            node_metrics=node_metrics,
            route_metrics=route_metrics,
            end_to_end_metrics=end_to_end_metrics,
            cost_metrics=cost_metrics,
            metadata={"samples": len(dataset)},
        )

    def _extract_predicted_labels(
        self,
        inference: InferenceResult,
        *,
        benign_label: str,
    ) -> tuple[str, str | None, str | None]:
        if inference.best_path is None:
            return benign_label, None, None

        major = benign_label
        middle = None
        cwe = None
        for result in inference.best_path.stage_results:
            if result.stage == "major":
                major = result.target_label
            elif result.stage == "middle":
                middle = result.target_label
            elif result.stage == "cwe":
                cwe = result.target_label
        return major, middle, cwe

    def _new_node_counter(self) -> NodeCounter:
        return {
            "tp": 0.0,
            "fp": 0.0,
            "fn": 0.0,
            "tn": 0.0,
            "target_total": 0.0,
            "target_accept": 0.0,
            "hard_negative_total": 0.0,
            "hard_negative_reject": 0.0,
            "benign_total": 0.0,
            "benign_reject": 0.0,
            "abstain": 0.0,
            "error": 0.0,
            "total": 0.0,
        }

    def _finalize_node_metrics(self, counters: Mapping[str, float]) -> NodeMetrics:
        tp = int(counters["tp"])
        fp = int(counters["fp"])
        fn = int(counters["fn"])
        tn = int(counters["tn"])
        total = counters["total"] or 1.0
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall)
            else 0.0
        )
        hard_total = counters["hard_negative_total"] or 1.0
        benign_total = counters["benign_total"] or 1.0
        negative_total = (
            counters["hard_negative_total"] + counters["benign_total"]
        ) or 1.0
        return NodeMetrics(
            tp=tp,
            fp=fp,
            fn=fn,
            tn=tn,
            target_accept_rate=counters["target_accept"]
            / (counters["target_total"] or 1.0),
            hard_negative_reject_rate=counters["hard_negative_reject"] / hard_total,
            benign_reject_rate=counters["benign_reject"] / benign_total,
            hard_negative_benign_reject_rate=(
                (counters["hard_negative_reject"] + counters["benign_reject"])
                / negative_total
            ),
            abstain_rate=counters["abstain"] / total,
            error_rate=counters["error"] / total,
            node_precision=precision,
            node_recall=recall,
            node_f1=f1,
        )

    def _accuracy(self, pairs: Sequence[tuple[str, str]]) -> float:
        if not pairs:
            return 0.0
        correct = sum(1 for truth, pred in pairs if truth == pred)
        return correct / len(pairs)

    def _binary_f1(self, pairs: Sequence[tuple[str, str]], *, positive: str) -> float:
        tp = fp = fn = 0
        for truth, pred in pairs:
            if pred == positive and truth == positive:
                tp += 1
            elif pred == positive and truth != positive:
                fp += 1
            elif pred != positive and truth == positive:
                fn += 1
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        return (
            2 * precision * recall / (precision + recall)
            if (precision + recall)
            else 0.0
        )

    def _macro_f1(self, pairs: Sequence[tuple[str, str]]) -> float:
        labels = sorted({truth for truth, _ in pairs} | {pred for _, pred in pairs})
        if not labels:
            return 0.0
        f1_scores = []
        for label in labels:
            tp = fp = fn = 0
            for truth, pred in pairs:
                if pred == label and truth == label:
                    tp += 1
                elif pred == label and truth != label:
                    fp += 1
                elif pred != label and truth == label:
                    fn += 1
            precision = tp / (tp + fp) if (tp + fp) else 0.0
            recall = tp / (tp + fn) if (tp + fn) else 0.0
            f1_scores.append(
                2 * precision * recall / (precision + recall)
                if (precision + recall)
                else 0.0
            )
        return sum(f1_scores) / len(f1_scores)
