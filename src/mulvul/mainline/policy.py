"""Cascade inference policies for prompt bundles."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from math import prod
from typing import Any, Protocol, Sequence

from .bundle import (
    EvidenceBundle,
    EvidenceItem,
    NodeScoreResult,
    NodeSpec,
    PromptBundle,
    ScorerContext,
)
from .scorer import NodeScorer


@dataclass
class DetectionPath:
    """Ordered accepted route through the taxonomy."""

    node_ids: list[str]
    stage_results: list[NodeScoreResult]
    final_label: str
    score: float


@dataclass
class InferenceResult:
    """Structured policy output."""

    prediction: str
    best_path: DetectionPath | None
    candidate_paths: list[DetectionPath]
    stage_results: dict[str, list[NodeScoreResult]]
    nodes_scored: int
    nodes_skipped: int


class EvidenceProvider(Protocol):
    """Policy-owned evidence retrieval hook."""

    def retrieve(
        self,
        bundle: PromptBundle,
        node: NodeSpec,
        ctx: ScorerContext,
    ) -> EvidenceBundle:
        """Return structured evidence for a node-local scorer call."""


class NullEvidenceProvider:
    """No-op evidence provider."""

    def retrieve(
        self,
        bundle: PromptBundle,
        node: NodeSpec,
        ctx: ScorerContext,
    ) -> EvidenceBundle:
        return EvidenceBundle(items=[])


class RetrieverEvidenceProvider:
    """Adapter from current retriever objects to structured v2 evidence."""

    def __init__(self, retriever: Any, top_k: int = 3):
        self.retriever = retriever
        self.top_k = top_k

    def retrieve(
        self,
        bundle: PromptBundle,
        node: NodeSpec,
        ctx: ScorerContext,
    ) -> EvidenceBundle:
        if self.retriever is None:
            return EvidenceBundle(items=[])

        samples = self._retrieve_samples(node, ctx.code)
        items: list[EvidenceItem] = []
        retrieval_ids: list[str] = []

        for index, sample in enumerate(samples, 1):
            if isinstance(sample, dict):
                source_id = str(
                    sample.get("cwe")
                    or sample.get("source_id")
                    or f"{node.node_id}:{index}"
                )
                title = str(
                    sample.get("description")
                    or sample.get("category")
                    or sample.get("middle")
                    or sample.get("major")
                    or source_id
                )
                text_parts = [sample.get("code", "")]
                if sample.get("description"):
                    text_parts.append(f"Description: {sample['description']}")
                items.append(
                    EvidenceItem(
                        kind="positive",
                        title=title,
                        text="\n".join(part for part in text_parts if part),
                        source_id=source_id,
                        metadata={
                            k: v
                            for k, v in sample.items()
                            if k not in {"code", "description"}
                        },
                    )
                )
                retrieval_ids.append(source_id)
            else:
                source_id = f"{node.node_id}:{index}"
                items.append(
                    EvidenceItem(
                        kind="positive",
                        title=source_id,
                        text=str(sample),
                        source_id=source_id,
                    )
                )
                retrieval_ids.append(source_id)

        return EvidenceBundle(
            items=items,
            retrieval_ids=retrieval_ids,
            metadata={"top_k": self.top_k},
        )

    def _retrieve_samples(self, node: NodeSpec, query_code: str) -> Sequence[object]:
        if node.stage == "major" and hasattr(self.retriever, "retrieve_from_category"):
            result = self.retriever.retrieve_from_category(
                query_code, node.target_label, top_k=self.top_k
            )
            return self._normalize_samples(result)
        if node.stage == "middle" and hasattr(self.retriever, "retrieve_from_middle"):
            result = self.retriever.retrieve_from_middle(
                query_code, node.target_label, top_k=self.top_k
            )
            return self._normalize_samples(result)
        if node.stage == "cwe" and hasattr(self.retriever, "retrieve_from_cwe"):
            result = self.retriever.retrieve_from_cwe(
                query_code, node.target_label, top_k=self.top_k
            )
            return self._normalize_samples(result)
        return []

    def _normalize_samples(self, value: Any) -> list[object]:
        if isinstance(value, Sequence) and not isinstance(
            value, (str, bytes, bytearray)
        ):
            return list(value)
        return []


class InferencePolicy(Protocol):
    """Policy contract for cascade execution."""

    def run(
        self,
        bundle: PromptBundle,
        scorer: NodeScorer,
        code: str,
    ) -> InferenceResult:
        """Run the complete inference cascade."""


class GreedyCascadePolicy:
    """Default greedy major -> middle -> cwe cascade policy."""

    def __init__(
        self,
        *,
        evidence_provider: EvidenceProvider | None = None,
        parallel: bool = False,
        major_top_k: int = 1,
        middle_top_k: int = 1,
    ):
        self.evidence_provider = evidence_provider or NullEvidenceProvider()
        self.parallel = parallel
        self.major_top_k = max(1, major_top_k)
        self.middle_top_k = max(1, middle_top_k)

    def run(
        self,
        bundle: PromptBundle,
        scorer: NodeScorer,
        code: str,
    ) -> InferenceResult:
        stage_results = self._empty_stage_results()
        candidate_paths: list[DetectionPath] = []
        accepted_major = self._major_stage(bundle, scorer, code, stage_results)

        for major_result in accepted_major:
            self._middle_stage(
                bundle,
                scorer,
                code,
                major_result,
                stage_results,
                candidate_paths,
            )

        self._finalize_stage_results(stage_results)
        return self._build_inference_result(
            bundle,
            stage_results,
            accepted_major,
            candidate_paths,
        )

    def _empty_stage_results(self) -> dict[str, list[NodeScoreResult]]:
        return {
            "major": [],
            "middle": [],
            "cwe": [],
        }

    def _major_stage(
        self,
        bundle: PromptBundle,
        scorer: NodeScorer,
        code: str,
        stage_results: dict[str, list[NodeScoreResult]],
    ) -> list[NodeScoreResult]:
        major_ids = self._existing_node_ids(
            bundle,
            bundle.taxonomy.node_ids_for_stage("major"),
        )
        major_results = self._score_nodes(
            bundle,
            scorer,
            major_ids,
            code=code,
            parent_result=None,
        )
        stage_results["major"] = self._sort_results(major_results)
        return [
            result for result in stage_results["major"] if result.decision == "accept"
        ][: self.major_top_k]

    def _middle_stage(
        self,
        bundle: PromptBundle,
        scorer: NodeScorer,
        code: str,
        major_result: NodeScoreResult,
        stage_results: dict[str, list[NodeScoreResult]],
        candidate_paths: list[DetectionPath],
    ) -> None:
        middle_ids = self._existing_node_ids(
            bundle,
            bundle.taxonomy.children_of(major_result.node_id),
        )
        if not middle_ids:
            candidate_paths.append(self._path_from_results([major_result]))
            return

        middle_results = self._score_nodes(
            bundle,
            scorer,
            middle_ids,
            code=code,
            parent_result=major_result,
        )
        sorted_middle_results = self._sort_results(middle_results)
        stage_results["middle"].extend(sorted_middle_results)
        accepted_middle = [
            result for result in sorted_middle_results if result.decision == "accept"
        ][: self.middle_top_k]

        if not accepted_middle:
            candidate_paths.append(self._path_from_results([major_result]))
            return

        for middle_result in accepted_middle:
            self._cwe_stage(
                bundle,
                scorer,
                code,
                major_result,
                middle_result,
                stage_results,
                candidate_paths,
            )

    def _cwe_stage(
        self,
        bundle: PromptBundle,
        scorer: NodeScorer,
        code: str,
        major_result: NodeScoreResult,
        middle_result: NodeScoreResult,
        stage_results: dict[str, list[NodeScoreResult]],
        candidate_paths: list[DetectionPath],
    ) -> None:
        cwe_ids = self._existing_node_ids(
            bundle,
            bundle.taxonomy.children_of(middle_result.node_id),
        )
        if not cwe_ids:
            candidate_paths.append(self._path_from_results([major_result, middle_result]))
            return

        cwe_results = self._score_nodes(
            bundle,
            scorer,
            cwe_ids,
            code=code,
            parent_result=middle_result,
        )
        sorted_cwe_results = self._sort_results(cwe_results)
        stage_results["cwe"].extend(sorted_cwe_results)
        accepted_cwes = [
            result for result in sorted_cwe_results if result.decision == "accept"
        ]

        if not accepted_cwes:
            candidate_paths.append(self._path_from_results([major_result, middle_result]))
            return

        for cwe_result in accepted_cwes:
            candidate_paths.append(
                self._path_from_results([major_result, middle_result, cwe_result])
            )

    def _finalize_stage_results(
        self,
        stage_results: dict[str, list[NodeScoreResult]],
    ) -> None:
        for stage in stage_results:
            stage_results[stage] = self._sort_results(stage_results[stage])

    def _build_inference_result(
        self,
        bundle: PromptBundle,
        stage_results: dict[str, list[NodeScoreResult]],
        accepted_major: list[NodeScoreResult],
        candidate_paths: list[DetectionPath],
    ) -> InferenceResult:
        nodes_scored = sum(len(results) for results in stage_results.values())
        nodes_skipped = max(len(bundle.nodes) - nodes_scored, 0)

        if not accepted_major:
            return InferenceResult(
                prediction=bundle.taxonomy.benign_label,
                best_path=None,
                candidate_paths=[],
                stage_results=stage_results,
                nodes_scored=nodes_scored,
                nodes_skipped=nodes_skipped,
            )

        candidate_paths.sort(key=lambda path: path.score, reverse=True)
        best_path = candidate_paths[0]
        return InferenceResult(
            prediction=best_path.final_label,
            best_path=best_path,
            candidate_paths=candidate_paths,
            stage_results=stage_results,
            nodes_scored=nodes_scored,
            nodes_skipped=nodes_skipped,
        )

    def _existing_node_ids(
        self,
        bundle: PromptBundle,
        node_ids: Sequence[str],
    ) -> list[str]:
        return [node_id for node_id in node_ids if node_id in bundle.nodes]

    def _score_nodes(
        self,
        bundle: PromptBundle,
        scorer: NodeScorer,
        node_ids: Sequence[str],
        *,
        code: str,
        parent_result: NodeScoreResult | None,
    ) -> list[NodeScoreResult]:
        if not node_ids:
            return []

        if not self.parallel or len(node_ids) == 1:
            return [
                self._score_single_node(
                    bundle,
                    scorer,
                    bundle.nodes[node_id],
                    code=code,
                    parent_result=parent_result,
                )
                for node_id in node_ids
            ]

        results: list[NodeScoreResult] = []
        with ThreadPoolExecutor(max_workers=len(node_ids)) as executor:
            futures = {
                executor.submit(
                    self._score_single_node,
                    bundle,
                    scorer,
                    bundle.nodes[node_id],
                    code=code,
                    parent_result=parent_result,
                ): node_id
                for node_id in node_ids
            }
            for future in as_completed(futures):
                results.append(future.result())
        return results

    def _score_single_node(
        self,
        bundle: PromptBundle,
        scorer: NodeScorer,
        node: NodeSpec,
        *,
        code: str,
        parent_result: NodeScoreResult | None,
    ) -> NodeScoreResult:
        candidate_labels = list(bundle.taxonomy.decision_labels_for(node.node_id))
        if bundle.taxonomy.benign_label not in candidate_labels:
            candidate_labels.append(bundle.taxonomy.benign_label)

        base_ctx = ScorerContext(
            code=code,
            candidate_labels=candidate_labels,
            mode="infer",
            parent_result=parent_result,
            request_id=node.node_id,
            metadata={"policy": "greedy"},
        )
        evidence = self.evidence_provider.retrieve(bundle, node, base_ctx)
        ctx = ScorerContext(
            code=code,
            candidate_labels=candidate_labels,
            mode="infer",
            parent_result=parent_result,
            evidence=evidence,
            request_id=node.node_id,
            metadata={"policy": "greedy"},
        )
        return scorer.score(node, ctx)

    def _path_from_results(self, results: list[NodeScoreResult]) -> DetectionPath:
        accepted_results = [result for result in results if result.decision == "accept"]
        final_result = accepted_results[-1]
        return DetectionPath(
            node_ids=[result.node_id for result in accepted_results],
            stage_results=accepted_results,
            final_label=final_result.target_label,
            score=prod(result.target_confidence for result in accepted_results),
        )

    def _sort_results(
        self, results: Sequence[NodeScoreResult]
    ) -> list[NodeScoreResult]:
        return sorted(
            results,
            key=lambda result: result.target_confidence,
            reverse=True,
        )


class TopKCascadePolicy(GreedyCascadePolicy):
    """Explicit top-k route expansion policy."""

    def __init__(
        self,
        *,
        evidence_provider: EvidenceProvider | None = None,
        parallel: bool = False,
        major_top_k: int = 2,
        middle_top_k: int = 2,
    ):
        super().__init__(
            evidence_provider=evidence_provider,
            parallel=parallel,
            major_top_k=major_top_k,
            middle_top_k=middle_top_k,
        )


class BeamCascadePolicy:
    """Beam-search cascade with optional benign gate and margin-based reject.

    Three improvements over GreedyCascadePolicy:
    1. Benign gate (Stage 0): If the highest-ranked major result has
       confidence below ``benign_gate_threshold``, the sample is classified
       as Benign immediately, skipping downstream stages.
    2. Beam search: Retain top-``major_beam_width`` accepted majors and
       top-``middle_beam_width`` accepted middles instead of committing to
       the single highest-confidence path immediately.
    3. Margin reject: At major and middle stages, if the gap between the
       top-1 and top-2 confidence is smaller than ``margin_threshold``, the
       sample is rejected as Benign (uncertain routing).
    """

    def __init__(
        self,
        *,
        evidence_provider: EvidenceProvider | None = None,
        parallel: bool = False,
        major_beam_width: int = 2,
        middle_beam_width: int = 2,
        benign_gate_threshold: float = 0.3,
        margin_threshold: float = 0.05,
    ):
        self.evidence_provider = evidence_provider or NullEvidenceProvider()
        self.parallel = parallel
        self.major_beam_width = max(1, major_beam_width)
        self.middle_beam_width = max(1, middle_beam_width)
        self.benign_gate_threshold = benign_gate_threshold
        self.margin_threshold = margin_threshold

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def run(
        self,
        bundle: PromptBundle,
        scorer: NodeScorer,
        code: str,
    ) -> InferenceResult:
        stage_results: dict[str, list[NodeScoreResult]] = {
            "major": [],
            "middle": [],
            "cwe": [],
        }
        candidate_paths: list[DetectionPath] = []

        # --- Stage 0: Benign gate ---
        accepted_major = self._major_stage(bundle, scorer, code, stage_results)

        if not accepted_major:
            return self._build_result(
                bundle, stage_results, [], candidate_paths,
                prediction=bundle.taxonomy.benign_label,
            )

        # Benign gate: if best major *target* confidence is very low, classify as Benign.
        # We use a very low threshold so only truly unconfident predictions are gated.
        best_major_conf = accepted_major[0].target_confidence
        if best_major_conf < self.benign_gate_threshold:
            return self._build_result(
                bundle, stage_results, accepted_major, candidate_paths,
                prediction=bundle.taxonomy.benign_label,
            )

        # --- Stage 1: Middle (beam) ---
        for major_result in accepted_major[: self.major_beam_width]:
            self._middle_stage(
                bundle, scorer, code, major_result,
                stage_results, candidate_paths,
            )

        self._finalize_stage_results(stage_results)
        return self._build_result(
            bundle, stage_results, accepted_major, candidate_paths,
        )

    # ------------------------------------------------------------------
    # Stage implementations
    # ------------------------------------------------------------------

    def _major_stage(
        self,
        bundle: PromptBundle,
        scorer: NodeScorer,
        code: str,
        stage_results: dict[str, list[NodeScoreResult]],
    ) -> list[NodeScoreResult]:
        major_ids = [
            nid for nid in bundle.taxonomy.node_ids_for_stage("major")
            if nid in bundle.nodes
        ]
        results = self._score_nodes(bundle, scorer, major_ids, code=code, parent_result=None)
        stage_results["major"] = self._sort_results(results)
        return [r for r in stage_results["major"] if r.decision == "accept"]

    def _middle_stage(
        self,
        bundle: PromptBundle,
        scorer: NodeScorer,
        code: str,
        major_result: NodeScoreResult,
        stage_results: dict[str, list[NodeScoreResult]],
        candidate_paths: list[DetectionPath],
    ) -> None:
        middle_ids = [
            nid for nid in bundle.taxonomy.children_of(major_result.node_id)
            if nid in bundle.nodes
        ]
        if not middle_ids:
            candidate_paths.append(self._path_from_results([major_result]))
            return

        results = self._score_nodes(
            bundle, scorer, middle_ids, code=code, parent_result=major_result,
        )
        sorted_results = self._sort_results(results)
        stage_results["middle"].extend(sorted_results)
        accepted = [r for r in sorted_results if r.decision == "accept"]

        if not accepted:
            candidate_paths.append(self._path_from_results([major_result]))
            return

        for mid_result in accepted[: self.middle_beam_width]:
            self._cwe_stage(
                bundle, scorer, code, major_result, mid_result,
                stage_results, candidate_paths,
            )

    def _cwe_stage(
        self,
        bundle: PromptBundle,
        scorer: NodeScorer,
        code: str,
        major_result: NodeScoreResult,
        middle_result: NodeScoreResult,
        stage_results: dict[str, list[NodeScoreResult]],
        candidate_paths: list[DetectionPath],
    ) -> None:
        cwe_ids = [
            nid for nid in bundle.taxonomy.children_of(middle_result.node_id)
            if nid in bundle.nodes
        ]
        if not cwe_ids:
            candidate_paths.append(self._path_from_results([major_result, middle_result]))
            return

        results = self._score_nodes(
            bundle, scorer, cwe_ids, code=code, parent_result=middle_result,
        )
        sorted_results = self._sort_results(results)
        stage_results["cwe"].extend(sorted_results)
        accepted = [r for r in sorted_results if r.decision == "accept"]

        if not accepted:
            candidate_paths.append(self._path_from_results([major_result, middle_result]))
            return

        for cwe_result in accepted:
            candidate_paths.append(
                self._path_from_results([major_result, middle_result, cwe_result])
            )

    # ------------------------------------------------------------------
    # Scoring helpers
    # ------------------------------------------------------------------

    def _score_nodes(
        self,
        bundle: PromptBundle,
        scorer: NodeScorer,
        node_ids: Sequence[str],
        *,
        code: str,
        parent_result: NodeScoreResult | None,
    ) -> list[NodeScoreResult]:
        if not node_ids:
            return []
        if not self.parallel or len(node_ids) == 1:
            return [
                self._score_single(bundle, scorer, bundle.nodes[nid], code=code, parent_result=parent_result)
                for nid in node_ids
            ]
        results: list[NodeScoreResult] = []
        with ThreadPoolExecutor(max_workers=len(node_ids)) as executor:
            futures = {
                executor.submit(
                    self._score_single, bundle, scorer, bundle.nodes[nid],
                    code=code, parent_result=parent_result,
                ): nid
                for nid in node_ids
            }
            for future in as_completed(futures):
                results.append(future.result())
        return results

    def _score_single(
        self,
        bundle: PromptBundle,
        scorer: NodeScorer,
        node: NodeSpec,
        *,
        code: str,
        parent_result: NodeScoreResult | None,
    ) -> NodeScoreResult:
        candidate_labels = list(bundle.taxonomy.decision_labels_for(node.node_id))
        if bundle.taxonomy.benign_label not in candidate_labels:
            candidate_labels.append(bundle.taxonomy.benign_label)

        base_ctx = ScorerContext(
            code=code,
            candidate_labels=candidate_labels,
            mode="infer",
            parent_result=parent_result,
            request_id=node.node_id,
            metadata={"policy": "beam"},
        )
        evidence = self.evidence_provider.retrieve(bundle, node, base_ctx)
        ctx = ScorerContext(
            code=code,
            candidate_labels=candidate_labels,
            mode="infer",
            parent_result=parent_result,
            evidence=evidence,
            request_id=node.node_id,
            metadata={"policy": "beam"},
        )
        return scorer.score(node, ctx)

    # ------------------------------------------------------------------
    # Result builders
    # ------------------------------------------------------------------

    @staticmethod
    def _path_from_results(results: list[NodeScoreResult]) -> DetectionPath:
        accepted = [r for r in results if r.decision == "accept"]
        final = accepted[-1]
        return DetectionPath(
            node_ids=[r.node_id for r in accepted],
            stage_results=accepted,
            final_label=final.target_label,
            score=prod(r.target_confidence for r in accepted),
        )

    @staticmethod
    def _sort_results(results: Sequence[NodeScoreResult]) -> list[NodeScoreResult]:
        return sorted(results, key=lambda r: r.target_confidence, reverse=True)

    def _finalize_stage_results(
        self,
        stage_results: dict[str, list[NodeScoreResult]],
    ) -> None:
        for stage in stage_results:
            stage_results[stage] = self._sort_results(stage_results[stage])

    def _build_result(
        self,
        bundle: PromptBundle,
        stage_results: dict[str, list[NodeScoreResult]],
        accepted_major: list[NodeScoreResult],
        candidate_paths: list[DetectionPath],
        *,
        prediction: str | None = None,
    ) -> InferenceResult:
        nodes_scored = sum(len(rs) for rs in stage_results.values())
        nodes_skipped = max(len(bundle.nodes) - nodes_scored, 0)

        if prediction is not None:
            return InferenceResult(
                prediction=prediction,
                best_path=None,
                candidate_paths=candidate_paths,
                stage_results=stage_results,
                nodes_scored=nodes_scored,
                nodes_skipped=nodes_skipped,
            )

        if not candidate_paths:
            return InferenceResult(
                prediction=bundle.taxonomy.benign_label,
                best_path=None,
                candidate_paths=[],
                stage_results=stage_results,
                nodes_scored=nodes_scored,
                nodes_skipped=nodes_skipped,
            )

        candidate_paths.sort(key=lambda p: p.score, reverse=True)
        best = candidate_paths[0]
        return InferenceResult(
            prediction=best.final_label,
            best_path=best,
            candidate_paths=candidate_paths,
            stage_results=stage_results,
            nodes_scored=nodes_scored,
            nodes_skipped=nodes_skipped,
        )
