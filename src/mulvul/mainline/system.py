"""Thin v1-compatible wrapper over the v2 bundle/scorer/policy runtime."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple

from mulvul.rag.retriever import MulVulRetriever

from .ablations import AblationConfig
from .artifacts import PromptArtifact
from .bundle import NodeScoreResult, PromptBundle, PromptBundleAdapter
from .policy import DetectionPath as V2DetectionPath
from .policy import (
    GreedyCascadePolicy,
    InferenceResult,
    RetrieverEvidenceProvider,
    TopKCascadePolicy,
)
from .scorer import LLMNodeScorer


@dataclass
class StageScore:
    """Compatibility view of a node-local score."""

    target: str
    confidence: float
    predicted_label: str
    ranking: List[Tuple[str, float]] = field(default_factory=list)
    raw_response: str = ""


@dataclass
class DetectionPath:
    """Compatibility view of a route through the cascade."""

    major: str
    major_confidence: float
    middle: str | None
    middle_confidence: float
    cwe: str | None
    cwe_confidence: float
    score: float


@dataclass
class MainlineDetectionResult:
    """Structured result preserved for external callers."""

    prediction: str
    major: str
    middle: str | None
    cwe: str | None
    score: float
    stage_scores: Dict[str, List[StageScore]] = field(default_factory=dict)
    candidate_paths: List[DetectionPath] = field(default_factory=list)

    @property
    def is_vulnerable(self) -> bool:
        return self.prediction != "Benign"

    def to_dict(self) -> Dict[str, object]:
        return {
            "prediction": self.prediction,
            "major": self.major,
            "middle": self.middle,
            "cwe": self.cwe,
            "score": self.score,
            "stage_scores": {
                stage: [
                    {
                        "target": item.target,
                        "confidence": item.confidence,
                        "predicted_label": item.predicted_label,
                        "ranking": item.ranking,
                    }
                    for item in values
                ]
                for stage, values in self.stage_scores.items()
            },
            "candidate_paths": [
                {
                    "major": path.major,
                    "major_confidence": path.major_confidence,
                    "middle": path.middle,
                    "middle_confidence": path.middle_confidence,
                    "cwe": path.cwe,
                    "cwe_confidence": path.cwe_confidence,
                    "score": path.score,
                }
                for path in self.candidate_paths
            ],
        }


class MainlineDetectorSystem:
    """Evaluate code with the frozen mainline bundle runtime."""

    def __init__(
        self,
        llm_client: Any,
        artifact: PromptArtifact | PromptBundle,
        ablations: AblationConfig | None = None,
        retriever: MulVulRetriever | None = None,
    ):
        self.llm_client = llm_client
        self.ablations = ablations or AblationConfig()
        self.retriever = retriever if self.ablations.use_retrieval else None

        if isinstance(artifact, PromptArtifact):
            self.bundle = PromptBundleAdapter.from_artifact(
                artifact,
                source_artifact="prompt_artifact.json",
                allow_partial=True,
            )
        else:
            self.bundle = artifact

        self.scorer = LLMNodeScorer(llm_client, self.bundle)
        evidence_provider = (
            RetrieverEvidenceProvider(self.retriever) if self.retriever else None
        )
        policy_cls = (
            TopKCascadePolicy
            if self.ablations.major_top_k > 1 or self.ablations.middle_top_k > 1
            else GreedyCascadePolicy
        )
        self.policy = policy_cls(
            evidence_provider=evidence_provider,
            parallel=self.ablations.parallel_scoring,
            major_top_k=self.ablations.major_top_k,
            middle_top_k=self.ablations.middle_top_k,
        )

    def detect(self, code: str) -> MainlineDetectionResult:
        inference = self.policy.run(self.bundle, self.scorer, code)
        return self._to_legacy_result(inference)

    def _to_legacy_result(self, inference: InferenceResult) -> MainlineDetectionResult:
        stage_scores = {
            stage: [self._to_stage_score(result) for result in results]
            for stage, results in inference.stage_results.items()
        }
        candidate_paths = [
            self._to_detection_path(path) for path in inference.candidate_paths
        ]

        if inference.best_path is None:
            return MainlineDetectionResult(
                prediction=inference.prediction,
                major="Benign",
                middle=None,
                cwe=None,
                score=0.0,
                stage_scores=stage_scores,
                candidate_paths=candidate_paths,
            )

        major, middle, cwe = self._path_labels(inference.best_path)
        return MainlineDetectionResult(
            prediction=inference.prediction,
            major=major,
            middle=middle,
            cwe=cwe,
            score=inference.best_path.score,
            stage_scores=stage_scores,
            candidate_paths=candidate_paths,
        )

    def _to_stage_score(self, result: NodeScoreResult) -> StageScore:
        return StageScore(
            target=result.target_label,
            confidence=result.target_confidence,
            predicted_label=result.predicted_label or "Benign",
            ranking=list(result.ranking),
            raw_response=result.raw_response,
        )

    def _to_detection_path(self, path: V2DetectionPath) -> DetectionPath:
        major, middle, cwe = self._path_labels(path)
        major_conf = 0.0
        middle_conf = 0.0
        cwe_conf = 0.0
        for result in path.stage_results:
            if result.stage == "major":
                major_conf = result.target_confidence
            elif result.stage == "middle":
                middle_conf = result.target_confidence
            elif result.stage == "cwe":
                cwe_conf = result.target_confidence
        return DetectionPath(
            major=major,
            major_confidence=major_conf,
            middle=middle,
            middle_confidence=middle_conf,
            cwe=cwe,
            cwe_confidence=cwe_conf,
            score=path.score,
        )

    def _path_labels(self, path: V2DetectionPath) -> tuple[str, str | None, str | None]:
        major = "Benign"
        middle = None
        cwe = None
        for result in path.stage_results:
            if result.stage == "major":
                major = result.target_label
            elif result.stage == "middle":
                middle = result.target_label
            elif result.stage == "cwe":
                cwe = result.target_label
        return major, middle, cwe
