"""Main router-detector system used by the two first-class workflows."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Tuple

from evoprompt.agents.hierarchical_detector import (
    CWE_TO_MIDDLE,
    MAJOR_TO_MIDDLE,
    MIDDLE_TO_CWE,
    MIDDLE_TO_MAJOR,
    LevelDetector,
)
from evoprompt.rag.retriever import MulVulRetriever

from .ablations import AblationConfig
from .artifacts import PromptArtifact


@dataclass
class StageScore:
    """Score assigned by a target-specific prompt."""

    target: str
    confidence: float
    predicted_label: str
    ranking: List[Tuple[str, float]] = field(default_factory=list)
    raw_response: str = ""


@dataclass
class DetectionPath:
    """A full route through the detector cascade."""

    major: str
    major_confidence: float
    middle: str
    middle_confidence: float
    cwe: str
    cwe_confidence: float
    score: float


@dataclass
class MainlineDetectionResult:
    """Structured result from the mainline detector system."""

    prediction: str
    major: str
    middle: str
    cwe: str
    score: float
    stage_scores: Dict[str, List[StageScore]] = field(default_factory=dict)
    candidate_paths: List[DetectionPath] = field(default_factory=list)

    @property
    def is_vulnerable(self) -> bool:
        return self.prediction != "Benign"

    def to_dict(self) -> Dict[str, object]:
        """Serialize the result for logging."""

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
    """Evaluate code with the frozen best-prompt router-detector cascade."""

    def __init__(
        self,
        llm_client,
        artifact: PromptArtifact,
        ablations: AblationConfig | None = None,
        retriever: MulVulRetriever | None = None,
    ):
        self.llm_client = llm_client
        self.artifact = artifact
        self.ablations = ablations or AblationConfig()
        self.retriever = retriever if self.ablations.use_retrieval else None

        self.major_detectors = self._build_major_detectors()
        self.middle_detectors = self._build_middle_detectors()
        self.cwe_detectors = self._build_cwe_detectors()

    def _build_major_detectors(self) -> Dict[str, LevelDetector]:
        candidates = list(MAJOR_TO_MIDDLE.keys()) + ["Benign"]
        return {
            major: LevelDetector(
                level="major",
                target=major,
                llm_client=self.llm_client,
                prompt=prompt,
                candidates=candidates,
                retriever=self.retriever,
            )
            for major, prompt in self.artifact.router_prompts.items()
        }

    def _build_middle_detectors(self) -> Dict[str, LevelDetector]:
        detectors: Dict[str, LevelDetector] = {}
        for middle, prompt in self.artifact.middle_prompts.items():
            major = MIDDLE_TO_MAJOR.get(middle)
            if not major:
                continue
            candidates = MAJOR_TO_MIDDLE.get(major, []) + ["Benign"]
            detectors[middle] = LevelDetector(
                level="middle",
                target=middle,
                llm_client=self.llm_client,
                prompt=prompt,
                candidates=candidates,
                retriever=self.retriever,
            )
        return detectors

    def _build_cwe_detectors(self) -> Dict[str, LevelDetector]:
        detectors: Dict[str, LevelDetector] = {}
        for cwe, prompt in self.artifact.cwe_prompts.items():
            middle = CWE_TO_MIDDLE.get(cwe)
            if not middle:
                continue
            candidates = MIDDLE_TO_CWE.get(middle, []) + ["Benign"]
            detectors[cwe] = LevelDetector(
                level="cwe",
                target=cwe,
                llm_client=self.llm_client,
                prompt=prompt,
                candidates=candidates,
                retriever=self.retriever,
            )
        return detectors

    def detect(self, code: str) -> MainlineDetectionResult:
        """Run the mainline router-detector cascade on one sample."""

        major_scores = self._score_detectors(self.major_detectors.values(), code)
        stage_scores: Dict[str, List[StageScore]] = {"major": major_scores}

        if not major_scores or major_scores[0].confidence < self.ablations.decision_threshold:
            return MainlineDetectionResult(
                prediction="Benign",
                major="Benign",
                middle="Benign",
                cwe="Benign",
                score=major_scores[0].confidence if major_scores else 0.0,
                stage_scores=stage_scores,
            )

        major_candidates = major_scores[: self.ablations.major_top_k]
        middle_scores = self._score_selected_middles(code, major_candidates)
        stage_scores["middle"] = middle_scores
        middle_lookup = {score.target: score for score in middle_scores}

        candidate_paths: List[DetectionPath] = []
        cwe_scores: List[StageScore] = []

        for major_score in major_candidates:
            major = major_score.target
            selected_middles = [
                score
                for score in middle_scores
                if MIDDLE_TO_MAJOR.get(score.target) == major
            ][: self.ablations.middle_top_k]

            for middle_score in selected_middles:
                cwe_candidates = [
                    detector
                    for cwe, detector in self.cwe_detectors.items()
                    if CWE_TO_MIDDLE.get(cwe) == middle_score.target
                ]
                if not cwe_candidates:
                    candidate_paths.append(
                        DetectionPath(
                            major=major,
                            major_confidence=major_score.confidence,
                            middle=middle_score.target,
                            middle_confidence=middle_score.confidence,
                            cwe="Unknown",
                            cwe_confidence=0.0,
                            score=major_score.confidence * middle_score.confidence,
                        )
                    )
                    continue

                scored_cwes = self._score_detectors(cwe_candidates, code)
                cwe_scores.extend(scored_cwes)
                if not scored_cwes:
                    continue

                best_cwe = scored_cwes[0]
                candidate_paths.append(
                    DetectionPath(
                        major=major,
                        major_confidence=major_score.confidence,
                        middle=middle_score.target,
                        middle_confidence=middle_score.confidence,
                        cwe=best_cwe.target,
                        cwe_confidence=best_cwe.confidence,
                        score=(
                            major_score.confidence
                            * middle_score.confidence
                            * best_cwe.confidence
                        ),
                    )
                )

        stage_scores["cwe"] = sorted(
            cwe_scores, key=lambda item: item.confidence, reverse=True
        )

        if not candidate_paths:
            top_major = major_scores[0]
            middle = "Unknown"
            middle_conf = 0.0
            if middle_scores:
                best_middle = middle_lookup.get(middle_scores[0].target, middle_scores[0])
                middle = best_middle.target
                middle_conf = best_middle.confidence
            return MainlineDetectionResult(
                prediction=top_major.target,
                major=top_major.target,
                middle=middle,
                cwe="Unknown",
                score=top_major.confidence * max(middle_conf, 1.0),
                stage_scores=stage_scores,
            )

        best_path = max(candidate_paths, key=lambda item: item.score)
        prediction = best_path.cwe if best_path.cwe != "Unknown" else best_path.middle
        return MainlineDetectionResult(
            prediction=prediction,
            major=best_path.major,
            middle=best_path.middle,
            cwe=best_path.cwe,
            score=best_path.score,
            stage_scores=stage_scores,
            candidate_paths=sorted(
                candidate_paths, key=lambda item: item.score, reverse=True
            ),
        )

    def _score_selected_middles(
        self,
        code: str,
        major_scores: Iterable[StageScore],
    ) -> List[StageScore]:
        middle_detectors = []
        for score in major_scores:
            major = score.target
            for middle in MAJOR_TO_MIDDLE.get(major, []):
                detector = self.middle_detectors.get(middle)
                if detector is not None:
                    middle_detectors.append(detector)
        return self._score_detectors(middle_detectors, code)

    def _score_detectors(
        self,
        detectors: Iterable[LevelDetector],
        code: str,
    ) -> List[StageScore]:
        detector_list = list(detectors)
        if not detector_list:
            return []

        if not self.ablations.parallel_scoring or len(detector_list) == 1:
            scores = [self._score_detector(detector, code) for detector in detector_list]
        else:
            scores = self._score_detectors_parallel(detector_list, code)
        return sorted(scores, key=lambda item: item.confidence, reverse=True)

    def _score_detectors_parallel(
        self,
        detectors: List[LevelDetector],
        code: str,
    ) -> List[StageScore]:
        scores: List[StageScore] = []
        with ThreadPoolExecutor(max_workers=len(detectors)) as executor:
            future_map = {
                executor.submit(self._score_detector, detector, code): detector.target
                for detector in detectors
            }
            for future in as_completed(future_map):
                target = future_map[future]
                try:
                    scores.append(future.result())
                except Exception as exc:
                    scores.append(
                        StageScore(
                            target=target,
                            confidence=0.0,
                            predicted_label="Error",
                            raw_response=str(exc),
                        )
                    )
        return scores

    def _score_detector(self, detector: LevelDetector, code: str) -> StageScore:
        candidates_str = ", ".join(detector.candidates)
        evidence = detector._retrieve_evidence(code)
        prompt = detector.prompt.format(
            code=code[:4000],
            evidence=evidence,
            candidates=candidates_str,
        )
        response = detector.llm_client.generate(prompt)
        ranking = detector._parse_response(response, top_k=len(detector.candidates))

        target_confidence = 0.0
        for label, confidence in ranking:
            if label == detector.target:
                target_confidence = confidence
                break

        predicted_label = ranking[0][0] if ranking else "Benign"
        return StageScore(
            target=detector.target,
            confidence=target_confidence,
            predicted_label=predicted_label,
            ranking=ranking,
            raw_response=response,
        )
