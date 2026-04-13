"""Node-local scoring contract shared by training and inference."""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Literal, Mapping, Protocol

from mulvul.utils.text import safe_format

from .bundle import (
    EvidenceBundle,
    NodeScoreResult,
    NodeSpec,
    PromptBundle,
    ScorerContext,
)


class NodeScorer(Protocol):
    """Protocol for node-local scoring."""

    def score(self, node: NodeSpec, ctx: ScorerContext) -> NodeScoreResult:
        """Score a node under a provided context."""


Decision = Literal["accept", "reject", "abstain", "error"]
ParseStatus = Literal["ok", "fallback", "error"]


class LLMNodeScorer:
    """Default prompt-rendering LLM scorer for v2 bundles."""

    DEFAULT_PROMPT_CODE_MAX_CHARS = 4000

    def __init__(self, llm_client: Any, bundle: PromptBundle):
        self.llm_client = llm_client
        self.bundle = bundle
        self.logger = logging.getLogger(__name__)

    def score(self, node: NodeSpec, ctx: ScorerContext) -> NodeScoreResult:
        """Score one node using the bundle-configured prompt contract."""
        try:
            prompt = self._render_prompt(node, ctx)
            response = self.llm_client.generate(prompt)
        except Exception as exc:
            return NodeScoreResult(
                node_id=node.node_id,
                stage=node.stage,
                target_label=node.target_label,
                predicted_label=None,
                top_confidence=0.0,
                target_confidence=0.0,
                ranking=[],
                matched_target=False,
                decision="error",
                parse_status="error",
                effective_threshold=self._effective_threshold(node),
                raw_response=str(exc),
                metadata={"exception_type": exc.__class__.__name__},
            )

        ranking, parse_status = self._parse_ranking(response, ctx.candidate_labels)
        if not ranking:
            return NodeScoreResult(
                node_id=node.node_id,
                stage=node.stage,
                target_label=node.target_label,
                predicted_label=None,
                top_confidence=0.0,
                target_confidence=0.0,
                ranking=[],
                matched_target=False,
                decision="error",
                parse_status="error",
                effective_threshold=self._effective_threshold(node),
                raw_response=response,
            )

        predicted_label, top_confidence = ranking[0]
        target_confidence = next(
            (confidence for label, confidence in ranking if label == node.target_label),
            0.0,
        )
        matched_target = predicted_label == node.target_label
        effective_threshold = self._effective_threshold(node)
        decision: Decision
        reject_label: str | None

        if parse_status == "fallback" and self.bundle.defaults.distrust_fallback:
            decision = "abstain"
            reject_label = None
        elif top_confidence < effective_threshold:
            decision = "abstain"
            reject_label = None
        elif matched_target:
            decision = "accept"
            reject_label = None
        else:
            decision = "reject"
            reject_label = predicted_label

        return NodeScoreResult(
            node_id=node.node_id,
            stage=node.stage,
            target_label=node.target_label,
            predicted_label=predicted_label,
            top_confidence=top_confidence,
            target_confidence=target_confidence,
            ranking=ranking,
            matched_target=matched_target,
            decision=decision,
            reject_label=reject_label,
            parse_status=parse_status,
            effective_threshold=effective_threshold,
            raw_response=response,
            metadata={
                "candidate_labels": list(ctx.candidate_labels),
                "evidence_count": len(ctx.evidence.items) if ctx.evidence else 0,
            },
        )

    def _effective_threshold(self, node: NodeSpec) -> float:
        if node.threshold is not None:
            return node.threshold
        return self.bundle.defaults.default_threshold

    def _scorer_config_value(self, key: str, default: Any) -> Any:
        return self.bundle.defaults.scorer_config.get(key, default)

    def _prompt_code_snippet(self, code: str) -> str:
        limit = self._scorer_config_value(
            "prompt_code_max_chars",
            self.DEFAULT_PROMPT_CODE_MAX_CHARS,
        )
        if limit is None:
            return code
        try:
            max_chars = int(limit)
        except (TypeError, ValueError):
            self.logger.warning(
                "Invalid prompt_code_max_chars configuration: %r. Falling back to default %d",
                limit, self.DEFAULT_PROMPT_CODE_MAX_CHARS
            )
            return code[: self.DEFAULT_PROMPT_CODE_MAX_CHARS]
        if max_chars <= 0:
            return code
        return code[:max_chars]

    def _render_prompt(self, node: NodeSpec, ctx: ScorerContext) -> str:
        evidence_text = self._render_evidence(node, ctx.evidence)
        query_text = self._render_query(node, ctx)
        parent_label = ctx.parent_result.target_label if ctx.parent_result else ""
        candidates = ", ".join(ctx.candidate_labels)
        prompt_code = self._prompt_code_snippet(ctx.code)
        return safe_format(
            node.instruction_template,
            code=prompt_code,
            input=prompt_code,
            evidence=evidence_text,
            candidates=candidates,
            query=query_text,
            target_label=node.target_label,
            parent_label=parent_label,
        )

    def _render_query(self, node: NodeSpec, ctx: ScorerContext) -> str:
        template = (
            node.query_template
            or self.bundle.defaults.default_query_templates.get(node.stage)
        )
        if not template:
            return ctx.code
        return safe_format(
            template,
            code=ctx.code,
            input=ctx.code,
            target_label=node.target_label,
            parent_label=(ctx.parent_result.target_label if ctx.parent_result else ""),
        )

    def _render_evidence(
        self,
        node: NodeSpec,
        evidence: EvidenceBundle | None,
    ) -> str:
        if evidence is None or not evidence.items:
            return "No evidence available."

        lines = []
        for item in evidence.items:
            title = (
                f"{item.kind.upper()}: {item.title}"
                if item.title
                else item.kind.upper()
            )
            lines.append(f"{title}\n{item.text}")
        evidence_text = "\n\n".join(lines)

        template = (
            node.evidence_template
            or self.bundle.defaults.default_evidence_templates.get(node.stage)
        )
        if not template:
            return evidence_text
        return safe_format(
            template,
            evidence=evidence_text,
            evidence_items=evidence_text,
        )

    def _parse_ranking(
        self,
        response: str,
        candidate_labels: list[str],
    ) -> tuple[list[tuple[str, float]], ParseStatus]:
        ranking = self._parse_json_ranking(response, candidate_labels)
        if ranking:
            return ranking, "ok"

        ranking = self._parse_fallback_ranking(response, candidate_labels)
        if ranking:
            return ranking, "fallback"

        return [], "error"

    def _parse_json_ranking(
        self,
        response: str,
        candidate_labels: list[str],
    ) -> list[tuple[str, float]]:
        json_blob = self._extract_json_blob(response)
        if json_blob is None:
            return []

        try:
            data = json.loads(json_blob)
        except json.JSONDecodeError:
            return []

        if isinstance(data, list):
            predictions = data
        else:
            predictions = data.get("predictions", [])
        if isinstance(predictions, Mapping):
            predictions = [predictions]
        if not isinstance(predictions, list):
            return []

        scores_by_label: dict[str, float] = {}
        allowed = set(candidate_labels)
        for item in predictions:
            if not isinstance(item, dict):
                continue
            label = item.get("category") or item.get("cwe") or item.get("label")
            if not isinstance(label, str) or label not in allowed:
                continue
            try:
                confidence = float(item.get("confidence", 0.0))
            except (TypeError, ValueError):
                continue
            scores_by_label[label] = max(scores_by_label.get(label, 0.0), confidence)

        return sorted(scores_by_label.items(), key=lambda pair: pair[1], reverse=True)

    def _extract_json_blob(self, response: str) -> str | None:
        stripped = response.strip()
        if stripped.startswith("{") or stripped.startswith("["):
            return stripped

        for pattern in (r"\[[\s\S]*\]", r"\{[\s\S]*\}"):
            match = re.search(pattern, response)
            if match:
                return match.group()
        return None

    def _parse_fallback_ranking(
        self,
        response: str,
        candidate_labels: list[str],
    ) -> list[tuple[str, float]]:
        results: list[tuple[str, float]] = []
        response_lower = response.lower()

        for candidate in candidate_labels:
            candidate_lower = candidate.lower()
            if candidate_lower not in response_lower:
                continue
            position = response_lower.find(candidate_lower)
            confidence = 1.0 - (position / max(len(response_lower), 1))
            results.append((candidate, min(confidence, 0.9)))

        results.sort(key=lambda pair: pair[1], reverse=True)
        return results
