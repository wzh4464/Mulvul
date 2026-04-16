from __future__ import annotations

import pytest

from mulvul.mainline.bundle import (
    BundleDefaults,
    NodeSpec,
    PromptBundle,
    ScorerContext,
    TaxonomyGraph,
    TaxonomyNode,
)
from mulvul.mainline.scorer import LLMNodeScorer


class _FakeClient:
    def __init__(self, response: str):
        self.response = response

    def generate(self, prompt: str) -> str:
        return self.response


def _build_bundle(*, scorer_config: dict | None = None) -> PromptBundle:
    taxonomy = TaxonomyGraph(
        version="test",
        stage_order=("major", "middle", "cwe"),
        benign_label="Benign",
        nodes={
            "middle_buffer": TaxonomyNode(
                node_id="middle_buffer",
                stage="middle",
                label="Buffer Errors",
                display_name="Buffer Errors",
                parent_id="major_memory",
            ),
            "cwd_1016": TaxonomyNode(
                node_id="cwd_1016",
                stage="cwe",
                label="CWD-1016",
                display_name="CWD-1016",
                parent_id="middle_buffer",
            ),
            "cwd_1015": TaxonomyNode(
                node_id="cwd_1015",
                stage="cwe",
                label="CWD-1015",
                display_name="CWD-1015",
                parent_id="middle_buffer",
            ),
        },
    )
    nodes = {
        "cwd_1016": NodeSpec(
            node_id="cwd_1016",
            stage="cwe",
            target_label="CWD-1016",
            instruction_template="{code}",
            threshold=0.5,
        ),
        "cwd_1015": NodeSpec(
            node_id="cwd_1015",
            stage="cwe",
            target_label="CWD-1015",
            instruction_template="{code}",
            threshold=0.5,
        ),
    }
    return PromptBundle(
        schema_version="2",
        taxonomy=taxonomy,
        nodes=nodes,
        defaults=BundleDefaults(
            default_threshold=0.5,
            distrust_fallback=False,
            scorer_config=scorer_config or {},
        ),
        training_metadata={},
        data_fingerprint="test",
        code_revision="test",
    )


def _ctx() -> ScorerContext:
    parent = type(
        "ParentResult",
        (),
        {"target_label": "Buffer Errors"},
    )()
    return ScorerContext(
        code="memcpy(dst, src, n);",
        candidate_labels=["CWD-1016", "CWD-1015", "Benign"],
        parent_result=parent,
    )


def test_scorer_abstains_when_target_margin_is_below_stage_requirement() -> None:
    bundle = _build_bundle(
        scorer_config={"stage_margin_thresholds": {"cwe": 0.1}},
    )
    scorer = LLMNodeScorer(
        _FakeClient(
            '{"predictions": ['
            '{"cwe": "CWD-1016", "confidence": 0.62},'
            '{"cwe": "CWD-1015", "confidence": 0.57},'
            '{"cwe": "Benign", "confidence": 0.10}'
            "]}",
        ),
        bundle,
    )

    result = scorer.score(bundle.nodes["cwd_1016"], _ctx())

    assert result.predicted_label == "CWD-1016"
    assert result.decision == "abstain"
    assert result.metadata["top_margin"] == pytest.approx(0.05)
    assert result.metadata["required_margin"] == 0.1


def test_scorer_accepts_when_target_margin_clears_stage_requirement() -> None:
    bundle = _build_bundle(
        scorer_config={"stage_margin_thresholds": {"cwe": 0.1}},
    )
    scorer = LLMNodeScorer(
        _FakeClient(
            '{"predictions": ['
            '{"cwe": "CWD-1016", "confidence": 0.72},'
            '{"cwe": "CWD-1015", "confidence": 0.50},'
            '{"cwe": "Benign", "confidence": 0.20}'
            "]}",
        ),
        bundle,
    )

    result = scorer.score(bundle.nodes["cwd_1016"], _ctx())

    assert result.decision == "accept"
    assert result.metadata["top_margin"] == pytest.approx(0.22)


def test_fallback_leaf_quarantine_raises_threshold_and_margin() -> None:
    bundle = _build_bundle(
        scorer_config={
            "stage_margin_thresholds": {"cwe": 0.05},
            "fallback_leaf_extra_threshold": 0.2,
            "fallback_leaf_extra_margin": 0.2,
        },
    )
    bundle.nodes["cwd_1016"].metadata["fallback_leaf_quarantine"] = True
    scorer = LLMNodeScorer(
        _FakeClient(
            '{"predictions": ['
            '{"cwe": "CWD-1016", "confidence": 0.64},'
            '{"cwe": "CWD-1015", "confidence": 0.48},'
            '{"cwe": "Benign", "confidence": 0.20}'
            "]}",
        ),
        bundle,
    )

    result = scorer.score(bundle.nodes["cwd_1016"], _ctx())

    assert result.decision == "abstain"
    assert result.effective_threshold == 0.7
    assert result.metadata["required_margin"] == 0.25
