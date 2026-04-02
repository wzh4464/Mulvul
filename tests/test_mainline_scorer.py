from mulvul.mainline.artifacts import PromptArtifact
from mulvul.mainline.bundle import PromptBundleAdapter, ScorerContext
from mulvul.mainline.scorer import LLMNodeScorer


class StubLLMClient:
    def __init__(self, response: str):
        self.response = response

    def generate(self, prompt: str, **kwargs) -> str:
        return self.response


def _make_bundle(*, distrust_fallback: bool = True):
    artifact = PromptArtifact.from_mapping(
        {
            "prompts": {
                "major_Memory": (
                    "Analyze code.\nEvidence: {evidence}\nCode:\n{code}\n"
                    "Candidates: {candidates}"
                )
            }
        }
    )
    bundle = PromptBundleAdapter.from_artifact(artifact, allow_partial=True)
    bundle.defaults.distrust_fallback = distrust_fallback
    return bundle


def _make_ctx(bundle):
    node = bundle.nodes["major_Memory"]
    candidate_labels = bundle.taxonomy.decision_labels_for(node.node_id) + [
        bundle.taxonomy.benign_label
    ]
    return node, ScorerContext(code="strcpy(buf, input);", candidate_labels=candidate_labels)


def test_llm_node_scorer_json_accept_path():
    bundle = _make_bundle()
    node, ctx = _make_ctx(bundle)
    scorer = LLMNodeScorer(
        StubLLMClient('{"predictions":[{"category":"Memory","confidence":0.91}]}'),
        bundle,
    )

    result = scorer.score(node, ctx)

    assert result.decision == "accept"
    assert result.predicted_label == "Memory"
    assert result.target_confidence == 0.91


def test_llm_node_scorer_json_reject_path():
    bundle = _make_bundle()
    node, ctx = _make_ctx(bundle)
    scorer = LLMNodeScorer(
        StubLLMClient(
            '{"predictions":['
            '{"category":"Benign","confidence":0.91},'
            '{"category":"Memory","confidence":0.60}'
            "]} "
        ),
        bundle,
    )

    result = scorer.score(node, ctx)

    assert result.decision == "reject"
    assert result.reject_label == "Benign"
    assert result.target_confidence == 0.60


def test_llm_node_scorer_fallback_distrusted_maps_to_abstain():
    bundle = _make_bundle(distrust_fallback=True)
    node, ctx = _make_ctx(bundle)
    scorer = LLMNodeScorer(StubLLMClient("The best label is Memory."), bundle)

    result = scorer.score(node, ctx)

    assert result.parse_status == "fallback"
    assert result.decision == "abstain"
    assert result.predicted_label == "Memory"


def test_llm_node_scorer_fallback_can_accept_when_trusted():
    bundle = _make_bundle(distrust_fallback=False)
    node, ctx = _make_ctx(bundle)
    scorer = LLMNodeScorer(StubLLMClient("Memory is the best label."), bundle)

    result = scorer.score(node, ctx)

    assert result.parse_status == "fallback"
    assert result.decision == "accept"
    assert result.predicted_label == "Memory"


def test_llm_node_scorer_total_parse_failure_maps_to_error():
    bundle = _make_bundle()
    node, ctx = _make_ctx(bundle)
    scorer = LLMNodeScorer(StubLLMClient("no parseable ranking here"), bundle)

    result = scorer.score(node, ctx)

    assert result.decision == "error"
    assert result.predicted_label is None


def test_llm_node_scorer_filters_labels_to_candidate_space():
    bundle = _make_bundle()
    node, ctx = _make_ctx(bundle)
    scorer = LLMNodeScorer(
        StubLLMClient(
            '{"predictions":['
            '{"category":"MadeUp","confidence":0.99},'
            '{"category":"Memory","confidence":0.91}'
            "]} "
        ),
        bundle,
    )

    result = scorer.score(node, ctx)

    assert result.ranking == [("Memory", 0.91)]
    assert result.decision == "accept"
