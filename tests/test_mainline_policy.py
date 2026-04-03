from mulvul.mainline.artifacts import PromptArtifact
from mulvul.mainline.bundle import EvidenceBundle, NodeScoreResult, PromptBundleAdapter
from mulvul.mainline.policy import GreedyCascadePolicy


class CountingEvidenceProvider:
    def __init__(self):
        self.calls = 0

    def retrieve(self, bundle, node, ctx):
        self.calls += 1
        return EvidenceBundle(items=[])


class RecordingScorer:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def score(self, node, ctx):
        self.calls.append((node.node_id, list(ctx.candidate_labels), ctx.parent_result))
        return self.responses[node.node_id]


def _make_bundle():
    artifact = PromptArtifact.from_mapping(
        {
            "prompts": {
                "major_Memory": "major-memory",
                "major_Injection": "major-injection",
                "middle_Buffer Errors": "middle-buffer",
                "cwe_CWE-120": "cwe-120",
            }
        }
    )
    return PromptBundleAdapter.from_artifact(artifact, allow_partial=True)


def _result(node_id, stage, target, decision, target_confidence, predicted=None):
    predicted_label = predicted or target
    top_confidence = (
        target_confidence if predicted_label == target else max(target_confidence, 0.8)
    )
    ranking = [(predicted_label, top_confidence)]
    if predicted_label != target:
        ranking.append((target, target_confidence))
    return NodeScoreResult(
        node_id=node_id,
        stage=stage,
        target_label=target,
        predicted_label=predicted_label,
        top_confidence=top_confidence,
        target_confidence=target_confidence,
        ranking=ranking,
        matched_target=predicted_label == target,
        decision=decision,
        reject_label=(predicted_label if decision == "reject" else None),
        parse_status="ok",
        effective_threshold=0.5,
        raw_response="stub",
    )


def test_greedy_policy_matches_major_middle_cwe_behavior():
    bundle = _make_bundle()
    memory_id = bundle.taxonomy.node_id_for_label("major", "Memory")
    injection_id = bundle.taxonomy.node_id_for_label("major", "Injection")
    buffer_id = bundle.taxonomy.node_id_for_label("middle", "Buffer Errors")
    cwe_id = bundle.taxonomy.node_id_for_label("cwe", "CWE-120")
    provider = CountingEvidenceProvider()
    scorer = RecordingScorer(
        {
            memory_id: _result(memory_id, "major", "Memory", "accept", 0.91),
            injection_id: _result(
                injection_id,
                "major",
                "Injection",
                "reject",
                0.10,
                predicted="Benign",
            ),
            buffer_id: _result(
                buffer_id,
                "middle",
                "Buffer Errors",
                "accept",
                0.84,
            ),
            cwe_id: _result(cwe_id, "cwe", "CWE-120", "accept", 0.88),
        }
    )
    policy = GreedyCascadePolicy(evidence_provider=provider)

    result = policy.run(bundle, scorer, "strcpy(buf, input);")

    assert result.prediction == "CWE-120"
    assert result.best_path is not None
    assert result.best_path.final_label == "CWE-120"
    assert result.nodes_scored == 4
    assert result.nodes_skipped == 0
    assert provider.calls == 4
    assert all(labels.count("Benign") == 1 for _, labels, _ in scorer.calls)


def test_greedy_policy_stops_descendants_after_middle_rejection():
    bundle = _make_bundle()
    memory_id = bundle.taxonomy.node_id_for_label("major", "Memory")
    injection_id = bundle.taxonomy.node_id_for_label("major", "Injection")
    buffer_id = bundle.taxonomy.node_id_for_label("middle", "Buffer Errors")
    cwe_id = bundle.taxonomy.node_id_for_label("cwe", "CWE-120")
    provider = CountingEvidenceProvider()
    scorer = RecordingScorer(
        {
            memory_id: _result(memory_id, "major", "Memory", "accept", 0.91),
            injection_id: _result(
                injection_id,
                "major",
                "Injection",
                "reject",
                0.10,
                predicted="Benign",
            ),
            buffer_id: _result(
                buffer_id,
                "middle",
                "Buffer Errors",
                "abstain",
                0.40,
            ),
            cwe_id: _result(cwe_id, "cwe", "CWE-120", "accept", 0.88),
        }
    )
    policy = GreedyCascadePolicy(evidence_provider=provider)

    result = policy.run(bundle, scorer, "strcpy(buf, input);")

    assert result.prediction == "Memory"
    assert result.best_path is not None
    assert result.best_path.final_label == "Memory"
    assert result.nodes_scored == 3
    assert result.nodes_skipped == 1
    assert provider.calls == 3
    assert "cwe" in result.stage_results
    assert result.stage_results["cwe"] == []
