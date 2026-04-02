from mulvul.mainline.artifacts import PromptArtifact
from mulvul.mainline.bundle import PromptBundleAdapter
from mulvul.mainline.evaluator import EvaluationSample, MainlineEvaluator
from mulvul.mainline.policy import DetectionPath, InferenceResult
from mulvul.mainline.bundle import NodeScoreResult


class DummyScorer:
    def score(self, node, ctx):
        raise AssertionError("Evaluator test should use policy outputs, not scorer calls")


class DummyPolicy:
    def __init__(self, results):
        self.results = results
        self.major_top_k = 1
        self.middle_top_k = 1

    def run(self, bundle, scorer, code):
        return self.results[code]


def _node_result(node_id, target, decision, confidence, predicted=None):
    predicted_label = predicted or target
    top_confidence = confidence if predicted_label == target else max(confidence, 0.8)
    ranking = [(predicted_label, top_confidence)]
    if predicted_label != target:
        ranking.append((target, confidence))
    return NodeScoreResult(
        node_id=node_id,
        stage="major",
        target_label=target,
        predicted_label=predicted_label,
        top_confidence=top_confidence,
        target_confidence=confidence,
        ranking=ranking,
        matched_target=predicted_label == target,
        decision=decision,
        reject_label=(predicted_label if decision == "reject" else None),
        parse_status="ok",
        effective_threshold=0.5,
        raw_response="stub",
    )


def test_mainline_evaluator_aggregates_policy_outputs():
    artifact = PromptArtifact.from_mapping({"prompts": {"major_Memory": "major-memory"}})
    bundle = PromptBundleAdapter.from_artifact(artifact, allow_partial=True)
    memory_accept = _node_result("major_Memory", "Memory", "accept", 0.91)
    memory_reject = _node_result("major_Memory", "Memory", "reject", 0.10, predicted="Benign")

    evaluator = MainlineEvaluator()
    policy = DummyPolicy(
        {
            "vuln": InferenceResult(
                prediction="Memory",
                best_path=DetectionPath(
                    node_ids=["major_Memory"],
                    stage_results=[memory_accept],
                    final_label="Memory",
                    score=0.91,
                ),
                candidate_paths=[
                    DetectionPath(
                        node_ids=["major_Memory"],
                        stage_results=[memory_accept],
                        final_label="Memory",
                        score=0.91,
                    )
                ],
                stage_results={"major": [memory_accept], "middle": [], "cwe": []},
                nodes_scored=1,
                nodes_skipped=0,
            ),
            "benign": InferenceResult(
                prediction="Benign",
                best_path=None,
                candidate_paths=[],
                stage_results={"major": [memory_reject], "middle": [], "cwe": []},
                nodes_scored=1,
                nodes_skipped=0,
            ),
        }
    )

    result = evaluator.evaluate(
        bundle,
        DummyScorer(),
        policy,
        [
            EvaluationSample(
                sample_id="1",
                code="vuln",
                major_label="Memory",
                middle_label=None,
                cwe_label=None,
                final_label="Memory",
            ),
            EvaluationSample(
                sample_id="2",
                code="benign",
                major_label=None,
                middle_label=None,
                cwe_label=None,
                final_label="Benign",
            ),
        ],
    )

    assert result.end_to_end_metrics["final_exact_match"] == 1.0
    assert result.end_to_end_metrics["major_accuracy"] == 1.0
    assert result.cost_metrics["avg_nodes_scored_per_sample"] == 1.0
    assert result.node_metrics["major_Memory"].tp == 1
    assert result.node_metrics["major_Memory"].tn == 1
