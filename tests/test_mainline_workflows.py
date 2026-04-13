import json

import pytest

from mulvul.data.cwe_hierarchy import MAJOR_TO_MIDDLE, MIDDLE_TO_CWE
from mulvul.mainline.artifacts import PromptArtifact
from mulvul.mainline.bundle import PromptBundleIO
from mulvul.mainline.workflows import (
    EvaluationWorkflowConfig,
    EvolutionWorkflowConfig,
    MAX_SUMMARY_RECORDS,
    load_jsonl,
    run_evaluation_workflow,
    run_evolution_workflow,
)


class StubLLMClient:
    model_name = "unit-test-model"
    api_base = "https://unit.test/v1"


class FakeTrainer:
    def __init__(self, llm_client, sampler, retriever, output_dir):
        self.best_prompts = {
            f"major_{major}": f"Judge {major}: {{code}}" for major in MAJOR_TO_MIDDLE
        }
        for middle in MIDDLE_TO_CWE:
            self.best_prompts[f"middle_{middle}"] = f"Judge {middle}: {{code}}"
            for cwe in MIDDLE_TO_CWE[middle]:
                self.best_prompts[f"cwe_{cwe}"] = f"Judge {cwe}: {{code}}"
        self.best_scores = {prompt_key: 0.9 for prompt_key in self.best_prompts}

    def train_all_levels(
        self,
        n_rounds,
        n_samples_per_class,
        population_size=5,
        tournament_k=3,
        migration_rate=0.2,
        max_workers=8,
        phase1_only=False,
        elitism_threshold=0.5,
        constrained_mutation=True,
    ):
        # Store parameters for testing
        self.last_call_params = {
            'elitism_threshold': elitism_threshold,
            'constrained_mutation': constrained_mutation,
        }
        return None

    def save_best_prompts(self):
        return None


class FakeDetectionResult:
    def __init__(self, *, prediction, major, middle, cwe):
        self.prediction = prediction
        self.major = major
        self.middle = middle
        self.cwe = cwe
        self.score = 0.9

    @property
    def is_vulnerable(self):
        return self.prediction != "Benign"

    def to_dict(self):
        return {
            "prediction": self.prediction,
            "major": self.major,
            "middle": self.middle,
            "cwe": self.cwe,
            "score": self.score,
            "stage_scores": {},
            "candidate_paths": [],
        }


class GreedyCascadePolicy:
    pass


class FakeSystem:
    def __init__(self, llm_client, artifact, ablations=None, retriever=None):
        self.bundle = artifact
        self.policy = GreedyCascadePolicy()

    def detect(self, code):
        if "strcpy" in code:
            return FakeDetectionResult(
                prediction="CWE-120",
                major="Memory",
                middle="Buffer Errors",
                cwe="CWE-120",
            )
        return FakeDetectionResult(
            prediction="Benign",
            major="Benign",
            middle=None,
            cwe=None,
        )


def _write_jsonl(path, records):
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record) + "\n")


def test_load_jsonl_fails_fast_on_invalid_json(temp_dir):
    dataset_path = temp_dir / "broken.jsonl"
    dataset_path.write_text(
        '{"func":"ok","target":0,"cwe":[]}\nnot-json\n', encoding="utf-8"
    )

    with pytest.raises(ValueError, match=r"Invalid JSON .* line 2"):
        load_jsonl(str(dataset_path))


def test_load_jsonl_fails_fast_on_missing_required_fields(temp_dir):
    dataset_path = temp_dir / "missing-fields.jsonl"
    _write_jsonl(dataset_path, [{"func": "strcpy(buf, src);", "target": 1}])

    with pytest.raises(ValueError, match=r"missing required fields cwe"):
        load_jsonl(str(dataset_path))


def test_run_evolution_workflow_emits_reproducibility_metadata(temp_dir, monkeypatch):
    train_file = temp_dir / "train.jsonl"
    _write_jsonl(
        train_file,
        [
            {"func": "int add(int a, int b) { return a + b; }", "target": 0, "cwe": []},
            {"func": "strcpy(buf, src);", "target": 1, "cwe": ["CWE-120"]},
        ],
    )

    monkeypatch.setattr("mulvul.mainline.workflows.load_env_vars", lambda: None)
    monkeypatch.setattr(
        "mulvul.mainline.workflows.create_llm_client",
        lambda llm_type=None: StubLLMClient(),
    )
    monkeypatch.setattr(
        "mulvul.mainline.workflows.HierarchicalSampler",
        lambda path: object(),
    )
    # Capture trainer instance for parameter verification
    trainer_instances = []
    original_fake_trainer = FakeTrainer

    def fake_trainer_factory(*args, **kwargs):
        trainer = original_fake_trainer(*args, **kwargs)
        trainer_instances.append(trainer)
        return trainer

    monkeypatch.setattr("mulvul.mainline.workflows.CoevolutionaryTrainer", fake_trainer_factory)

    summary = run_evolution_workflow(
        EvolutionWorkflowConfig(
            train_file=str(train_file),
            output_dir=str(temp_dir / "evolution"),
        )
    )

    # Assert that EvolutionWorkflowConfig passes elitism_threshold and constrained_mutation through to trainer
    assert len(trainer_instances) > 0, "Expected at least one trainer instance"
    trainer = trainer_instances[0]
    assert hasattr(trainer, 'last_call_params'), "Trainer should have recorded call parameters"
    assert trainer.last_call_params['elitism_threshold'] == 0.5, "Default elitism_threshold should be passed"
    assert trainer.last_call_params['constrained_mutation'] is True, "Default constrained_mutation should be passed"

    bundle = PromptBundleIO.load(summary["prompt_bundle"], load_mode="strict_v2")
    memory_id = bundle.taxonomy.node_id_for_label("major", "Memory")
    buffer_id = bundle.taxonomy.node_id_for_label("middle", "Buffer Errors")

    assert summary["runtime_prompt_format"] == "v2_bundle"
    assert summary["policy_class"] == "GreedyCascadePolicy"
    assert summary["model_name"] == "unit-test-model"
    assert summary["endpoint_kind"] == "openai_compatible"
    assert len(summary["dataset_hash"]) == 64
    assert len(summary["prompt_artifact_hash"]) == 64
    assert len(summary["prompt_bundle_hash"]) == 64
    assert summary["active_ablations"] == []
    assert bundle.data_fingerprint == summary["dataset_hash"]
    assert bundle.code_revision == summary["git_sha"]
    assert memory_id == "major_memory"
    assert buffer_id == "middle_buffer_errors"
    assert bundle.taxonomy.node(memory_id).display_name == "Memory"


def test_run_evaluation_workflow_uses_non_benign_only_middle_and_cwe_counts(
    temp_dir,
    monkeypatch,
):
    eval_file = temp_dir / "eval.jsonl"
    _write_jsonl(
        eval_file,
        [
            {"func": "strcpy(buf, src);", "target": 1, "cwe": ["CWE-120"]},
            {"func": "return a + b;", "target": 0, "cwe": []},
        ],
    )
    prompts_path = temp_dir / "prompt_artifact.json"
    PromptArtifact.from_mapping(
        {
            "prompts": {
                "major_Memory": "major-memory",
                "middle_Buffer Errors": "middle-buffer",
                "cwe_CWE-120": "cwe-120",
            }
        }
    ).save(prompts_path)

    monkeypatch.setattr("mulvul.mainline.workflows.load_env_vars", lambda: None)
    monkeypatch.setattr(
        "mulvul.mainline.workflows.create_llm_client",
        lambda llm_type=None: StubLLMClient(),
    )
    monkeypatch.setattr("mulvul.mainline.workflows.MainlineDetectorSystem", FakeSystem)

    summary = run_evaluation_workflow(
        EvaluationWorkflowConfig(
            eval_file=str(eval_file),
            prompts_path=str(prompts_path),
            output_dir=str(temp_dir / "evaluation"),
        )
    )

    assert summary["prompt_format"] == "v1_artifact"
    assert summary["runtime_prompt_format"] == "v2_bundle"
    assert summary["policy_class"] == "GreedyCascadePolicy"
    assert summary["accuracy"]["major"] == 1.0
    assert summary["accuracy"]["middle"] == 1.0
    assert summary["accuracy"]["cwe"] == 1.0
    assert summary["accuracy"]["binary"] == 1.0
    assert summary["counts"]["middle"]["total"] == 1
    assert summary["counts"]["cwe"]["total"] == 1
    assert summary["records"][1]["ground_truth"]["middle"] is None
    assert summary["records"][1]["prediction"]["middle"] is None
    assert len(summary["prompt_artifact_hash"]) == 64
    assert len(summary["prompt_bundle_hash"]) == 64


@pytest.mark.parametrize("max_samples", [10, 50, 120, None])
def test_run_evaluation_workflow_streams_input_and_caps_records(
    temp_dir,
    monkeypatch,
    max_samples,
):
    eval_file = temp_dir / "streamed.jsonl"
    eval_file.write_text("", encoding="utf-8")
    prompts_path = temp_dir / "prompt_artifact.json"
    PromptArtifact.from_mapping(
        {
            "prompts": {
                "major_Memory": "major-memory",
                "middle_Buffer Errors": "middle-buffer",
                "cwe_CWE-120": "cwe-120",
            }
        }
    ).save(prompts_path)

    monkeypatch.setattr("mulvul.mainline.workflows.load_env_vars", lambda: None)
    monkeypatch.setattr(
        "mulvul.mainline.workflows.create_llm_client",
        lambda llm_type=None: StubLLMClient(),
    )
    monkeypatch.setattr("mulvul.mainline.workflows.MainlineDetectorSystem", FakeSystem)
    monkeypatch.setattr(
        "mulvul.mainline.workflows.load_jsonl",
        lambda path: pytest.fail("run_evaluation_workflow should stream unbalanced input"),
    )
    monkeypatch.setattr(
        "mulvul.mainline.workflows.iter_jsonl",
        lambda path: iter(
            [
                {"func": f"strcpy(buf_{idx}, src);", "target": 1, "cwe": ["CWE-120"]}
                for idx in range(150)
            ]
        ),
    )

    summary = run_evaluation_workflow(
        EvaluationWorkflowConfig(
            eval_file=str(eval_file),
            prompts_path=str(prompts_path),
            output_dir=str(temp_dir / "evaluation"),
            max_samples=max_samples,
        )
    )

    expected_samples = 150 if max_samples is None else max_samples
    assert summary["samples"] == expected_samples
    assert len(summary["records"]) == min(MAX_SUMMARY_RECORDS, expected_samples)
    assert summary["records"][0]["ground_truth"]["cwe"] == "CWE-120"
    assert summary["accuracy"]["major"] == 1.0


def test_run_evolution_workflow_propagates_non_default_elitism_mutation_settings(temp_dir, monkeypatch):
    """Test that non-default elitism_threshold and constrained_mutation settings are propagated to trainer."""
    train_file = temp_dir / "train.jsonl"
    _write_jsonl(
        train_file,
        [
            {"func": "function test() { return 1; }", "target": 0, "cwe": []},
            {"func": "strcpy(buf, src);", "target": 1, "cwe": ["CWE-120"]},
        ],
    )

    monkeypatch.setattr("mulvul.mainline.workflows.load_env_vars", lambda: None)
    monkeypatch.setattr(
        "mulvul.mainline.workflows.create_llm_client",
        lambda llm_type=None: StubLLMClient(),
    )
    monkeypatch.setattr(
        "mulvul.mainline.workflows.HierarchicalSampler",
        lambda path: object(),
    )

    # Capture trainer instance for parameter verification
    trainer_instances = []
    original_fake_trainer = FakeTrainer

    def fake_trainer_factory(*args, **kwargs):
        trainer = original_fake_trainer(*args, **kwargs)
        trainer_instances.append(trainer)
        return trainer

    monkeypatch.setattr("mulvul.mainline.workflows.CoevolutionaryTrainer", fake_trainer_factory)

    summary = run_evolution_workflow(
        EvolutionWorkflowConfig(
            train_file=str(train_file),
            output_dir=str(temp_dir / "evolution"),
            elitism_threshold=0.8,
            constrained_mutation=False,
        )
    )

    # Assert that non-default EvolutionWorkflowConfig values are propagated through to trainer
    assert len(trainer_instances) > 0, "Expected at least one trainer instance"
    trainer = trainer_instances[0]
    assert hasattr(trainer, 'last_call_params'), "Trainer should have recorded call parameters"
    assert trainer.last_call_params['elitism_threshold'] == 0.8, "Custom elitism_threshold should be passed"
    assert trainer.last_call_params['constrained_mutation'] is False, "Custom constrained_mutation should be passed"
