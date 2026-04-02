"""Tests for PromptContract validator and BaselineManager."""
from __future__ import annotations

import pytest

from evoprompt.prompts.contract import (
    PromptContract,
    PromptContractValidator,
)
from evoprompt.core.baseline import (
    BaselineConfig,
    BaselineManager,
    BaselineSnapshot,
)


class TestPromptContractValidation:
    """Tests for PromptContract and PromptContractValidator."""

    def test_valid_prompt_with_input_placeholder_passes(self):
        prompt = (
            "Analyze this code for vulnerabilities:\n"
            "{input}\n"
            "Respond with vulnerable or benign."
        )
        result = PromptContractValidator.validate(prompt)
        assert result.is_valid
        assert result.has_placeholder

    def test_valid_prompt_with_code_placeholder_passes(self):
        prompt = (
            "Check for bugs:\n"
            "{CODE}\n"
            "Respond with CONFIDENCE: <score>"
        )
        result = PromptContractValidator.validate(prompt)
        assert result.is_valid
        assert result.has_placeholder

    def test_valid_prompt_with_double_brace_code_placeholder_passes(self):
        prompt = (
            "Check for bugs:\n"
            "{{CODE}}\n"
            "Respond with CONFIDENCE: <score>"
        )
        result = PromptContractValidator.validate(prompt)
        assert result.is_valid
        assert result.has_placeholder

    def test_missing_placeholder_fails_validation(self):
        prompt = (
            "Analyze this code for vulnerabilities. "
            "Respond with vulnerable or benign."
        )
        result = PromptContractValidator.validate(prompt)
        assert not result.is_valid
        assert not result.has_placeholder
        assert any(
            "placeholder" in e.lower() for e in result.errors
        )

    def test_output_constraint_detected(self):
        prompt = (
            "Analyze code:\n{input}\n"
            "Respond with vulnerable or benign."
        )
        result = PromptContractValidator.validate(prompt)
        assert result.has_output_constraint

    def test_output_constraint_confidence_format(self):
        prompt = "Analyze code:\n{input}\nCONFIDENCE: <score>"
        result = PromptContractValidator.validate(prompt)
        assert result.has_output_constraint

    def test_missing_output_constraint_warns(self):
        prompt = (
            "Analyze this code for vulnerabilities.\n{input}"
        )
        result = PromptContractValidator.validate(prompt)
        assert result.is_valid  # still valid, just a warning
        assert not result.has_output_constraint
        assert len(result.warnings) > 0

    def test_trainable_boundary_detection_guidance(self):
        prompt = (
            "Fixed part\n"
            "### ANALYSIS GUIDANCE START\n"
            "Trainable part\n"
            "### ANALYSIS GUIDANCE END\n"
            "More fixed\n{input}"
        )
        result = PromptContractValidator.validate(prompt)
        assert result.has_trainable_boundaries

    def test_trainable_boundary_detection_trainable_markers(self):
        prompt = (
            "Fixed part\n"
            "{{TRAINABLE_START}}\n"
            "Trainable part\n"
            "{{TRAINABLE_END}}\n"
            "More fixed\n{input}"
        )
        result = PromptContractValidator.validate(prompt)
        assert result.has_trainable_boundaries

    def test_no_trainable_boundaries(self):
        prompt = (
            "Just a prompt with {input} "
            "and Respond with answer."
        )
        result = PromptContractValidator.validate(prompt)
        assert not result.has_trainable_boundaries

    def test_extract_trainable_section_guidance_markers(self):
        prompt = (
            "Fixed\n"
            "### ANALYSIS GUIDANCE START\n"
            "Trainable content here\n"
            "### ANALYSIS GUIDANCE END\n"
            "Fixed\n{input}"
        )
        sections = (
            PromptContractValidator.extract_trainable_sections(
                prompt
            )
        )
        assert len(sections) == 1
        assert "Trainable content here" in sections[0]

    def test_extract_trainable_section_trainable_markers(self):
        prompt = (
            "Fixed\n"
            "{{TRAINABLE_START}}\n"
            "Evolvable content\n"
            "{{TRAINABLE_END}}\n"
            "Fixed\n{input}"
        )
        sections = (
            PromptContractValidator.extract_trainable_sections(
                prompt
            )
        )
        assert len(sections) == 1
        assert "Evolvable content" in sections[0]

    def test_extract_trainable_section_none(self):
        prompt = "No trainable boundaries here {input}"
        sections = (
            PromptContractValidator.extract_trainable_sections(
                prompt
            )
        )
        assert len(sections) == 0

    def test_custom_contract(self):
        contract = PromptContract(
            required_placeholders=["{input}", "{context}"],
        )
        validator = PromptContractValidator(contract)
        result = validator.validate(
            "Use {input} with {context}"
        )
        assert result.is_valid

    def test_custom_contract_missing_placeholder(self):
        contract = PromptContract(
            required_placeholders=["{input}", "{context}"],
        )
        validator = PromptContractValidator(contract)
        result = validator.validate("Use {input} only")
        assert not result.is_valid

    def test_all_seed_prompts_pass_contract(self):
        """Validate all prompts from seed_prompts.py."""
        from evoprompt.prompts.seed_prompts import (
            LAYER1_SEED_PROMPTS,
            LAYER2_SEED_PROMPTS,
            LAYER3_SEED_PROMPTS,
        )

        for category, prompts in LAYER1_SEED_PROMPTS.items():
            for i, prompt in enumerate(prompts):
                result = PromptContractValidator.validate(
                    prompt
                )
                assert result.has_placeholder, (
                    f"L1 {category}[{i}] missing placeholder"
                )

        for major, middles in LAYER2_SEED_PROMPTS.items():
            for middle, prompts in middles.items():
                for i, prompt in enumerate(prompts):
                    result = PromptContractValidator.validate(
                        prompt
                    )
                    assert result.has_placeholder, (
                        f"L2 {major}/{middle}[{i}] "
                        "missing placeholder"
                    )

        for middle, cwes in LAYER3_SEED_PROMPTS.items():
            for cwe, prompts in cwes.items():
                for i, prompt in enumerate(prompts):
                    result = PromptContractValidator.validate(
                        prompt
                    )
                    assert result.has_placeholder, (
                        f"L3 {middle}/{cwe}[{i}] "
                        "missing placeholder"
                    )

    def test_all_hierarchical_prompts_pass_contract(self):
        """Validate HierarchicalPromptSet prompts."""
        from evoprompt.detectors.parallel_hierarchical_detector import (  # noqa: E501
            HierarchicalPromptSet,
        )
        from evoprompt.prompts.hierarchical_three_layer import (
            ThreeLayerPromptFactory,
        )

        three_layer = (
            ThreeLayerPromptFactory.create_default_prompt_set()
        )
        h_set = HierarchicalPromptSet.from_three_layer_set(
            three_layer
        )

        for cat, prompt in h_set.layer1_prompts.items():
            result = PromptContractValidator.validate(prompt)
            assert result.has_placeholder, (
                f"Hierarchical L1 {cat} missing placeholder"
            )


class TestBaselineManager:
    """Tests for BaselineManager."""

    def test_baseline_config_defaults(self):
        config = BaselineConfig()
        assert config.sample_count == 50
        assert config.seed == 42
        assert config.dataset_split == "dev"

    def test_baseline_snapshot_creation(self):
        snapshot = BaselineSnapshot(
            prompt_text="Test prompt {input}",
            prompt_hash="abc123",
            metrics={"accuracy": 0.85, "f1": 0.80},
            sample_ids=["s1", "s2"],
            predictions=["1", "0"],
            ground_truths=["1", "1"],
        )
        assert snapshot.prompt_text == "Test prompt {input}"
        assert snapshot.metrics["accuracy"] == 0.85
        assert len(snapshot.sample_ids) == 2

    def test_baseline_snapshot_serialization(self):
        snapshot = BaselineSnapshot(
            prompt_text="Test prompt {input}",
            prompt_hash="abc123",
            metrics={"accuracy": 0.85},
            sample_ids=["s1"],
            predictions=["1"],
            ground_truths=["1"],
        )
        d = snapshot.to_dict()
        restored = BaselineSnapshot.from_dict(d)
        assert restored.prompt_text == snapshot.prompt_text
        assert restored.prompt_hash == snapshot.prompt_hash
        assert restored.metrics == snapshot.metrics

    def test_baseline_snapshot_json_roundtrip(self, tmp_path):
        snapshot = BaselineSnapshot(
            prompt_text="Test {input}",
            prompt_hash="xyz",
            metrics={"f1": 0.9},
            sample_ids=["a", "b"],
            predictions=["0", "1"],
            ground_truths=["0", "1"],
        )
        path = tmp_path / "baseline.json"
        snapshot.save(path)
        loaded = BaselineSnapshot.load(path)
        assert loaded.prompt_text == snapshot.prompt_text
        assert loaded.metrics == snapshot.metrics

    def test_baseline_comparison_detects_regression(self):
        baseline = BaselineSnapshot(
            prompt_text="old",
            prompt_hash="h1",
            metrics={"accuracy": 0.90, "f1": 0.85},
            sample_ids=[],
            predictions=[],
            ground_truths=[],
        )
        current = BaselineSnapshot(
            prompt_text="new",
            prompt_hash="h2",
            metrics={"accuracy": 0.80, "f1": 0.75},
            sample_ids=[],
            predictions=[],
            ground_truths=[],
        )
        result = BaselineManager.compare(current, baseline)
        assert result.has_regression
        assert result.metric_deltas["accuracy"] == pytest.approx(
            -0.10
        )

    def test_baseline_comparison_detects_improvement(self):
        baseline = BaselineSnapshot(
            prompt_text="old",
            prompt_hash="h1",
            metrics={"accuracy": 0.80},
            sample_ids=[],
            predictions=[],
            ground_truths=[],
        )
        current = BaselineSnapshot(
            prompt_text="new",
            prompt_hash="h2",
            metrics={"accuracy": 0.90},
            sample_ids=[],
            predictions=[],
            ground_truths=[],
        )
        result = BaselineManager.compare(current, baseline)
        assert not result.has_regression
        assert result.metric_deltas["accuracy"] == pytest.approx(
            0.10
        )

    def test_baseline_comparison_with_threshold(self):
        baseline = BaselineSnapshot(
            prompt_text="old",
            prompt_hash="h1",
            metrics={"accuracy": 0.85},
            sample_ids=[],
            predictions=[],
            ground_truths=[],
        )
        current = BaselineSnapshot(
            prompt_text="new",
            prompt_hash="h2",
            metrics={"accuracy": 0.84},  # only 0.01 drop
            sample_ids=[],
            predictions=[],
            ground_truths=[],
        )
        # Small drops within threshold are non-regression
        result = BaselineManager.compare(
            current, baseline, regression_threshold=0.05
        )
        assert not result.has_regression
