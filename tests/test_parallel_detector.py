"""Tests for parallel hierarchical detector and meta-learning components."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import asyncio

from evoprompt.detectors.scoring import (
    ScoredPrediction,
    DetectionPath,
    SelectionStrategy,
    MaxConfidenceSelection,
    ThresholdSelection,
    create_selection_strategy,
)
from evoprompt.detectors.parallel_hierarchical_detector import (
    ParallelHierarchicalDetector,
    ParallelDetectorConfig,
    HierarchicalPromptSet,
    NoOpEnhancer,
)
from evoprompt.meta.error_accumulator import (
    ClassificationError,
    ErrorPattern,
    ErrorAccumulator,
    ErrorType,
)
from evoprompt.meta.prompt_tuner import (
    TuningResult,
    MetaLearningPromptTuner,
)
from evoprompt.detectors.hierarchical_coordinator import (
    HierarchicalDetectionCoordinator,
    CoordinatorConfig,
    DetectionResult,
)


class TestScoredPrediction:
    """Tests for ScoredPrediction dataclass."""
    
    def test_basic_creation(self):
        pred = ScoredPrediction(
            category="Memory",
            confidence=0.85,
            layer=1
        )
        assert pred.category == "Memory"
        assert pred.confidence == 0.85
        assert pred.layer == 1
        assert pred.parent_category is None
    
    def test_confidence_clamping_high(self):
        pred = ScoredPrediction(category="Test", confidence=1.5, layer=1)
        assert pred.confidence == 1.0
    
    def test_confidence_clamping_low(self):
        pred = ScoredPrediction(category="Test", confidence=-0.5, layer=1)
        assert pred.confidence == 0.0
    
    def test_with_parent_category(self):
        pred = ScoredPrediction(
            category="BufferOverflow",
            confidence=0.7,
            layer=2,
            parent_category="Memory"
        )
        assert pred.parent_category == "Memory"


class TestDetectionPath:
    """Tests for DetectionPath dataclass."""
    
    def test_basic_creation(self):
        path = DetectionPath(
            layer1_category="Memory",
            layer1_confidence=0.9
        )
        assert path.layer1_category == "Memory"
        assert path.layer1_confidence == 0.9
        assert path.layer2_category is None
    
    def test_full_path(self):
        path = DetectionPath(
            layer1_category="Memory",
            layer1_confidence=0.9,
            layer2_category="BufferOverflow",
            layer2_confidence=0.8,
            layer3_cwe="CWE-120",
            layer3_confidence=0.75
        )
        assert path.layer3_cwe == "CWE-120"
    
    def test_compute_aggregated_confidence_equal_weights(self):
        path = DetectionPath(
            layer1_category="Memory",
            layer1_confidence=0.9,
            layer2_category="BufferOverflow",
            layer2_confidence=0.6,
            layer3_cwe="CWE-120",
            layer3_confidence=0.3
        )
        agg = path.compute_aggregated_confidence()
        expected = (0.9 + 0.6 + 0.3) / 3
        assert abs(agg - expected) < 0.001
    
    def test_compute_aggregated_confidence_custom_weights(self):
        path = DetectionPath(
            layer1_category="Memory",
            layer1_confidence=1.0,
            layer2_category="BufferOverflow",
            layer2_confidence=0.5,
        )
        weights = {"layer1": 2.0, "layer2": 1.0, "layer3": 1.0}
        agg = path.compute_aggregated_confidence(weights)
        expected = (2.0 * 1.0 + 1.0 * 0.5) / 3.0
        assert abs(agg - expected) < 0.001
    
    def test_get_final_prediction_cwe(self):
        path = DetectionPath(
            layer1_category="Memory",
            layer1_confidence=0.9,
            layer2_category="BufferOverflow",
            layer2_confidence=0.8,
            layer3_cwe="CWE-120",
            layer3_confidence=0.75
        )
        assert path.get_final_prediction() == "CWE-120"
    
    def test_get_final_prediction_middle(self):
        path = DetectionPath(
            layer1_category="Memory",
            layer1_confidence=0.9,
            layer2_category="BufferOverflow",
            layer2_confidence=0.8,
        )
        assert path.get_final_prediction() == "BufferOverflow"
    
    def test_get_final_prediction_major(self):
        path = DetectionPath(
            layer1_category="Memory",
            layer1_confidence=0.9,
        )
        assert path.get_final_prediction() == "Memory"
    
    def test_is_benign(self):
        benign_path = DetectionPath(layer1_category="Benign", layer1_confidence=0.95)
        vuln_path = DetectionPath(layer1_category="Memory", layer1_confidence=0.9)
        
        assert benign_path.is_benign()
        assert not vuln_path.is_benign()
    
    def test_to_dict(self):
        path = DetectionPath(
            layer1_category="Memory",
            layer1_confidence=0.9,
            layer2_category="BufferOverflow",
            layer2_confidence=0.8,
        )
        d = path.to_dict()
        
        assert d["layer1"]["category"] == "Memory"
        assert d["layer1"]["confidence"] == 0.9
        assert d["layer2"]["category"] == "BufferOverflow"
        assert d["layer3"] is None


class TestMaxConfidenceSelection:
    """Tests for MaxConfidenceSelection strategy."""
    
    def test_select_single(self):
        paths = [
            DetectionPath("Memory", 0.9, "BufferOverflow", 0.8),
            DetectionPath("Injection", 0.7, "SQLi", 0.6),
        ]
        
        selector = MaxConfidenceSelection()
        selected = selector.select(paths, top_k=1)
        
        assert len(selected) == 1
        assert selected[0].layer1_category == "Memory"
    
    def test_select_top_k(self):
        paths = [
            DetectionPath("Memory", 0.9, "BufferOverflow", 0.8),
            DetectionPath("Injection", 0.7, "SQLi", 0.6),
            DetectionPath("Crypto", 0.5, "WeakCrypto", 0.4),
        ]
        
        selector = MaxConfidenceSelection()
        selected = selector.select(paths, top_k=2)
        
        assert len(selected) == 2
        assert selected[0].layer1_category == "Memory"
        assert selected[1].layer1_category == "Injection"
    
    def test_select_empty_list(self):
        selector = MaxConfidenceSelection()
        selected = selector.select([], top_k=1)
        assert selected == []
    
    def test_strategy_name(self):
        selector = MaxConfidenceSelection()
        assert selector.name == "MaxConfidenceSelection"


class TestThresholdSelection:
    """Tests for ThresholdSelection strategy."""
    
    def test_filters_by_threshold(self):
        paths = [
            DetectionPath("Memory", 0.9, "BufferOverflow", 0.8),
            DetectionPath("Injection", 0.2, "SQLi", 0.6),  # Layer 1 below threshold
        ]
        
        selector = ThresholdSelection(min_layer1=0.5)
        selected = selector.select(paths, top_k=2)
        
        assert len(selected) == 1
        assert selected[0].layer1_category == "Memory"
    
    def test_all_filtered(self):
        paths = [
            DetectionPath("Memory", 0.3, "BufferOverflow", 0.2),
            DetectionPath("Injection", 0.2, "SQLi", 0.1),
        ]
        
        selector = ThresholdSelection(min_layer1=0.5)
        selected = selector.select(paths, top_k=2)
        
        assert len(selected) == 0


class TestCreateSelectionStrategy:
    """Tests for factory function."""
    
    def test_create_max_confidence(self):
        strategy = create_selection_strategy("max_confidence")
        assert isinstance(strategy, MaxConfidenceSelection)
    
    def test_create_threshold(self):
        strategy = create_selection_strategy("threshold", min_layer1=0.5)
        assert isinstance(strategy, ThresholdSelection)
    
    def test_unknown_strategy(self):
        with pytest.raises(ValueError):
            create_selection_strategy("unknown_strategy")


class TestClassificationError:
    """Tests for ClassificationError."""
    
    def test_from_detection_result_false_positive(self):
        error = ClassificationError.from_detection_result(
            code="int x = 0;",
            predicted="Memory",
            actual="Benign",
            layer=1,
            confidence=0.8
        )
        assert error.error_type == ErrorType.FALSE_POSITIVE
    
    def test_from_detection_result_false_negative(self):
        error = ClassificationError.from_detection_result(
            code="strcpy(buf, input);",
            predicted="Benign",
            actual="Memory",
            layer=1,
            confidence=0.7
        )
        assert error.error_type == ErrorType.FALSE_NEGATIVE
    
    def test_from_detection_result_category_mismatch(self):
        error = ClassificationError.from_detection_result(
            code="sql = \"SELECT * FROM users WHERE id = \" + id;",
            predicted="Memory",
            actual="Injection",
            layer=1,
            confidence=0.6
        )
        assert error.error_type == ErrorType.CATEGORY_MISMATCH
    
    def test_code_snippet_truncation(self):
        long_code = "x" * 1000
        error = ClassificationError.from_detection_result(
            code=long_code,
            predicted="Memory",
            actual="Injection",
            max_snippet_length=100
        )
        assert len(error.code_snippet) == 103  # 100 + "..."


class TestErrorPattern:
    """Tests for ErrorPattern."""
    
    def test_add_error(self):
        pattern = ErrorPattern(
            predicted_category="Memory",
            actual_category="Injection",
            layer=1
        )
        
        error = ClassificationError(
            code_snippet="test",
            predicted_category="Memory",
            actual_category="Injection",
            confidence=0.8
        )
        
        pattern.add_error(error)
        
        assert pattern.count == 1
        assert pattern.avg_confidence == 0.8
        assert len(pattern.example_snippets) == 1
    
    def test_running_average(self):
        pattern = ErrorPattern(
            predicted_category="Memory",
            actual_category="Injection",
            layer=1
        )
        
        for conf in [0.6, 0.8, 1.0]:
            error = ClassificationError(
                code_snippet="test",
                predicted_category="Memory",
                actual_category="Injection",
                confidence=conf
            )
            pattern.add_error(error)
        
        assert pattern.count == 3
        assert abs(pattern.avg_confidence - 0.8) < 0.001


class TestErrorAccumulator:
    """Tests for ErrorAccumulator."""
    
    def test_add_error(self):
        acc = ErrorAccumulator()
        error = ClassificationError.from_detection_result(
            code="test",
            predicted="Memory",
            actual="Injection"
        )
        acc.add_error(error)
        
        assert acc.total_errors == 1
    
    def test_add_correct_prediction(self):
        acc = ErrorAccumulator()
        acc.add_correct_prediction()
        acc.add_correct_prediction()
        
        assert acc._total_predictions == 2
        assert acc.total_errors == 0
    
    def test_recent_error_rate(self):
        acc = ErrorAccumulator()
        
        # 3 correct, 1 error
        acc.add_correct_prediction()
        acc.add_correct_prediction()
        acc.add_correct_prediction()
        error = ClassificationError.from_detection_result(
            code="test", predicted="A", actual="B"
        )
        acc.add_error(error)
        
        assert abs(acc.recent_error_rate - 0.25) < 0.001
    
    def test_should_trigger_meta_learning_not_enough_errors(self):
        acc = ErrorAccumulator(threshold_count=10)
        
        for _ in range(5):
            error = ClassificationError.from_detection_result(
                code="test", predicted="A", actual="B"
            )
            acc.add_error(error)
        
        assert not acc.should_trigger_meta_learning()
    
    def test_get_top_confusion_patterns(self):
        acc = ErrorAccumulator()
        
        # Add multiple errors of same pattern
        for _ in range(5):
            error = ClassificationError.from_detection_result(
                code="test", predicted="Memory", actual="Injection", layer=1
            )
            acc.add_error(error)
        
        # Add fewer errors of different pattern
        for _ in range(2):
            error = ClassificationError.from_detection_result(
                code="test", predicted="Crypto", actual="Logic", layer=1
            )
            acc.add_error(error)
        
        patterns = acc.get_top_confusion_patterns(top_k=1, min_count=3)
        
        assert len(patterns) == 1
        assert patterns[0].predicted_category == "Memory"
        assert patterns[0].actual_category == "Injection"
    
    def test_generate_meta_learning_context(self):
        acc = ErrorAccumulator()
        
        for _ in range(5):
            error = ClassificationError.from_detection_result(
                code="test", predicted="Memory", actual="Injection", layer=1
            )
            acc.add_error(error)
        
        context = acc.generate_meta_learning_context()
        
        assert "total_errors" in context
        assert "layer_analysis" in context
        assert context["total_errors"] == 5


class TestHierarchicalPromptSet:
    """Tests for HierarchicalPromptSet."""
    
    def test_from_three_layer_set(self):
        from evoprompt.prompts.hierarchical_three_layer import ThreeLayerPromptFactory
        
        base_set = ThreeLayerPromptFactory.create_default_prompt_set()
        hier_set = HierarchicalPromptSet.from_three_layer_set(base_set)
        
        # Should have prompts for each major category
        assert len(hier_set.layer1_prompts) == 6  # 6 MajorCategory values
        assert "Memory" in hier_set.layer1_prompts
        assert "Benign" in hier_set.layer1_prompts
    
    def test_get_layer2_prompts_for_major(self):
        from evoprompt.prompts.hierarchical_three_layer import ThreeLayerPromptFactory
        
        base_set = ThreeLayerPromptFactory.create_default_prompt_set()
        hier_set = HierarchicalPromptSet.from_three_layer_set(base_set)
        
        memory_prompts = hier_set.get_layer2_prompts_for_major("Memory")
        
        assert len(memory_prompts) > 0
        assert "Buffer Overflow" in memory_prompts or "Use After Free" in memory_prompts
    
    def test_update_prompt(self):
        hier_set = HierarchicalPromptSet()
        hier_set.layer1_prompts["Memory"] = "original"
        
        hier_set.update_prompt(layer=1, category="Memory", new_prompt="updated")
        
        assert hier_set.layer1_prompts["Memory"] == "updated"


class TestNoOpEnhancer:
    """Tests for NoOpEnhancer."""
    
    def test_enhance_returns_unchanged(self):
        enhancer = NoOpEnhancer()
        code = "int x = 0;"
        assert enhancer.enhance(code) == code
    
    def test_enhance_async_returns_unchanged(self):
        import asyncio
        enhancer = NoOpEnhancer()
        code = "int x = 0;"
        result = asyncio.run(enhancer.enhance_async(code))
        assert result == code


class TestParallelDetectorConfig:
    """Tests for ParallelDetectorConfig."""
    
    def test_default_values(self):
        config = ParallelDetectorConfig()
        
        assert config.layer1_top_k == 2
        assert config.layer2_top_k == 2
        assert config.layer3_top_k == 1
        assert config.max_concurrent_requests == 20
    
    def test_custom_values(self):
        config = ParallelDetectorConfig(
            layer1_top_k=3,
            layer2_top_k=4,
            max_concurrent_requests=10
        )
        
        assert config.layer1_top_k == 3
        assert config.layer2_top_k == 4
        assert config.max_concurrent_requests == 10


class TestTuningResult:
    """Tests for TuningResult."""
    
    def test_basic_creation(self):
        result = TuningResult(
            layer=1,
            category="Memory",
            original_prompt="original",
            tuned_prompt="tuned",
            success=True
        )
        
        assert result.layer == 1
        assert result.success
    
    def test_to_dict(self):
        result = TuningResult(
            layer=1,
            category="Memory",
            original_prompt="original",
            tuned_prompt="tuned longer",
            patterns_addressed=[("Memory", "Injection")],
            success=True
        )
        
        d = result.to_dict()
        
        assert d["layer"] == 1
        assert d["success"]
        assert d["prompt_length_change"] == 4  # len("tuned longer") - len("original") = 12 - 8


class TestDetectionResult:
    """Tests for DetectionResult."""
    
    def test_basic_creation(self):
        path = DetectionPath("Memory", 0.9, "BufferOverflow", 0.8, "CWE-120", 0.7)
        result = DetectionResult(
            code="int x;",
            paths=[path],
            final_prediction="CWE-120",
            ground_truth="CWE-120",
            is_correct=True
        )
        
        assert result.is_correct
        assert result.final_prediction == "CWE-120"
    
    def test_to_dict(self):
        path = DetectionPath("Memory", 0.9)
        result = DetectionResult(
            code="int x;",
            paths=[path],
            final_prediction="Memory"
        )
        
        d = result.to_dict()
        
        assert d["final_prediction"] == "Memory"
        assert d["num_paths"] == 1


class TestCoordinatorConfig:
    """Tests for CoordinatorConfig."""
    
    def test_default_values(self):
        config = CoordinatorConfig()
        
        assert config.enable_meta_learning
        assert config.meta_learning_check_interval == 100
        assert config.save_checkpoints
