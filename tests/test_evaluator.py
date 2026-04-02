"""Tests for the evaluator module."""

import pytest
from unittest.mock import Mock, patch

from evoprompt.core.evaluator import Evaluator, EvaluationResult


class TestEvaluator:
    """Test cases for the Evaluator class."""
    
    def test_evaluator_initialization(self, mock_dataset, mock_metric, mock_llm_client):
        """Test evaluator initialization."""
        evaluator = Evaluator(
            dataset=mock_dataset,
            metric=mock_metric,
            llm_client=mock_llm_client
        )
        
        assert evaluator.dataset == mock_dataset
        assert evaluator.metric == mock_metric
        assert evaluator.llm_client == mock_llm_client
        
    def test_evaluate_prompt(self, mock_evaluator):
        """Test prompt evaluation."""
        result = mock_evaluator.evaluate("Test prompt: {input}")
        
        assert isinstance(result, EvaluationResult)
        assert result.score == 0.85
        assert "num_samples" in result.details
        assert result.details["num_samples"] == 2
        
    def test_evaluate_with_sample_size(self, mock_evaluator):
        """Test evaluation with limited sample size."""
        result = mock_evaluator.evaluate("Test prompt: {input}", sample_size=1)
        
        # Should call get_samples with sample_size
        mock_evaluator.dataset.get_samples.assert_called_with(1)
        
    def test_format_prompt(self, mock_evaluator):
        """Test prompt formatting."""
        class MockSample:
            input_text = "2+2"
            
        sample = MockSample()
        formatted = mock_evaluator._format_prompt("Calculate: {input}", sample)
        assert formatted == "Calculate: 2+2"


class TestEvaluationResult:
    """Test cases for EvaluationResult class."""
    
    def test_result_creation(self):
        """Test evaluation result creation."""
        result = EvaluationResult(0.95, {"accuracy": 0.95})
        
        assert result.score == 0.95
        assert result.details["accuracy"] == 0.95
        
    def test_result_without_details(self):
        """Test result creation without details."""
        result = EvaluationResult(0.85)
        
        assert result.score == 0.85
        assert result.details == {}
        
    def test_result_repr(self):
        """Test result string representation."""
        result = EvaluationResult(0.85, {"test": True})
        repr_str = repr(result)
        
        assert "EvaluationResult" in repr_str
        assert "0.85" in repr_str