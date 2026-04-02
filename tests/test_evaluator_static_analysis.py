"""Integration tests for Evaluator with static analysis."""

import pytest
from unittest.mock import Mock

from evoprompt.core.evaluator import Evaluator
from evoprompt.data.dataset import Sample, Dataset
from evoprompt.metrics.base import Metric
from evoprompt.analysis import BanditAnalyzer


class MockDataset(Dataset):
    """Mock dataset for testing"""

    def __init__(self, samples):
        super().__init__("mock")
        self._samples = samples

    def load_data(self, path):
        return self._samples


class MockMetric(Metric):
    """Mock metric that returns fixed score"""

    def compute(self, predictions, targets):
        return 0.75


class MockLLMClient:
    """Mock LLM client"""

    def generate(self, prompt, **kwargs):
        return "vulnerable" if "pickle" in prompt.lower() else "safe"


class TestEvaluatorStaticAnalysis:
    """Integration tests for Evaluator with static analysis"""

    def test_evaluator_without_static_analysis(self):
        """Test evaluator with static analysis disabled (default)"""
        samples = [
            Sample(
                input_text="print('hello')",
                target="0",
                metadata={"lang": "python"}
            )
        ]

        dataset = MockDataset(samples)
        evaluator = Evaluator(
            dataset=dataset,
            metric=MockMetric(),
            llm_client=MockLLMClient(),
            template_config={"enable_static_analysis": False}
        )

        result = evaluator.evaluate("Analyze: {input}")

        assert result.score == 0.75
        assert "analysis_stats" not in result.details
        assert "analysis_summary" not in result.details

    @pytest.mark.skipif(
        not BanditAnalyzer.is_available(),
        reason="Bandit not installed"
    )
    def test_evaluator_with_static_analysis_enabled(self):
        """Test evaluator with static analysis enabled"""
        samples = [
            Sample(
                input_text="import pickle; pickle.loads(data)",
                target="1",
                metadata={"lang": "python"}
            )
        ]

        dataset = MockDataset(samples)
        evaluator = Evaluator(
            dataset=dataset,
            metric=MockMetric(),
            llm_client=MockLLMClient(),
            template_config={
                "enable_static_analysis": True,
                "analysis_cache_dir": ".cache/test_analysis"
            }
        )

        result = evaluator.evaluate("Analyze: {input}")

        # Should have analysis results
        assert result.score == 0.75
        assert "analysis_stats" in result.details
        assert "analysis_summary" in result.details

        stats = result.details["analysis_stats"]
        assert stats["total_analyzed"] >= 1
        assert stats["total_vulnerabilities"] > 0

    @pytest.mark.skipif(
        not BanditAnalyzer.is_available(),
        reason="Bandit not installed"
    )
    def test_format_prompt_includes_static_analysis(self):
        """Test that _format_prompt includes static analysis hints"""
        samples = [
            Sample(
                input_text="import pickle; pickle.loads(user_input)",
                target="1",
                metadata={"lang": "python"}
            )
        ]

        dataset = MockDataset(samples)
        evaluator = Evaluator(
            dataset=dataset,
            metric=MockMetric(),
            llm_client=MockLLMClient(),
            template_config={"enable_static_analysis": True}
        )

        sample = samples[0]
        formatted = evaluator._format_prompt("Code: {input}", sample)

        # Should contain static analysis section
        assert "Static Analysis Hints" in formatted
        assert "issues" in formatted.lower() or "found" in formatted.lower()

    def test_evaluator_with_non_python_code(self):
        """Test evaluator with C code (no analyzer available)"""
        samples = [
            Sample(
                input_text="int main() { return 0; }",
                target="0",
                metadata={"lang": "c"}
            )
        ]

        dataset = MockDataset(samples)
        evaluator = Evaluator(
            dataset=dataset,
            metric=MockMetric(),
            llm_client=MockLLMClient(),
            template_config={"enable_static_analysis": True}
        )

        result = evaluator.evaluate("Analyze: {input}")

        # Should work but no analysis results (no C analyzer)
        assert result.score == 0.75
        # Stats should be empty since no analyzer for C
        if "analysis_stats" in result.details:
            assert result.details["analysis_stats"]["total_analyzed"] == 0

    @pytest.mark.skipif(
        not BanditAnalyzer.is_available(),
        reason="Bandit not installed"
    )
    def test_evaluator_analysis_cache(self):
        """Test that analysis results are cached"""
        code = "import pickle; pickle.loads(data)"
        samples = [
            Sample(input_text=code, target="1", metadata={"lang": "python"}),
            Sample(input_text=code, target="1", metadata={"lang": "python"}),
        ]

        dataset = MockDataset(samples)
        evaluator = Evaluator(
            dataset=dataset,
            metric=MockMetric(),
            llm_client=MockLLMClient(),
            template_config={
                "enable_static_analysis": True,
                "analysis_cache_dir": ".cache/test_cache"
            }
        )

        # First evaluation should populate cache
        result1 = evaluator.evaluate("Analyze: {input}")
        assert "analysis_stats" in result1.details

        # Second evaluation should use cache
        result2 = evaluator.evaluate("Analyze: {input}")
        assert "analysis_stats" in result2.details

        # Results should be the same
        assert (result1.details["analysis_stats"]["total_vulnerabilities"] ==
                result2.details["analysis_stats"]["total_vulnerabilities"])

    def test_evaluator_graceful_degradation_no_bandit(self):
        """Test graceful degradation when Bandit is not available"""
        samples = [
            Sample(
                input_text="print('hello')",
                target="0",
                metadata={"lang": "python"}
            )
        ]

        dataset = MockDataset(samples)

        # Even if static analysis is enabled, should work without Bandit
        evaluator = Evaluator(
            dataset=dataset,
            metric=MockMetric(),
            llm_client=MockLLMClient(),
            template_config={"enable_static_analysis": True}
        )

        result = evaluator.evaluate("Analyze: {input}")

        # Should complete successfully
        assert result.score == 0.75
        assert "num_samples" in result.details

    @pytest.mark.skipif(
        not BanditAnalyzer.is_available(),
        reason="Bandit not installed"
    )
    def test_analysis_severity_counts(self):
        """Test that severity levels are correctly counted"""
        samples = [
            Sample(
                input_text="""
import pickle
import hashlib
pickle.loads(data)  # HIGH
hashlib.md5(data)  # MEDIUM
""",
                target="1",
                metadata={"lang": "python"}
            )
        ]

        dataset = MockDataset(samples)
        evaluator = Evaluator(
            dataset=dataset,
            metric=MockMetric(),
            llm_client=MockLLMClient(),
            template_config={"enable_static_analysis": True}
        )

        result = evaluator.evaluate("Analyze: {input}")

        stats = result.details["analysis_stats"]
        # Should have at least one high or medium severity issue
        assert (stats["high_severity_count"] > 0 or
                stats["medium_severity_count"] > 0)
