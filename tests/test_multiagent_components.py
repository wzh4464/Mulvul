"""
Unit tests for multi-agent components.

This tests the core functionality without requiring API calls.
"""

import pytest
from unittest.mock import Mock, MagicMock

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from evoprompt.prompts.hierarchical import (
    HierarchicalPrompt,
    PromptHierarchy,
    CWECategory,
    get_cwe_major_category
)
from evoprompt.evaluators.statistics import (
    DetectionStatistics,
    BatchStatistics,
    StatisticsCollector
)
from evoprompt.multiagent.agents import (
    AgentConfig,
    AgentRole,
    DetectionAgent,
    MetaAgent
)


class TestHierarchicalPrompts:
    """Test hierarchical prompt structure."""

    def test_cwe_category_mapping(self):
        """Test CWE to category mapping."""
        assert get_cwe_major_category("CWE-120") == CWECategory.MEMORY
        assert get_cwe_major_category("CWE-79") == CWECategory.INJECTION
        assert get_cwe_major_category("CWE-999") == CWECategory.BENIGN  # Unknown

    def test_prompt_hierarchy_initialization(self):
        """Test prompt hierarchy initialization."""
        hierarchy = PromptHierarchy()
        hierarchy.initialize_with_defaults()

        assert hierarchy.router_prompt is not None
        assert len(hierarchy.category_prompts) > 0
        assert CWECategory.MEMORY in hierarchy.category_prompts

    def test_hierarchical_prompt_creation(self):
        """Test hierarchical prompt object."""
        prompt = HierarchicalPrompt(
            router_prompt="Route this code...",
            category_prompts={
                CWECategory.MEMORY: "Check memory issues...",
                CWECategory.INJECTION: "Check injection..."
            }
        )

        assert prompt.router_prompt == "Route this code..."
        assert prompt.get_detection_prompt(CWECategory.MEMORY) == "Check memory issues..."
        assert prompt.get_detection_prompt(CWECategory.CRYPTO) is None

    def test_hierarchical_prompt_serialization(self):
        """Test serialization to/from dict."""
        original = HierarchicalPrompt(
            router_prompt="Test router",
            category_prompts={CWECategory.MEMORY: "Test memory"}
        )

        # Serialize
        data = original.to_dict()
        assert "router_prompt" in data
        assert "category_prompts" in data

        # Deserialize
        restored = HierarchicalPrompt.from_dict(data)
        assert restored.router_prompt == original.router_prompt


class TestStatistics:
    """Test statistics collection."""

    def test_detection_statistics_basic(self):
        """Test basic statistics collection."""
        stats = DetectionStatistics()

        # Add predictions
        stats.add_prediction("vulnerable", "vulnerable", category="CWE-120")
        stats.add_prediction("benign", "benign", category="CWE-120")
        stats.add_prediction("vulnerable", "benign", category="CWE-120")  # FP
        stats.add_prediction("benign", "vulnerable", category="CWE-79")  # FN

        stats.compute_metrics()

        assert stats.total_samples == 4
        assert stats.correct == 2
        assert stats.accuracy == 0.5
        assert stats.true_positives == 1
        assert stats.false_positives == 1
        assert stats.false_negatives == 1

    def test_detection_statistics_f1(self):
        """Test F1 score calculation."""
        stats = DetectionStatistics()

        # Perfect precision, 50% recall
        stats.add_prediction("vulnerable", "vulnerable")
        stats.add_prediction("benign", "benign")
        stats.add_prediction("benign", "vulnerable")  # FN

        stats.compute_metrics()

        assert stats.precision == 1.0  # No FP
        assert stats.recall == 0.5  # 1 TP, 1 FN
        # F1 = 2 * (1.0 * 0.5) / (1.0 + 0.5) = 2/3
        assert abs(stats.f1_score - 2/3) < 0.001

    def test_category_statistics(self):
        """Test per-category statistics."""
        stats = DetectionStatistics()

        # CWE-120: 2 correct, 1 incorrect
        stats.add_prediction("vulnerable", "vulnerable", category="CWE-120")
        stats.add_prediction("benign", "benign", category="CWE-120")
        stats.add_prediction("vulnerable", "benign", category="CWE-120")  # FP

        # CWE-79: 1 correct
        stats.add_prediction("vulnerable", "vulnerable", category="CWE-79")

        stats.compute_metrics()

        summary = stats.get_summary()
        cat_stats = summary["category_stats"]

        assert "CWE-120" in cat_stats
        assert cat_stats["CWE-120"]["total"] == 3
        assert cat_stats["CWE-120"]["correct"] == 2
        assert cat_stats["CWE-120"]["accuracy"] == round(2/3, 4)

    def test_batch_statistics(self):
        """Test batch statistics."""
        stats = DetectionStatistics()
        stats.add_prediction("vulnerable", "vulnerable")
        stats.add_prediction("benign", "benign")
        stats.compute_metrics()

        batch_stat = BatchStatistics(
            batch_id=0,
            batch_size=2,
            statistics=stats
        )

        summary = batch_stat.get_summary()
        assert summary["batch_id"] == 0
        assert summary["batch_size"] == 2
        assert "statistics" in summary

    def test_statistics_collector(self):
        """Test statistics collector."""
        collector = StatisticsCollector()

        # Add generation stats
        stats1 = DetectionStatistics()
        stats1.accuracy = 0.7
        stats1.f1_score = 0.65

        stats2 = DetectionStatistics()
        stats2.accuracy = 0.8
        stats2.f1_score = 0.75

        collector.add_generation_stats(0, stats1)
        collector.add_generation_stats(1, stats2)

        # Get trend
        trend = collector.get_historical_trend()
        assert len(trend) == 2
        assert trend[0]["generation"] == 0
        assert trend[0]["accuracy"] == 0.7
        assert trend[1]["accuracy"] == 0.8


class TestAgentConfigurations:
    """Test agent configurations."""

    def test_agent_config_creation(self):
        """Test agent config creation."""
        config = AgentConfig(
            role=AgentRole.DETECTION,
            model_name="gpt-4",
            temperature=0.1
        )

        assert config.role == AgentRole.DETECTION
        assert config.model_name == "gpt-4"
        assert config.temperature == 0.1

    def test_detection_agent_config(self):
        """Test detection agent requires DETECTION role."""
        mock_client = Mock()

        config = AgentConfig(
            role=AgentRole.DETECTION,
            model_name="test-model"
        )

        agent = DetectionAgent(config, mock_client)
        assert agent.role == AgentRole.DETECTION

        # Should raise error with wrong role
        with pytest.raises(ValueError):
            wrong_config = AgentConfig(
                role=AgentRole.META,
                model_name="test-model"
            )
            DetectionAgent(wrong_config, mock_client)

    def test_meta_agent_config(self):
        """Test meta agent requires META role."""
        mock_client = Mock()

        config = AgentConfig(
            role=AgentRole.META,
            model_name="claude-4.5"
        )

        agent = MetaAgent(config, mock_client)
        assert agent.role == AgentRole.META

        # Should raise error with wrong role
        with pytest.raises(ValueError):
            wrong_config = AgentConfig(
                role=AgentRole.DETECTION,
                model_name="claude-4.5"
            )
            MetaAgent(wrong_config, mock_client)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
