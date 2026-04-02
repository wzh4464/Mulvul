"""Tests for RAG integration in factory functions and coordinator."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from evoprompt.detectors.parallel_hierarchical_detector import (
    ParallelHierarchicalDetector,
    create_parallel_detector,
)
from evoprompt.detectors.hierarchical_coordinator import (
    HierarchicalDetectionCoordinator,
    create_coordinator,
)
from evoprompt.rag.knowledge_base import KnowledgeBase, KnowledgeBaseBuilder
from evoprompt.rag.retriever import CodeSimilarityRetriever


def _make_mock_llm() -> AsyncMock:
    client = AsyncMock()
    client.generate_async = AsyncMock(return_value="CONFIDENCE: 0.75")
    return client


def _make_mock_kb() -> MagicMock:
    """Create a mock KnowledgeBase with minimal structure."""
    kb = MagicMock(spec=KnowledgeBase)
    kb.major_examples = {}
    kb.middle_examples = {}
    kb.cwe_examples = {}
    return kb


class TestFactoryWithoutRag:
    def test_no_retriever_created(self):
        """Without RAG, detector should have no retriever."""
        llm = _make_mock_llm()
        detector = create_parallel_detector(llm_client=llm)

        assert detector.retriever is None
        assert detector.config.enable_rag is False

    def test_backward_compatible(self):
        """Factory should work exactly as before without RAG args."""
        llm = _make_mock_llm()
        detector = create_parallel_detector(
            llm_client=llm,
            layer1_top_k=3,
            layer2_top_k=2,
        )

        assert detector.config.layer1_top_k == 3
        assert detector.config.layer2_top_k == 2
        assert detector.retriever is None


class TestFactoryWithRag:
    def test_retriever_created(self):
        """With RAG enabled and KB provided, retriever should be created."""
        llm = _make_mock_llm()
        kb = _make_mock_kb()

        detector = create_parallel_detector(
            llm_client=llm,
            knowledge_base=kb,
            enable_rag=True,
            rag_top_k=3,
        )

        assert detector.retriever is not None
        assert detector.config.enable_rag is True
        assert detector.config.rag_top_k == 3

    def test_rag_enabled_without_kb_raises(self):
        """RAG enabled without KB should raise (since no retriever is created)."""
        llm = _make_mock_llm()

        with pytest.raises(ValueError, match="enable_rag"):
            create_parallel_detector(
                llm_client=llm,
                enable_rag=True,
            )


class TestCoordinatorFactoryWithoutRag:
    def test_backward_compatible(self):
        """Coordinator factory should work exactly as before."""
        llm = _make_mock_llm()
        coordinator = create_coordinator(llm_client=llm, enable_meta_learning=False)

        assert isinstance(coordinator, HierarchicalDetectionCoordinator)
        assert coordinator.detector.retriever is None


class TestCoordinatorFactoryWithRag:
    def test_retriever_passes_through(self):
        """Coordinator factory should pass retriever to inner detector."""
        llm = _make_mock_llm()
        kb = _make_mock_kb()

        coordinator = create_coordinator(
            llm_client=llm,
            enable_meta_learning=False,
            knowledge_base=kb,
            enable_rag=True,
            rag_top_k=2,
        )

        assert coordinator.detector.retriever is not None
        assert coordinator.detector.config.enable_rag is True

    def test_rag_disabled_by_default(self):
        """Without explicit enable_rag, RAG should be off."""
        llm = _make_mock_llm()
        kb = _make_mock_kb()

        coordinator = create_coordinator(
            llm_client=llm,
            knowledge_base=kb,
        )

        assert coordinator.detector.retriever is None
        assert coordinator.detector.config.enable_rag is False


class TestCoordinatorStatsRag:
    def test_stats_rag_enabled(self):
        """When RAG is enabled, stats should include 'rag' section."""
        llm = _make_mock_llm()
        kb = _make_mock_kb()

        coordinator = create_coordinator(
            llm_client=llm,
            enable_meta_learning=False,
            knowledge_base=kb,
            enable_rag=True,
            rag_top_k=3,
            rag_retriever_type="lexical",
        )

        stats = coordinator.get_statistics_summary()
        assert "rag" in stats
        assert stats["rag"]["enabled"] is True
        assert stats["rag"]["top_k"] == 3
        assert stats["rag"]["retriever_type"] == "lexical"

    def test_stats_rag_disabled(self):
        """When RAG is disabled, stats should not include 'rag' section."""
        llm = _make_mock_llm()
        coordinator = create_coordinator(
            llm_client=llm,
            enable_meta_learning=False,
        )

        stats = coordinator.get_statistics_summary()
        assert "rag" not in stats
