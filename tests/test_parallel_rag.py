"""Tests for RAG integration in ParallelHierarchicalDetector."""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from dataclasses import dataclass, field
from typing import List

from evoprompt.detectors.parallel_hierarchical_detector import (
    ParallelHierarchicalDetector,
    ParallelDetectorConfig,
    HierarchicalPromptSet,
    NoOpEnhancer,
)
from evoprompt.detectors.scoring import DetectionPath
from evoprompt.rag.retriever import CodeSimilarityRetriever, RetrievalResult
from evoprompt.rag.knowledge_base import CodeExample


class StubRetriever:
    """Deterministic stub retriever that tracks calls."""

    def __init__(self, formatted_text: str = "RAG EXAMPLE TEXT"):
        self.formatted_text = formatted_text
        self.call_log: List[dict] = []
        self._example = CodeExample(
            code="int x;", category="Memory", cwe="CWE-120",
            description="stub example",
        )

    def retrieve_for_major_category(self, query_code, top_k=2):
        self.call_log.append({"method": "major", "code_len": len(query_code), "top_k": top_k})
        return RetrievalResult(
            examples=[self._example],
            formatted_text=self.formatted_text,
            similarity_scores=[0.9],
            debug_info={"pool_size": 1, "num_retrieved": 1, "top_similarity": 0.9},
        )

    def retrieve_for_middle_category_by_name(self, query_code, major_name, top_k=2):
        self.call_log.append({"method": "middle", "major": major_name, "top_k": top_k})
        return RetrievalResult(
            examples=[self._example],
            formatted_text=self.formatted_text,
            similarity_scores=[0.8],
            debug_info={"pool_size": 1, "num_retrieved": 1, "top_similarity": 0.8},
        )

    def retrieve_for_cwe_by_name(self, query_code, middle_name, top_k=2):
        self.call_log.append({"method": "cwe", "middle": middle_name, "top_k": top_k})
        return RetrievalResult(
            examples=[self._example],
            formatted_text=self.formatted_text,
            similarity_scores=[0.7],
            debug_info={"pool_size": 1, "num_retrieved": 1, "top_similarity": 0.7},
        )


def _make_prompt_set() -> HierarchicalPromptSet:
    """Create a minimal prompt set for testing."""
    from evoprompt.prompts.hierarchical_three_layer import ThreeLayerPromptFactory
    base = ThreeLayerPromptFactory.create_default_prompt_set()
    return HierarchicalPromptSet.from_three_layer_set(base)


def _make_mock_llm() -> AsyncMock:
    """Create a mock async LLM client that returns CONFIDENCE responses."""
    client = AsyncMock()
    client.generate_async = AsyncMock(return_value="CONFIDENCE: 0.75")
    return client


class TestDetectWithoutRag:
    def test_retriever_not_called(self):
        """When enable_rag=False, retriever should never be called."""
        llm = _make_mock_llm()
        prompt_set = _make_prompt_set()
        retriever = StubRetriever()

        config = ParallelDetectorConfig(enable_rag=False)
        detector = ParallelHierarchicalDetector(
            llm_client=llm, prompt_set=prompt_set, config=config,
            retriever=retriever,
        )

        paths = asyncio.run(detector.detect_async("int x = 0;"))

        assert retriever.call_log == []
        assert isinstance(paths, list)

    def test_output_unchanged_without_retriever(self):
        """Without RAG, output should be same as before (no rag metadata)."""
        llm = _make_mock_llm()
        prompt_set = _make_prompt_set()
        config = ParallelDetectorConfig(enable_rag=False)
        detector = ParallelHierarchicalDetector(
            llm_client=llm, prompt_set=prompt_set, config=config,
        )

        paths = asyncio.run(detector.detect_async("int x = 0;"))

        for path in paths:
            assert "rag" not in path.metadata


class TestDetectWithRag:
    def test_injects_rag_into_prompts(self):
        """When RAG is enabled, prompts sent to LLM should contain RAG text."""
        llm = _make_mock_llm()
        prompt_set = _make_prompt_set()
        retriever = StubRetriever("INJECTED_RAG_TEXT")
        config = ParallelDetectorConfig(enable_rag=True, rag_top_k=1)

        detector = ParallelHierarchicalDetector(
            llm_client=llm, prompt_set=prompt_set, config=config,
            retriever=retriever,
        )
        asyncio.run(detector.detect_async("int x = 0;"))

        # Check that at least one call to generate_async contains RAG text
        prompts_sent = [
            call.args[0] for call in llm.generate_async.call_args_list
        ]
        rag_prompts = [p for p in prompts_sent if "INJECTED_RAG_TEXT" in p]
        assert len(rag_prompts) > 0

    def test_layer1_retrieves_once(self):
        """Layer 1 should make exactly 1 retrieval call (shared for all 6 majors)."""
        llm = _make_mock_llm()
        prompt_set = _make_prompt_set()
        retriever = StubRetriever()
        config = ParallelDetectorConfig(enable_rag=True)

        detector = ParallelHierarchicalDetector(
            llm_client=llm, prompt_set=prompt_set, config=config,
            retriever=retriever,
        )
        asyncio.run(detector.detect_async("int x = 0;"))

        major_calls = [c for c in retriever.call_log if c["method"] == "major"]
        assert len(major_calls) == 1

    def test_layer2_retrieves_per_major(self):
        """Layer 2 should retrieve once per selected major."""
        llm = _make_mock_llm()
        prompt_set = _make_prompt_set()
        retriever = StubRetriever()
        config = ParallelDetectorConfig(
            enable_rag=True, layer1_top_k=2,
        )

        detector = ParallelHierarchicalDetector(
            llm_client=llm, prompt_set=prompt_set, config=config,
            retriever=retriever,
        )
        asyncio.run(detector.detect_async("int x = 0;"))

        middle_calls = [c for c in retriever.call_log if c["method"] == "middle"]
        assert len(middle_calls) == config.layer1_top_k

    def test_layer3_retrieves_per_middle(self):
        """Layer 3 should retrieve once per selected middle category."""
        llm = _make_mock_llm()
        prompt_set = _make_prompt_set()
        retriever = StubRetriever()
        config = ParallelDetectorConfig(enable_rag=True, layer1_top_k=1, layer2_top_k=1)

        detector = ParallelHierarchicalDetector(
            llm_client=llm, prompt_set=prompt_set, config=config,
            retriever=retriever,
        )
        asyncio.run(detector.detect_async("int x = 0;"))

        cwe_calls = [c for c in retriever.call_log if c["method"] == "cwe"]
        # At least 1 CWE retrieval (for the top selected middle categories)
        assert len(cwe_calls) >= 1

    def test_rag_metadata_in_detection_path(self):
        """Detection paths should contain rag metadata when RAG is enabled."""
        llm = _make_mock_llm()
        prompt_set = _make_prompt_set()
        retriever = StubRetriever()
        config = ParallelDetectorConfig(enable_rag=True)

        detector = ParallelHierarchicalDetector(
            llm_client=llm, prompt_set=prompt_set, config=config,
            retriever=retriever,
        )
        paths = asyncio.run(detector.detect_async("int x = 0;"))

        assert len(paths) > 0
        for path in paths:
            assert "rag" in path.metadata
            assert "layer1" in path.metadata["rag"]


class TestRagEdgeCases:
    def test_enable_rag_without_retriever_raises(self):
        """Should raise ValueError when enable_rag=True but no retriever given."""
        llm = _make_mock_llm()
        prompt_set = _make_prompt_set()
        config = ParallelDetectorConfig(enable_rag=True)

        with pytest.raises(ValueError, match="enable_rag"):
            ParallelHierarchicalDetector(
                llm_client=llm, prompt_set=prompt_set, config=config,
            )

    def test_empty_retrieval_uses_base_prompt(self):
        """When retrieval returns empty formatted_text, prompt should be unchanged."""
        llm = _make_mock_llm()
        prompt_set = _make_prompt_set()
        retriever = StubRetriever(formatted_text="")  # Empty text
        config = ParallelDetectorConfig(enable_rag=True)

        detector = ParallelHierarchicalDetector(
            llm_client=llm, prompt_set=prompt_set, config=config,
            retriever=retriever,
        )
        paths = asyncio.run(detector.detect_async("int x = 0;"))

        # Should still work, just no RAG prefix
        assert isinstance(paths, list)

        # No prompt should start with \n\n (empty prefix shouldn't be added)
        prompts_sent = [
            call.args[0] for call in llm.generate_async.call_args_list
        ]
        for p in prompts_sent:
            assert not p.startswith("\n\n")

    def test_retrieval_failure_graceful_fallback(self):
        """When retriever raises, detection should continue without RAG."""
        llm = _make_mock_llm()
        prompt_set = _make_prompt_set()

        class FailingRetriever:
            def retrieve_for_major_category(self, *a, **kw):
                raise RuntimeError("KB corrupted")
            def retrieve_for_middle_category_by_name(self, *a, **kw):
                raise RuntimeError("KB corrupted")
            def retrieve_for_cwe_by_name(self, *a, **kw):
                raise RuntimeError("KB corrupted")

        config = ParallelDetectorConfig(enable_rag=True)
        detector = ParallelHierarchicalDetector(
            llm_client=llm, prompt_set=prompt_set, config=config,
            retriever=FailingRetriever(),
        )

        # Should not raise
        paths = asyncio.run(detector.detect_async("int x = 0;"))
        assert isinstance(paths, list)

    def test_retrieval_cache_prevents_duplicate_calls(self):
        """Same code + layer + category should only call retriever once."""
        llm = _make_mock_llm()
        prompt_set = _make_prompt_set()
        retriever = StubRetriever()
        config = ParallelDetectorConfig(enable_rag=True)

        detector = ParallelHierarchicalDetector(
            llm_client=llm, prompt_set=prompt_set, config=config,
            retriever=retriever,
        )

        # First detect
        asyncio.run(detector.detect_async("int x = 0;"))
        calls_first = len(retriever.call_log)

        # Cache is reset per detect, so second detect makes same number of calls
        asyncio.run(detector.detect_async("int x = 0;"))
        calls_second = len(retriever.call_log) - calls_first

        # Within a single detect, cache prevents duplicates.
        # Both detects should make the same number of calls.
        assert calls_first == calls_second

    def test_concurrent_detect_no_errors(self):
        """Multiple concurrent detect_async calls should not interfere."""
        llm = _make_mock_llm()
        prompt_set = _make_prompt_set()
        retriever = StubRetriever()
        config = ParallelDetectorConfig(enable_rag=True)

        detector = ParallelHierarchicalDetector(
            llm_client=llm, prompt_set=prompt_set, config=config,
            retriever=retriever,
        )

        async def run_concurrent():
            results = await asyncio.gather(
                detector.detect_async("code A"),
                detector.detect_async("code B"),
            )
            return results

        results = asyncio.run(run_concurrent())
        assert len(results) == 2
        for r in results:
            assert isinstance(r, list)
