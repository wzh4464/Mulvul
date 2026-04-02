"""Tests for RAG retriever string-accept wrappers for parallel detector integration."""

import pytest
from unittest.mock import MagicMock

from evoprompt.rag.retriever import (
    CodeSimilarityRetriever,
    RetrievalResult,
    _resolve_major_category,
    _resolve_middle_category,
)
from evoprompt.rag.knowledge_base import KnowledgeBase, CodeExample
from evoprompt.prompts.hierarchical_three_layer import MajorCategory, MiddleCategory


def _make_kb_with_examples() -> KnowledgeBase:
    """Create a KnowledgeBase with some examples for testing."""
    kb = MagicMock(spec=KnowledgeBase)

    mem_example = CodeExample(
        code="char buf[10]; strcpy(buf, input);",
        category="Memory",
        cwe="CWE-120",
        description="Buffer overflow via strcpy",
    )
    inj_example = CodeExample(
        code="query = 'SELECT * FROM users WHERE id=' + user_id",
        category="Injection",
        cwe="CWE-89",
        description="SQL injection via string concat",
    )

    kb.major_examples = {
        "Memory": [mem_example],
        "Injection": [inj_example],
    }
    kb.middle_examples = {
        "Buffer Overflow": [mem_example],
        "SQL Injection": [inj_example],
    }
    kb.cwe_examples = {
        "CWE-120": [mem_example],
        "CWE-89": [inj_example],
    }
    return kb


class TestResolveMajorCategory:
    def test_valid_exact_case(self):
        assert _resolve_major_category("Memory") == MajorCategory.MEMORY

    def test_valid_lower_case(self):
        assert _resolve_major_category("memory") == MajorCategory.MEMORY

    def test_valid_upper_case(self):
        assert _resolve_major_category("INJECTION") == MajorCategory.INJECTION

    def test_invalid(self):
        assert _resolve_major_category("Unknown") is None

    def test_empty_string(self):
        assert _resolve_major_category("") is None


class TestResolveMiddleCategory:
    def test_valid(self):
        assert _resolve_middle_category("Buffer Overflow") == MiddleCategory.BUFFER_OVERFLOW

    def test_valid_case_insensitive(self):
        assert _resolve_middle_category("buffer overflow") == MiddleCategory.BUFFER_OVERFLOW

    def test_invalid(self):
        assert _resolve_middle_category("NonExistent") is None


class TestRetrieveMiddleCategoryByName:
    def test_valid_name(self):
        kb = _make_kb_with_examples()
        retriever = CodeSimilarityRetriever(kb)
        result = retriever.retrieve_for_middle_category_by_name(
            "char buf[10]; gets(buf);", "Memory", top_k=1
        )
        assert isinstance(result, RetrievalResult)
        # Should return examples (may be from major fallback)
        assert result.debug_info is not None

    def test_invalid_name_returns_empty_with_error(self):
        kb = _make_kb_with_examples()
        retriever = CodeSimilarityRetriever(kb)
        result = retriever.retrieve_for_middle_category_by_name(
            "some code", "CompletelyFake", top_k=2
        )
        assert result.examples == []
        assert result.formatted_text == ""
        assert result.similarity_scores == []
        assert "error" in result.debug_info
        assert "CompletelyFake" in result.debug_info["error"]


class TestRetrieveCweByName:
    def test_valid_name(self):
        kb = _make_kb_with_examples()
        retriever = CodeSimilarityRetriever(kb)
        result = retriever.retrieve_for_cwe_by_name(
            "query = 'SELECT * FROM users WHERE id=' + uid", "SQL Injection", top_k=1
        )
        assert isinstance(result, RetrievalResult)
        assert result.debug_info is not None

    def test_invalid_name_returns_empty_with_error(self):
        kb = _make_kb_with_examples()
        retriever = CodeSimilarityRetriever(kb)
        result = retriever.retrieve_for_cwe_by_name(
            "some code", "FakeMiddle", top_k=2
        )
        assert result.examples == []
        assert "error" in result.debug_info
        assert "FakeMiddle" in result.debug_info["error"]


class TestEmptyPoolFallback:
    def test_empty_pool_returns_empty_result(self):
        kb = MagicMock(spec=KnowledgeBase)
        kb.major_examples = {}
        kb.middle_examples = {}
        kb.cwe_examples = {}

        retriever = CodeSimilarityRetriever(kb)
        result = retriever.retrieve_for_major_category("int x = 0;", top_k=2)

        assert result.examples == []
        assert result.formatted_text == ""
        assert result.similarity_scores == []
        assert result.debug_info["pool_size"] == 0


class TestDebugInfoAlwaysHasPoolSize:
    def test_debug_false_still_has_pool_size(self):
        """Even with debug=False, debug_info should have pool_size."""
        kb = _make_kb_with_examples()
        retriever = CodeSimilarityRetriever(kb, debug=False)
        result = retriever.retrieve_for_major_category("char buf[10];", top_k=1)

        assert result.debug_info is not None
        assert "pool_size" in result.debug_info
        assert "num_retrieved" in result.debug_info
        assert "top_similarity" in result.debug_info
        assert isinstance(result.debug_info["pool_size"], int)

    def test_debug_true_has_extended_info(self):
        """With debug=True, debug_info should also have retrieved details."""
        kb = _make_kb_with_examples()
        retriever = CodeSimilarityRetriever(kb, debug=True)
        result = retriever.retrieve_for_major_category("char buf[10];", top_k=1)

        assert "pool_size" in result.debug_info
        assert "retrieved" in result.debug_info
        assert "query_preview" in result.debug_info
