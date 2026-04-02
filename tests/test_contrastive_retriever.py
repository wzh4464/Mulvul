# tests/test_contrastive_retriever.py
"""Tests for contrastive retrieval functionality."""
import pytest
from evoprompt.rag.knowledge_base import KnowledgeBase, CodeExample
from evoprompt.rag.retriever import CodeSimilarityRetriever


def test_retriever_accepts_contrastive_flag():
    """Retriever should accept contrastive parameter."""
    kb = KnowledgeBase()
    retriever = CodeSimilarityRetriever(kb, contrastive=True)
    assert retriever.contrastive is True


def test_retriever_accepts_clean_pool_frac():
    """Retriever should accept clean_pool_frac parameter."""
    kb = KnowledgeBase()
    retriever = CodeSimilarityRetriever(kb, clean_pool_frac=0.5)
    assert retriever.clean_pool_frac == 0.5


def test_retrieve_contrastive_returns_both_types():
    """retrieve_contrastive should return vulnerable and clean examples."""
    kb = KnowledgeBase()

    # Add vulnerable example
    kb.major_examples["Memory"] = [CodeExample(
        code="strcpy(buf, input);",
        category="Memory",
        description="Buffer overflow",
        cwe="CWE-120"
    )]

    # Add clean example
    kb.add_clean_example(CodeExample(
        code="strncpy(buf, input, sizeof(buf));",
        category="Benign",
        description="Safe copy"
    ))

    retriever = CodeSimilarityRetriever(kb, contrastive=True)
    result = retriever.retrieve_contrastive(
        "char buf[64]; strcpy(buf, user_input);",
        vulnerable_top_k=1,
        clean_top_k=1
    )

    assert len(result.examples) == 2
    # Check formatted text has IDs
    assert "[VUL-" in result.formatted_text
    assert "[CLEAN-" in result.formatted_text


def test_clean_pool_subsampling():
    """Should subsample clean pool based on fraction."""
    kb = KnowledgeBase()

    # Add 10 clean examples
    for i in range(10):
        kb.add_clean_example(CodeExample(
            code=f"safe_code_{i}",
            category="Benign",
            description=f"Safe {i}"
        ))

    retriever = CodeSimilarityRetriever(kb, clean_pool_frac=0.5, clean_pool_seed=42)

    # Should have ~5 examples in subsampled pool
    assert len(retriever._get_clean_pool()) == 5


def test_contrastive_debug_info():
    """Debug info should contain contrastive-specific metadata."""
    kb = KnowledgeBase()

    kb.major_examples["Memory"] = [CodeExample(
        code="strcpy(buf, input);",
        category="Memory",
        description="Buffer overflow",
        cwe="CWE-120"
    )]

    kb.add_clean_example(CodeExample(
        code="strncpy(buf, input, sizeof(buf));",
        category="Benign",
        description="Safe copy"
    ))

    retriever = CodeSimilarityRetriever(kb, contrastive=True)
    result = retriever.retrieve_contrastive(
        "char buf[64]; strcpy(buf, user_input);",
        vulnerable_top_k=1,
        clean_top_k=1
    )

    assert "vulnerable_count" in result.debug_info
    assert "clean_count" in result.debug_info
    assert "clean_pool_size" in result.debug_info
    assert result.debug_info["vulnerable_count"] == 1
    assert result.debug_info["clean_count"] == 1


def test_clean_pool_frac_default():
    """Default clean_pool_frac should be 1.0 (use all)."""
    kb = KnowledgeBase()
    retriever = CodeSimilarityRetriever(kb)
    assert retriever.clean_pool_frac == 1.0


def test_contrastive_default_false():
    """Default contrastive should be False."""
    kb = KnowledgeBase()
    retriever = CodeSimilarityRetriever(kb)
    assert retriever.contrastive is False


def test_retrieve_contrastive_empty_clean_pool():
    """retrieve_contrastive should handle empty clean pool gracefully."""
    kb = KnowledgeBase()

    kb.major_examples["Memory"] = [CodeExample(
        code="strcpy(buf, input);",
        category="Memory",
        description="Buffer overflow",
        cwe="CWE-120"
    )]

    retriever = CodeSimilarityRetriever(kb, contrastive=True)
    result = retriever.retrieve_contrastive(
        "char buf[64]; strcpy(buf, user_input);",
        vulnerable_top_k=1,
        clean_top_k=1
    )

    # Should have only vulnerable example
    assert len(result.examples) == 1
    assert "[VUL-" in result.formatted_text
    # Clean section should be empty or not present
    assert result.debug_info["clean_count"] == 0


def test_clean_pool_seed_determinism():
    """Same seed should produce same subsample."""
    kb = KnowledgeBase()
    for i in range(20):
        kb.add_clean_example(CodeExample(
            code=f"safe_code_{i}",
            category="Benign",
            description=f"Safe {i}"
        ))

    retriever1 = CodeSimilarityRetriever(kb, clean_pool_frac=0.3, clean_pool_seed=123)
    retriever2 = CodeSimilarityRetriever(kb, clean_pool_frac=0.3, clean_pool_seed=123)
    retriever3 = CodeSimilarityRetriever(kb, clean_pool_frac=0.3, clean_pool_seed=456)

    pool1 = retriever1._get_clean_pool()
    pool2 = retriever2._get_clean_pool()
    pool3 = retriever3._get_clean_pool()

    # Same seed = same result
    assert [e.code for e in pool1] == [e.code for e in pool2]
    # Different seed = different result
    assert [e.code for e in pool1] != [e.code for e in pool3]
