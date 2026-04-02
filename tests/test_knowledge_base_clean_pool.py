# tests/test_knowledge_base_clean_pool.py
"""Tests for KnowledgeBase clean_examples field (contrastive retrieval support)."""

import pytest
from evoprompt.rag.knowledge_base import KnowledgeBase, CodeExample


def test_knowledge_base_has_clean_examples_field():
    """KnowledgeBase should have clean_examples field."""
    kb = KnowledgeBase()
    assert hasattr(kb, 'clean_examples')
    assert kb.clean_examples == []


def test_add_clean_example():
    """Should be able to add clean/benign examples."""
    kb = KnowledgeBase()
    example = CodeExample(
        code="int x = 5; return x;",
        category="Benign",
        description="Safe integer assignment"
    )
    kb.add_clean_example(example)
    assert len(kb.clean_examples) == 1
    assert kb.clean_examples[0].category == "Benign"


def test_clean_examples_in_statistics():
    """Statistics should include clean pool size."""
    kb = KnowledgeBase()
    kb.add_clean_example(CodeExample(
        code="safe code",
        category="Benign",
        description="Safe"
    ))
    stats = kb.statistics()
    assert "clean_examples" in stats
    assert stats["clean_examples"] == 1


def test_save_and_load_with_clean_examples():
    """Clean examples should be saved and loaded correctly."""
    import tempfile
    import os

    kb = KnowledgeBase()
    kb.add_clean_example(CodeExample(
        code="safe code here",
        category="Benign",
        description="Safe operation"
    ))

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_path = f.name

    try:
        kb.save(temp_path)
        loaded_kb = KnowledgeBase.load(temp_path)
        assert len(loaded_kb.clean_examples) == 1
        assert loaded_kb.clean_examples[0].code == "safe code here"
    finally:
        os.unlink(temp_path)


def test_build_clean_pool_from_dataset():
    """Should build clean pool from dataset benign samples."""
    from unittest.mock import MagicMock
    from evoprompt.rag.knowledge_base import build_clean_pool_from_dataset

    # Mock dataset with benign samples
    mock_dataset = MagicMock()
    mock_sample1 = MagicMock()
    mock_sample1.input_text = "int safe_func() { return 0; }"
    mock_sample1.target = "0"  # benign
    mock_sample1.metadata = {"idx": 1}

    mock_sample2 = MagicMock()
    mock_sample2.input_text = "void vuln() { strcpy(buf, input); }"
    mock_sample2.target = "1"  # vulnerable
    mock_sample2.metadata = {"idx": 2, "cwe": ["CWE-120"]}

    mock_sample3 = MagicMock()
    mock_sample3.input_text = "int another_safe() { return 1; }"
    mock_sample3.target = "0"  # benign
    mock_sample3.metadata = {"idx": 3}

    mock_dataset.get_samples.return_value = [mock_sample1, mock_sample2, mock_sample3]

    kb = KnowledgeBase()
    build_clean_pool_from_dataset(kb, mock_dataset, max_samples=10, seed=42)

    # Should only have benign samples
    assert len(kb.clean_examples) == 2
    assert all(ex.category == "Benign" for ex in kb.clean_examples)
