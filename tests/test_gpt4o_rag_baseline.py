# tests/test_gpt4o_rag_baseline.py
"""Tests for GPT-4o + RAG single-pass baseline."""

import pytest
from unittest.mock import MagicMock, AsyncMock
import asyncio


def test_gpt4o_rag_prompt_constant():
    """GPT4O_RAG_PROMPT should be defined."""
    from evoprompt.baselines.gpt4o_rag_singlepass import GPT4O_RAG_PROMPT
    assert "{code_snippet}" in GPT4O_RAG_PROMPT
    assert "{packed_evidence_with_ids}" in GPT4O_RAG_PROMPT
    assert "JSON" in GPT4O_RAG_PROMPT


def test_parse_baseline_response_json():
    """Should parse JSON response correctly."""
    from evoprompt.baselines.gpt4o_rag_singlepass import parse_baseline_response

    response = '{"cwe": "CWE-120", "rationale": "Buffer overflow", "evidence_ids": ["VUL-1"]}'
    result = parse_baseline_response(response)

    assert result["cwe"] == "CWE-120"
    assert result["rationale"] == "Buffer overflow"
    assert result["evidence_ids"] == ["VUL-1"]


def test_parse_baseline_response_json_with_text():
    """Should extract JSON from response with surrounding text."""
    from evoprompt.baselines.gpt4o_rag_singlepass import parse_baseline_response

    response = 'Here is my analysis:\n{"cwe": "CWE-787", "rationale": "Out-of-bounds write", "evidence_ids": ["VUL-2", "CLEAN-1"]}\nEnd of analysis.'
    result = parse_baseline_response(response)

    assert result["cwe"] == "CWE-787"
    assert result["rationale"] == "Out-of-bounds write"
    assert result["evidence_ids"] == ["VUL-2", "CLEAN-1"]


def test_parse_baseline_response_fallback():
    """Should extract CWE from non-JSON response."""
    from evoprompt.baselines.gpt4o_rag_singlepass import parse_baseline_response

    response = "This code has CWE-476 null pointer dereference"
    result = parse_baseline_response(response)

    assert result["cwe"] == "CWE-476"


def test_parse_baseline_response_none():
    """Should return NONE for unrecognized responses."""
    from evoprompt.baselines.gpt4o_rag_singlepass import parse_baseline_response

    response = "This code looks safe to me"
    result = parse_baseline_response(response)

    assert result["cwe"] == "NONE"


def test_parse_baseline_response_empty():
    """Should handle empty response."""
    from evoprompt.baselines.gpt4o_rag_singlepass import parse_baseline_response

    response = ""
    result = parse_baseline_response(response)

    assert result["cwe"] == "NONE"
    assert result["rationale"] == ""


def test_parse_baseline_response_none_in_json():
    """Should handle NONE in JSON response."""
    from evoprompt.baselines.gpt4o_rag_singlepass import parse_baseline_response

    response = '{"cwe": "NONE", "rationale": "No vulnerability detected", "evidence_ids": []}'
    result = parse_baseline_response(response)

    assert result["cwe"] == "NONE"
    assert result["rationale"] == "No vulnerability detected"
    assert result["evidence_ids"] == []


@pytest.mark.asyncio
async def test_run_gpt4o_rag_singlepass_basic():
    """Basic integration test for run_gpt4o_rag_singlepass."""
    from evoprompt.baselines.gpt4o_rag_singlepass import run_gpt4o_rag_singlepass
    from evoprompt.rag.retriever import RetrievalResult

    # Create mock sample
    mock_sample = MagicMock()
    mock_sample.input_text = "void foo() { char buf[10]; strcpy(buf, input); }"
    mock_sample.target = "1"  # Vulnerable
    mock_sample.metadata = {"idx": 0, "cwe": ["CWE-120"]}

    # Create mock retriever
    mock_retriever = MagicMock()
    mock_retriever.retrieve_contrastive.return_value = RetrievalResult(
        examples=[],
        formatted_text="[VUL-1] Example vulnerable code...\n[CLEAN-1] Example safe code...",
        similarity_scores=[0.8, 0.7]
    )

    # Create mock LLM client
    mock_llm = MagicMock()
    mock_llm.generate_async = AsyncMock(
        return_value='{"cwe": "CWE-120", "rationale": "Buffer overflow in strcpy", "evidence_ids": ["VUL-1"]}'
    )

    # Run baseline
    results = await run_gpt4o_rag_singlepass(
        samples=[mock_sample],
        retriever=mock_retriever,
        llm_client=mock_llm,
        vulnerable_top_k=2,
        clean_top_k=1
    )

    assert len(results) == 1
    assert results[0]["cwe"] == "CWE-120"
    assert results[0]["sample_id"] == 0
    assert results[0]["ground_truth"] == "1"

    # Verify retriever was called with correct arguments
    mock_retriever.retrieve_contrastive.assert_called_once()
    call_args = mock_retriever.retrieve_contrastive.call_args
    assert "void foo()" in call_args[0][0]  # query_code
    assert call_args[1]["vulnerable_top_k"] == 2
    assert call_args[1]["clean_top_k"] == 1

    # Verify LLM was called
    mock_llm.generate_async.assert_called_once()


@pytest.mark.asyncio
async def test_run_gpt4o_rag_singlepass_with_cost_tracker():
    """Test that cost tracking works correctly."""
    import tempfile
    from pathlib import Path
    from evoprompt.baselines.gpt4o_rag_singlepass import run_gpt4o_rag_singlepass
    from evoprompt.utils.cost_tracker import CostTracker
    from evoprompt.rag.retriever import RetrievalResult

    # Create mock sample
    mock_sample = MagicMock()
    mock_sample.input_text = "int main() { return 0; }"
    mock_sample.target = "0"  # Benign
    mock_sample.metadata = {"idx": 1}

    # Create mock retriever
    mock_retriever = MagicMock()
    mock_retriever.retrieve_contrastive.return_value = RetrievalResult(
        examples=[],
        formatted_text="[VUL-1] Example...",
        similarity_scores=[0.5]
    )

    # Create mock LLM client
    mock_llm = MagicMock()
    mock_llm.generate_async = AsyncMock(
        return_value='{"cwe": "NONE", "rationale": "Safe code", "evidence_ids": []}'
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "cost.jsonl"
        cost_tracker = CostTracker(output_path)

        results = await run_gpt4o_rag_singlepass(
            samples=[mock_sample],
            retriever=mock_retriever,
            llm_client=mock_llm,
            cost_tracker=cost_tracker
        )

        # Check results
        assert len(results) == 1
        assert results[0]["cwe"] == "NONE"

        # Check cost tracking output file exists
        assert output_path.exists()


@pytest.mark.asyncio
async def test_run_gpt4o_rag_singlepass_multiple_samples():
    """Test processing multiple samples."""
    from evoprompt.baselines.gpt4o_rag_singlepass import run_gpt4o_rag_singlepass
    from evoprompt.rag.retriever import RetrievalResult

    # Create mock samples
    samples = []
    for i in range(3):
        mock_sample = MagicMock()
        mock_sample.input_text = f"void func_{i}() {{ }}"
        mock_sample.target = str(i % 2)
        mock_sample.metadata = {"idx": i}
        samples.append(mock_sample)

    # Create mock retriever
    mock_retriever = MagicMock()
    mock_retriever.retrieve_contrastive.return_value = RetrievalResult(
        examples=[],
        formatted_text="Evidence...",
        similarity_scores=[0.5]
    )

    # Create mock LLM client
    mock_llm = MagicMock()
    mock_llm.generate_async = AsyncMock(
        return_value='{"cwe": "NONE", "rationale": "Safe", "evidence_ids": []}'
    )

    results = await run_gpt4o_rag_singlepass(
        samples=samples,
        retriever=mock_retriever,
        llm_client=mock_llm
    )

    assert len(results) == 3
    assert all(r["cwe"] == "NONE" for r in results)
    assert [r["sample_id"] for r in results] == [0, 1, 2]
