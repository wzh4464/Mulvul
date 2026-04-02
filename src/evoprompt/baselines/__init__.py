"""Baseline implementations for supplementary experiments."""

from .gpt4o_rag_singlepass import (
    GPT4O_RAG_PROMPT,
    parse_baseline_response,
    run_gpt4o_rag_singlepass,
)

__all__ = [
    "GPT4O_RAG_PROMPT",
    "parse_baseline_response",
    "run_gpt4o_rag_singlepass",
]
