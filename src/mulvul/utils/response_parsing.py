"""Utility helpers for parsing LLM responses in classification workflows."""

from __future__ import annotations

from typing import Optional

from ..data.cwe_categories import canonicalize_category


def normalize_text(text: Optional[str]) -> str:
    """Normalize response text for downstream parsing."""
    if not text:
        return ""
    return text.strip()


def extract_vulnerability_label(response: Optional[str]) -> str:
    """Map free-form LLM output to the binary labels used in vulnerability detection.

    The function mirrors the heuristics inside ``VulnerabilityEvaluator`` so that both
    production workflows and standalone harnesses rely on the exact same parsing logic.
    """
    text = normalize_text(response).lower()

    if not text:
        return "0"

    if "vulnerable" in text:
        return "1"
    if "benign" in text:
        return "0"

    if text.startswith("1") or text.startswith("yes") or "yes" in text:
        return "1"

    return "0"


def extract_cwe_major(response: Optional[str]) -> str:
    """Parse CWE大类分类输出."""
    normalized = normalize_text(response)
    category = canonicalize_category(normalized)
    return category or "Other"

