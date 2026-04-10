"""Detection tools for agentic vulnerability analysis.

Three lightweight tools the LLM can call during multi-turn detection:

- CWELookupTool: returns CWE description from the canonical taxonomy.
- ASTSummaryTool: regex-based code structure analysis (no tree-sitter).
- RAGRetrieveTool: retrieves similar code from an optional knowledge base.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, Optional


class CWELookupTool:
    """Look up a CWE description from the canonical CWE_DESCRIPTIONS dict."""

    name = "lookup_cwe"

    def execute(self, **kwargs: Any) -> str:
        from mulvul.data.cwe_hierarchy import CWE_DESCRIPTIONS

        cwe_id: str = kwargs.get("cwe_id", "")
        description = CWE_DESCRIPTIONS.get(cwe_id)
        if description is None:
            return f"No description found for {cwe_id}."
        return f"{cwe_id}: {description}"

    def to_function_schema(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": "Look up the description of a CWE by its ID (e.g. CWE-119).",
            "parameters": {
                "type": "object",
                "properties": {
                    "cwe_id": {
                        "type": "string",
                        "description": "The CWE identifier, e.g. 'CWE-119'.",
                    }
                },
                "required": ["cwe_id"],
            },
        }


# Patterns for ASTSummaryTool
_DANGEROUS_APIS = (
    "strcpy", "strcat", "sprintf", "gets",
    "malloc", "calloc", "realloc", "free",
    "system", "exec", "popen",
    "memcpy", "memmove", "memset",
)
_DANGEROUS_API_RE = re.compile(
    r"\b(" + "|".join(re.escape(api) for api in _DANGEROUS_APIS) + r")\s*\(",
)
_FUNC_CALL_RE = re.compile(r"\b([a-zA-Z_]\w*)\s*\(")
_CONTROL_FLOW_RE = re.compile(r"\b(if|else|while|for|switch|do)\b")
_NULL_REF_RE = re.compile(r"\bNULL\b|nullptr\b")


class ASTSummaryTool:
    """Lightweight regex-based code analysis -- no tree-sitter required."""

    name = "get_ast_summary"

    def execute(self, **kwargs: Any) -> str:
        code: str = kwargs.get("code", "")

        # Extract function calls
        func_calls = sorted(set(_FUNC_CALL_RE.findall(code)))

        # Dangerous APIs found
        dangerous = sorted(set(_DANGEROUS_API_RE.findall(code)))

        # Control flow keywords
        control = sorted(set(_CONTROL_FLOW_RE.findall(code)))

        # NULL references
        null_refs = _NULL_REF_RE.findall(code)

        lines = []
        if func_calls:
            lines.append(f"Function calls: {', '.join(func_calls)}")
        if dangerous:
            lines.append(f"Dangerous APIs: {', '.join(dangerous)}")
        if control:
            lines.append(f"Control flow: {', '.join(control)}")
        if null_refs:
            lines.append(f"NULL references: {len(null_refs)} occurrence(s)")

        if not lines:
            return "No notable patterns detected."
        return "\n".join(lines)

    def to_function_schema(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": "Analyze code structure: extract function calls, dangerous APIs, control flow, and NULL references.",
            "parameters": {
                "type": "object",
                "properties": {
                    "code": {
                        "type": "string",
                        "description": "The source code to analyze.",
                    }
                },
                "required": ["code"],
            },
        }


class RAGRetrieveTool:
    """Retrieve similar code from a knowledge base."""

    name = "retrieve_similar"

    def __init__(self, retriever: Any | None = None) -> None:
        self._retriever = retriever

    def execute(self, **kwargs: Any) -> str:
        code: str = kwargs.get("code", "")
        candidate: str | None = kwargs.get("candidate")

        if self._retriever is None:
            return "RAG retrieval is unavailable (no knowledge base configured)."

        try:
            results = self._retriever.retrieve(code, top_k=3)
        except Exception as exc:
            return f"RAG retrieval failed: {exc}"

        if not results:
            return "No similar code found in the knowledge base."

        lines = []
        for i, item in enumerate(results[:3], 1):
            cwe = item.get("cwe", "unknown")
            score = item.get("score", 0.0)
            snippet = item.get("code", "")[:200]
            lines.append(f"Match {i} [CWE: {cwe}, score: {score:.2f}]: {snippet}...")
        return "\n".join(lines)

    def to_function_schema(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": "Retrieve similar code snippets from the vulnerability knowledge base.",
            "parameters": {
                "type": "object",
                "properties": {
                    "code": {
                        "type": "string",
                        "description": "The source code to find similar examples for.",
                    },
                    "candidate": {
                        "type": "string",
                        "description": "Optional candidate vulnerability type to focus retrieval on.",
                    },
                },
                "required": ["code"],
            },
        }
