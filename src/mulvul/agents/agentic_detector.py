"""Agentic detector with progressive context disclosure.

Uses multi-turn tool-calling to let the LLM gather additional context
(CWE descriptions, code analysis, RAG examples) before making a final
vulnerability classification.  Falls back to single-prompt detection
when the LLM client does not support ``chat_with_tools``.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

_JSON_RE = re.compile(r"\{[\s\S]*\}")


class AgenticDetector:
    """Multi-turn detector with progressive context disclosure.

    Parameters
    ----------
    llm_client:
        An LLM client.  If it exposes ``chat_with_tools``, the agentic
        loop is used; otherwise detection falls back to a single
        ``generate()`` call identical to ``LevelDetector``.
    tools:
        List of tool instances (each must have ``name``, ``execute``,
        ``to_function_schema``).
    candidates:
        Possible classification labels at this stage.
    max_turns:
        Maximum number of tool-call rounds before forcing a final answer.
    target:
        The taxonomy node being evaluated (e.g. "Memory").
    stage:
        One of "major", "middle", "cwe".
    """

    def __init__(
        self,
        llm_client: Any,
        tools: List[Any],
        candidates: List[str],
        max_turns: int = 3,
        target: str = "",
        stage: str = "major",
    ) -> None:
        self.llm_client = llm_client
        self.tools = {t.name: t for t in tools}
        self.candidates = candidates
        self.max_turns = max_turns
        self.target = target
        self.stage = stage

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect(self, code: str, top_k: int = 2) -> List[Tuple[str, float]]:
        """Classify *code* and return up to *top_k* ranked predictions.

        Returns a list of ``(label, confidence)`` tuples sorted by
        descending confidence.
        """
        if hasattr(self.llm_client, "chat_with_tools"):
            return self._agentic_detect(code, top_k)
        return self._fallback_detect(code, top_k)

    # ------------------------------------------------------------------
    # Agentic (multi-turn) path
    # ------------------------------------------------------------------

    def _agentic_detect(self, code: str, top_k: int) -> List[Tuple[str, float]]:
        candidates_str = ", ".join(self.candidates)
        tool_schemas = [t.to_function_schema() for t in self.tools.values()]

        messages: List[Dict[str, Any]] = [
            {
                "role": "system",
                "content": (
                    "You are a vulnerability detector. "
                    f"Classify the following code into one of: {candidates_str}. "
                    "You have tools available. Use them if you need more context "
                    "before making your decision.\n\n"
                    "When ready, respond with a JSON object containing a "
                    '"predictions" array, each with "category" (or "cwe") and '
                    '"confidence" fields.'
                ),
            },
            {
                "role": "user",
                "content": f"```\n{code[:4000]}\n```",
            },
        ]

        for turn in range(self.max_turns):
            response = self.llm_client.chat_with_tools(
                messages, tools=tool_schemas
            )

            # If the response has tool_calls, execute them and loop
            tool_calls = response.get("tool_calls")
            if tool_calls:
                # Append the assistant message with tool calls
                messages.append(response)
                for tc in tool_calls:
                    func_name = tc["function"]["name"]
                    try:
                        args = json.loads(tc["function"]["arguments"])
                    except (json.JSONDecodeError, KeyError):
                        args = {}

                    tool = self.tools.get(func_name)
                    if tool is not None:
                        result = tool.execute(**args)
                    else:
                        result = f"Unknown tool: {func_name}"

                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc.get("id", ""),
                        "content": result,
                    })
                continue

            # No tool calls -- treat content as the final answer
            content = response.get("content", "")
            return self._parse_response(content, top_k)

        # Exhausted max_turns -- try to parse whatever we have
        # Make one last call without tools to force a content response
        logger.debug(
            "AgenticDetector exhausted %d turns; forcing final answer",
            self.max_turns,
        )
        # Try the last response if it had content
        last_content = messages[-1].get("content", "") if messages else ""
        parsed = self._parse_response(last_content, top_k)
        if parsed and parsed[0][0] != "Benign":
            return parsed
        return [("Benign", 0.5)]

    # ------------------------------------------------------------------
    # Fallback (single-prompt) path -- identical to LevelDetector
    # ------------------------------------------------------------------

    def _fallback_detect(self, code: str, top_k: int) -> List[Tuple[str, float]]:
        candidates_str = ", ".join(self.candidates)
        prompt = (
            f"You are a vulnerability detector. "
            f"Classify the code into one of: {candidates_str}.\n\n"
            f"## Code:\n```\n{code[:4000]}\n```\n\n"
            '## Output (JSON):\n{"predictions":[{"category":"...","confidence":0.0}]}'
        )
        response = self.llm_client.generate(prompt)
        return self._parse_response(response, top_k)

    # ------------------------------------------------------------------
    # Response parsing
    # ------------------------------------------------------------------

    def _parse_response(
        self, response: str, top_k: int
    ) -> List[Tuple[str, float]]:
        """Extract ranked predictions from an LLM response string."""
        try:
            json_match = _JSON_RE.search(response)
            if json_match:
                data = json.loads(json_match.group())
                predictions = data.get("predictions", [])
                results = [
                    (
                        p.get("category", p.get("cwe", "Unknown")),
                        float(p.get("confidence", 0.5)),
                    )
                    for p in predictions[:top_k]
                ]
                if results:
                    return results
        except (json.JSONDecodeError, ValueError, TypeError):
            pass

        # Fallback: keyword matching against candidates
        results: List[Tuple[str, float]] = []
        response_lower = response.lower()
        for candidate in self.candidates:
            if candidate.lower() in response_lower:
                pos = response_lower.find(candidate.lower())
                score = 1.0 - (pos / max(len(response_lower), 1))
                results.append((candidate, min(score, 0.9)))

        results.sort(key=lambda x: x[1], reverse=True)
        return results[:top_k] if results else [("Benign", 0.5)]
