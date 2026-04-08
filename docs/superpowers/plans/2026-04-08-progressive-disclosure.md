# Progressive Disclosure (Agentic Tool-Use) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace single-prompt detection with multi-turn agentic tool-use where the LLM decides which context (AST, RAG, CWE knowledge) to request.

**Architecture:** `AgenticDetector` replaces `LevelDetector`. First turn: LLM sees code + candidates. LLM can call tools (`get_ast_summary`, `retrieve_similar`, `lookup_cwe`). After 0-N tool calls, LLM outputs final `ranking_v2` JSON. Falls back to single-prompt if endpoint lacks tool support.

**Tech Stack:** Python 3.9+, OpenAI function-calling API, existing RAG retriever, tree-sitter for AST

**Worktree:** `../Mulvul-progressive-disclosure` on branch `feat/progressive-disclosure`

---

## File Structure

| File | Responsibility |
|---|---|
| `src/mulvul/agents/detection_tools.py` | **Create.** `DetectionTool` protocol + `ASTSummaryTool`, `RAGRetrieveTool`, `CWELookupTool` |
| `src/mulvul/agents/agentic_detector.py` | **Create.** `AgenticDetector` with multi-turn tool-use loop |
| `tests/test_agentic_detector.py` | **Create.** Unit tests |
| `src/mulvul/agents/coevolutionary_trainer.py` | **Modify.** Use `AgenticDetector` instead of `LevelDetector` when tools available |

---

### Task 1: Detection Tools

**Files:**
- Create: `src/mulvul/agents/detection_tools.py`
- Test: `tests/test_agentic_detector.py`

- [ ] **Step 1: Write failing tests**

```python
"""Tests for agentic detection with progressive disclosure."""
from __future__ import annotations

import json
import pytest


class TestDetectionTools:
    def test_cwe_lookup_returns_description(self):
        from mulvul.agents.detection_tools import CWELookupTool

        tool = CWELookupTool()
        result = tool.execute(cwe_id="CWE-119")
        assert "buffer" in result.lower() or "overflow" in result.lower()

    def test_ast_summary_extracts_function_calls(self):
        from mulvul.agents.detection_tools import ASTSummaryTool

        tool = ASTSummaryTool()
        code = "void f(char *src) { char buf[8]; strcpy(buf, src); }"
        result = tool.execute(code=code)
        assert "strcpy" in result

    def test_rag_retrieve_returns_examples(self):
        from mulvul.agents.detection_tools import RAGRetrieveTool

        # Without a real KB, should return "no examples" gracefully
        tool = RAGRetrieveTool(retriever=None)
        result = tool.execute(code="int x = 0;", candidate="CWE-119")
        assert "no" in result.lower() or "unavailable" in result.lower()

    def test_tool_schema_has_required_fields(self):
        from mulvul.agents.detection_tools import CWELookupTool

        tool = CWELookupTool()
        schema = tool.to_function_schema()
        assert schema["name"] == "lookup_cwe"
        assert "parameters" in schema
```

- [ ] **Step 2: Implement tools**

```python
"""Detection tools for progressive context disclosure."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Protocol

from mulvul.data.cwe_hierarchy import CWE_DESCRIPTIONS


class DetectionTool(Protocol):
    """Protocol for tools the agentic detector can call."""

    name: str
    description: str

    def execute(self, **kwargs: Any) -> str: ...

    def to_function_schema(self) -> Dict[str, Any]: ...


@dataclass
class CWELookupTool:
    name: str = "lookup_cwe"
    description: str = "Look up the definition and common patterns of a CWE ID"

    def execute(self, *, cwe_id: str, **kwargs: Any) -> str:
        desc = CWE_DESCRIPTIONS.get(cwe_id)
        if desc:
            return f"{cwe_id}: {desc}"
        return f"{cwe_id}: No description available."

    def to_function_schema(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {"cwe_id": {"type": "string", "description": "CWE identifier, e.g. CWE-119"}},
                "required": ["cwe_id"],
            },
        }


@dataclass
class ASTSummaryTool:
    name: str = "get_ast_summary"
    description: str = "Get a summary of the code's structure: function calls, dangerous APIs, control flow"

    def execute(self, *, code: str, **kwargs: Any) -> str:
        # Lightweight regex-based extraction (no tree-sitter dependency required)
        dangerous = ["strcpy", "strcat", "sprintf", "gets", "scanf", "malloc",
                      "free", "realloc", "memcpy", "memmove", "system", "exec",
                      "popen", "eval", "atoi", "rand"]
        found = [fn for fn in dangerous if fn in code]
        funcs = re.findall(r'\b(\w+)\s*\(', code)
        unique_calls = list(dict.fromkeys(funcs))[:20]
        lines = [f"Function calls: {', '.join(unique_calls[:10])}"]
        if found:
            lines.append(f"Dangerous APIs: {', '.join(found)}")
        if "if" in code or "while" in code or "for" in code:
            lines.append("Has control flow (if/while/for)")
        if "NULL" in code or "null" in code or "nullptr" in code:
            lines.append("Contains NULL/null checks or references")
        return "\n".join(lines)

    def to_function_schema(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {"code": {"type": "string", "description": "Source code to analyze"}},
                "required": ["code"],
            },
        }


@dataclass
class RAGRetrieveTool:
    name: str = "retrieve_similar"
    description: str = "Retrieve similar code examples from the vulnerability knowledge base"
    retriever: Any = None

    def execute(self, *, code: str, candidate: str = "", **kwargs: Any) -> str:
        if self.retriever is None:
            return "Knowledge base unavailable. No similar examples found."
        try:
            samples = self.retriever.retrieve(code, top_k=3)
            if not samples:
                return "No similar examples found."
            lines = []
            for i, s in enumerate(samples[:3], 1):
                lines.append(f"Example {i} [{s.get('cwe', '')}]: {s.get('code', '')[:200]}...")
            return "\n".join(lines)
        except Exception:
            return "Retrieval failed. No examples available."

    def to_function_schema(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "code": {"type": "string", "description": "Code to find similar examples for"},
                    "candidate": {"type": "string", "description": "Optional CWE to focus retrieval on"},
                },
                "required": ["code"],
            },
        }
```

- [ ] **Step 3: Run tests, commit**

```bash
uv run pytest tests/test_agentic_detector.py::TestDetectionTools -v
git add src/mulvul/agents/detection_tools.py tests/test_agentic_detector.py
git commit -m "feat: add detection tools for progressive disclosure"
```

---

### Task 2: AgenticDetector

**Files:**
- Create: `src/mulvul/agents/agentic_detector.py`
- Test: `tests/test_agentic_detector.py`

- [ ] **Step 1: Write failing tests**

```python
class TestAgenticDetector:
    def test_detect_returns_ranked_predictions(self):
        from mulvul.agents.agentic_detector import AgenticDetector
        from mulvul.agents.detection_tools import CWELookupTool

        class StubClient:
            def chat_with_tools(self, messages, tools, **kw):
                # Simulate: LLM calls lookup_cwe, then returns prediction
                return {
                    "role": "assistant",
                    "content": '{"predictions":[{"category":"Memory","confidence":0.9}]}',
                    "tool_calls": None,
                }

        detector = AgenticDetector(
            llm_client=StubClient(),
            tools=[CWELookupTool()],
            candidates=["Memory", "Injection", "Benign"],
        )
        results = detector.detect("strcpy(buf, input);")
        assert len(results) >= 1
        assert results[0][0] == "Memory"

    def test_fallback_single_prompt_when_no_tool_support(self):
        from mulvul.agents.agentic_detector import AgenticDetector

        class BasicClient:
            def generate(self, prompt, **kw):
                return '{"predictions":[{"category":"Benign","confidence":0.8}]}'

        detector = AgenticDetector(
            llm_client=BasicClient(),
            tools=[],
            candidates=["Memory", "Benign"],
        )
        results = detector.detect("int x = 0;")
        assert results[0][0] == "Benign"

    def test_max_turns_limits_tool_calls(self):
        from mulvul.agents.agentic_detector import AgenticDetector
        from mulvul.agents.detection_tools import CWELookupTool

        call_count = 0

        class LoopyClient:
            def chat_with_tools(self, messages, tools, **kw):
                nonlocal call_count
                call_count += 1
                if call_count <= 5:
                    return {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [{"function": {"name": "lookup_cwe",
                                        "arguments": '{"cwe_id":"CWE-119"}'}}],
                    }
                return {
                    "role": "assistant",
                    "content": '{"predictions":[{"category":"Memory","confidence":0.5}]}',
                    "tool_calls": None,
                }

        detector = AgenticDetector(
            llm_client=LoopyClient(),
            tools=[CWELookupTool()],
            candidates=["Memory", "Benign"],
            max_turns=3,
        )
        results = detector.detect("code")
        assert call_count <= 4  # max_turns + 1 for final answer
```

- [ ] **Step 2: Implement AgenticDetector**

```python
"""Multi-turn agentic detector with progressive context disclosure."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Tuple

from .detection_tools import DetectionTool


class AgenticDetector:
    """Detector that lets the LLM call tools to gather context before classifying."""

    def __init__(
        self,
        llm_client: Any,
        tools: List[DetectionTool],
        candidates: List[str],
        max_turns: int = 3,
        target: str = "",
        stage: str = "major",
    ):
        self.llm_client = llm_client
        self.tools = {t.name: t for t in tools}
        self.tool_schemas = [t.to_function_schema() for t in tools]
        self.candidates = candidates
        self.max_turns = max_turns
        self.target = target
        self.stage = stage

    def detect(self, code: str, top_k: int = 2) -> List[Tuple[str, float]]:
        """Run multi-turn detection. Falls back to single-prompt if tools unavailable."""
        if not self.tools or not hasattr(self.llm_client, "chat_with_tools"):
            return self._fallback_detect(code, top_k)
        return self._agentic_detect(code, top_k)

    def _agentic_detect(self, code: str, top_k: int) -> List[Tuple[str, float]]:
        candidates_str = ", ".join(self.candidates)
        messages = [
            {"role": "system", "content": (
                f"You are a vulnerability detector. Classify the code into one of: {candidates_str}.\n"
                "You have tools available to get more context. Use them if needed, then output your classification.\n"
                'Final answer must be JSON: {"predictions":[{"category":"...","confidence":0.0}]}'
            )},
            {"role": "user", "content": f"```\n{code[:4000]}\n```"},
        ]

        for turn in range(self.max_turns):
            response = self.llm_client.chat_with_tools(
                messages, self.tool_schemas
            )

            if response.get("tool_calls"):
                for tc in response["tool_calls"]:
                    fn_name = tc["function"]["name"]
                    fn_args = json.loads(tc["function"]["arguments"])
                    tool = self.tools.get(fn_name)
                    if tool:
                        result = tool.execute(**fn_args)
                    else:
                        result = f"Unknown tool: {fn_name}"
                    messages.append({"role": "assistant", "content": None, "tool_calls": [tc]})
                    messages.append({"role": "tool", "name": fn_name, "content": result})
            else:
                # LLM gave final answer
                content = response.get("content", "")
                return self._parse_response(content, top_k)

        # Max turns exhausted — force final answer
        messages.append({"role": "user", "content": "Please provide your final classification now."})
        response = self.llm_client.chat_with_tools(messages, [])
        return self._parse_response(response.get("content", ""), top_k)

    def _fallback_detect(self, code: str, top_k: int) -> List[Tuple[str, float]]:
        """Single-prompt fallback for clients without tool support."""
        candidates_str = ", ".join(self.candidates)
        prompt = (
            f"Classify this code into one of: {candidates_str}.\n\n"
            f"```\n{code[:4000]}\n```\n\n"
            '{"predictions":[{"category":"...","confidence":0.0}]}'
        )
        response = self.llm_client.generate(prompt)
        return self._parse_response(response, top_k)

    def _parse_response(self, text: str, top_k: int) -> List[Tuple[str, float]]:
        try:
            match = re.search(r'\{[\s\S]*\}', text)
            if match:
                data = json.loads(match.group())
                predictions = data.get("predictions", [])
                return [
                    (p.get("category", p.get("cwe", "Benign")), float(p.get("confidence", 0.5)))
                    for p in predictions[:top_k]
                ]
        except (json.JSONDecodeError, ValueError):
            pass
        return [("Benign", 0.5)]
```

- [ ] **Step 3: Run tests, commit**

```bash
uv run pytest tests/test_agentic_detector.py -v
git add src/mulvul/agents/agentic_detector.py tests/test_agentic_detector.py
git commit -m "feat: add AgenticDetector with multi-turn tool-use"
```

---

### Task 3: Integration & Ablation

- [ ] **Step 1: Add `--agentic` flag to CLI and wire into trainer**
- [ ] **Step 2: Run ablation on PrimeVul-Balanced-20**
- [ ] **Step 3: Push PR with results**
