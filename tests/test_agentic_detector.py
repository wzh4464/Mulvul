"""Tests for agentic detector and detection tools."""
from __future__ import annotations

import json

import pytest


# ---------------------------------------------------------------------------
# Tool tests
# ---------------------------------------------------------------------------


class TestCWELookupTool:
    def test_returns_description_for_known_cwe(self):
        from mulvul.agents.detection_tools import CWELookupTool

        tool = CWELookupTool()
        result = tool.execute(cwe_id="CWE-119")
        assert "buffer" in result.lower()

    def test_returns_not_found_for_unknown_cwe(self):
        from mulvul.agents.detection_tools import CWELookupTool

        tool = CWELookupTool()
        result = tool.execute(cwe_id="CWE-99999")
        assert "no description" in result.lower() or "not found" in result.lower()

    def test_schema_has_name_and_parameters(self):
        from mulvul.agents.detection_tools import CWELookupTool

        tool = CWELookupTool()
        schema = tool.to_function_schema()
        assert schema["name"] == "lookup_cwe"
        assert "parameters" in schema
        assert "cwe_id" in schema["parameters"]["properties"]

    def test_name_attribute(self):
        from mulvul.agents.detection_tools import CWELookupTool

        tool = CWELookupTool()
        assert tool.name == "lookup_cwe"


class TestASTSummaryTool:
    def test_extracts_strcpy_from_buffer_overflow_code(self):
        from mulvul.agents.detection_tools import ASTSummaryTool

        tool = ASTSummaryTool()
        code = """
void vulnerable(char *input) {
    char buf[64];
    strcpy(buf, input);
}
"""
        result = tool.execute(code=code)
        assert "strcpy" in result

    def test_detects_malloc_and_free(self):
        from mulvul.agents.detection_tools import ASTSummaryTool

        tool = ASTSummaryTool()
        code = """
void f() {
    int *p = malloc(sizeof(int));
    free(p);
    *p = 42;
}
"""
        result = tool.execute(code=code)
        assert "malloc" in result
        assert "free" in result

    def test_detects_null_references(self):
        from mulvul.agents.detection_tools import ASTSummaryTool

        tool = ASTSummaryTool()
        code = """
void f(int *p) {
    if (p == NULL) return;
    *p = 0;
}
"""
        result = tool.execute(code=code)
        assert "NULL" in result

    def test_detects_control_flow(self):
        from mulvul.agents.detection_tools import ASTSummaryTool

        tool = ASTSummaryTool()
        code = """
void f(int x) {
    if (x > 0) {
        while (x--) {}
    }
}
"""
        result = tool.execute(code=code)
        assert "if" in result.lower() or "control" in result.lower()

    def test_schema_has_name_and_parameters(self):
        from mulvul.agents.detection_tools import ASTSummaryTool

        tool = ASTSummaryTool()
        schema = tool.to_function_schema()
        assert schema["name"] == "get_ast_summary"
        assert "parameters" in schema
        assert "code" in schema["parameters"]["properties"]

    def test_name_attribute(self):
        from mulvul.agents.detection_tools import ASTSummaryTool

        tool = ASTSummaryTool()
        assert tool.name == "get_ast_summary"


class TestRAGRetrieveTool:
    def test_returns_unavailable_when_no_retriever(self):
        from mulvul.agents.detection_tools import RAGRetrieveTool

        tool = RAGRetrieveTool()
        result = tool.execute(code="void f() {}")
        assert "unavailable" in result.lower()

    def test_returns_unavailable_with_none_retriever(self):
        from mulvul.agents.detection_tools import RAGRetrieveTool

        tool = RAGRetrieveTool(retriever=None)
        result = tool.execute(code="void f() {}")
        assert "unavailable" in result.lower()

    def test_calls_retriever_when_provided(self):
        from mulvul.agents.detection_tools import RAGRetrieveTool

        class StubRetriever:
            def retrieve(self, code, top_k=3):
                return [{"code": "similar code", "cwe": "CWE-119", "score": 0.9}]

        tool = RAGRetrieveTool(retriever=StubRetriever())
        result = tool.execute(code="void f() { char buf[8]; strcpy(buf, x); }")
        assert "CWE-119" in result or "similar" in result.lower()

    def test_schema_has_name_and_parameters(self):
        from mulvul.agents.detection_tools import RAGRetrieveTool

        tool = RAGRetrieveTool()
        schema = tool.to_function_schema()
        assert schema["name"] == "retrieve_similar"
        assert "parameters" in schema
        assert "code" in schema["parameters"]["properties"]

    def test_name_attribute(self):
        from mulvul.agents.detection_tools import RAGRetrieveTool

        tool = RAGRetrieveTool()
        assert tool.name == "retrieve_similar"


# ---------------------------------------------------------------------------
# AgenticDetector tests
# ---------------------------------------------------------------------------


class StubToolCallClient:
    """Simulates a client with chat_with_tools that returns tool calls then content."""

    def __init__(self, tool_responses=None, final_response=None):
        self._call_count = 0
        self._tool_responses = tool_responses or []
        self._final_response = final_response or json.dumps({
            "predictions": [
                {"category": "Memory", "confidence": 0.85},
                {"category": "Benign", "confidence": 0.15},
            ]
        })

    def chat_with_tools(self, messages, tools=None, **kwargs):
        if self._call_count < len(self._tool_responses):
            resp = self._tool_responses[self._call_count]
            self._call_count += 1
            return resp
        self._call_count += 1
        return {"role": "assistant", "content": self._final_response}

    def generate(self, prompt, **kwargs):
        return self._final_response


class StubSimpleClient:
    """Client without chat_with_tools -- triggers fallback path."""

    def __init__(self, response=None):
        self._response = response or json.dumps({
            "predictions": [
                {"category": "Memory", "confidence": 0.90},
                {"category": "Benign", "confidence": 0.10},
            ]
        })

    def generate(self, prompt, **kwargs):
        return self._response


class TestAgenticDetector:
    def test_detect_returns_ranked_predictions_with_tool_client(self):
        from mulvul.agents.agentic_detector import AgenticDetector
        from mulvul.agents.detection_tools import CWELookupTool, ASTSummaryTool

        client = StubToolCallClient()
        detector = AgenticDetector(
            llm_client=client,
            tools=[CWELookupTool(), ASTSummaryTool()],
            candidates=["Memory", "Injection", "Benign"],
            stage="major",
        )
        results = detector.detect("void f() { char buf[8]; strcpy(buf, x); }")
        assert len(results) >= 1
        assert isinstance(results[0], tuple)
        assert len(results[0]) == 2
        name, confidence = results[0]
        assert isinstance(name, str)
        assert isinstance(confidence, float)

    def test_fallback_to_single_prompt_when_no_tool_support(self):
        from mulvul.agents.agentic_detector import AgenticDetector
        from mulvul.agents.detection_tools import CWELookupTool

        client = StubSimpleClient()
        detector = AgenticDetector(
            llm_client=client,
            tools=[CWELookupTool()],
            candidates=["Memory", "Injection", "Benign"],
            stage="major",
        )
        results = detector.detect("void f() { char buf[8]; strcpy(buf, x); }")
        assert len(results) >= 1
        # Should parse the response from generate()
        assert results[0][0] == "Memory"

    def test_max_turns_limits_tool_call_loops(self):
        from mulvul.agents.agentic_detector import AgenticDetector
        from mulvul.agents.detection_tools import CWELookupTool

        # Client returns tool_calls every time, never content
        infinite_tool_calls = [
            {
                "role": "assistant",
                "tool_calls": [
                    {"id": f"call_{i}", "function": {"name": "lookup_cwe", "arguments": '{"cwe_id": "CWE-119"}'}}
                ],
            }
            for i in range(10)
        ]

        client = StubToolCallClient(
            tool_responses=infinite_tool_calls,
            final_response=json.dumps({
                "predictions": [{"category": "Memory", "confidence": 0.80}]
            }),
        )
        detector = AgenticDetector(
            llm_client=client,
            tools=[CWELookupTool()],
            candidates=["Memory", "Benign"],
            max_turns=3,
            stage="major",
        )
        results = detector.detect("void f() {}")
        # Should have stopped after max_turns tool call rounds
        # The client was called at most max_turns+1 times (max_turns tool rounds + 1 final)
        assert client._call_count <= 4  # 3 tool rounds + 1 final or just 3 tool rounds with fallback

    def test_tool_calls_are_executed_and_results_appended(self):
        from mulvul.agents.agentic_detector import AgenticDetector
        from mulvul.agents.detection_tools import CWELookupTool

        tool_call_response = {
            "role": "assistant",
            "tool_calls": [
                {
                    "id": "call_1",
                    "function": {
                        "name": "lookup_cwe",
                        "arguments": json.dumps({"cwe_id": "CWE-119"}),
                    },
                }
            ],
        }

        client = StubToolCallClient(
            tool_responses=[tool_call_response],
            final_response=json.dumps({
                "predictions": [{"category": "Memory", "confidence": 0.90}]
            }),
        )
        detector = AgenticDetector(
            llm_client=client,
            tools=[CWELookupTool()],
            candidates=["Memory", "Benign"],
            stage="major",
        )
        results = detector.detect("int *p = malloc(4);")
        assert results[0][0] == "Memory"
        # Client should have been called twice: once for tool call, once for final
        assert client._call_count == 2

    def test_detect_with_empty_candidates_returns_benign(self):
        from mulvul.agents.agentic_detector import AgenticDetector

        client = StubSimpleClient(response='{"predictions": []}')
        detector = AgenticDetector(
            llm_client=client,
            tools=[],
            candidates=[],
            stage="major",
        )
        results = detector.detect("safe code")
        assert len(results) >= 1
        assert results[0][0] == "Benign"

    def test_detect_with_top_k(self):
        from mulvul.agents.agentic_detector import AgenticDetector

        response = json.dumps({
            "predictions": [
                {"category": "Memory", "confidence": 0.50},
                {"category": "Injection", "confidence": 0.30},
                {"category": "Benign", "confidence": 0.20},
            ]
        })
        client = StubSimpleClient(response=response)
        detector = AgenticDetector(
            llm_client=client,
            tools=[],
            candidates=["Memory", "Injection", "Benign"],
            stage="major",
        )
        results = detector.detect("void f() {}", top_k=2)
        assert len(results) == 2


# ---------------------------------------------------------------------------
# Integration: coevolutionary trainer with use_agentic flag
# ---------------------------------------------------------------------------


class TestCoevolutionaryTrainerAgenticFlag:
    def test_use_agentic_flag_accepted(self):
        """Trainer __init__ accepts use_agentic parameter."""
        from mulvul.agents.coevolutionary_trainer import CoevolutionaryTrainer

        class MinimalSampler:
            def get_all_majors(self):
                return ["Memory"]
            def get_all_middles(self):
                return ["Buffer Errors"]
            def get_all_cwes(self, min_samples=0):
                return ["CWE-120"]
            def sample_for_major(self, target, n):
                return []
            def sample_for_middle(self, target, n):
                return []
            def sample_for_cwe(self, target, n):
                return []

        class MinimalClient:
            def generate(self, prompt, **kwargs):
                return '{"predictions":[{"category":"Benign","confidence":0.7}]}'

        trainer = CoevolutionaryTrainer(
            llm_client=MinimalClient(),
            sampler=MinimalSampler(),
            output_dir="/tmp/test_agentic",
            use_agentic=True,
        )
        assert trainer.use_agentic is True

    def test_use_agentic_defaults_to_false(self, tmp_path):
        """Without explicit flag, use_agentic defaults to False."""
        from mulvul.agents.coevolutionary_trainer import CoevolutionaryTrainer

        class MinimalSampler:
            def get_all_majors(self):
                return ["Memory"]
            def get_all_middles(self):
                return ["Buffer Errors"]
            def get_all_cwes(self, min_samples=0):
                return ["CWE-120"]
            def sample_for_major(self, target, n):
                return []
            def sample_for_middle(self, target, n):
                return []
            def sample_for_cwe(self, target, n):
                return []

        class MinimalClient:
            def generate(self, prompt, **kwargs):
                return '{"predictions":[{"category":"Benign","confidence":0.7}]}'

        trainer = CoevolutionaryTrainer(
            llm_client=MinimalClient(),
            sampler=MinimalSampler(),
            output_dir=str(tmp_path),
        )
        assert trainer.use_agentic is False
