"""Regression tests for evolution startup and bootstrap issues."""

from __future__ import annotations

import importlib.util
from pathlib import Path

from mulvul.core.evolution import EvolutionEngine


class _RecordingAlgorithm:
    def __init__(self):
        self.last_kwargs = None

    def evolve(self, evaluator, llm_client, **kwargs):
        self.last_kwargs = {
            "evaluator": evaluator,
            "llm_client": llm_client,
            **kwargs,
        }
        return {"ok": True}


def test_evolution_engine_forwards_runtime_overrides():
    algorithm = _RecordingAlgorithm()
    evaluator = object()
    llm_client = object()
    engine = EvolutionEngine(
        algorithm=algorithm,
        evaluator=evaluator,
        llm_client=llm_client,
        config={"population_size": 5, "max_generations": 2},
    )

    result = engine.evolve(initial_prompts=["prompt-a"], population_size=3)

    assert result == {"ok": True}
    assert algorithm.last_kwargs is not None
    assert algorithm.last_kwargs["evaluator"] is evaluator
    assert algorithm.last_kwargs["llm_client"] is llm_client
    assert algorithm.last_kwargs["initial_prompts"] == ["prompt-a"]
    assert algorithm.last_kwargs["population_size"] == 3
    assert algorithm.last_kwargs["max_generations"] == 2


def test_create_default_client_falls_back_when_openai_sdk_unavailable(monkeypatch):
    from mulvul.llm import client as client_module

    class FakeSVENBackend:
        model_name = "gpt-4o"

    sentinel = FakeSVENBackend()

    def fake_sven_client(**kwargs):
        assert kwargs["model_name"] == "gpt-4o"
        assert kwargs["api_base"] == "https://example.invalid/v1"
        assert kwargs["api_key"] == "dummy-key"
        return sentinel

    monkeypatch.setattr(client_module, "HAS_OPENAI", False)
    monkeypatch.setattr(
        client_module,
        "OPENAI_IMPORT_ERROR",
        ModuleNotFoundError("pydantic_core._pydantic_core"),
    )
    monkeypatch.setattr(client_module, "SVENLLMClient", fake_sven_client)

    client = client_module.create_default_client(
        model_name="gpt-4o",
        api_base="https://example.invalid/v1",
        api_key="dummy-key",
    )

    assert isinstance(client, client_module.LLMRuntime)
    assert client.backend is sentinel
    assert client.config.enable_cache is True


def test_llm_client_module_imports_cleanly():
    from mulvul.llm import client as client_module

    assert hasattr(client_module, "LLMClient")


def test_async_llm_client_module_imports_cleanly():
    from mulvul.llm import async_client as async_client_module

    assert hasattr(async_client_module, "AsyncLLMClient")


def test_parallel_hierarchical_runner_imports_cleanly():
    project_root = Path(__file__).resolve().parents[1]
    script_path = project_root / "scripts" / "ablations" / "run_parallel_hierarchical_evolution.py"

    spec = importlib.util.spec_from_file_location(
        "test_parallel_hierarchical_runner",
        script_path,
    )
    assert spec is not None
    assert spec.loader is not None

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    assert hasattr(module, "ParallelHierarchicalEvolutionPipeline")
