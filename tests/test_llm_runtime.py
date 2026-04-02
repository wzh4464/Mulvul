"""Tests for unified LLM runtime, stub client, and response cache."""
from __future__ import annotations

import asyncio
import json
import pytest
from pathlib import Path

from evoprompt.llm.stub import DeterministicStubClient
from evoprompt.llm.cache import ResponseCache
from evoprompt.llm.runtime import LLMRuntime, LLMRuntimeConfig


class TestDeterministicStubClient:
    """Tests for DeterministicStubClient."""

    def test_stub_client_exact_match(self):
        stub = DeterministicStubClient(
            responses={"What is 1+1?": "2"}
        )
        assert stub.generate("What is 1+1?") == "2"

    def test_stub_client_default_response(self):
        stub = DeterministicStubClient(default_response="Benign")
        assert stub.generate("unknown prompt") == "Benign"

    def test_stub_client_pattern_matching(self):
        stub = DeterministicStubClient()
        stub.add_response(r".*buffer overflow.*", "CWE-120 vulnerability detected")
        assert stub.generate("check for buffer overflow in this code") == "CWE-120 vulnerability detected"

    def test_stub_client_exact_match_takes_priority(self):
        stub = DeterministicStubClient(
            responses={"exact prompt": "exact response"}
        )
        stub.add_response(r"exact.*", "pattern response")
        assert stub.generate("exact prompt") == "exact response"

    def test_stub_client_generate_sync(self):
        stub = DeterministicStubClient(responses={"hello": "world"})
        assert stub.generate("hello") == "world"

    def test_stub_client_generate_async(self):
        stub = DeterministicStubClient(responses={"hello": "world"})
        result = asyncio.run(stub.generate_async("hello"))
        assert result == "world"

    def test_stub_client_batch_generate(self):
        stub = DeterministicStubClient(
            responses={"a": "1", "b": "2"},
            default_response="0"
        )
        results = stub.batch_generate(["a", "b", "c"])
        assert results == ["1", "2", "0"]

    def test_stub_client_batch_generate_async(self):
        stub = DeterministicStubClient(
            responses={"x": "10"},
            default_response="0"
        )
        results = asyncio.run(stub.batch_generate_async(["x", "y"]))
        assert results == ["10", "0"]

    def test_stub_client_call_count(self):
        stub = DeterministicStubClient(default_response="ok")
        stub.generate("a")
        stub.generate("b")
        assert stub.call_count == 2

    def test_stub_client_call_history(self):
        stub = DeterministicStubClient(default_response="ok")
        stub.generate("prompt1")
        stub.generate("prompt2")
        assert stub.call_history == ["prompt1", "prompt2"]


class TestResponseCache:
    """Tests for ResponseCache."""

    def test_cache_put_get_roundtrip(self, tmp_path):
        cache = ResponseCache(cache_dir=tmp_path / "cache")
        cache.put("prompt1", "response1", model="test-model")
        result = cache.get("prompt1", model="test-model")
        assert result == "response1"

    def test_cache_miss_returns_none(self, tmp_path):
        cache = ResponseCache(cache_dir=tmp_path / "cache")
        assert cache.get("missing", model="test") is None

    def test_cache_key_includes_temperature(self, tmp_path):
        cache = ResponseCache(cache_dir=tmp_path / "cache")
        cache.put("same prompt", "cold response", model="m", temperature=0.0)
        cache.put("same prompt", "hot response", model="m", temperature=1.0)
        assert cache.get("same prompt", model="m", temperature=0.0) == "cold response"
        assert cache.get("same prompt", model="m", temperature=1.0) == "hot response"

    def test_cache_key_includes_model(self, tmp_path):
        cache = ResponseCache(cache_dir=tmp_path / "cache")
        cache.put("prompt", "resp_a", model="model-a")
        cache.put("prompt", "resp_b", model="model-b")
        assert cache.get("prompt", model="model-a") == "resp_a"
        assert cache.get("prompt", model="model-b") == "resp_b"

    def test_cache_stats(self, tmp_path):
        cache = ResponseCache(cache_dir=tmp_path / "cache")
        cache.put("p1", "r1", model="m")
        cache.get("p1", model="m")  # hit
        cache.get("p2", model="m")  # miss
        stats = cache.stats()
        assert stats["hits"] == 1
        assert stats["misses"] == 1
        assert stats["size"] == 1

    def test_cache_clear(self, tmp_path):
        cache = ResponseCache(cache_dir=tmp_path / "cache")
        cache.put("p1", "r1", model="m")
        cache.clear()
        assert cache.get("p1", model="m") is None
        assert cache.stats()["size"] == 0

    def test_cache_persistence(self, tmp_path):
        cache_dir = tmp_path / "cache"
        cache1 = ResponseCache(cache_dir=cache_dir)
        cache1.put("persistent", "data", model="m")

        cache2 = ResponseCache(cache_dir=cache_dir)
        assert cache2.get("persistent", model="m") == "data"


class TestLLMRuntimeConfig:
    """Tests for LLMRuntimeConfig."""

    def test_runtime_config_defaults(self):
        config = LLMRuntimeConfig()
        assert config.max_retries == 3
        assert config.retry_delay == 1.0
        assert config.max_concurrency == 16
        assert config.timeout == 30.0
        assert config.enable_cache is False

    def test_runtime_config_custom(self):
        config = LLMRuntimeConfig(
            max_retries=5,
            enable_cache=True,
            model_name="test-model",
        )
        assert config.max_retries == 5
        assert config.enable_cache is True
        assert config.model_name == "test-model"


class TestLLMRuntime:
    """Tests for LLMRuntime."""

    def test_runtime_generate_uses_stub(self):
        stub = DeterministicStubClient(responses={"hello": "world"})
        runtime = LLMRuntime(backend=stub)
        assert runtime.generate("hello") == "world"

    def test_runtime_generate_async(self):
        stub = DeterministicStubClient(responses={"async": "result"})
        runtime = LLMRuntime(backend=stub)
        result = asyncio.run(runtime.generate_async("async"))
        assert result == "result"

    def test_runtime_batch_generate(self):
        stub = DeterministicStubClient(
            responses={"a": "1", "b": "2"},
            default_response="?"
        )
        runtime = LLMRuntime(backend=stub)
        results = runtime.batch_generate(["a", "b", "c"])
        assert results == ["1", "2", "?"]

    def test_runtime_caching_integration(self, tmp_path):
        stub = DeterministicStubClient(default_response="cached_value")
        config = LLMRuntimeConfig(enable_cache=True, cache_dir=str(tmp_path / "cache"))
        runtime = LLMRuntime(backend=stub, config=config)

        # First call - cache miss
        result1 = runtime.generate("cache_test")
        assert result1 == "cached_value"
        assert stub.call_count == 1

        # Second call - should use cache
        result2 = runtime.generate("cache_test")
        assert result2 == "cached_value"
        assert stub.call_count == 1  # Not called again

    def test_runtime_without_cache(self):
        stub = DeterministicStubClient(default_response="value")
        config = LLMRuntimeConfig(enable_cache=False)
        runtime = LLMRuntime(backend=stub, config=config)

        runtime.generate("prompt")
        runtime.generate("prompt")
        assert stub.call_count == 2  # Called both times
