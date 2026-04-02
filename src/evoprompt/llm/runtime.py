"""Unified LLM runtime with caching, retry, and backend abstraction.

Wraps any LLM backend (real or stub) with optional caching and
unified sync/async interface.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .cache import ResponseCache


@dataclass
class LLMRuntimeConfig:
    """Configuration for LLMRuntime."""

    max_retries: int = 3
    retry_delay: float = 1.0
    max_concurrency: int = 16
    timeout: float = 30.0
    enable_cache: bool = False
    cache_dir: str = ""
    model_name: str = ""
    temperature: float = 0.0


class LLMRuntime:
    """Unified LLM runtime that wraps any backend.

    Provides optional caching and a unified sync/async interface.
    """

    def __init__(
        self,
        backend: Any,
        config: Optional[LLMRuntimeConfig] = None,
    ):
        self.backend = backend
        self.config = config or LLMRuntimeConfig()
        self._cache: Optional[ResponseCache] = None
        if self.config.enable_cache and self.config.cache_dir:
            self._cache = ResponseCache(self.config.cache_dir)

    def generate(self, prompt: str, **kwargs) -> str:
        if self._cache:
            cached = self._cache.get(
                prompt,
                model=self.config.model_name,
                temperature=kwargs.get("temperature", self.config.temperature),
            )
            if cached is not None:
                return cached

        result = self.backend.generate(prompt, **kwargs)

        if self._cache:
            self._cache.put(
                prompt,
                result,
                model=self.config.model_name,
                temperature=kwargs.get("temperature", self.config.temperature),
            )
        return result

    async def generate_async(self, prompt: str, **kwargs) -> str:
        if self._cache:
            cached = self._cache.get(
                prompt,
                model=self.config.model_name,
                temperature=kwargs.get("temperature", self.config.temperature),
            )
            if cached is not None:
                return cached

        result = await self.backend.generate_async(prompt, **kwargs)

        if self._cache:
            self._cache.put(
                prompt,
                result,
                model=self.config.model_name,
                temperature=kwargs.get("temperature", self.config.temperature),
            )
        return result

    def batch_generate(self, prompts: List[str], **kwargs) -> List[str]:
        return [self.generate(p, **kwargs) for p in prompts]

    async def batch_generate_async(self, prompts: List[str], **kwargs) -> List[str]:
        results = []
        for p in prompts:
            results.append(await self.generate_async(p, **kwargs))
        return results
