"""Unified LLM runtime with caching, retry, and backend abstraction.

Wraps any LLM backend (real or stub) with optional caching and
unified sync/async interface.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, List, Optional

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

    def __getattr__(self, name: str) -> Any:
        return getattr(self.backend, name)

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

        if hasattr(self.backend, "generate_async"):
            result = await self.backend.generate_async(prompt, **kwargs)
        else:
            result = await asyncio.to_thread(self.backend.generate, prompt, **kwargs)

        if self._cache:
            self._cache.put(
                prompt,
                result,
                model=self.config.model_name,
                temperature=kwargs.get("temperature", self.config.temperature),
            )
        return result

    def batch_generate(self, prompts: List[str], **kwargs) -> List[str]:
        if not self._cache and hasattr(self.backend, "batch_generate"):
            return self.backend.batch_generate(prompts, **kwargs)

        results: list[str | None] = [None] * len(prompts)
        missing_indices: list[int] = []
        missing_prompts: list[str] = []

        for index, prompt in enumerate(prompts):
            if not self._cache:
                missing_indices.append(index)
                missing_prompts.append(prompt)
                continue

            cached = self._cache.get(
                prompt,
                model=self.config.model_name,
                temperature=kwargs.get("temperature", self.config.temperature),
            )
            if cached is None:
                missing_indices.append(index)
                missing_prompts.append(prompt)
            else:
                results[index] = cached

        if missing_prompts:
            if hasattr(self.backend, "batch_generate"):
                generated = self.backend.batch_generate(missing_prompts, **kwargs)
            else:
                generated = [self.backend.generate(prompt, **kwargs) for prompt in missing_prompts]

            for index, prompt, response in zip(missing_indices, missing_prompts, generated):
                results[index] = response
                if self._cache:
                    self._cache.put(
                        prompt,
                        response,
                        model=self.config.model_name,
                        temperature=kwargs.get("temperature", self.config.temperature),
                    )

        return [result or "" for result in results]

    async def batch_generate_async(self, prompts: List[str], **kwargs) -> List[str]:
        if not self._cache and hasattr(self.backend, "batch_generate_async"):
            return await self.backend.batch_generate_async(prompts, **kwargs)

        results: list[str] = []
        for prompt in prompts:
            results.append(await self.generate_async(prompt, **kwargs))
        return results
