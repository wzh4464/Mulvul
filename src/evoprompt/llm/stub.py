"""Deterministic stub LLM client for testing.

Provides a mock LLM client that returns pre-configured responses
based on exact matches or regex patterns.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple


class DeterministicStubClient:
    """A deterministic LLM client for testing.

    Returns pre-configured responses based on exact prompt matches
    or regex patterns. Falls back to a default response.

    Attributes:
        responses: Mapping of exact prompts to responses
        patterns: List of (compiled_regex, response) for pattern matching
        default_response: Fallback response for unmatched prompts
        call_count: Number of generate calls made
        call_history: List of prompts passed to generate
    """

    def __init__(
        self,
        responses: Optional[Dict[str, str]] = None,
        default_response: str = "Benign",
    ):
        self.responses: Dict[str, str] = responses or {}
        self.patterns: List[Tuple[re.Pattern, str]] = []
        self.default_response = default_response
        self.call_count: int = 0
        self.call_history: List[str] = []

    def add_response(self, pattern: str, response: str) -> None:
        """Add a regex pattern-based response."""
        self.patterns.append((re.compile(pattern, re.IGNORECASE | re.DOTALL), response))

    def _resolve(self, prompt: str) -> str:
        """Resolve prompt to response."""
        # Exact match first
        if prompt in self.responses:
            return self.responses[prompt]
        # Pattern match
        for compiled, response in self.patterns:
            if compiled.search(prompt):
                return response
        return self.default_response

    def generate(self, prompt: str, **kwargs) -> str:
        self.call_count += 1
        self.call_history.append(prompt)
        return self._resolve(prompt)

    async def generate_async(self, prompt: str, **kwargs) -> str:
        self.call_count += 1
        self.call_history.append(prompt)
        return self._resolve(prompt)

    def batch_generate(self, prompts: List[str], **kwargs) -> List[str]:
        return [self.generate(p, **kwargs) for p in prompts]

    async def batch_generate_async(self, prompts: List[str], **kwargs) -> List[str]:
        results = []
        for p in prompts:
            results.append(await self.generate_async(p, **kwargs))
        return results
