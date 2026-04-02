"""Response caching for LLM calls.

Provides disk-based caching of LLM responses keyed by prompt,
model, and temperature to avoid redundant API calls.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Optional


class ResponseCache:
    """Disk-based response cache for LLM calls.

    Keys are computed from prompt + model + temperature.
    Values are stored as JSON files in the cache directory.
    """

    def __init__(self, cache_dir: Path | str):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._hits = 0
        self._misses = 0

    def _compute_key(
        self,
        prompt: str,
        model: str = "",
        temperature: float = 0.0,
    ) -> str:
        raw = f"{prompt}||{model}||{temperature}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def get(
        self,
        prompt: str,
        model: str = "",
        temperature: float = 0.0,
    ) -> Optional[str]:
        key = self._compute_key(prompt, model, temperature)
        path = self.cache_dir / f"{key}.json"
        if path.exists():
            self._hits += 1
            with open(path) as f:
                data = json.load(f)
            return data["response"]
        self._misses += 1
        return None

    def put(
        self,
        prompt: str,
        response: str,
        model: str = "",
        temperature: float = 0.0,
    ) -> None:
        key = self._compute_key(prompt, model, temperature)
        path = self.cache_dir / f"{key}.json"
        with open(path, "w") as f:
            json.dump(
                {
                    "prompt": prompt,
                    "response": response,
                    "model": model,
                    "temperature": temperature,
                },
                f,
            )

    def stats(self) -> Dict[str, int]:
        size = len(list(self.cache_dir.glob("*.json")))
        return {"hits": self._hits, "misses": self._misses, "size": size}

    def clear(self) -> None:
        for f in self.cache_dir.glob("*.json"):
            f.unlink()
        self._hits = 0
        self._misses = 0
