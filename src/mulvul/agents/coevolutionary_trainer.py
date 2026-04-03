"""Cooperative coevolutionary trainer with population-level prompt evolution."""

from __future__ import annotations

import json
import random
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List


class EvolutionLog:
    """Append-only JSONL log with in-memory ring buffer for external monitoring.

    Each event is flushed immediately so an external process (or LLM) can
    tail the file to detect stalled fitness, low-diversity populations, or
    inefficient evolution patterns.
    """

    def __init__(self, path: Path | str, buffer_size: int = 200):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._buffer: deque[Dict[str, Any]] = deque(maxlen=buffer_size)
        self._handle = open(self._path, "a", encoding="utf-8")

    def emit(self, event: str, data: Dict[str, Any]) -> None:
        record = {
            "timestamp": datetime.now().isoformat(),
            "event": event,
            "data": data,
        }
        self._buffer.append(record)
        self._handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        self._handle.flush()

    def recent(self, n: int = 10) -> List[Dict[str, Any]]:
        items = list(self._buffer)
        return items[-n:]

    def summary(self) -> Dict[str, Dict[str, Any]]:
        latest: Dict[str, Dict[str, Any]] = {}
        for record in self._buffer:
            latest[record["event"]] = record
        return latest

    def close(self) -> None:
        self._handle.close()


@dataclass
class PromptIndividual:
    """A single prompt variant within a node's population."""

    prompt: str
    node_fitness: float = 0.0
    cascade_fitness: float = 0.0
    generation: int = 0
    origin: str = "seed"

    @property
    def combined_fitness(self) -> float:
        return 0.4 * self.node_fitness + 0.6 * self.cascade_fitness


@dataclass
class NodePopulation:
    """A taxonomy node's prompt population."""

    node_key: str
    stage: str
    individuals: List[PromptIndividual] = field(default_factory=list)

    @property
    def size(self) -> int:
        return len(self.individuals)

    def best(self) -> PromptIndividual:
        return max(self.individuals, key=lambda ind: ind.combined_fitness)

    def worst(self) -> PromptIndividual:
        return min(self.individuals, key=lambda ind: ind.combined_fitness)

    def tournament_select(
        self, k: int = 3, rng_seed: int | None = None
    ) -> PromptIndividual:
        rng = random.Random(rng_seed)
        contestants = rng.sample(self.individuals, min(k, len(self.individuals)))
        return max(contestants, key=lambda ind: ind.combined_fitness)


def attribute_cascade_error(
    *,
    true_major: str,
    pred_major: str,
    true_middle: str | None,
    pred_middle: str | None,
    true_cwe: str | None,
    pred_cwe: str | None,
) -> str | None:
    """Return the first cascade stage where prediction diverges from truth."""
    if pred_major != true_major:
        return "major"
    if pred_middle != true_middle:
        return "middle"
    if pred_cwe != true_cwe:
        return "cwe"
    return None
