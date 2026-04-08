"""Append-only evolution memory with relevance-based retrieval.

Records experiences (mutation/crossover/migration outcomes) as JSONL and
retrieves the most relevant past experiences for a given node to inject
into mutation prompts as historical context.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List


@dataclass
class Experience:
    """A single recorded evolution outcome for a taxonomy node."""

    node: str  # e.g. "cwe_CWE-189"
    action: str  # "mutation" | "crossover" | "migration"
    description: str  # natural language: what was changed
    f1_before: float
    f1_after: float
    delta: float
    generation: int

    @property
    def is_positive(self) -> bool:
        return self.delta > 0

    def to_dict(self) -> dict:
        return {
            "node": self.node,
            "action": self.action,
            "description": self.description,
            "f1_before": self.f1_before,
            "f1_after": self.f1_after,
            "delta": self.delta,
            "generation": self.generation,
        }

    @classmethod
    def from_dict(cls, data: dict) -> Experience:
        return cls(
            node=data["node"],
            action=data["action"],
            description=data["description"],
            f1_before=data["f1_before"],
            f1_after=data["f1_after"],
            delta=data["delta"],
            generation=data["generation"],
        )


class EvolutionMemory:
    """Append-only JSONL store with relevance-based retrieval.

    Loads existing records on construction so a new instance picks up
    where the previous session left off.
    """

    def __init__(self, path: Path | str) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._experiences: List[Experience] = []

        # Load existing records
        if self._path.exists():
            with self._path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        self._experiences.append(Experience.from_dict(json.loads(line)))

    def record(self, exp: Experience) -> None:
        """Append an experience to the in-memory list and JSONL file."""
        self._experiences.append(exp)
        with self._path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(exp.to_dict(), ensure_ascii=False) + "\n")

    def retrieve(self, node: str, stage: str, top_k: int = 5) -> List[Experience]:
        """Return the most relevant experiences for *node* at *stage*.

        Ranking: same node (score 3) > same stage (score 2) > global (score 1).
        Within each tier, sort by ``|delta|`` descending.
        """
        if not self._experiences:
            return []

        def _relevance_key(exp: Experience) -> tuple:
            if exp.node == node:
                tier = 3
            elif exp.node.split("_", 1)[0] == stage:
                tier = 2
            else:
                tier = 1
            return (tier, abs(exp.delta))

        ranked = sorted(self._experiences, key=_relevance_key, reverse=True)
        return ranked[:top_k]

    def format_for_prompt(self, experiences: List[Experience]) -> str:
        """Format experiences as a markdown section for injection into mutation prompts.

        Returns an empty string when *experiences* is empty.
        """
        if not experiences:
            return ""

        lines = ["## Lessons from previous evolution rounds:"]
        for exp in experiences:
            sign = "+" if exp.delta >= 0 else ""
            lines.append(
                f"- [{sign}{exp.delta:.2f}] {exp.node}: {exp.description}"
            )
        return "\n".join(lines)
