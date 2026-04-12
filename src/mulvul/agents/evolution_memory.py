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


# Seed experiences distilled from ablation experiments (docs/ablation-mutation-elitism-analysis.md)
# These are universal lessons that apply across all nodes
SEED_EXPERIENCES: List[dict] = [
    # Success patterns
    {
        "node": "_global",
        "action": "insight",
        "description": "Adding CWE semantic definitions is the most effective improvement — helps LLM understand category meanings",
        "f1_before": 0.0,
        "f1_after": 0.35,
        "delta": 0.35,
        "generation": -1,
    },
    {
        "node": "_global",
        "action": "insight",
        "description": "Adding decision boundaries between similar candidates resolves confusion (e.g., 'Choose X only when...')",
        "f1_before": 0.0,
        "f1_after": 0.27,
        "delta": 0.27,
        "generation": -1,
    },
    {
        "node": "_global",
        "action": "insight",
        "description": "Hierarchical exclusion works well: 'Use CWE-399 when NOT more specifically CWE-400/770/835'",
        "f1_before": 0.0,
        "f1_after": 0.20,
        "delta": 0.20,
        "generation": -1,
    },
    {
        "node": "middle_Memory Management",
        "action": "crossover",
        "description": "Combined buffer/memory/pointer distinction with explicit criteria: 'out-of-bounds' vs 'double-free' vs 'null deref'",
        "f1_before": 0.19,
        "f1_after": 0.56,
        "delta": 0.37,
        "generation": -1,
    },
    {
        "node": "cwe_CWE-399",
        "action": "crossover",
        "description": "Added exclusion logic: CWE-399 is for general resource issues NOT covered by CWE-400/770/835",
        "f1_before": 0.0,
        "f1_after": 0.44,
        "delta": 0.44,
        "generation": -1,
    },
    {
        "node": "cwe_CWE-189",
        "action": "crossover",
        "description": "Added semantic: CWE-189 for general numeric errors, CWE-190 for integer overflow, CWE-191 for underflow",
        "f1_before": 0.18,
        "f1_after": 0.44,
        "delta": 0.27,
        "generation": -1,
    },
    # Failure patterns (negative delta = things to avoid)
    {
        "node": "_global",
        "action": "warning",
        "description": "AVOID: Removing {code} or {evidence} placeholders breaks prompt structure",
        "f1_before": 0.30,
        "f1_after": 0.0,
        "delta": -0.30,
        "generation": -1,
    },
    {
        "node": "_global",
        "action": "warning",
        "description": "AVOID: Over-generalizing specific CWE prompts loses discrimination ability",
        "f1_before": 0.25,
        "f1_after": 0.10,
        "delta": -0.15,
        "generation": -1,
    },
    {
        "node": "_global",
        "action": "warning",
        "description": "AVOID: Deleting content usually causes information loss — prefer adding to modifying",
        "f1_before": 0.20,
        "f1_after": 0.08,
        "delta": -0.12,
        "generation": -1,
    },
]


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
    where the previous session left off. Also includes seed experiences
    from prior ablation studies.
    """

    def __init__(self, path: Path | str, include_seeds: bool = True) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._experiences: List[Experience] = []
        self._seed_experiences: List[Experience] = []

        # Load seed experiences from ablation analysis
        if include_seeds:
            for seed in SEED_EXPERIENCES:
                self._seed_experiences.append(Experience.from_dict(seed))

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

        Combines seed experiences (from ablation analysis) with runtime experiences.
        Ranking: same node (score 4) > same stage (score 3) > global seed (score 2) > other (score 1).
        Within each tier, sort by ``|delta|`` descending.
        """
        all_experiences = self._seed_experiences + self._experiences
        if not all_experiences:
            return []

        def _relevance_key(exp: Experience) -> tuple:
            if exp.node == node:
                tier = 4  # Exact node match (highest)
            elif exp.node.split("_", 1)[0] == stage:
                tier = 3  # Same stage
            elif exp.node == "_global":
                tier = 2  # Global insights from seeds
            else:
                tier = 1  # Other
            return (tier, abs(exp.delta))

        ranked = sorted(all_experiences, key=_relevance_key, reverse=True)
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
