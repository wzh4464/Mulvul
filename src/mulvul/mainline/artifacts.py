"""Prompt artifacts shared by the evolution and evaluation workflows."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Mapping

PROMPT_KEY_PREFIXES = ("major_", "middle_", "cwe_")


@dataclass
class PromptArtifact:
    """Frozen prompts for the main router-detector system."""

    router_prompts: Dict[str, str] = field(default_factory=dict)
    middle_prompts: Dict[str, str] = field(default_factory=dict)
    cwe_prompts: Dict[str, str] = field(default_factory=dict)
    scores: Dict[str, float] = field(default_factory=dict)
    raw_prompts: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> "PromptArtifact":
        """Build an artifact from a trainer or on-disk mapping."""

        prompts_obj = data.get("prompts", data)
        if not isinstance(prompts_obj, Mapping):
            raise ValueError("Prompt artifact must contain a 'prompts' mapping.")

        prompts: Dict[str, str] = {}
        for raw_key, raw_value in prompts_obj.items():
            key = str(raw_key)
            if not any(key.startswith(prefix) for prefix in PROMPT_KEY_PREFIXES):
                raise ValueError(
                    "Prompt artifact keys must start with one of "
                    f"{PROMPT_KEY_PREFIXES!r}; got {key!r}."
                )
            if not isinstance(raw_value, str):
                raise ValueError(f"Prompt artifact value for {key!r} must be a string.")
            prompts[key] = raw_value

        scores_obj = data.get("scores", {})
        scores: Dict[str, float] = {}
        if isinstance(scores_obj, Mapping):
            scores = {str(key): float(value) for key, value in scores_obj.items()}

        artifact = cls(scores=scores, raw_prompts=prompts)
        for key, prompt in prompts.items():
            if key.startswith("major_"):
                artifact.router_prompts[key.replace("major_", "", 1)] = prompt
            elif key.startswith("middle_"):
                artifact.middle_prompts[key.replace("middle_", "", 1)] = prompt
            elif key.startswith("cwe_"):
                artifact.cwe_prompts[key.replace("cwe_", "", 1)] = prompt

        return artifact

    @classmethod
    def load(cls, path: str | Path) -> "PromptArtifact":
        """Load a prompt artifact from JSON."""

        artifact_path = Path(path)
        with artifact_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        return cls.from_mapping(data)

    def to_dict(self) -> Dict[str, object]:
        """Serialize the artifact to JSON-compatible data."""

        return {
            "prompts": dict(self.raw_prompts),
            "scores": dict(self.scores),
            "router_prompts": dict(self.router_prompts),
            "middle_prompts": dict(self.middle_prompts),
            "cwe_prompts": dict(self.cwe_prompts),
        }

    def save(self, path: str | Path) -> Path:
        """Save the artifact to disk and return the resolved path."""

        artifact_path = Path(path)
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        with artifact_path.open("w", encoding="utf-8") as handle:
            json.dump(self.to_dict(), handle, indent=2, ensure_ascii=False)
        return artifact_path
