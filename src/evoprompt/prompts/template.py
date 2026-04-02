"""Unified prompt template architecture.

Provides PromptTemplate as a first-class serializable, versionable
object with trainable/fixed sections and metadata tracking.
"""
from __future__ import annotations

import json
import re
import copy
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .contract import PromptContractValidator, ValidationResult


# Supported trainable marker pairs
_TRAINABLE_MARKER_PAIRS: List[Tuple[str, str]] = [
    ("### ANALYSIS GUIDANCE START", "### ANALYSIS GUIDANCE END"),
    ("{{TRAINABLE_START}}", "{{TRAINABLE_END}}"),
]

# Placeholder normalization: all map to {input} for rendering
_PLACEHOLDER_MAP = {
    "{CODE}": "{input}",
    "{{CODE}}": "{input}",
}


@dataclass
class PromptSection:
    """A section of a prompt template.

    Attributes:
        content: The text content of this section
        is_trainable: Whether this section can be modified by evolution
        name: Optional name for referencing this section
    """
    content: str
    is_trainable: bool = False
    name: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "content": self.content,
            "is_trainable": self.is_trainable,
            "name": self.name,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PromptSection":
        return cls(
            content=data["content"],
            is_trainable=data.get("is_trainable", False),
            name=data.get("name", ""),
        )


@dataclass
class PromptMetadata:
    """Metadata for a prompt template."""
    version: str = ""
    created_at: str = field(
        default_factory=lambda: datetime.utcnow().isoformat()
    )
    description: str = ""
    layer: Optional[int] = None
    category: Optional[str] = None
    generation: int = 0
    fitness: Optional[float] = None
    change_log: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "created_at": self.created_at,
            "description": self.description,
            "layer": self.layer,
            "category": self.category,
            "generation": self.generation,
            "fitness": self.fitness,
            "change_log": self.change_log,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PromptMetadata":
        return cls(
            version=data.get("version", ""),
            created_at=data.get("created_at", ""),
            description=data.get("description", ""),
            layer=data.get("layer"),
            category=data.get("category"),
            generation=data.get("generation", 0),
            fitness=data.get("fitness"),
            change_log=data.get("change_log", []),
        )


class PromptTemplate:
    """A prompt template with trainable/fixed sections.

    Attributes:
        sections: List of PromptSection objects
        metadata: PromptMetadata for versioning and tracking
    """

    def __init__(
        self,
        sections: List[PromptSection],
        metadata: Optional[PromptMetadata] = None,
    ):
        self.sections = sections
        self.metadata = metadata or PromptMetadata()

    @property
    def full_text(self) -> str:
        """Get the full prompt text by joining all sections."""
        return "".join(s.content for s in self.sections)

    def render(self, input: str = "", **kwargs) -> str:
        """Render the template by substituting placeholders."""
        text = self.full_text
        # Normalize all placeholder variants to actual value
        # Order matters: replace {{CODE}} before {CODE} to avoid partial match
        text = text.replace("{{CODE}}", input)
        text = text.replace("{CODE}", input)
        text = text.replace("{input}", input)
        # Apply any additional kwargs
        for key, value in kwargs.items():
            text = text.replace(f"{{{key}}}", str(value))
        return text

    def get_trainable_sections(self) -> List[PromptSection]:
        """Return only trainable sections."""
        return [s for s in self.sections if s.is_trainable]

    def set_trainable_content(
        self, name: str, new_content: str
    ) -> "PromptTemplate":
        """Return a new template with updated trainable section.

        The original template is not modified (immutable operation).
        """
        new_sections = []
        for s in self.sections:
            if s.is_trainable and s.name == name:
                new_sections.append(
                    PromptSection(
                        content=new_content,
                        is_trainable=True,
                        name=s.name,
                    )
                )
            else:
                new_sections.append(copy.deepcopy(s))
        return PromptTemplate(
            sections=new_sections,
            metadata=copy.deepcopy(self.metadata),
        )

    def validate(self) -> ValidationResult:
        """Validate this template against the default contract."""
        return PromptContractValidator.validate(self.full_text)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sections": [s.to_dict() for s in self.sections],
            "metadata": self.metadata.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PromptTemplate":
        sections = [
            PromptSection.from_dict(s)
            for s in data["sections"]
        ]
        metadata = PromptMetadata.from_dict(
            data.get("metadata", {})
        )
        return cls(sections=sections, metadata=metadata)

    def to_json(self, path: Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def from_json(cls, path: Path) -> "PromptTemplate":
        with open(path) as f:
            return cls.from_dict(json.load(f))

    @classmethod
    def from_raw_prompt(
        cls,
        raw: str,
        metadata: Optional[PromptMetadata] = None,
    ) -> "PromptTemplate":
        """Create a PromptTemplate from a raw prompt string.

        Auto-detects trainable section markers.
        """
        sections: List[PromptSection] = []
        remaining = raw

        for start_marker, end_marker in _TRAINABLE_MARKER_PAIRS:
            parts: List[PromptSection] = []
            while start_marker in remaining:
                idx_start = remaining.index(start_marker)
                # Fixed section before the marker
                if idx_start > 0:
                    before = remaining[:idx_start].rstrip("\n")
                    if before:
                        parts.append(
                            PromptSection(content=before + "\n")
                        )

                # Find end marker
                after_start = remaining[
                    idx_start + len(start_marker):
                ]
                if end_marker not in after_start:
                    break
                idx_end = after_start.index(end_marker)
                trainable_content = after_start[:idx_end].strip()
                parts.append(
                    PromptSection(
                        content=trainable_content,
                        is_trainable=True,
                        name=f"trainable_{len(parts)}",
                    )
                )

                remaining = after_start[
                    idx_end + len(end_marker):
                ].lstrip("\n")

            if parts:
                sections.extend(parts)
                break  # Only use first matching marker pair

        # Add remaining text as fixed section
        if remaining.strip():
            sections.append(
                PromptSection(content=remaining.lstrip("\n"))
            )

        # If no markers found, entire prompt is a single fixed section
        if not sections:
            sections = [PromptSection(content=raw)]

        return cls(
            sections=sections,
            metadata=metadata or PromptMetadata(),
        )
