"""Unified prompt set for managing collections of prompt templates.

PromptSet organizes PromptTemplate objects by layer and category,
providing migration paths from existing prompt structures.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from .template import PromptTemplate, PromptSection, PromptMetadata
from .contract import ValidationResult, PromptContractValidator


class PromptSet:
    """A collection of PromptTemplate objects organized by layer+category.

    Templates are keyed by (layer_number, category_name).
    """

    def __init__(self):
        self._templates: Dict[
            Tuple[int, str], PromptTemplate
        ] = {}

    def get_template(
        self, layer: int, category: str
    ) -> Optional[PromptTemplate]:
        return self._templates.get((layer, category))

    def set_template(
        self, layer: int, category: str, template: PromptTemplate
    ) -> None:
        self._templates[(layer, category)] = template

    def count_templates(self) -> int:
        return len(self._templates)

    def validate_all(
        self,
    ) -> Dict[Tuple[int, str], ValidationResult]:
        results = {}
        for key, template in self._templates.items():
            results[key] = template.validate()
        return results

    def to_dict(self) -> Dict[str, Any]:
        templates = {}
        for (layer, category), template in self._templates.items():
            key = f"{layer}:{category}"
            templates[key] = template.to_dict()
        return {"templates": templates}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PromptSet":
        ps = cls()
        for key, tdata in data.get("templates", {}).items():
            layer_str, category = key.split(":", 1)
            layer = int(layer_str)
            template = PromptTemplate.from_dict(tdata)
            ps.set_template(layer, category, template)
        return ps

    @classmethod
    def from_three_layer_prompt_set(
        cls, three_layer
    ) -> "PromptSet":
        """Convert from ThreeLayerPromptSet."""
        ps = cls()

        # Layer 1: single prompt keyed as "default"
        ps.set_template(
            1,
            "default",
            PromptTemplate.from_raw_prompt(
                three_layer.layer1_prompt,
                metadata=PromptMetadata(layer=1, category="default"),
            ),
        )

        # Layer 2: one per major category
        for cat, prompt in three_layer.layer2_prompts.items():
            cat_name = cat.value if hasattr(cat, "value") else str(cat)
            ps.set_template(
                2,
                cat_name,
                PromptTemplate.from_raw_prompt(
                    prompt,
                    metadata=PromptMetadata(
                        layer=2, category=cat_name
                    ),
                ),
            )

        # Layer 3: one per middle category
        for cat, prompt in three_layer.layer3_prompts.items():
            cat_name = cat.value if hasattr(cat, "value") else str(cat)
            ps.set_template(
                3,
                cat_name,
                PromptTemplate.from_raw_prompt(
                    prompt,
                    metadata=PromptMetadata(
                        layer=3, category=cat_name
                    ),
                ),
            )

        return ps

    @classmethod
    def from_hierarchical_prompt_set(
        cls, h_set
    ) -> "PromptSet":
        """Convert from HierarchicalPromptSet."""
        ps = cls()

        # Layer 1 prompts
        for cat_name, prompt in h_set.layer1_prompts.items():
            ps.set_template(
                1,
                cat_name,
                PromptTemplate.from_raw_prompt(
                    prompt,
                    metadata=PromptMetadata(
                        layer=1, category=cat_name
                    ),
                ),
            )

        # Layer 2 prompts (nested by major -> middle)
        for major, middles in h_set.layer2_prompts.items():
            for middle, prompt in middles.items():
                ps.set_template(
                    2,
                    f"{major}/{middle}",
                    PromptTemplate.from_raw_prompt(
                        prompt,
                        metadata=PromptMetadata(
                            layer=2,
                            category=f"{major}/{middle}",
                        ),
                    ),
                )

        # Layer 3 prompts (nested by middle -> CWE)
        for middle, cwes in h_set.layer3_prompts.items():
            for cwe, prompt in cwes.items():
                ps.set_template(
                    3,
                    f"{middle}/{cwe}",
                    PromptTemplate.from_raw_prompt(
                        prompt,
                        metadata=PromptMetadata(
                            layer=3,
                            category=f"{middle}/{cwe}",
                        ),
                    ),
                )

        return ps
