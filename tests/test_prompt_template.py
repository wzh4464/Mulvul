"""Tests for PromptTemplate and PromptSet."""
from __future__ import annotations

import json
import pytest
from pathlib import Path

from evoprompt.prompts.template import (
    PromptSection,
    PromptMetadata,
    PromptTemplate,
)
from evoprompt.prompts.prompt_set import PromptSet


class TestPromptSection:
    """Tests for PromptSection dataclass."""

    def test_section_defaults(self):
        s = PromptSection(content="Hello")
        assert s.content == "Hello"
        assert not s.is_trainable
        assert s.name == ""

    def test_section_trainable(self):
        s = PromptSection(
            content="Evolvable part",
            is_trainable=True,
            name="guidance",
        )
        assert s.is_trainable
        assert s.name == "guidance"


class TestPromptMetadata:
    """Tests for PromptMetadata."""

    def test_metadata_defaults(self):
        m = PromptMetadata()
        assert m.version == ""
        assert m.description == ""
        assert m.layer is None
        assert m.category is None
        assert m.generation == 0
        assert m.fitness is None

    def test_metadata_with_values(self):
        m = PromptMetadata(
            version="1.0",
            layer=1,
            category="Memory",
            generation=3,
            fitness=0.85,
        )
        assert m.version == "1.0"
        assert m.layer == 1


class TestPromptTemplate:
    """Tests for PromptTemplate."""

    def test_template_sections_trainable_vs_fixed(self):
        sections = [
            PromptSection(content="Fixed intro"),
            PromptSection(
                content="Trainable guidance",
                is_trainable=True,
                name="guidance",
            ),
            PromptSection(content="Fixed code:\n{input}"),
        ]
        template = PromptTemplate(sections=sections)
        trainable = template.get_trainable_sections()
        assert len(trainable) == 1
        assert trainable[0].content == "Trainable guidance"

    def test_render_substitutes_input_placeholder(self):
        template = PromptTemplate(
            sections=[
                PromptSection(content="Analyze:\n{input}")
            ]
        )
        rendered = template.render(input="int x = 0;")
        assert "int x = 0;" in rendered
        assert "{input}" not in rendered

    def test_render_substitutes_code_placeholder(self):
        template = PromptTemplate(
            sections=[
                PromptSection(content="Check:\n{CODE}")
            ]
        )
        rendered = template.render(input="void f() {}")
        assert "void f() {}" in rendered
        assert "{CODE}" not in rendered

    def test_render_substitutes_double_brace_code(self):
        template = PromptTemplate(
            sections=[
                PromptSection(
                    content="Code to analyze:\n{{CODE}}"
                )
            ]
        )
        rendered = template.render(input="return 0;")
        assert "return 0;" in rendered

    def test_set_trainable_content_immutable(self):
        sections = [
            PromptSection(content="Fixed"),
            PromptSection(
                content="Old content",
                is_trainable=True,
                name="g",
            ),
        ]
        original = PromptTemplate(sections=sections)
        new_template = original.set_trainable_content(
            "g", "New content"
        )
        # Original unchanged
        assert (
            original.get_trainable_sections()[0].content
            == "Old content"
        )
        # New template has updated content
        assert (
            new_template.get_trainable_sections()[0].content
            == "New content"
        )

    def test_get_trainable_sections(self):
        sections = [
            PromptSection(content="A"),
            PromptSection(
                content="B", is_trainable=True, name="b"
            ),
            PromptSection(content="C"),
            PromptSection(
                content="D", is_trainable=True, name="d"
            ),
        ]
        template = PromptTemplate(sections=sections)
        trainable = template.get_trainable_sections()
        assert len(trainable) == 2
        assert trainable[0].name == "b"
        assert trainable[1].name == "d"

    def test_serialization_dict_roundtrip(self):
        sections = [
            PromptSection(content="Fixed"),
            PromptSection(
                content="Trainable",
                is_trainable=True,
                name="g",
            ),
        ]
        meta = PromptMetadata(
            version="1.0", layer=1, category="Memory"
        )
        template = PromptTemplate(
            sections=sections, metadata=meta
        )
        d = template.to_dict()
        restored = PromptTemplate.from_dict(d)
        assert len(restored.sections) == 2
        assert restored.sections[1].is_trainable
        assert restored.metadata.version == "1.0"
        assert restored.metadata.category == "Memory"

    def test_serialization_json_roundtrip(self, tmp_path):
        sections = [
            PromptSection(content="Hello {input}"),
        ]
        template = PromptTemplate(sections=sections)
        path = tmp_path / "template.json"
        template.to_json(path)
        restored = PromptTemplate.from_json(path)
        assert restored.sections[0].content == "Hello {input}"

    def test_version_in_serialized_metadata(self):
        template = PromptTemplate(
            sections=[PromptSection(content="X {input}")],
            metadata=PromptMetadata(version="2.0"),
        )
        d = template.to_dict()
        assert d["metadata"]["version"] == "2.0"

    def test_from_raw_prompt_autodetects_guidance_markers(self):
        raw = (
            "Fixed intro\n"
            "### ANALYSIS GUIDANCE START\n"
            "Trainable guidance content\n"
            "### ANALYSIS GUIDANCE END\n"
            "Fixed output: {input}"
        )
        template = PromptTemplate.from_raw_prompt(raw)
        trainable = template.get_trainable_sections()
        assert len(trainable) == 1
        assert "Trainable guidance content" in (
            trainable[0].content
        )

    def test_from_raw_prompt_autodetects_trainable_markers(self):
        raw = (
            "Analyze code:\n"
            "{{TRAINABLE_START}}\n"
            "Focus on patterns\n"
            "{{TRAINABLE_END}}\n"
            "Code:\n{{CODE}}"
        )
        template = PromptTemplate.from_raw_prompt(raw)
        trainable = template.get_trainable_sections()
        assert len(trainable) == 1
        assert "Focus on patterns" in trainable[0].content

    def test_from_raw_prompt_no_markers(self):
        raw = "Simple prompt with {input}"
        template = PromptTemplate.from_raw_prompt(raw)
        assert len(template.sections) == 1
        assert not template.sections[0].is_trainable

    def test_validate_passes_with_contract(self):
        template = PromptTemplate(
            sections=[
                PromptSection(
                    content="Check:\n{input}\nRespond with answer"
                ),
            ]
        )
        result = template.validate()
        assert result.is_valid

    def test_validate_fails_without_placeholder(self):
        template = PromptTemplate(
            sections=[
                PromptSection(content="No placeholder here"),
            ]
        )
        result = template.validate()
        assert not result.is_valid

    def test_full_text_property(self):
        sections = [
            PromptSection(content="Part 1\n"),
            PromptSection(content="Part 2\n"),
        ]
        template = PromptTemplate(sections=sections)
        assert template.full_text == "Part 1\nPart 2\n"


class TestPromptSet:
    """Tests for PromptSet."""

    def test_prompt_set_get_set_template(self):
        ps = PromptSet()
        template = PromptTemplate(
            sections=[PromptSection(content="Test {input}")]
        )
        ps.set_template(1, "Memory", template)
        retrieved = ps.get_template(1, "Memory")
        assert retrieved is not None
        assert "Test" in retrieved.full_text

    def test_prompt_set_get_missing_returns_none(self):
        ps = PromptSet()
        assert ps.get_template(1, "Missing") is None

    def test_prompt_set_validate_all(self):
        ps = PromptSet()
        ps.set_template(
            1,
            "Memory",
            PromptTemplate(
                sections=[
                    PromptSection(
                        content="Check {input}\nRespond with X"
                    )
                ]
            ),
        )
        ps.set_template(
            1,
            "Bad",
            PromptTemplate(
                sections=[
                    PromptSection(content="No placeholder")
                ]
            ),
        )
        results = ps.validate_all()
        assert len(results) == 2
        # One should pass, one should fail
        valid_count = sum(1 for r in results.values() if r.is_valid)
        assert valid_count == 1

    def test_prompt_set_serialization_roundtrip(self, tmp_path):
        ps = PromptSet()
        ps.set_template(
            1,
            "Memory",
            PromptTemplate(
                sections=[
                    PromptSection(content="Check {input}")
                ]
            ),
        )
        ps.set_template(
            2,
            "Buffer",
            PromptTemplate(
                sections=[
                    PromptSection(content="Buf {input}")
                ]
            ),
        )
        d = ps.to_dict()
        restored = PromptSet.from_dict(d)
        assert restored.get_template(1, "Memory") is not None
        assert restored.get_template(2, "Buffer") is not None

    def test_prompt_set_count_templates(self):
        ps = PromptSet()
        ps.set_template(
            1,
            "A",
            PromptTemplate(
                sections=[PromptSection(content="{input}")]
            ),
        )
        ps.set_template(
            2,
            "B",
            PromptTemplate(
                sections=[PromptSection(content="{input}")]
            ),
        )
        assert ps.count_templates() == 2

    def test_migration_from_three_layer_prompt_set(self):
        """Convert ThreeLayerPromptSet to PromptSet."""
        from evoprompt.prompts.hierarchical_three_layer import (
            ThreeLayerPromptFactory,
        )

        three_layer = (
            ThreeLayerPromptFactory.create_default_prompt_set()
        )
        ps = PromptSet.from_three_layer_prompt_set(three_layer)
        # Should have layer1 prompt
        layer1_count = sum(
            1
            for key in ps._templates
            if key[0] == 1
        )
        assert layer1_count >= 1
        # Total count should match
        orig_counts = three_layer.count_prompts()
        assert ps.count_templates() == orig_counts["total"]

    def test_migration_from_hierarchical_prompt_set(self):
        """Convert HierarchicalPromptSet to PromptSet."""
        from evoprompt.detectors.parallel_hierarchical_detector import (
            HierarchicalPromptSet,
        )
        from evoprompt.prompts.hierarchical_three_layer import (
            ThreeLayerPromptFactory,
        )

        three_layer = (
            ThreeLayerPromptFactory.create_default_prompt_set()
        )
        h_set = HierarchicalPromptSet.from_three_layer_set(
            three_layer
        )
        ps = PromptSet.from_hierarchical_prompt_set(h_set)
        # Should have prompts at all layers
        layer1_count = sum(
            1 for key in ps._templates if key[0] == 1
        )
        layer2_count = sum(
            1 for key in ps._templates if key[0] == 2
        )
        layer3_count = sum(
            1 for key in ps._templates if key[0] == 3
        )
        assert layer1_count > 0
        assert layer2_count > 0
        assert layer3_count > 0
