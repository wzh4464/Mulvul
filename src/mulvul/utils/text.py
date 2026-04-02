"""Utility helpers for working with prompt templates and free-form text."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Mapping, Optional, Tuple


_PLACEHOLDER_PATTERN = re.compile(r"\{([^{}]+)\}")


def escape_braces(value: str) -> str:
    """Escape curly braces so they survive ``str.format`` templating."""
    return value.replace("{", "{{").replace("}", "}}")


def _protect_placeholders(template: str, placeholder_keys: Mapping[str, Any]) -> Tuple[str, List[Tuple[str, str]]]:
    """Temporarily replace format placeholders to avoid escaping them."""
    markers: List[Tuple[str, str]] = []

    def _replacer(match: re.Match[str]) -> str:
        field_name = match.group(1).split("!")[0].split(":")[0].strip()
        if field_name in placeholder_keys:
            token = f"__SAFE_PLACEHOLDER_{len(markers)}__"
            markers.append((token, match.group(0)))
            return token
        return match.group(0)

    protected = _PLACEHOLDER_PATTERN.sub(_replacer, template)
    return protected, markers


def _restore_placeholders(template: str, markers: List[Tuple[str, str]]) -> str:
    restored = template
    for token, original in markers:
        restored = restored.replace(token, original)
    return restored


def safe_format(template: str, mapping: Optional[Mapping[str, Any]] = None, **kwargs: Any) -> str:
    """Format a template while preserving literal braces in values and the template.

    When templating prompts that embed source code or JSON fragments, raw braces
    would normally break ``str.format`` with ``ValueError: unmatched '{'``. This
    helper escapes braces in arguments and literal template text, while keeping
    legitimate placeholders (e.g. ``{input}``) intact.
    """
    values: Dict[str, Any] = {}
    if mapping:
        values.update(mapping)
    values.update(kwargs)

    escaped_values = {
        key: escape_braces(val) if isinstance(val, str) else val
        for key, val in values.items()
    }

    protected_template, markers = _protect_placeholders(template, escaped_values)
    # 双倍转义字面花括号，这样格式化后会保留为 {{ 和 }}
    sanitized_template = protected_template.replace("{", "{{{{").replace("}", "}}}}")
    restored_template = _restore_placeholders(sanitized_template, markers)

    return restored_template.format(**escaped_values)


__all__ = ["escape_braces", "safe_format"]
