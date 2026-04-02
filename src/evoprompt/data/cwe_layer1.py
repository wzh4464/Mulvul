"""Layer-1 CWE hierarchy utilities backed by cwe_researchview.json."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[3]
CWE_RESEARCHVIEW_PATH = PROJECT_ROOT / "data" / "cwe_researchview.json"
CWE_KNOWLEDGE_PATH = PROJECT_ROOT / "data" / "primevul" / "knowledge-cwe.jsonl"
CWE_ID_PATTERN = re.compile(r"cwe-\d+", re.IGNORECASE)


def _format_cwe_label(node: Dict[str, Any]) -> str:
    """Return a stable label combining CWE ID and name."""
    return f"{node['id']} {node['name']}".strip()


def _format_subcategory_lines(
    node_id: str,
    children: Dict[str, List[str]],
    id_to_node: Dict[str, Dict[str, Any]],
    indent: int = 2,
) -> List[str]:
    """Render a subtree as indented bullet lines."""
    lines: List[str] = []
    for child_id in children.get(node_id, []):
        child_node = id_to_node[child_id]
        lines.append(" " * indent + f"- {_format_cwe_label(child_node)}")
        lines.extend(
            _format_subcategory_lines(child_id, children, id_to_node, indent + 2)
        )
    return lines


@lru_cache(maxsize=1)
def load_layer1_hierarchy() -> Dict[str, Any]:
    """Load and cache the CWE hierarchy derived from cwe_researchview.json."""
    if not CWE_RESEARCHVIEW_PATH.exists():
        # Return minimal hierarchy if file doesn't exist
        import warnings
        warnings.warn(
            f"CWE hierarchy file not found: {CWE_RESEARCHVIEW_PATH}. "
            "Using fallback CWE mapping. Run scripts/ablations/convert_cwe_researchview.py for full hierarchy.",
            UserWarning
        )
        return {
            "nodes": [],
            "id_to_node": {},
            "children": {},
            "root_nodes": [],
            "root_labels": [],
            "descendant_to_root": {},
            "alias_map": {"benign": "Benign"},
            "subcategory_reference": ""
        }

    with CWE_RESEARCHVIEW_PATH.open("r", encoding="utf-8") as f:
        nodes = json.load(f)

    if not isinstance(nodes, list):
        raise ValueError(f"Invalid hierarchy format in {CWE_RESEARCHVIEW_PATH}")

    id_to_node: Dict[str, Dict[str, Any]] = {}
    children: Dict[str, List[str]] = defaultdict(list)

    for node in nodes:
        node_id = node.get("id")
        if not node_id:
            continue
        id_to_node[node_id] = node
        parent_id = node.get("parent_id")
        if parent_id:
            children[parent_id].append(node_id)

    root_nodes = [node for node in nodes if node.get("level") == 0]

    def collect_descendants(current_id: str) -> List[str]:
        descendants = [current_id]
        for child_id in children.get(current_id, []):
            descendants.extend(collect_descendants(child_id))
        return descendants

    descendant_to_root: Dict[str, str] = {}
    alias_map: Dict[str, str] = {}
    subcategory_lines: List[str] = []

    for root in root_nodes:
        label = _format_cwe_label(root)
        alias_map[label.lower()] = label
        alias_map[root["id"].lower()] = label
        alias_map[root["name"].lower()] = label

        descendants = collect_descendants(root["id"])
        for descendant_id in descendants:
            node = id_to_node[descendant_id]
            formatted = _format_cwe_label(node)
            alias_map[formatted.lower()] = label
            alias_map[node["id"].lower()] = label
            alias_map[node["name"].lower()] = label
            descendant_to_root[node["id"].upper()] = label

        subcategory_lines.append(f"{label}:")
        subcategory_lines.extend(
            _format_subcategory_lines(root["id"], children, id_to_node, indent=2)
        )

    alias_map["benign"] = "Benign"

    subcategory_reference = "\n".join(line for line in subcategory_lines if line).strip()

    return {
        "nodes": nodes,
        "id_to_node": id_to_node,
        "children": {key: list(value) for key, value in children.items()},
        "root_nodes": root_nodes,
        "root_labels": [_format_cwe_label(node) for node in root_nodes],
        "descendant_to_root": descendant_to_root,
        "alias_map": alias_map,
        "subcategory_reference": subcategory_reference,
    }


_HIERARCHY = load_layer1_hierarchy()
LAYER1_ROOT_LABELS = list(_HIERARCHY["root_labels"])
LAYER1_DESCENDANT_TO_ROOT: Dict[str, str] = dict(_HIERARCHY["descendant_to_root"])
LAYER1_ALIAS_MAP: Dict[str, str] = dict(_HIERARCHY["alias_map"])
LAYER1_SUBCATEGORY_REFERENCE: str = _HIERARCHY["subcategory_reference"]
LAYER1_CLASS_LABELS: List[str] = ["Benign", *LAYER1_ROOT_LABELS, "Other"]


@lru_cache(maxsize=1)
def _load_cwe_knowledge() -> Dict[str, Dict[str, Any]]:
    """Load CWE knowledge entries from knowledge-cwe.jsonl."""
    knowledge: Dict[str, Dict[str, Any]] = {}

    if not CWE_KNOWLEDGE_PATH.exists():
        return knowledge

    with CWE_KNOWLEDGE_PATH.open("r", encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            cwe_id = entry.get("cwe_id")
            if not cwe_id:
                continue

            knowledge[str(cwe_id).upper()] = entry

    return knowledge


def _extract_description(entry: Dict[str, Any]) -> Optional[str]:
    """Extract a concise description from a CWE knowledge entry."""
    if not entry:
        return None

    definition = entry.get("definition")
    explanation = entry.get("explanation")

    for text in (definition, explanation):
        if isinstance(text, str) and text.strip():
            cleaned = " ".join(text.strip().split())
            return cleaned

    return None


def _build_root_descriptions(root_labels: Iterable[str]) -> str:
    """Create a description block text for the root categories."""
    knowledge = _load_cwe_knowledge()
    description_lines: List[str] = []

    for label in root_labels:
        cwe_id = label.split(" ", 1)[0].upper()
        entry = knowledge.get(cwe_id, {})
        description = _extract_description(entry) or "Description unavailable."
        description_line = f"- {label}: {description}"
        description_lines.append(description_line)

    description_block = "\n".join(description_lines)
    return description_block


LAYER1_CATEGORY_DESCRIPTIONS_BLOCK = _build_root_descriptions(LAYER1_ROOT_LABELS)


def map_cwe_codes_to_layer1(cwe_codes: Iterable[str]) -> str:
    """Map a collection of CWE codes/names to the corresponding layer-1 root label."""
    for code in cwe_codes:
        if code is None:
            continue

        normalized = str(code).strip()
        if not normalized:
            continue

        for candidate in CWE_ID_PATTERN.findall(normalized):
            label = LAYER1_DESCENDANT_TO_ROOT.get(candidate.upper())
            if label:
                return label

        if normalized.isdigit():
            candidate = f"CWE-{int(normalized)}"
            label = LAYER1_DESCENDANT_TO_ROOT.get(candidate.upper())
            if label:
                return label

        label = LAYER1_DESCENDANT_TO_ROOT.get(normalized.upper())
        if label:
            return label

        lower = normalized.lower()
        direct = LAYER1_ALIAS_MAP.get(lower)
        if direct:
            return direct

        for key, mapped_label in LAYER1_ALIAS_MAP.items():
            if len(key) <= 4:
                continue
            if key in lower:
                return mapped_label

    return "Other"


def map_cwe_to_layer1(cwe_codes: Iterable[str]) -> str:
    """Alias for compatibility with existing code paths."""
    return map_cwe_codes_to_layer1(cwe_codes)


def canonicalize_layer1_category(text: str) -> Optional[str]:
    """Normalize text output to one of the predefined layer-1 labels."""
    if not text:
        return None

    normalized = text.strip()
    if not normalized:
        return None

    lower = normalized.lower()

    direct = LAYER1_ALIAS_MAP.get(lower)
    if direct:
        return direct

    for candidate in CWE_ID_PATTERN.findall(lower):
        label = LAYER1_DESCENDANT_TO_ROOT.get(candidate.upper())
        if label:
            return label

    for label in LAYER1_CLASS_LABELS:
        if lower == label.lower():
            return label

    for key, mapped_label in LAYER1_ALIAS_MAP.items():
        if len(key) <= 4:
            continue
        if key in lower:
            return mapped_label

    if "unknown" in lower:
        return "Other"
    if "benign" in lower:
        return "Benign"
    if "other" in lower:
        return "Other"

    return None
