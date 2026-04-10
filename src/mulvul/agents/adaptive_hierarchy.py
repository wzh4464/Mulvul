"""Adaptive hierarchy — data-driven taxonomy construction.

Builds a ``DynamicTaxonomy`` from training data, grouping CWEs by their
canonical middle/major categories and splitting oversized groups into
subgroups so that no routing node faces more than ``max_candidates``
choices.
"""

from __future__ import annotations

import json
import logging
import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from mulvul.data.cwe_hierarchy import (
    CWE_DESCRIPTIONS,
    CWE_TO_MIDDLE,
    MAJOR_TO_MIDDLE,
    MIDDLE_TO_CWE,
    MIDDLE_TO_MAJOR,
)

logger = logging.getLogger(__name__)

BENIGN_LABEL = "Benign"


# ---------------------------------------------------------------------------
# DynamicTaxonomy
# ---------------------------------------------------------------------------


@dataclass
class DynamicTaxonomy:
    """A data-driven taxonomy replacing static maps.

    The tree is stored as two dictionaries:

    * ``parent_map``   — child -> parent (``None`` for root nodes)
    * ``children_map`` — parent -> [children]

    ``stages`` lists the stage names from root to leaf
    (e.g. ``["major", "middle", "cwe"]``).
    """

    stages: List[str]
    parent_map: Dict[str, Optional[str]]
    children_map: Dict[str, List[str]]
    labels: Dict[str, str]

    # -- queries -----------------------------------------------------------

    def candidates_for(self, node_id: str) -> List[str]:
        """Return siblings (children of same parent) plus Benign.

        Raises ``KeyError`` if *node_id* is not in the taxonomy.
        """
        if node_id not in self.parent_map:
            raise KeyError(f"Unknown node: {node_id!r}")

        parent = self.parent_map[node_id]
        if parent is None:
            # Root node — siblings are all other roots
            siblings = self.root_nodes()
        else:
            siblings = list(self.children_map.get(parent, []))

        if BENIGN_LABEL not in siblings:
            siblings = siblings + [BENIGN_LABEL]
        return siblings

    def depth(self) -> int:
        """Number of stages in the taxonomy."""
        return len(self.stages)

    def root_nodes(self) -> List[str]:
        """Return nodes whose parent is ``None``."""
        return [n for n, p in self.parent_map.items() if p is None]

    def all_leaves(self) -> List[str]:
        """Return nodes that have no children."""
        parents_with_children = set(self.children_map.keys())
        return [
            n
            for n in self.parent_map
            if n not in parents_with_children
        ]

    # -- serialisation -----------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a JSON-friendly dictionary."""
        return {
            "stages": list(self.stages),
            "parent_map": {k: v for k, v in self.parent_map.items()},
            "children_map": {k: list(v) for k, v in self.children_map.items()},
            "labels": dict(self.labels),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> DynamicTaxonomy:
        """Deserialise from a dictionary produced by ``to_dict``."""
        return cls(
            stages=list(data["stages"]),
            parent_map=dict(data["parent_map"]),
            children_map={k: list(v) for k, v in data["children_map"].items()},
            labels=dict(data["labels"]),
        )


# ---------------------------------------------------------------------------
# AdaptiveHierarchyBuilder
# ---------------------------------------------------------------------------


def _sorted_chunks(items: List[str], max_size: int) -> List[List[str]]:
    """Split a sorted list into roughly equal-sized chunks of at most *max_size*.

    Uses simple sorted-chunking — no sklearn dependency.
    """
    if len(items) <= max_size:
        return [items]
    n_chunks = math.ceil(len(items) / max_size)
    chunk_size = math.ceil(len(items) / n_chunks)
    return [
        items[i : i + chunk_size]
        for i in range(0, len(items), chunk_size)
    ]


class AdaptiveHierarchyBuilder:
    """Build a :class:`DynamicTaxonomy` from training data.

    Algorithm:

    1. Count CWE occurrences in the JSONL training file.
    2. Filter CWEs with fewer than ``min_samples`` occurrences.
    3. Group remaining CWEs by their canonical middle and major categories
       (from ``cwe_hierarchy.py``).
    4. If a middle group has more than ``max_candidates`` CWEs, split it into
       subgroups using sorted-chunking.
    5. Build and return a :class:`DynamicTaxonomy`.
    """

    def __init__(
        self,
        max_candidates: int = 6,
        min_candidates: int = 2,
        min_samples: int = 10,
    ) -> None:
        self.max_candidates = max_candidates
        self.min_candidates = min_candidates
        self.min_samples = min_samples

    def build(self, data_path: str) -> DynamicTaxonomy:
        """Build a DynamicTaxonomy from a JSONL training file."""

        # 1. Count CWE occurrences
        cwe_counts = self._count_cwes(data_path)
        logger.info(
            "Counted %d unique CWEs across %d vulnerable samples",
            len(cwe_counts),
            sum(cwe_counts.values()),
        )

        # 2. Filter rare CWEs
        filtered_cwes = {
            cwe for cwe, count in cwe_counts.items() if count >= self.min_samples
        }
        dropped = set(cwe_counts) - filtered_cwes
        if dropped:
            logger.info(
                "Filtered %d rare CWEs (< %d samples): %s",
                len(dropped),
                self.min_samples,
                sorted(dropped),
            )

        # 3. Group by middle/major from canonical hierarchy
        #    middle_group -> [cwes]
        middle_groups: Dict[str, List[str]] = defaultdict(list)
        unknown_cwes: List[str] = []
        for cwe in sorted(filtered_cwes):
            middle = CWE_TO_MIDDLE.get(cwe)
            if middle is not None:
                middle_groups[middle].append(cwe)
            else:
                unknown_cwes.append(cwe)
        if unknown_cwes:
            middle_groups["Other"].extend(unknown_cwes)
            logger.info(
                "Assigned %d CWEs without canonical middle to 'Other': %s",
                len(unknown_cwes),
                unknown_cwes,
            )

        # Determine which majors are actually present
        active_majors: Dict[str, List[str]] = defaultdict(list)
        for middle in middle_groups:
            major = MIDDLE_TO_MAJOR.get(middle, "Logic")
            active_majors[major].append(middle)

        # 4. Build the taxonomy tree
        parent_map: Dict[str, Optional[str]] = {}
        children_map: Dict[str, List[str]] = {}
        labels: Dict[str, str] = {}

        # Add major (root) nodes
        for major in sorted(active_majors):
            parent_map[major] = None
            labels[major] = major

        # Add middle nodes and handle splitting
        for major, middles in sorted(active_majors.items()):
            major_children: List[str] = []
            for middle in sorted(middles):
                cwes = middle_groups[middle]

                if len(cwes) <= self.max_candidates:
                    # No splitting needed — keep middle as-is
                    parent_map[middle] = major
                    labels[middle] = middle
                    major_children.append(middle)
                    children_map[middle] = list(cwes)
                    for cwe in cwes:
                        parent_map[cwe] = middle
                        labels[cwe] = CWE_DESCRIPTIONS.get(cwe, cwe)
                else:
                    # Split into subgroups
                    chunks = _sorted_chunks(cwes, self.max_candidates)
                    if len(chunks) == 1:
                        # Still fits after chunking (shouldn't happen but be safe)
                        parent_map[middle] = major
                        labels[middle] = middle
                        major_children.append(middle)
                        children_map[middle] = list(cwes)
                        for cwe in cwes:
                            parent_map[cwe] = middle
                            labels[cwe] = CWE_DESCRIPTIONS.get(cwe, cwe)
                    else:
                        # Create sub-middle nodes
                        parent_map[middle] = major
                        labels[middle] = middle
                        major_children.append(middle)
                        sub_children: List[str] = []
                        for ci, chunk in enumerate(chunks):
                            sub_id = f"{middle}_{ci + 1}"
                            parent_map[sub_id] = middle
                            labels[sub_id] = f"{middle} (group {ci + 1})"
                            sub_children.append(sub_id)
                            children_map[sub_id] = list(chunk)
                            for cwe in chunk:
                                parent_map[cwe] = sub_id
                                labels[cwe] = CWE_DESCRIPTIONS.get(cwe, cwe)
                        children_map[middle] = sub_children

            children_map[major] = major_children

        # Determine stages: always major/middle/cwe for three-level;
        # if splitting occurred, the extra sub-middle nodes are transparent
        # to the stage labeling (they're still "middle" depth).
        # If no middle nodes exist (degenerate case), use two levels.
        has_middle = any(
            parent_map[n] is not None
            and parent_map.get(parent_map[n]) is not None
            for n in parent_map
            if n in self.all_leaf_nodes(parent_map, children_map)
        )
        if has_middle:
            stages = ["major", "middle", "cwe"]
        else:
            stages = ["major", "cwe"]

        taxonomy = DynamicTaxonomy(
            stages=stages,
            parent_map=parent_map,
            children_map=children_map,
            labels=labels,
        )

        logger.info(
            "Built DynamicTaxonomy: %d stages, %d roots, %d leaves",
            taxonomy.depth(),
            len(taxonomy.root_nodes()),
            len(taxonomy.all_leaves()),
        )
        return taxonomy

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def all_leaf_nodes(
        parent_map: Dict[str, Optional[str]],
        children_map: Dict[str, List[str]],
    ) -> List[str]:
        """Return nodes that have no children."""
        parents_with_children = set(children_map.keys())
        return [n for n in parent_map if n not in parents_with_children]

    @staticmethod
    def _count_cwes(data_path: str) -> Dict[str, int]:
        """Count CWE occurrences from a JSONL file.

        Only counts samples with ``target == 1`` (vulnerable).
        """
        counts: Counter[str] = Counter()
        with open(data_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                if record.get("target") != 1:
                    continue
                for cwe in record.get("cwe", []):
                    counts[cwe] += 1
        return dict(counts)
