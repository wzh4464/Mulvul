from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from cwd_optimized_cascade_experiment import CWDDataset, OptimizedBundleFactory
from cwd_hierarchy import get_hierarchy_path


def _example(idx: int, cwd_id: str) -> dict:
    return {
        "id": idx,
        "labels": {
            "cwd_id": cwd_id,
            "language": "C",
        },
        "code": {
            "context": "",
            "vulnerable": f"bad_{idx}();",
            "benign": f"good_{idx}();",
        },
    }


def test_cwd_dataset_prunes_low_sample_nodes_from_question_bank(tmp_path) -> None:
    payload = {
        "cwd_definitions": {
            "CWD-1007": {"name": "bit copy", "description": "too small"},
            "CWD-1015": {"name": "source too long", "description": "keep"},
        },
        "examples": [
            *[_example(i, "CWD-1007") for i in range(1, 6)],
            *[_example(i, "CWD-1015") for i in range(6, 12)],
        ],
    }
    dataset_path = tmp_path / "cwd_dataset.json"
    dataset_path.write_text(json.dumps(payload), encoding="utf-8")

    dataset = CWDDataset(dataset_path, min_cwe_vulnerable_samples=6)

    assert dataset.excluded_cwds == ["CWD-1007"]
    assert dataset.active_cwds == ["CWD-1015"]
    assert "CWD-1007" not in dataset.cwd_definitions
    assert all(record.source_cwd != "CWD-1007" for record in dataset.records)
    assert {record.cwe for record in dataset.vulnerable_records} == {"CWD-1015"}
    assert dataset.filter_summary["removed_example_count"] == 5


def test_optimized_bundle_factory_prunes_low_sample_nodes_from_taxonomy() -> None:
    cwd_definitions = {
        "CWD-1015": {"name": "source too long", "description": "drop from bundle"},
        "CWD-1071": {"name": "expression language injection", "description": "keep"},
    }
    factory = OptimizedBundleFactory(
        cwd_definitions,
        active_cwds=["CWD-1071"],
    )

    bundle = factory.build(
        major_threshold=0.2,
        middle_threshold=0.2,
        cwe_threshold=0.2,
    )

    cwe_labels = {node.target_label for node in bundle.nodes.values() if node.stage == "cwe"}
    major_labels = {node.target_label for node in bundle.nodes.values() if node.stage == "major"}
    active_major, _, _ = get_hierarchy_path("CWD-1071")
    removed_major, _, _ = get_hierarchy_path("CWD-1015")

    assert cwe_labels == {"CWD-1071"}
    assert active_major in major_labels
    assert removed_major not in major_labels
    assert bundle.training_metadata["excluded_cwds"] == ["CWD-1015"]
