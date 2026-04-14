import json

import pytest

from mulvul.data.cwe_hierarchy import MAJOR_TO_MIDDLE
from mulvul.mainline.artifacts import PromptArtifact
from mulvul.mainline.bundle import (
    BundleDefaults,
    NodeSpec,
    PromptBundle,
    PromptBundleAdapter,
    PromptBundleIO,
    TaxonomyGraph,
)


def test_taxonomy_graph_round_trip_and_decision_labels():
    graph = TaxonomyGraph.from_current_mainline()

    reloaded = TaxonomyGraph.from_dict(graph.to_dict())
    memory_id = reloaded.node_id_for_label("major", "Memory")
    buffer_id = reloaded.node_id_for_label("middle", "Buffer Errors")
    expected_memory_middles = MAJOR_TO_MIDDLE["Memory"]

    assert reloaded.stage_order == ("major", "middle", "cwe")
    assert reloaded.node(buffer_id).display_name == "Buffer Errors"
    assert reloaded.parent_of(buffer_id) == memory_id
    assert reloaded.children_of(memory_id) == [
        reloaded.node_id_for_label("middle", middle) for middle in expected_memory_middles
    ]
    assert reloaded.decision_labels_for(buffer_id) == expected_memory_middles


def test_prompt_bundle_adapter_maps_v1_labels_to_stable_v2_node_ids_and_defaults():
    artifact = PromptArtifact.from_mapping(
        {
            "prompts": {
                "major_Memory": "major-memory",
                "middle_Buffer Errors": "middle-buffer",
                "cwe_CWE-120": "cwe-120",
            }
        }
    )

    bundle = PromptBundleAdapter.from_artifact(artifact, allow_partial=True)
    memory_id = bundle.taxonomy.node_id_for_label("major", "Memory")
    buffer_id = bundle.taxonomy.node_id_for_label("middle", "Buffer Errors")
    cwe_id = bundle.taxonomy.node_id_for_label("cwe", "CWE-120")

    assert set(bundle.nodes) == {
        memory_id,
        buffer_id,
        cwe_id,
    }
    assert memory_id == "major_memory"
    assert buffer_id == "middle_buffer_errors"
    assert cwe_id == "cwe_120"
    assert bundle.taxonomy.node(memory_id).display_name == "Memory"
    assert bundle.nodes[memory_id].threshold is None
    assert bundle.defaults.default_threshold == 0.5
    assert bundle.validate(allow_partial=True) == []


def test_prompt_bundle_io_strict_rejects_partial_bundle(temp_dir):
    artifact = PromptArtifact.from_mapping(
        {"prompts": {"major_Memory": "major-memory"}}
    )
    bundle = PromptBundleAdapter.from_artifact(artifact, allow_partial=True)
    bundle_path = temp_dir / "prompt_bundle.json"

    with pytest.raises(
        ValueError, match="missing node specs|Bundle is missing node specs"
    ):
        PromptBundleIO.save(bundle, bundle_path, allow_partial=False)


def test_prompt_bundle_io_legacy_compat_loads_v1_artifact(temp_dir):
    artifact = PromptArtifact.from_mapping(
        {"prompts": {"major_Memory": "major-memory"}}
    )
    artifact_path = temp_dir / "prompt_artifact.json"
    artifact.save(artifact_path)

    bundle = PromptBundleIO.load(artifact_path, load_mode="legacy_compat")
    memory_id = bundle.taxonomy.node_id_for_label("major", "Memory")

    assert bundle.schema_version == "2"
    assert memory_id in bundle.nodes
    assert bundle.validate(allow_partial=True) == []


def test_prompt_bundle_io_strict_round_trip_for_full_bundle(temp_dir):
    taxonomy = TaxonomyGraph.from_current_mainline()
    bundle = PromptBundle(
        schema_version="2",
        taxonomy=taxonomy,
        nodes={
            node_id: NodeSpec(
                node_id=node_id,
                stage=node.stage,
                target_label=node.label,
                instruction_template=f"Judge {node.label}: {{code}} {{evidence}} {{candidates}}",
            )
            for node_id, node in taxonomy.nodes.items()
        },
        defaults=BundleDefaults(),
        training_metadata={"trainer_seed": 42},
        data_fingerprint="dataset-hash",
        code_revision="git-sha",
    )
    bundle_path = temp_dir / "prompt_bundle.json"

    PromptBundleIO.save(bundle, bundle_path, allow_partial=False)
    loaded = PromptBundleIO.load(bundle_path, load_mode="strict_v2")

    assert loaded.schema_version == "2"
    assert loaded.taxonomy.version == taxonomy.version
    assert loaded.validate(allow_partial=False) == []


def test_prompt_bundle_io_loads_older_v2_bundles_without_display_name(temp_dir):
    taxonomy = TaxonomyGraph.from_current_mainline()
    bundle = PromptBundle(
        schema_version="2",
        taxonomy=taxonomy,
        nodes={
            node_id: NodeSpec(
                node_id=node_id,
                stage=node.stage,
                target_label=node.label,
                instruction_template=f"Judge {node.label}: {{code}}",
            )
            for node_id, node in taxonomy.nodes.items()
        },
        defaults=BundleDefaults(),
        training_metadata={"trainer_seed": 42},
        data_fingerprint="dataset-hash",
        code_revision="git-sha",
    )
    data = bundle.to_dict()
    for node in data["taxonomy"]["nodes"].values():
        node.pop("display_name", None)

    bundle_path = temp_dir / "older_prompt_bundle.json"
    bundle_path.write_text(json.dumps(data), encoding="utf-8")

    loaded = PromptBundleIO.load(bundle_path, load_mode="strict_v2")
    buffer_id = loaded.taxonomy.node_id_for_label("middle", "Buffer Errors")

    assert loaded.taxonomy.node(buffer_id).display_name == "Buffer Errors"


def test_v2_display_name_can_change_without_changing_stable_node_id(temp_dir):
    taxonomy = TaxonomyGraph.from_current_mainline()
    buffer_id = taxonomy.node_id_for_label("middle", "Buffer Errors")
    taxonomy.nodes[buffer_id].display_name = "Buffer Error Family"

    bundle = PromptBundle(
        schema_version="2",
        taxonomy=taxonomy,
        nodes={
            node_id: NodeSpec(
                node_id=node_id,
                stage=node.stage,
                target_label=node.label,
                instruction_template=f"Judge {node.label}: {{code}}",
            )
            for node_id, node in taxonomy.nodes.items()
        },
        defaults=BundleDefaults(),
        training_metadata={"trainer_seed": 42},
        data_fingerprint="dataset-hash",
        code_revision="git-sha",
    )
    bundle_path = temp_dir / "display_name_bundle.json"

    PromptBundleIO.save(bundle, bundle_path, allow_partial=False)
    loaded = PromptBundleIO.load(bundle_path, load_mode="strict_v2")

    assert buffer_id == "middle_buffer_errors"
    assert loaded.taxonomy.node(buffer_id).display_name == "Buffer Error Family"


def test_prompt_bundle_io_rejects_missing_required_top_level_fields(temp_dir):
    bundle_path = temp_dir / "prompt_bundle.json"
    bundle_path.write_text('{"schema_version":"2","nodes":{}}', encoding="utf-8")

    with pytest.raises(ValueError, match="bundle is missing required fields"):
        PromptBundleIO.load(bundle_path, load_mode="strict_v2")


def test_prompt_bundle_io_v1_and_v2_loaders_normalize_to_equivalent_runtime_bundle(
    temp_dir,
):
    artifact = PromptArtifact.from_mapping(
        {
            "prompts": {
                "major_Memory": "major-memory",
                "major_Injection": "major-injection",
                "middle_Buffer Errors": "middle-buffer",
                "cwe_CWE-120": "cwe-120",
            }
        }
    )
    artifact_path = temp_dir / "prompt_artifact.json"
    artifact.save(artifact_path)

    bundle = PromptBundleAdapter.from_artifact(
        artifact,
        source_artifact=str(artifact_path),
        allow_partial=True,
    )
    bundle_path = temp_dir / "prompt_bundle.json"
    PromptBundleIO.save(bundle, bundle_path, allow_partial=True)

    runtime_from_v1 = PromptBundleIO.load(artifact_path, load_mode="legacy_compat")
    runtime_from_v2 = PromptBundleIO.load(bundle_path, load_mode="legacy_compat")

    assert runtime_from_v1.to_dict() == runtime_from_v2.to_dict()
