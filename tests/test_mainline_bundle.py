import pytest

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

    assert reloaded.stage_order == ("major", "middle", "cwe")
    assert reloaded.parent_of("middle_Buffer Errors") == "major_Memory"
    assert reloaded.children_of("major_Memory") == [
        "middle_Buffer Errors",
        "middle_Memory Management",
        "middle_Pointer Dereference",
        "middle_Integer Errors",
    ]
    assert reloaded.decision_labels_for("middle_Buffer Errors") == [
        "Buffer Errors",
        "Memory Management",
        "Pointer Dereference",
        "Integer Errors",
    ]


def test_prompt_bundle_adapter_preserves_v1_node_ids_and_defaults():
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

    assert set(bundle.nodes) == {
        "major_Memory",
        "middle_Buffer Errors",
        "cwe_CWE-120",
    }
    assert bundle.nodes["major_Memory"].threshold is None
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

    assert bundle.schema_version == "2"
    assert "major_Memory" in bundle.nodes
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
