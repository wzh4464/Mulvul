"""V2 prompt bundle and taxonomy contracts for mainline runtime."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal, Mapping, cast

from mulvul.data.cwe_hierarchy import (
    MAJOR_TO_MIDDLE,
    MIDDLE_TO_CWE,
    cwe_node_id,
    major_node_id,
    middle_node_id,
)

from .artifacts import PromptArtifact

Stage = Literal["major", "middle", "cwe"]
STAGE_ORDER: tuple[Stage, ...] = ("major", "middle", "cwe")
REQUIRED_BUNDLE_FIELDS: tuple[str, ...] = (
    "schema_version",
    "taxonomy",
    "nodes",
    "defaults",
    "training_metadata",
    "data_fingerprint",
    "code_revision",
)
REQUIRED_TAXONOMY_FIELDS: tuple[str, ...] = (
    "version",
    "stage_order",
    "nodes",
    "benign_label",
)


def _parse_stage_template_mapping(
    value: Any,
    *,
    field_name: str,
) -> dict[Stage, str]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{field_name} must be a mapping")

    parsed: dict[Stage, str] = {}
    for raw_key, raw_value in value.items():
        key = str(raw_key)
        if key not in STAGE_ORDER:
            raise ValueError(
                f"{field_name} keys must be one of {STAGE_ORDER!r}; got {key!r}"
            )
        parsed[cast(Stage, key)] = str(raw_value)
    return parsed


@dataclass
class TaxonomyNode:
    """Single executable taxonomy node."""

    node_id: str
    stage: Stage
    label: str
    display_name: str
    parent_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "TaxonomyNode":
        label = str(data["label"])
        return cls(
            node_id=str(data["node_id"]),
            stage=str(data["stage"]),  # type: ignore[arg-type]
            label=label,
            display_name=str(data.get("display_name", label)),
            parent_id=(
                str(data["parent_id"]) if data.get("parent_id") is not None else None
            ),
        )


@dataclass
class TaxonomyGraph:
    """Self-describing hierarchy for v2 bundles."""

    version: str
    stage_order: tuple[Stage, ...]
    nodes: dict[str, TaxonomyNode]
    benign_label: str = "Benign"

    def node(self, node_id: str) -> TaxonomyNode:
        return self.nodes[node_id]

    def parent_of(self, node_id: str) -> str | None:
        return self.node(node_id).parent_id

    def children_of(self, node_id: str) -> list[str]:
        return [
            child.node_id for child in self.nodes.values() if child.parent_id == node_id
        ]

    def node_ids_for_stage(self, stage: Stage) -> list[str]:
        return [node.node_id for node in self.nodes.values() if node.stage == stage]

    def labels_for_stage(self, stage: Stage) -> list[str]:
        return [self.node(node_id).label for node_id in self.node_ids_for_stage(stage)]

    def display_names_for_stage(self, stage: Stage) -> list[str]:
        return [
            self.node(node_id).display_name
            for node_id in self.node_ids_for_stage(stage)
        ]

    def node_id_for_label(self, stage: Stage, label: str) -> str:
        for node in self.nodes.values():
            if node.stage == stage and node.label == label:
                return node.node_id
        raise KeyError(f"No taxonomy node for stage={stage!r}, label={label!r}")

    def decision_labels_for(self, node_id: str) -> list[str]:
        node = self.node(node_id)
        if node.stage == "major":
            return self.labels_for_stage("major")

        return [
            sibling.label
            for sibling in self.nodes.values()
            if sibling.stage == node.stage and sibling.parent_id == node.parent_id
        ]

    def validate_bundle(
        self,
        bundle_nodes: dict[str, "NodeSpec"],
        allow_partial: bool = False,
    ) -> list[str]:
        errors: list[str] = []
        for node_id, spec in bundle_nodes.items():
            taxonomy_node = self.nodes.get(node_id)
            if taxonomy_node is None:
                errors.append(f"NodeSpec references unknown taxonomy node: {node_id}")
                continue
            if spec.stage != taxonomy_node.stage:
                errors.append(
                    f"NodeSpec {node_id} stage mismatch: {spec.stage!r} != "
                    f"{taxonomy_node.stage!r}"
                )
            if spec.target_label != taxonomy_node.label:
                errors.append(
                    f"NodeSpec {node_id} target mismatch: {spec.target_label!r} != "
                    f"{taxonomy_node.label!r}"
                )

        if not allow_partial:
            missing = [
                node_id for node_id in self.nodes.keys() if node_id not in bundle_nodes
            ]
            if missing:
                errors.append(
                    "Bundle is missing node specs for taxonomy nodes: "
                    + ", ".join(missing)
                )

        return errors

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "stage_order": list(self.stage_order),
            "benign_label": self.benign_label,
            "nodes": {node_id: node.to_dict() for node_id, node in self.nodes.items()},
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "TaxonomyGraph":
        missing_fields = [
            field_name
            for field_name in REQUIRED_TAXONOMY_FIELDS
            if field_name not in data
        ]
        if missing_fields:
            raise ValueError(
                "taxonomy is missing required fields: " + ", ".join(missing_fields)
            )

        nodes_obj = data["nodes"]
        if not isinstance(nodes_obj, Mapping):
            raise ValueError("taxonomy.nodes must be a mapping")
        invalid_nodes = [
            str(node_id)
            for node_id, node_data in nodes_obj.items()
            if not isinstance(node_data, Mapping)
        ]
        if invalid_nodes:
            raise ValueError(
                "taxonomy.nodes entries must be mappings for: "
                + ", ".join(invalid_nodes)
            )

        stage_order = data["stage_order"]
        if not isinstance(stage_order, (list, tuple)):
            raise ValueError("taxonomy.stage_order must be a list or tuple")

        return cls(
            version=str(data["version"]),
            stage_order=tuple(stage_order),  # type: ignore[arg-type]
            nodes={
                str(node_id): TaxonomyNode.from_dict(node_data)
                for node_id, node_data in nodes_obj.items()
            },
            benign_label=str(data["benign_label"]),
        )

    @classmethod
    def from_current_mainline(
        cls,
        version: str = "mainline-2026-04",
    ) -> "TaxonomyGraph":
        nodes: dict[str, TaxonomyNode] = {}

        for major, middles in MAJOR_TO_MIDDLE.items():
            major_id = major_node_id(major)
            nodes[major_id] = TaxonomyNode(
                node_id=major_id,
                stage="major",
                label=major,
                display_name=major,
                parent_id=None,
            )
            for middle in middles:
                middle_id = middle_node_id(middle)
                nodes[middle_id] = TaxonomyNode(
                    node_id=middle_id,
                    stage="middle",
                    label=middle,
                    display_name=middle,
                    parent_id=major_id,
                )
                for cwe in MIDDLE_TO_CWE.get(middle, []):
                    cwe_id = cwe_node_id(cwe)
                    nodes[cwe_id] = TaxonomyNode(
                        node_id=cwe_id,
                        stage="cwe",
                        label=cwe,
                        display_name=cwe,
                        parent_id=middle_id,
                    )

        return cls(version=version, stage_order=STAGE_ORDER, nodes=nodes)


@dataclass
class NodeSpec:
    """Executable config for one taxonomy node."""

    node_id: str
    stage: Stage
    target_label: str
    instruction_template: str
    query_template: str | None = None
    evidence_template: str | None = None
    output_schema: str = "ranking_v2"
    threshold: float | None = None
    allow_abstain: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "NodeSpec":
        return cls(
            node_id=str(data["node_id"]),
            stage=str(data["stage"]),  # type: ignore[arg-type]
            target_label=str(data["target_label"]),
            instruction_template=str(data["instruction_template"]),
            query_template=(
                str(data["query_template"])
                if data.get("query_template") is not None
                else None
            ),
            evidence_template=(
                str(data["evidence_template"])
                if data.get("evidence_template") is not None
                else None
            ),
            output_schema=str(data.get("output_schema", "ranking_v2")),
            threshold=(
                float(data["threshold"]) if data.get("threshold") is not None else None
            ),
            allow_abstain=bool(data.get("allow_abstain", True)),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass
class EvidenceItem:
    """Single structured evidence item."""

    kind: Literal["positive", "hard_negative", "benign", "rule", "other"]
    title: str
    text: str
    source_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "EvidenceItem":
        return cls(
            kind=str(data.get("kind", "other")),  # type: ignore[arg-type]
            title=str(data.get("title", "")),
            text=str(data.get("text", "")),
            source_id=str(data.get("source_id", "")),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass
class EvidenceBundle:
    """Structured evidence passed to the scorer."""

    items: list[EvidenceItem]
    retrieval_ids: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "items": [item.to_dict() for item in self.items],
            "retrieval_ids": list(self.retrieval_ids),
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "EvidenceBundle":
        return cls(
            items=[
                EvidenceItem.from_dict(item)
                for item in data.get("items", [])
                if isinstance(item, Mapping)
            ],
            retrieval_ids=[str(item) for item in data.get("retrieval_ids", [])],
            metadata=dict(data.get("metadata", {})),
        )


@dataclass
class BundleDefaults:
    """Bundle-level execution defaults."""

    default_threshold: float = 0.5
    default_query_templates: dict[Stage, str] = field(default_factory=dict)
    default_evidence_templates: dict[Stage, str] = field(default_factory=dict)
    distrust_fallback: bool = True
    max_abstain_delta_pp: float = 5.0
    max_benign_reject_drop_pp: float = 2.0
    max_hard_negative_reject_drop_pp: float = 2.0
    policy_name: str = "greedy"
    policy_config: dict[str, Any] = field(default_factory=dict)
    scorer_config: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "default_threshold": self.default_threshold,
            "default_query_templates": dict(self.default_query_templates),
            "default_evidence_templates": dict(self.default_evidence_templates),
            "distrust_fallback": self.distrust_fallback,
            "max_abstain_delta_pp": self.max_abstain_delta_pp,
            "max_benign_reject_drop_pp": self.max_benign_reject_drop_pp,
            "max_hard_negative_reject_drop_pp": self.max_hard_negative_reject_drop_pp,
            "policy_name": self.policy_name,
            "policy_config": dict(self.policy_config),
            "scorer_config": dict(self.scorer_config),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "BundleDefaults":
        default_query_templates = _parse_stage_template_mapping(
            data.get("default_query_templates", {}),
            field_name="defaults.default_query_templates",
        )
        default_evidence_templates = _parse_stage_template_mapping(
            data.get("default_evidence_templates", {}),
            field_name="defaults.default_evidence_templates",
        )
        return cls(
            default_threshold=float(data.get("default_threshold", 0.5)),
            default_query_templates=default_query_templates,
            default_evidence_templates=default_evidence_templates,
            distrust_fallback=bool(data.get("distrust_fallback", True)),
            max_abstain_delta_pp=float(data.get("max_abstain_delta_pp", 5.0)),
            max_benign_reject_drop_pp=float(data.get("max_benign_reject_drop_pp", 2.0)),
            max_hard_negative_reject_drop_pp=float(
                data.get("max_hard_negative_reject_drop_pp", 2.0)
            ),
            policy_name=str(data.get("policy_name", "greedy")),
            policy_config=dict(data.get("policy_config", {})),
            scorer_config=dict(data.get("scorer_config", {})),
        )


@dataclass
class PromptBundle:
    """Self-describing v2 executable artifact."""

    schema_version: str
    taxonomy: TaxonomyGraph
    nodes: dict[str, NodeSpec]
    defaults: BundleDefaults
    training_metadata: dict[str, Any]
    data_fingerprint: str
    code_revision: str

    def validate(self, allow_partial: bool = False) -> list[str]:
        errors: list[str] = []
        if self.schema_version != "2":
            errors.append(f"Unsupported bundle schema_version: {self.schema_version!r}")
        if tuple(self.taxonomy.stage_order) != STAGE_ORDER:
            errors.append(
                "Taxonomy stage_order must be ('major', 'middle', 'cwe'), got "
                f"{self.taxonomy.stage_order!r}"
            )
        errors.extend(
            self.taxonomy.validate_bundle(self.nodes, allow_partial=allow_partial)
        )
        return errors

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "taxonomy": self.taxonomy.to_dict(),
            "nodes": {node_id: node.to_dict() for node_id, node in self.nodes.items()},
            "defaults": self.defaults.to_dict(),
            "training_metadata": dict(self.training_metadata),
            "data_fingerprint": self.data_fingerprint,
            "code_revision": self.code_revision,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "PromptBundle":
        missing_fields = [
            field_name
            for field_name in REQUIRED_BUNDLE_FIELDS
            if field_name not in data
        ]
        if missing_fields:
            raise ValueError(
                "bundle is missing required fields: " + ", ".join(missing_fields)
            )

        taxonomy_obj = data["taxonomy"]
        if not isinstance(taxonomy_obj, Mapping):
            raise ValueError("bundle.taxonomy must be a mapping")

        nodes_obj = data["nodes"]
        if not isinstance(nodes_obj, Mapping):
            raise ValueError("bundle.nodes must be a mapping")
        invalid_nodes = [
            str(node_id)
            for node_id, node_data in nodes_obj.items()
            if not isinstance(node_data, Mapping)
        ]
        if invalid_nodes:
            raise ValueError(
                "bundle.nodes entries must be mappings for: " + ", ".join(invalid_nodes)
            )

        defaults_obj = data["defaults"]
        if not isinstance(defaults_obj, Mapping):
            raise ValueError("bundle.defaults must be a mapping")

        training_metadata = data["training_metadata"]
        if not isinstance(training_metadata, Mapping):
            raise ValueError("bundle.training_metadata must be a mapping")

        return cls(
            schema_version=str(data["schema_version"]),
            taxonomy=TaxonomyGraph.from_dict(taxonomy_obj),
            nodes={
                str(node_id): NodeSpec.from_dict(node_data)
                for node_id, node_data in nodes_obj.items()
            },
            defaults=BundleDefaults.from_dict(defaults_obj),
            training_metadata=dict(training_metadata),
            data_fingerprint=str(data["data_fingerprint"]),
            code_revision=str(data["code_revision"]),
        )


@dataclass
class ScorerContext:
    """Node-local scoring context."""

    code: str
    candidate_labels: list[str]
    mode: Literal["train", "eval", "infer"] = "infer"
    parent_result: "NodeScoreResult | None" = None
    evidence: EvidenceBundle | None = None
    request_id: str = ""
    sample_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class NodeScoreResult:
    """Unified train/infer scoring result."""

    node_id: str
    stage: Stage
    target_label: str
    predicted_label: str | None
    top_confidence: float
    target_confidence: float
    ranking: list[tuple[str, float]]
    matched_target: bool
    decision: Literal["accept", "reject", "abstain", "error"]
    reject_label: str | None = None
    parse_status: Literal["ok", "fallback", "error"] = "ok"
    effective_threshold: float | None = None
    raw_response: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class PromptBundleAdapter:
    """Compatibility adapter from the frozen v1 artifact to v2 runtime objects."""

    @classmethod
    def from_artifact(
        cls,
        artifact: PromptArtifact,
        *,
        source_artifact: str = "unknown",
        allow_partial: bool = True,
        training_metadata: Mapping[str, Any] | None = None,
        data_fingerprint: str = "unknown",
        code_revision: str = "unknown",
    ) -> PromptBundle:
        taxonomy = TaxonomyGraph.from_current_mainline(version="legacy")
        nodes: dict[str, NodeSpec] = {}

        for label, prompt in artifact.router_prompts.items():
            node_id = taxonomy.node_id_for_label("major", label)
            nodes[node_id] = NodeSpec(
                node_id=node_id,
                stage="major",
                target_label=label,
                instruction_template=prompt,
                threshold=None,
                metadata={"source_format": "v1"},
            )

        for label, prompt in artifact.middle_prompts.items():
            node_id = taxonomy.node_id_for_label("middle", label)
            nodes[node_id] = NodeSpec(
                node_id=node_id,
                stage="middle",
                target_label=label,
                instruction_template=prompt,
                threshold=None,
                metadata={"source_format": "v1"},
            )

        for label, prompt in artifact.cwe_prompts.items():
            node_id = taxonomy.node_id_for_label("cwe", label)
            nodes[node_id] = NodeSpec(
                node_id=node_id,
                stage="cwe",
                target_label=label,
                instruction_template=prompt,
                threshold=None,
                metadata={"source_format": "v1"},
            )

        normalized_training_metadata = {
            "trainer_name": "legacy_v1_adapter",
            "trainer_seed": "unknown",
            "split_hash": "unknown",
            "retrieval_snapshot_id": "unknown",
            "created_at": "unknown",
            "source_dataset": "unknown",
            "source_artifact": source_artifact,
        }
        if training_metadata is not None:
            normalized_training_metadata.update(dict(training_metadata))
        normalized_training_metadata.setdefault("source_artifact", source_artifact)

        bundle = PromptBundle(
            schema_version="2",
            taxonomy=taxonomy,
            nodes=nodes,
            defaults=BundleDefaults(),
            training_metadata=normalized_training_metadata,
            data_fingerprint=data_fingerprint,
            code_revision=code_revision,
        )

        errors = bundle.validate(allow_partial=allow_partial)
        if errors:
            raise ValueError("; ".join(errors))
        return bundle


class PromptBundleIO:
    """Read/write ownership for v2 bundles."""

    @staticmethod
    def _read_json(path: str | Path) -> dict[str, Any]:
        bundle_path = Path(path)
        with bundle_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        if not isinstance(data, Mapping):
            raise ValueError("Prompt bundle file must decode to a JSON object.")
        return dict(data)

    @classmethod
    def load(
        cls,
        path: str | Path,
        *,
        load_mode: Literal["strict_v2", "legacy_compat"] = "strict_v2",
    ) -> PromptBundle:
        data = cls._read_json(path)
        if data.get("schema_version") == "2":
            bundle = PromptBundle.from_dict(data)
            errors = bundle.validate(allow_partial=(load_mode == "legacy_compat"))
            if errors:
                raise ValueError("; ".join(errors))
            return bundle

        if load_mode != "legacy_compat":
            raise ValueError(
                "Expected a v2 prompt bundle with schema_version='2'; got a v1 "
                "artifact or unknown file format."
            )

        artifact = PromptArtifact.from_mapping(data)
        return PromptBundleAdapter.from_artifact(
            artifact,
            source_artifact=str(path),
            allow_partial=True,
        )

    @classmethod
    def save(
        cls,
        bundle: PromptBundle,
        path: str | Path,
        *,
        allow_partial: bool = False,
    ) -> Path:
        errors = bundle.validate(allow_partial=allow_partial)
        if errors:
            raise ValueError("; ".join(errors))

        bundle_path = Path(path)
        bundle_path.parent.mkdir(parents=True, exist_ok=True)
        with bundle_path.open("w", encoding="utf-8") as handle:
            json.dump(bundle.to_dict(), handle, indent=2, ensure_ascii=False)
        return bundle_path
