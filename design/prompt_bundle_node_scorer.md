# Design Spec: PromptBundle, NodeScorer, Trainer, InferencePolicy, and Evaluator

Status: **accepted**

Date: **2026-04-02**

Owners: `mainline/`

## 1. Purpose

This document defines the next-generation mainline contracts for Mulvul.

It replaces the current split responsibilities of:

- `PromptArtifact`
- `LevelDetector`
- `MainlineDetectorSystem`
- `HierarchicalTrainer`

with a coherent v2 architecture built around:

- `TaxonomyGraph`
- `PromptBundle`
- `NodeScorer`
- `Sampler`
- `NodeTrainer`
- `BundleTrainer`
- `InferencePolicy`
- `Evaluator`

The goal is not to introduce a new research algorithm. The goal is to make the
existing system internally coherent so that:

1. prompts are saved and consumed under one schema
2. training and inference share the same scoring contract
3. taxonomy is self-describing and versioned
4. routing policy is separate from node scoring
5. retrieval context becomes an explicit input instead of an implicit side path
6. v1 behavior remains available during migration

## 2. Scope

This spec covers:

- prompt artifact schema for mainline
- taxonomy ownership
- node scoring semantics
- node-level training semantics
- cascade inference semantics
- runtime feature ownership for RAG, parallel scoring, and top-k routing
- v1/v2 compatibility and migration

This spec does not cover:

- legacy `scripts/ablations/*` behavior beyond adapter compatibility
- specific prompt wording
- retriever ranking algorithm details
- path calibration model implementation details
- model-specific decoding settings

## 3. Current Repository Facts

These are repository facts today, not design goals.

### 3.1 Current scoring semantics

`src/mulvul/agents/hierarchical_detector.py` implements `LevelDetector.detect()`
as a ranking API:

- return type is `List[Tuple[label, confidence]]`
- JSON success path uses model self-reported confidence
- fallback path uses heuristic keyword-position confidence
- final fallback is `[("Benign", 0.5)]`

Therefore the current output is:

- not calibrated
- not a stable business decision
- not safely comparable across stages

### 3.2 Current train/infer mismatch

Current node training in `src/mulvul/agents/hierarchical_trainer.py` checks the
top-1 predicted label only.

Current mainline inference in `src/mulvul/mainline/system.py`:

- parses the full ranking
- extracts `target_confidence` if target appears anywhere
- separately records `predicted_label = ranking[0][0]`

So training and inference optimize different success criteria.

### 3.3 Current label semantics

- `Benign` is a real business output
- `Unknown` is a fallback sentinel, not a real business output
- `abstain` does not exist as an explicit contract

### 3.4 Current taxonomy ownership

There is no single taxonomy source. Independent hierarchy definitions exist in:

- `src/mulvul/data/cwe_hierarchy.py`
- `src/mulvul/agents/hierarchical_detector.py`
- `src/mulvul/prompts/hierarchical_three_layer.py`

### 3.5 Current sampling and training behavior

Current sampler behavior is fixed three-way sampling:

- `target`
- `other_vul`
- `benign`

Current mainline training:

- does not maintain a fixed per-node validation split
- re-samples across rounds
- does not define a first-class hard-negative metric contract
- does not explicitly propagate workflow seed through all layers

### 3.6 Current public surface

The following must be treated as externally visible:

- CLI subcommands `evolve` and `evaluate`
- `prompt_artifact.json`
- `best_prompts.json`
- `summary.json`
- `PromptArtifact` exported from `mulvul.__init__`

Current tests lock at least these legacy behaviors:

1. v1 artifact prefix splitting
2. best-path inference from a partial artifact

## 4. Core Design Decisions

This spec fixes the following decisions.

### 4.1 Taxonomy is a first-class artifact object

`TaxonomyGraph` is the single hierarchy source for v2 bundles.

Loading a v2 bundle must not require importing a second hierarchy definition.

### 4.2 PromptBundle stores executable node config, not just prompt text

Each node carries:

- node identity
- stage
- target label
- instruction prompt
- optional query template
- optional evidence formatting template
- threshold override
- local metadata

This is intentionally richer than v1 `PromptArtifact`.

### 4.3 NodeScorer is the single scoring contract

Training and inference must call the same scorer API and consume the same
`NodeScoreResult`.

No separate train-only interpretation of scores is allowed.

### 4.4 InferencePolicy owns cascade execution

Node scoring is node-local.

Cascade logic belongs to `InferencePolicy`, including:

- scheduling
- branch expansion
- pruning
- parallel execution
- retrieval orchestration
- path aggregation
- final prediction selection

### 4.5 Evaluator owns end-to-end metrics

NodeTrainer optimizes node-level metrics.

`Evaluator` is the only owner of:

- route metrics
- path metrics
- end-to-end classification metrics
- cost metrics

### 4.6 v1 remains frozen

`PromptArtifact` remains a stable v1 surface.

v2 must be added alongside it, not by changing its semantics.

## 5. Non-Goals

This spec deliberately does not require:

- immediate deletion of v1 artifact flow
- immediate deletion of legacy scripts
- global score comparability across all stages
- beam search in the first migration step
- immediate introduction of learned path calibrators

## 6. Terminology

- `stage`: one of `major`, `middle`, `cwe`
- `target`: the node's own positive label
- `hard_negative`: a vulnerable negative sample from a confusable sibling or
  nearby branch; this is the v2 name for legacy `other_vul`
- `benign_negative`: a benign sample
- `decision`: one of `accept`, `reject`, `abstain`, `error`
- `policy`: runtime object that decides which nodes to score and how to combine
  them
- `bundle`: self-describing artifact containing taxonomy, node config, and
  defaults

## 7. Normative Data Model

This section is normative.

### 7.1 Identifier convention

Every taxonomy node has a canonical `node_id`.

The canonical format is the current v1 prefix form:

- `major_Memory`
- `middle_Buffer Errors`
- `cwe_CWE-120`

Rationale:

- it matches current artifact keys
- it minimizes adapter churn
- it already appears in tests and output files

### 7.2 Stage

```python
Stage = Literal["major", "middle", "cwe"]
```

Stage order is fixed:

```python
("major", "middle", "cwe")
```

### 7.3 TaxonomyNode

```python
@dataclass
class TaxonomyNode:
    node_id: str
    stage: Stage
    label: str
    parent_id: str | None = None
```

Rules:

- every node belongs to exactly one stage
- every middle node has exactly one major parent
- every cwe node has exactly one middle parent
- major nodes have `parent_id = None`
- `Benign` is not represented as a taxonomy node

### 7.4 TaxonomyGraph

```python
@dataclass
class TaxonomyGraph:
    version: str
    stage_order: tuple[Stage, ...]
    nodes: dict[str, TaxonomyNode]
    benign_label: str = "Benign"

    def node(self, node_id: str) -> TaxonomyNode: ...
    def parent_of(self, node_id: str) -> str | None: ...
    def children_of(self, node_id: str) -> list[str]: ...
    def node_ids_for_stage(self, stage: Stage) -> list[str]: ...
    def labels_for_stage(self, stage: Stage) -> list[str]: ...
    def decision_labels_for(self, node_id: str) -> list[str]: ...
    def validate_bundle(
        self,
        bundle_nodes: dict[str, "NodeSpec"],
        allow_partial: bool = False,
    ) -> list[str]: ...
```

Rules:

- `TaxonomyGraph` is the single source of truth for v2 hierarchy
- `stage_order` must be `("major", "middle", "cwe")`
- production v2 bundles must validate against the full graph with
  `allow_partial=False`
- `allow_partial=True` is reserved for tests, debugging, and legacy-adapter
  compatibility mode

Definition of `decision_labels_for(node_id)`:

- for a major node: labels of all major nodes
- for a middle node: labels of all middle nodes sharing the same parent major
- for a cwe node: labels of all cwe nodes sharing the same parent middle

This method is the only taxonomy-backed source of node-local decision space.

### 7.5 NodeSpec

```python
@dataclass
class NodeSpec:
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
```

Rules:

- `NodeSpec` is execution config for one taxonomy node
- `NodeSpec` MUST NOT store `parent_id`
- `NodeSpec` MUST NOT store `child_ids`
- `NodeSpec` MUST NOT store candidate labels
- `NodeSpec` MUST NOT store `Benign`
- `instruction_template` is the node's main task definition
- `query_template` is optional and used by policy-owned retrieval components
- `evidence_template` is optional and used by scorer-side prompt rendering
- `threshold=None` means "use bundle default"

Validation:

- `node_id`, `stage`, and `target_label` must match the embedded taxonomy node
- bundle validation must fail if a `NodeSpec` references a node missing from the
  taxonomy

### 7.6 EvidenceItem and EvidenceBundle

```python
@dataclass
class EvidenceItem:
    kind: Literal["positive", "hard_negative", "benign", "rule", "other"]
    title: str
    text: str
    source_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class EvidenceBundle:
    items: list[EvidenceItem]
    retrieval_ids: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
```

Rules:

- retrieval returns structured evidence, not pre-concatenated raw text
- `hard_negative` is a first-class evidence kind
- `rule` evidence supports non-exemplar guidance
- policy MAY supply an empty evidence bundle
- scorer formats evidence through `NodeSpec.evidence_template` or a stage
  default

### 7.7 BundleDefaults

```python
@dataclass
class BundleDefaults:
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
```

Rules:

- per-node `threshold=None` means "use `default_threshold`"
- v1 adapters MUST populate bundle defaults, not invent node-local thresholds
- stage-default query/evidence templates exist primarily for v1 adaptation and
  stage-shared configs

### 7.8 PromptBundle

```python
@dataclass
class PromptBundle:
    schema_version: str
    taxonomy: TaxonomyGraph
    nodes: dict[str, NodeSpec]
    defaults: BundleDefaults
    training_metadata: dict[str, Any]
    data_fingerprint: str
    code_revision: str
```

Rules:

- v2 bundles use `schema_version = "2"`
- bundle loading must not import any external hierarchy file
- a v2 bundle is self-describing and executable by itself
- production v2 load must validate full taxonomy coverage

Recommended `training_metadata` keys:

- `trainer_name`
- `trainer_seed`
- `split_hash`
- `retrieval_snapshot_id`
- `created_at`
- `source_dataset`
- `source_artifact`

### 7.9 ScorerContext

```python
@dataclass
class ScorerContext:
    code: str
    candidate_labels: list[str]
    mode: Literal["train", "eval", "infer"] = "infer"
    parent_result: "NodeScoreResult | None" = None
    evidence: EvidenceBundle | None = None
    request_id: str = ""
    sample_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
```

Rules:

- every scorer call MUST receive a `ScorerContext`
- `candidate_labels` MUST already include `taxonomy.benign_label`
- `parent_result` MAY be a synthetic oracle result during training
- scorer MUST NOT fetch evidence on its own
- scorer MUST NOT inspect global cascade state outside `ctx`
- `metadata` MAY carry cache hints, oracle flags, or runtime trace data

### 7.10 NodeScoreResult

```python
@dataclass
class NodeScoreResult:
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
```

Rules:

- `predicted_label` is the top-1 label if one exists, else `None`
- `ranking` labels MUST be a subset of `ctx.candidate_labels`
- `target_confidence` is the score attached to `target_label` if present in
  `ranking`, else `0.0`
- `matched_target` is diagnostic only; it is not the primary optimization
  signal
- `Unknown` is not a valid v2 label
- if legacy logic would have emitted `Unknown`, v2 MUST emit either:
  - `decision="abstain"` with `predicted_label=None`, or
  - `decision="error"` with `predicted_label=None`

Decision assignment:

- `accept`
  - `predicted_label == target_label`
  - `top_confidence >= effective_threshold`
- `reject`
  - `predicted_label is not None`
  - `predicted_label != target_label`
  - `top_confidence >= effective_threshold`
  - `reject_label = predicted_label`
- `abstain`
  - parse succeeded or a fallback ranking exists
  - but no candidate confidently crosses threshold
  - or fallback output is distrusted by config
- `error`
  - model call failure
  - or completely unparseable output with no usable fallback

### 7.11 DetectionPath

```python
@dataclass
class DetectionPath:
    node_ids: list[str]
    stage_results: list[NodeScoreResult]
    final_label: str
    score: float
```

Rules:

- `node_ids` are ordered by stage
- `stage_results` are ordered by stage
- `final_label` is the deepest accepted label on the path
- `score` is owned by the policy, not by the scorer

### 7.12 InferenceResult

```python
@dataclass
class InferenceResult:
    prediction: str
    best_path: DetectionPath | None
    candidate_paths: list[DetectionPath]
    stage_results: dict[Stage, list[NodeScoreResult]]
    nodes_scored: int
    nodes_skipped: int
```

Rules:

- `prediction` MUST never be `Unknown`
- valid final outputs are:
  - `taxonomy.benign_label`
  - or a taxonomy label

### 7.13 NodeSample

```python
@dataclass
class NodeSample:
    sample_id: str
    code: str
    sample_kind: Literal["target", "hard_negative", "benign"]
    ground_truth_label: str
    metadata: dict[str, Any] = field(default_factory=dict)
```

Rules:

- `hard_negative` is the v2 name for legacy `other_vul`
- `ground_truth_label` stores the business label, not just binary polarity

### 7.14 NodeMetrics

```python
@dataclass
class NodeMetrics:
    tp: int
    fp: int
    fn: int
    tn: int
    target_accept_rate: float
    hard_negative_reject_rate: float
    benign_reject_rate: float
    hard_negative_benign_reject_rate: float
    abstain_rate: float
    error_rate: float
    node_precision: float
    node_recall: float
    node_f1: float
```

Rules:

- `node_f1` is the primary node-level optimization target
- `hard_negative_reject_rate` and `benign_reject_rate` are guardrail metrics
- `hard_negative_benign_reject_rate` is diagnostic only

### 7.15 EvaluationSample and EvaluationResult

```python
@dataclass
class EvaluationSample:
    sample_id: str
    code: str
    major_label: str | None
    middle_label: str | None
    cwe_label: str | None
    final_label: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class EvaluationResult:
    node_metrics: dict[str, NodeMetrics]
    route_metrics: dict[str, float]
    end_to_end_metrics: dict[str, float]
    cost_metrics: dict[str, float]
    metadata: dict[str, Any] = field(default_factory=dict)
```

Rules:

- `route_metrics` cover routing quality, not final business accuracy alone
- `end_to_end_metrics` cover final output quality
- `cost_metrics` cover API/token/runtime cost

## 8. Normative Contracts

### 8.1 NodeScorer

```python
class NodeScorer(Protocol):
    def score(self, node: NodeSpec, ctx: ScorerContext) -> NodeScoreResult: ...
```

Rules:

- scorer is stateless and node-local
- scorer owns prompt rendering and response parsing
- scorer MAY use `node.query_template` only for prompt construction or trace
  metadata; retrieval execution remains policy-owned
- scorer MUST render evidence from `ctx.evidence` plus node/bundle templates
- scorer does not own retrieval
- scorer does not own branch scheduling
- scorer does not own path aggregation
- scorer does not own parallel execution

### 8.2 EvidenceProvider

```python
class EvidenceProvider(Protocol):
    def retrieve(
        self,
        bundle: PromptBundle,
        node: NodeSpec,
        ctx: ScorerContext,
    ) -> EvidenceBundle: ...
```

Rules:

- `EvidenceProvider` is policy-owned
- it may use `node.query_template` to form retrieval queries
- it must not mutate node config

### 8.3 Sampler

```python
class Sampler(Protocol):
    def get_split(
        self,
        node_id: str,
        split: Literal["train", "valid"],
        seed: int,
    ) -> list[NodeSample]: ...
```

Rules:

- `get_split(node_id, split, seed)` MUST be deterministic
- the validation split for a node MUST remain fixed for the full training run
- sampler is responsible for negative sampling policy
- trainer is responsible for consuming that split consistently

### 8.4 NodeTrainer

```python
class NodeTrainer(Protocol):
    def train_node(
        self,
        bundle: PromptBundle,
        node_id: str,
        scorer: NodeScorer,
        sampler: Sampler,
        seed: int,
    ) -> NodeSpec: ...
```

Rules:

- `NodeTrainer` optimizes one node at a time
- it MUST evaluate candidates on a fixed validation split
- it MUST select prompts by node-level metrics only
- it MAY use any optimization strategy:
  - rewrite loop
  - pairwise comparison
  - beam
  - population search
- optimization algorithm choice is not part of the contract

### 8.5 BundleTrainer

```python
class BundleTrainer(Protocol):
    def train_bundle(
        self,
        initial_bundle: PromptBundle,
        scorer: NodeScorer,
        sampler: Sampler,
        seed: int,
    ) -> PromptBundle: ...
```

Rules:

- `BundleTrainer` orchestrates node training over the taxonomy
- it MUST NOT replace node-level selection with end-to-end path F1
- it MAY run evaluator-based regression checks between checkpoints
- it returns a full `PromptBundle`, not just raw prompt text

### 8.6 InferencePolicy

```python
class InferencePolicy(Protocol):
    def run(
        self,
        bundle: PromptBundle,
        scorer: NodeScorer,
        code: str,
    ) -> InferenceResult: ...
```

Rules:

`InferencePolicy` owns the entire cascade:

1. node scheduling
2. context construction
3. retrieval orchestration
4. parallel execution
5. branch pruning
6. path assembly
7. path scoring
8. final prediction selection

### 8.7 Evaluator

```python
class Evaluator(Protocol):
    def evaluate(
        self,
        bundle: PromptBundle,
        scorer: NodeScorer,
        policy: InferencePolicy,
        dataset: Sequence[EvaluationSample],
    ) -> EvaluationResult: ...
```

Rules:

- `Evaluator` is the owner of route-level and end-to-end metrics
- `Evaluator` MUST NOT mutate bundle contents
- `Evaluator` MAY reuse `policy.run()` without a separate inference path

## 9. Semantic Rules

### 9.1 Benign / Unknown / abstain

- `Benign`
  - global reject label
  - valid final business output
  - not a taxonomy node
  - appended exactly once at runtime from `taxonomy.benign_label`
- `Unknown`
  - legacy-only sentinel
  - not a valid v2 prediction
  - must not appear in v2 bundle contents or v2 inference output
- `abstain`
  - explicit v2 internal decision
  - means "insufficient confidence to accept or reject this node"
  - not equivalent to `Benign`

### 9.2 Candidate label ownership

Candidate labels are not stored in `NodeSpec`.

Runtime label assembly is:

1. policy selects a node
2. policy computes `taxonomy.decision_labels_for(node.node_id)`
3. policy appends `taxonomy.benign_label`
4. policy stores that ordered list in `ScorerContext.candidate_labels`

This is the only place where `Benign` is appended.

Implications:

- `Benign` has exactly one owner: `TaxonomyGraph.benign_label`
- adapters cannot double-append it
- bundle validation does not depend on candidate-label duplication

### 9.3 Threshold resolution

Effective threshold resolution order is:

1. `NodeSpec.threshold`, if not `None`
2. `PromptBundle.defaults.default_threshold`

v1 adapter rule:

- adapted nodes MUST set `threshold=None`
- adapter MAY set `defaults.default_threshold=0.5`

This preserves the fact that v1 had no real per-node thresholds.

### 9.4 Query and evidence template resolution

Resolution order for query template:

1. `NodeSpec.query_template`, if not `None`
2. `PromptBundle.defaults.default_query_templates[node.stage]`, if present
3. empty template

Resolution order for evidence template:

1. `NodeSpec.evidence_template`, if not `None`
2. `PromptBundle.defaults.default_evidence_templates[node.stage]`, if present
3. scorer-native fallback formatter

### 9.5 Parse fallback semantics

Fallback parsing is allowed, but must be explicit.

Rules:

- fallback parse MUST set `parse_status="fallback"`
- if `defaults.distrust_fallback=True`, fallback output MUST map to `abstain`
  unless the scorer has a documented stronger fallback
- total parse failure with no usable ranking MUST map to `error`

### 9.6 Score comparability

- `top_confidence` and `target_confidence` are only comparable:
  - within the same stage
  - under the same scorer configuration
  - under the same calibration scheme
- cross-stage comparability is not guaranteed
- path aggregation is therefore policy-owned, not scorer-owned

### 9.7 Training sample semantics

For node target label `T`:

- `target` samples are positives
- `hard_negative` samples are vulnerable negatives
- `benign` samples are benign negatives

`hard_negative` is a mandatory first-class category because node training must
not collapse "confusable vulnerability" and "obvious benign" into one bucket.

### 9.8 Node metric semantics

Node metrics are computed on the fixed validation split for that node.

Binary counting for the primary objective:

- `target + accept` -> TP
- `target + reject/abstain/error` -> FN
- `negative + accept` -> FP
- `negative + reject/abstain/error` -> TN

Where:

- `negative` means `hard_negative` or `benign`

Required guardrail metrics:

- `target_accept_rate`
- `hard_negative_reject_rate`
- `benign_reject_rate`
- `hard_negative_benign_reject_rate`
- `abstain_rate`
- `error_rate`
- `node_precision`
- `node_recall`
- `node_f1`

Interpretation:

- `node_f1` is the primary selection metric
- `hard_negative_reject_rate` ensures sibling negatives remain explicit
- `benign_reject_rate` prevents prompts that merely overfit hard negatives
- `hard_negative_benign_reject_rate` is diagnostic; it does not require the
  scorer to identify the correct sibling label
- `abstain_rate` and `error_rate` prevent degenerate prompts from winning by
  refusing to decide

### 9.9 Prompt selection rule

A candidate node replaces the incumbent only if all of the following hold on the
fixed validation split:

1. `node_f1` improves
2. `benign_reject_rate` does not drop by more than
   `defaults.max_benign_reject_drop_pp`
3. `hard_negative_reject_rate` does not drop by more than
   `defaults.max_hard_negative_reject_drop_pp`
4. `abstain_rate` does not increase by more than
   `defaults.max_abstain_delta_pp`

Tie-breakers, in order:

1. lower `error_rate`
2. lower `abstain_rate`
3. shorter rendered prompt text

### 9.10 Oracle-parent training

Default staged training policy is:

- major nodes train without parent context
- middle nodes train with oracle or synthetic major parent context
- cwe nodes train with oracle or synthetic middle parent context

End-to-end routed evaluation remains evaluator-owned and separate from node
selection.

### 9.11 Default greedy cascade policy

The default `GreedyCascadePolicy` behaves as follows:

1. score all major nodes
2. keep major results ordered by `target_confidence` descending
3. expand only major nodes with `decision="accept"`
4. for each accepted major, score all eligible middle nodes under that major
5. expand only middle nodes with `decision="accept"`
6. for each accepted middle, score all eligible cwe nodes under that middle
7. construct candidate paths from accepted nodes
8. if no major node accepts, final prediction is `Benign`
9. if a path terminates because deeper nodes reject, abstain, or error, the
   path final label is the deepest accepted label on that path
10. choose the best path by policy score, not by raw scorer score alone

Default greedy path score:

- product of `target_confidence` over accepted nodes on the path

This is a default policy choice, not a scorer invariant.

### 9.12 Final prediction rules

Final prediction must be:

- `taxonomy.benign_label` if no major path accepts
- otherwise the deepest accepted label on the best path

`Unknown` must never be emitted as a v2 final prediction.

## 10. Runtime Feature Ownership

### 10.1 RAG

Owner: `InferencePolicy` plus `EvidenceProvider`

Rationale:

- retrieval may depend on parent decisions
- retrieval is part of runtime scheduling, not node scoring
- scorer should remain pure with respect to external stores

### 10.2 Parallel scoring

Owner: `InferencePolicy`

Rationale:

- parallelism is a scheduling concern
- the same scorer must work in sequential and parallel modes

### 10.3 Top-k and beam routing

Owner: `InferencePolicy`

Rationale:

- branch fan-out is route policy
- scorer must not know whether siblings are explored greedily or via beam

### 10.4 Path calibration

Owner: `InferencePolicy`

Rationale:

- calibration changes path ranking, not node scoring semantics
- a later `PathCalibrator` helper MAY be introduced, but it remains
  policy-owned rather than trainer-owned or scorer-owned

## 11. Evaluation Metrics

`Evaluator` SHOULD report three layers of metrics.

### 11.1 Node-level metrics

Per node:

- `node_f1`
- `target_accept_rate`
- `hard_negative_reject_rate`
- `benign_reject_rate`
- `abstain_rate`
- `error_rate`

### 11.2 Route-level metrics

For policy quality:

- `major_route_recall_at_1`
- `major_route_recall_at_k`
- `middle_route_recall_at_1`
- `middle_route_recall_at_k`
- `path_coverage`
- `top1_top2_margin_mean`

### 11.3 End-to-end metrics

For business quality:

- `final_exact_match`
- `major_accuracy`
- `middle_accuracy`
- `cwe_accuracy`
- `vuln_vs_benign_f1`
- `macro_f1`
- `avg_tokens_per_sample`
- `avg_cost_per_sample`

`NodeTrainer` MUST NOT directly optimize these end-to-end metrics.

## 12. Artifact Format and Compatibility

### 12.1 Preserved external contracts

The following remain unchanged:

- CLI subcommands `evolve` and `evaluate`
- `prompt_artifact.json`
- `best_prompts.json`
- `summary.json`
- `PromptArtifact` public export

### 12.2 v1 isolation principle

`PromptArtifact` remains frozen.

No semantic changes are allowed to:

- `src/mulvul/mainline/artifacts.py`
- `PromptArtifact.load()`
- `PromptArtifact.save()`
- `PromptArtifact.from_mapping()`
- `PromptArtifact.to_dict()`
- existing v1 artifact tests

### 12.3 v2 file

v2 introduces a new file:

- `prompt_bundle.json`

Read and write ownership:

| Format | File | Reader | Writer |
|---|---|---|---|
| v1 | `prompt_artifact.json` | `PromptArtifact` | `PromptArtifact` |
| v2 | `prompt_bundle.json` | `PromptBundleIO` | `PromptBundleIO` |

### 12.4 Load modes

There are two supported load modes:

- `strict_v2`
  - native v2 bundle
  - full taxonomy validation
  - `allow_partial=False`
- `legacy_compat`
  - v1 artifact adapted into v2 runtime objects
  - partial coverage allowed to preserve legacy behavior
  - used only for compatibility flows and old tests

This resolves the migration tension:

- new v2 production artifacts must be complete
- old v1 partial artifacts must still run through the compatibility path

### 12.5 CLI behavior

`evolve` writes both:

- `prompt_artifact.json` through the v1 path
- `prompt_bundle.json` through the v2 path

`evaluate` accepts either:

- if given v2, load with `strict_v2`
- if given v1, adapt with `legacy_compat`

### 12.6 Adapter semantics

`PromptBundleAdapter.from_artifact()` must:

1. preserve existing node IDs
2. reconstruct taxonomy with `version="legacy"`
3. set every adapted node `threshold=None`
4. set `defaults.default_threshold=0.5`
5. populate unknown provenance fields with `"unknown"`
6. populate missing query/evidence templates from bundle defaults or leave them
   `None`
7. never mutate `PromptArtifact`

### 12.7 Minimal v2 JSON shape

Example:

```json
{
  "schema_version": "2",
  "taxonomy": {
    "version": "mainline-2026-04",
    "stage_order": ["major", "middle", "cwe"],
    "benign_label": "Benign",
    "nodes": {
      "major_Memory": {
        "node_id": "major_Memory",
        "stage": "major",
        "label": "Memory",
        "parent_id": null
      }
    }
  },
  "defaults": {
    "default_threshold": 0.5,
    "policy_name": "greedy",
    "policy_config": {},
    "scorer_config": {}
  },
  "nodes": {
    "major_Memory": {
      "node_id": "major_Memory",
      "stage": "major",
      "target_label": "Memory",
      "instruction_template": "...",
      "query_template": null,
      "evidence_template": null,
      "output_schema": "ranking_v2",
      "threshold": null,
      "allow_abstain": true,
      "metadata": {}
    }
  },
  "training_metadata": {
    "trainer_seed": 42
  },
  "data_fingerprint": "dataset-hash",
  "code_revision": "git-sha"
}
```

## 13. Required Tests

Migration is not complete until all tests below exist.

### 13.1 Bundle and taxonomy tests

- `TaxonomyGraph` serialization round-trip
- bundle validation fail-fast on missing nodes
- partial bundle allowed only in explicit compatibility mode
- candidate labels contain `Benign` exactly once
- `decision_labels_for(node_id)` returns the expected sibling set

### 13.2 Adapter tests

- v1 artifact to v2 bundle preserves node IDs
- adapted node thresholds are `None`
- bundle defaults hold the v1 default threshold
- v1 `PromptArtifact.load()` behavior remains unchanged
- adapted v1 bundle can still execute old partial-artifact fixtures

### 13.3 Scorer tests

- JSON accept path
- JSON reject path
- fallback parse with `distrust_fallback=True` maps to `abstain`
- fallback parse with `distrust_fallback=False` can accept or reject by threshold
- total parse failure maps to `error`
- no `Unknown` is emitted in v2 result
- ranking labels are limited to `ctx.candidate_labels`

### 13.4 Training metric tests

- target accept counts as TP
- hard-negative accept counts as FP
- benign accept counts as FP
- hard-negative reject contributes to `hard_negative_reject_rate`
- benign reject contributes to `benign_reject_rate`
- `abstain` counts against guardrails but not as acceptance
- selection rule blocks guardrail regressions

### 13.5 Policy tests

- greedy policy matches current major -> middle -> cwe behavior on stub fixtures
- top-k policy expands the configured number of accepted nodes
- early rejection skips descendants
- nodes scored and skipped counts are correct
- final prediction never equals `Unknown`
- policy owns retrieval invocation count

### 13.6 Evaluator tests

- route metrics are computed from policy outputs, not from scorer internals
- end-to-end metrics match fixture expectations
- token/cost metrics aggregate over dataset

### 13.7 Regression tests

- v1 inference and adapted v2 inference agree on the same v1 fixture
- `tests/test_mainline_artifact.py` remains unchanged
- `tests/test_mainline_system.py` remains unchanged

## 14. Implementation Plan

### Step 1

Create `src/mulvul/mainline/bundle.py` with:

- `TaxonomyNode`
- `TaxonomyGraph`
- `NodeSpec`
- `EvidenceItem`
- `EvidenceBundle`
- `BundleDefaults`
- `PromptBundle`
- `ScorerContext`
- `NodeScoreResult`
- `PromptBundleAdapter`
- `PromptBundleIO`

### Step 2

Create `src/mulvul/mainline/scorer.py` with:

- `NodeScorer`
- `LLMNodeScorer`

Do not modify v1 code paths in this step.

### Step 3

Create `src/mulvul/mainline/policy.py` with:

- `InferencePolicy`
- `GreedyCascadePolicy`
- optional `TopKCascadePolicy`
- optional `EvidenceProvider`

### Step 4

Refactor training to a fixed-split `Sampler` contract and move node evaluation
to `decision`-based metrics with explicit hard-negative and benign guardrails.

### Step 5

Split training responsibilities into:

- `NodeTrainer`
- `BundleTrainer`

The current rewrite loop may remain the first optimizer implementation.

### Step 6

Create `src/mulvul/mainline/evaluator.py` with:

- `Evaluator`
- `EvaluationResult`

### Step 7

Make `MainlineDetectorSystem` a thin wrapper over:

- bundle
- scorer
- policy

### Step 8

Add dual-write artifact behavior:

- keep writing `prompt_artifact.json`
- add `prompt_bundle.json`

### Step 9

Move current ablations into explicit policy-owned or retrieval-owned plugins:

- RAG
- parallel scoring
- top-k routing

## 15. Explicit Rejections

The following designs are rejected by this spec:

- storing `Benign` inside `NodeSpec`
- storing topology in both `TaxonomyGraph` and `NodeSpec`
- keeping `Unknown` as a valid v2 prediction token
- mutating `PromptArtifact` to read or write v2 schema
- training on top-1 while routing on a different scorer contract
- letting scorer fetch retrieval evidence internally
- silently treating partial v2 bundles as production-valid
- inventing fake per-node thresholds during v1 adaptation

## 16. Summary

The mainline converges to five core invariants:

1. `TaxonomyGraph` is the single source of truth for hierarchy
2. `PromptBundle` is the self-describing executable artifact
3. `NodeScorer` is the single scoring contract shared by training and inference
4. `InferencePolicy` owns all cascade behavior
5. `Evaluator` owns route-level and end-to-end metrics

The most important corrections relative to the old system are:

- training and inference now share `NodeScoreResult.decision`
- `other_vul` becomes first-class `hard_negative`
- `Benign` has exactly one owner
- query template and evidence template become part of the executable config
- v1 thresholds migrate as bundle defaults, not fake per-node thresholds
