# Mainline Contracts

This document defines the payload-level contracts for Mulvul mainline evolution
and evaluation. `CLAUDE.md` defines defaults and invariants; this file defines
accepted shapes and fail-fast rules.

## Dataset Records

Train and evaluation datasets use JSONL. The mainline code path only depends on
these required fields:

- `func`: source code string
- `target`: `0` for benign, `1` for vulnerable
- `cwe`: list of CWE labels such as `["CWE-120"]` for vulnerable samples

Optional fields such as `idx`, `project`, `commit_id`, and `cve_desc` may be
present and are preserved only as metadata outside the strict parser contract.

Contract rules:

- Each JSONL line must decode to an object
- `func` must be a string
- `target` must be `0` or `1`
- `cwe` must be a list
- Vulnerable samples must include at least one CWE label
- Invalid JSON or missing required fields fail fast with line-level context

### Vulnerable Record

```json
{
  "func": "void f(char *src) { char buf[8]; strcpy(buf, src); }",
  "target": 1,
  "cwe": ["CWE-120"],
  "cve_desc": "Stack buffer overflow in strcpy path"
}
```

### Benign Record

```json
{
  "func": "int add(int a, int b) { return a + b; }",
  "target": 0,
  "cwe": []
}
```

Benign semantics:

- Ground truth major label is `Benign`
- Ground truth middle label is `null`
- Ground truth CWE label is `null`

## `prompt_artifact.json` (v1)

Required fields:

- `prompts`: mapping from stage-prefixed key to prompt string

Optional fields:

- `scores`: mapping from stage-prefixed key to scalar score

Minimal example:

```json
{
  "prompts": {
    "major_Memory": "You are a security expert specializing in Memory vulnerabilities. {code}",
    "middle_Buffer Errors": "You are a Buffer Errors vulnerability expert. {code}",
    "cwe_CWE-120": "Identify whether this code is CWE-120. {code}"
  },
  "scores": {
    "major_Memory": 0.81,
    "middle_Buffer Errors": 0.76,
    "cwe_CWE-120": 0.72
  }
}
```

Contract rules:

- Keys must start with `major_`, `middle_`, or `cwe_`
- Prompt values must be strings
- Invalid JSON or non-mapping `prompts` fails fast
- v1 is a compatibility input format; runtime execution normalizes it to `PromptBundle`

## `prompt_bundle.json` (v2)

Required top-level fields:

- `schema_version`
- `taxonomy`
- `nodes`
- `defaults`
- `training_metadata`
- `data_fingerprint`
- `code_revision`

Minimal example:

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
      },
      "middle_Buffer Errors": {
        "node_id": "middle_Buffer Errors",
        "stage": "middle",
        "label": "Buffer Errors",
        "parent_id": "major_Memory"
      },
      "cwe_CWE-120": {
        "node_id": "cwe_CWE-120",
        "stage": "cwe",
        "label": "CWE-120",
        "parent_id": "middle_Buffer Errors"
      }
    }
  },
  "nodes": {
    "major_Memory": {
      "node_id": "major_Memory",
      "stage": "major",
      "target_label": "Memory",
      "instruction_template": "Analyze {code}",
      "output_schema": "ranking_v2",
      "threshold": null,
      "allow_abstain": true,
      "metadata": {
        "source_format": "v1"
      }
    }
  },
  "defaults": {
    "default_threshold": 0.5,
    "policy_name": "greedy",
    "policy_config": {},
    "scorer_config": {}
  },
  "training_metadata": {
    "trainer_name": "legacy_v1_adapter",
    "source_artifact": "prompt_artifact.json"
  },
  "data_fingerprint": "unknown",
  "code_revision": "unknown"
}
```

Contract rules:

- `schema_version` must be `"2"`
- `taxonomy.stage_order` must be `["major", "middle", "cwe"]`
- Each `nodes[*].node_id` must exist in `taxonomy.nodes`
- Each `nodes[*].target_label` and `nodes[*].stage` must match its taxonomy node
- Invalid JSON, missing required top-level mappings, or schema mismatches fail fast

## `ranking_v2` Response

Mainline scorer expects either:

- a JSON object with `predictions`
- or a top-level JSON list of prediction objects

Each prediction object may use one of `category`, `cwe`, or `label` as its
label field, and must include numeric `confidence`.

Minimal accepted object form:

```json
{
  "predictions": [
    { "category": "Memory", "confidence": 0.91 },
    { "category": "Benign", "confidence": 0.08 }
  ]
}
```

Minimal accepted list form:

```json
[
  { "label": "Buffer Errors", "confidence": 0.84 },
  { "label": "Benign", "confidence": 0.11 }
]
```

Parser rules:

- Labels outside the candidate set are dropped
- Duplicate labels keep the highest confidence
- If JSON parsing fails, fallback string matching may be attempted
- If no valid ranking is recovered, scoring fails with parser status `error`
- Fallback parsing is not baseline-trusted when `distrust_fallback = true`

## `summary.json`

Evolution summary required fields:

- `timestamp`
- `train_file`
- `rounds`
- `samples_per_class`
- `prompt_artifact`
- `prompt_bundle`
- `runtime_prompt_format`
- `seed`
- `model_name`
- `api_base`
- `endpoint_kind`
- `temperature`
- `top_p`
- `dataset_hash`
- `git_sha`
- `prompt_artifact_hash`
- `prompt_bundle_hash`
- `active_ablations`
- `policy_class`
- prompt counts

Minimal evolution summary:

```json
{
  "timestamp": "2026-04-03T12:00:00",
  "train_file": "data/primevul_train.jsonl",
  "kb_path": null,
  "rounds": 3,
  "samples_per_class": 50,
  "prompt_artifact": "outputs/mainline/evolution/prompt_artifact.json",
  "prompt_bundle": "outputs/mainline/evolution/prompt_bundle.json",
  "runtime_prompt_format": "v2_bundle",
  "seed": null,
  "model_name": "gpt-4o",
  "api_base": "https://api.chatanywhere.tech/v1",
  "endpoint_kind": "openai_compatible",
  "temperature": 0.1,
  "top_p": null,
  "dataset_hash": "8c3d...",
  "git_sha": "abc123def456",
  "prompt_artifact_hash": "11aa...",
  "prompt_bundle_hash": "22bb...",
  "active_ablations": [],
  "policy_class": "GreedyCascadePolicy",
  "router_prompt_count": 5,
  "middle_prompt_count": 13,
  "cwe_prompt_count": 42
}
```

Evaluation summary required fields:

- `timestamp`
- `eval_file`
- `prompts_path`
- `prompt_format`
- `runtime_prompt_format`
- `ablations`
- `active_ablations`
- `seed`
- `model_name`
- `api_base`
- `endpoint_kind`
- `temperature`
- `top_p`
- `dataset_hash`
- `git_sha`
- `prompt_artifact_hash`
- `prompt_bundle_hash`
- `policy_class`
- `samples`
- `elapsed_seconds`
- `accuracy`
- `counts`
- `per_major`

Optional fields:

- `records`: truncated per-sample records

Minimal evaluation summary:

```json
{
  "timestamp": "2026-04-03T12:30:00",
  "eval_file": "data/primevul_valid.jsonl",
  "prompts_path": "outputs/mainline/evolution/prompt_artifact.json",
  "prompt_format": "v1_artifact",
  "runtime_prompt_format": "v2_bundle",
  "ablations": [],
  "active_ablations": [],
  "seed": 42,
  "model_name": "gpt-4o",
  "api_base": "https://api.chatanywhere.tech/v1",
  "endpoint_kind": "openai_compatible",
  "temperature": 0.1,
  "top_p": null,
  "dataset_hash": "8c3d...",
  "git_sha": "abc123def456",
  "prompt_artifact_hash": "11aa...",
  "prompt_bundle_hash": "22bb...",
  "policy_class": "GreedyCascadePolicy",
  "samples": 200,
  "elapsed_seconds": 18.2,
  "accuracy": {
    "major": 0.82,
    "middle": 0.61,
    "cwe": 0.47,
    "binary": 0.89
  },
  "counts": {
    "major": { "correct": 164, "total": 200 },
    "middle": { "correct": 73, "total": 120 },
    "cwe": { "correct": 56, "total": 120 },
    "binary": { "correct": 178, "total": 200 }
  },
  "per_major": {
    "Memory": { "total": 52, "correct": 41 },
    "Benign": { "total": 80, "correct": 74 }
  }
}
```

Metric rules:

- `major` and `binary` counts include all samples
- `middle` and `cwe` counts include only non-benign samples
- Benign predictions serialize as `major="Benign", middle=null, cwe=null`
- `prompt_artifact_hash` records the raw v1 file when the input is a v1 artifact; otherwise it is `null`
- `prompt_bundle_hash` records the normalized runtime `PromptBundle` payload hash

## Fail-fast Rules

- Invalid JSON must raise immediately
- Missing required top-level schema fields must raise immediately
- Taxonomy-node mismatches in v2 bundles must raise immediately
- Invalid `ranking_v2` payloads must not silently become accepted predictions
- Compatibility behavior is limited to documented v1-to-v2 normalization; undocumented implicit parsing is not part of the contract
