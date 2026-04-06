"""Unified workflows for prompt evolution and vulnerability evaluation."""

from __future__ import annotations

import hashlib
import json
import os
import random
import subprocess
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterator, List, Mapping, Optional, Tuple

from mulvul.agents.hierarchical_sampler import HierarchicalSampler
from mulvul.agents.coevolutionary_trainer import CoevolutionaryTrainer
from mulvul.data.cwe_hierarchy import cwe_to_major, cwe_to_middle
from mulvul.llm.client import create_llm_client, load_env_vars
from mulvul.rag.retriever import MulVulRetriever

from .ablations import AblationConfig, apply_ablation_presets
from .artifacts import PromptArtifact
from .bundle import PromptBundle, PromptBundleAdapter, PromptBundleIO
from .system import MainlineDetectorSystem

REQUIRED_DATASET_FIELDS: tuple[str, ...] = ("func", "target", "cwe")
MAINLINE_ROOT = Path(__file__).resolve().parents[3]
MAX_SUMMARY_RECORDS = 100


@dataclass
class EvolutionWorkflowConfig:
    """Configuration for the prompt evolution workflow."""

    train_file: str
    output_dir: str = "./outputs/mainline/evolution"
    kb_path: Optional[str] = None
    rounds: int = 3
    samples_per_class: int = 50
    max_workers: int = 8
    llm_type: Optional[str] = None
    population_size: int = 5
    tournament_k: int = 3
    migration_rate: float = 0.2
    phase1_only: bool = False


@dataclass
class EvaluationWorkflowConfig:
    """Configuration for the vulnerability evaluation workflow."""

    eval_file: str
    prompts_path: str
    output_dir: str = "./outputs/mainline/evaluation"
    kb_path: Optional[str] = None
    max_samples: Optional[int] = None
    max_workers: int = 8
    balanced: bool = False
    seed: int = 42
    llm_type: Optional[str] = None
    ablations: List[str] = field(default_factory=list)


def load_jsonl(path: str) -> List[Dict[str, Any]]:
    """Load JSONL records from disk."""

    return list(iter_jsonl(path))


def iter_jsonl(path: str) -> Iterator[Dict[str, Any]]:
    """Yield validated JSONL records from disk one line at a time."""

    with open(path, "r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON in {path} at line {line_number}: {exc.msg}"
                ) from exc
            yield _validate_jsonl_record(record, path=path, line_number=line_number)


def get_ground_truth(item: Dict[str, Any]) -> Tuple[str | None, str | None, str]:
    """Return ground-truth CWE, middle, and major labels."""

    target = int(item["target"])
    if target == 0:
        return None, None, "Benign"

    cwe_codes = item["cwe"]
    if not cwe_codes:
        return "Unknown", "Other", "Logic"

    cwe = cwe_codes[0]
    middle = cwe_to_middle(cwe_codes)
    major = cwe_to_major(cwe_codes)
    return cwe, middle, major


def balanced_sample(samples: List[Dict[str, Any]], seed: int) -> List[Dict[str, Any]]:
    """Return a benign:vulnerable balanced sample."""

    random.seed(seed)
    benign = [sample for sample in samples if int(sample.get("target", 0)) == 0]
    vulnerable = [sample for sample in samples if int(sample.get("target", 0)) == 1]
    n = min(len(benign), len(vulnerable))
    if n == 0:
        return samples
    result = random.sample(benign, n) + random.sample(vulnerable, n)
    random.shuffle(result)
    return result


def run_evolution_workflow(config: EvolutionWorkflowConfig) -> Dict[str, Any]:
    """Train the best prompt for each router/detector stage."""

    load_env_vars()
    llm_client = _create_runtime_client(config.llm_type)
    retriever = (
        MulVulRetriever(knowledge_base_path=config.kb_path) if config.kb_path else None
    )
    sampler = HierarchicalSampler(config.train_file)
    trainer = CoevolutionaryTrainer(
        llm_client=llm_client,
        sampler=sampler,
        retriever=retriever,
        output_dir=config.output_dir,
    )

    trainer.train_all_levels(
        n_rounds=config.rounds,
        n_samples_per_class=config.samples_per_class,
        population_size=config.population_size,
        tournament_k=config.tournament_k,
        migration_rate=config.migration_rate,
        max_workers=config.max_workers,
        phase1_only=config.phase1_only,
    )
    trainer.save_best_prompts()

    timestamp = datetime.now().isoformat()
    dataset_hash = _sha256_file(config.train_file)
    git_sha = _current_git_sha()
    artifact_path = Path(config.output_dir) / "prompt_artifact.json"
    artifact = PromptArtifact.from_mapping(
        {"prompts": trainer.best_prompts, "scores": trainer.best_scores}
    )
    artifact.save(artifact_path)
    bundle_path = Path(config.output_dir) / "prompt_bundle.json"
    bundle = PromptBundleAdapter.from_artifact(
        artifact,
        source_artifact=str(artifact_path),
        allow_partial=False,
        training_metadata={
            "trainer_name": type(trainer).__name__,
            "trainer_seed": None,
            "split_hash": dataset_hash,
            "retrieval_snapshot_id": config.kb_path,
            "created_at": timestamp,
            "source_dataset": config.train_file,
            "rounds": config.rounds,
            "samples_per_class": config.samples_per_class,
        },
        data_fingerprint=dataset_hash,
        code_revision=git_sha,
    )
    PromptBundleIO.save(bundle, bundle_path, allow_partial=False)

    summary: Dict[str, Any] = {
        "timestamp": timestamp,
        "train_file": config.train_file,
        "kb_path": config.kb_path,
        "rounds": config.rounds,
        "samples_per_class": config.samples_per_class,
        "prompt_artifact": str(artifact_path),
        "prompt_bundle": str(bundle_path),
        "runtime_prompt_format": "v2_bundle",
        "seed": None,
        "model_name": _runtime_model_name(llm_client),
        "api_base": getattr(llm_client, "api_base", None),
        "endpoint_kind": _endpoint_kind(llm_client),
        "temperature": 0.1,
        "top_p": None,
        "dataset_hash": dataset_hash,
        "git_sha": git_sha,
        "prompt_artifact_hash": _sha256_file(artifact_path),
        "prompt_bundle_hash": _sha256_json(bundle.to_dict()),
        "active_ablations": [],
        "policy_class": "GreedyCascadePolicy",
        "router_prompt_count": len(artifact.router_prompts),
        "middle_prompt_count": len(artifact.middle_prompts),
        "cwe_prompt_count": len(artifact.cwe_prompts),
    }

    summary_path = Path(config.output_dir) / "summary.json"
    with summary_path.open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2, ensure_ascii=False)
    return summary


def run_evaluation_workflow(config: EvaluationWorkflowConfig) -> Dict[str, Any]:
    """Evaluate frozen prompts on vulnerability detection."""

    load_env_vars()
    llm_client = _create_runtime_client(config.llm_type)
    ablation_config = apply_ablation_presets(config.ablations, AblationConfig())

    # RAG is enabled by default.  Resolve KB path: explicit > sibling of
    # eval_file > disabled.
    kb_path = config.kb_path
    if kb_path is None and ablation_config.use_retrieval:
        candidate = Path(config.eval_file).parent / "knowledge_base.json"
        if candidate.exists():
            kb_path = str(candidate)

    retriever = (
        MulVulRetriever(knowledge_base_path=kb_path)
        if kb_path and ablation_config.use_retrieval
        else None
    )
    prompt_format = _detect_prompt_format(config.prompts_path)
    bundle_or_artifact = _load_runtime_prompts(config.prompts_path)
    system = MainlineDetectorSystem(
        llm_client=llm_client,
        artifact=bundle_or_artifact,
        ablations=ablation_config,
        retriever=retriever,
    )

    if config.balanced:
        samples_iter = iter(
            balanced_sample(load_jsonl(config.eval_file), config.seed)
        )
    else:
        samples_iter = iter_jsonl(config.eval_file)

    timestamp = datetime.now().isoformat()
    dataset_hash = _sha256_file(config.eval_file)
    git_sha = _current_git_sha()
    start = time.time()
    records: list[dict[str, Any]] = []
    sample_count = 0
    metrics: dict[str, dict[str, int]] = {
        "major": {"correct": 0, "total": 0},
        "middle": {"correct": 0, "total": 0},
        "cwe": {"correct": 0, "total": 0},
        "binary": {"correct": 0, "total": 0},
    }
    per_major: defaultdict[str, dict[str, int]] = defaultdict(
        lambda: {"total": 0, "correct": 0}
    )

    for item in samples_iter:
        if config.max_samples is not None and sample_count >= config.max_samples:
            break

        sample_count += 1
        gt_cwe, gt_middle, gt_major = get_ground_truth(item)
        result = system.detect(item["func"])
        pred_binary = "Vulnerable" if result.is_vulnerable else "Benign"
        gt_binary = "Vulnerable" if gt_major != "Benign" else "Benign"

        metrics["major"]["total"] += 1
        metrics["binary"]["total"] += 1

        if result.major == gt_major:
            metrics["major"]["correct"] += 1
        if pred_binary == gt_binary:
            metrics["binary"]["correct"] += 1

        if gt_major != "Benign":
            metrics["middle"]["total"] += 1
            metrics["cwe"]["total"] += 1
            if result.middle == gt_middle:
                metrics["middle"]["correct"] += 1
            if result.cwe == gt_cwe:
                metrics["cwe"]["correct"] += 1

        per_major[gt_major]["total"] += 1
        if result.major == gt_major:
            per_major[gt_major]["correct"] += 1

        if len(records) < MAX_SUMMARY_RECORDS:
            records.append(
                {
                    "ground_truth": {
                        "major": gt_major,
                        "middle": gt_middle,
                        "cwe": gt_cwe,
                        "binary": gt_binary,
                    },
                    "prediction": result.to_dict(),
                }
            )

    elapsed = time.time() - start
    summary: Dict[str, Any] = {
        "timestamp": timestamp,
        "eval_file": config.eval_file,
        "prompts_path": config.prompts_path,
        "prompt_format": prompt_format,
        "runtime_prompt_format": "v2_bundle",
        "ablations": list(config.ablations),
        "active_ablations": list(config.ablations),
        "seed": config.seed,
        "model_name": _runtime_model_name(llm_client),
        "api_base": getattr(llm_client, "api_base", None),
        "endpoint_kind": _endpoint_kind(llm_client),
        "temperature": 0.1,
        "top_p": None,
        "dataset_hash": dataset_hash,
        "git_sha": git_sha,
        "prompt_artifact_hash": (
            _sha256_file(config.prompts_path)
            if prompt_format == "v1_artifact"
            else None
        ),
        "prompt_bundle_hash": _sha256_json(bundle_or_artifact.to_dict()),
        "policy_class": type(system.policy).__name__,
        "samples": sample_count,
        "elapsed_seconds": elapsed,
        "accuracy": {
            level: (values["correct"] / values["total"] if values["total"] else 0.0)
            for level, values in metrics.items()
        },
        "counts": metrics,
        "per_major": {key: dict(value) for key, value in per_major.items()},
        "records": records,
    }

    output_dir = Path(config.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = output_dir / "summary.json"
    with summary_path.open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2, ensure_ascii=False)
    return summary


def _detect_prompt_format(path: str) -> str:
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    return "v2_bundle" if data.get("schema_version") == "2" else "v1_artifact"


def _load_runtime_prompts(path: str) -> PromptBundle:
    return PromptBundleIO.load(path, load_mode="legacy_compat")


def _create_runtime_client(llm_type: Optional[str]) -> Any:
    if llm_type is None:
        return create_llm_client()
    return create_llm_client(llm_type=llm_type)


def _validate_jsonl_record(
    record: Any,
    *,
    path: str,
    line_number: int,
) -> Dict[str, Any]:
    if not isinstance(record, Mapping):
        raise ValueError(
            f"Invalid JSONL record in {path} at line {line_number}: expected an object."
        )

    missing_fields = [
        field_name for field_name in REQUIRED_DATASET_FIELDS if field_name not in record
    ]
    if missing_fields:
        raise ValueError(
            f"Invalid JSONL record in {path} at line {line_number}: missing required "
            f"fields {', '.join(missing_fields)}."
        )

    func = record["func"]
    if not isinstance(func, str):
        raise ValueError(
            f"Invalid JSONL record in {path} at line {line_number}: func must be a string."
        )

    try:
        target = int(record["target"])
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"Invalid JSONL record in {path} at line {line_number}: target must be 0 or 1."
        ) from exc
    if target not in (0, 1):
        raise ValueError(
            f"Invalid JSONL record in {path} at line {line_number}: target must be 0 or 1."
        )

    cwe_codes = record["cwe"]
    if not isinstance(cwe_codes, list):
        raise ValueError(
            f"Invalid JSONL record in {path} at line {line_number}: cwe must be a list."
        )
    if target == 1 and not cwe_codes:
        raise ValueError(
            f"Invalid JSONL record in {path} at line {line_number}: vulnerable samples "
            "must include at least one CWE label."
        )
    invalid_cwes = [
        cwe for cwe in cwe_codes if not isinstance(cwe, (str, int)) or str(cwe) == ""
    ]
    if invalid_cwes:
        raise ValueError(
            f"Invalid JSONL record in {path} at line {line_number}: cwe entries must "
            "be non-empty strings or integers."
        )

    return dict(record)


def _sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_json(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _current_git_sha() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=MAINLINE_ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def _runtime_model_name(llm_client: Any) -> str:
    return str(getattr(llm_client, "model_name", os.getenv("MODEL_NAME", "unknown")))


def _endpoint_kind(llm_client: Any) -> str:
    if getattr(llm_client, "api_base", None):
        return "openai_compatible"
    return type(llm_client).__name__
