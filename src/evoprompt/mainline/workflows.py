"""Unified workflows for prompt evolution and vulnerability evaluation."""

from __future__ import annotations

import json
import random
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from evoprompt.agents.hierarchical_trainer import HierarchicalTrainer
from evoprompt.agents.hierarchical_sampler import HierarchicalSampler
from evoprompt.data.cwe_hierarchy import cwe_to_major, cwe_to_middle
from evoprompt.llm.client import create_llm_client, load_env_vars
from evoprompt.rag.retriever import MulVulRetriever

from .ablations import AblationConfig, apply_ablation_presets
from .artifacts import PromptArtifact
from .system import MainlineDetectorSystem


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

    records: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


def get_ground_truth(item: Dict[str, Any]) -> Tuple[str, str, str]:
    """Return ground-truth CWE, middle, and major labels."""

    target = int(item.get("target", 0))
    if target == 0:
        return "Benign", "Benign", "Benign"

    cwe_codes = item.get("cwe", [])
    if isinstance(cwe_codes, str):
        cwe_codes = [cwe_codes] if cwe_codes else []
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
    llm_client = create_llm_client(llm_type=config.llm_type)
    retriever = (
        MulVulRetriever(knowledge_base_path=config.kb_path)
        if config.kb_path
        else None
    )
    sampler = HierarchicalSampler(config.train_file)
    trainer = HierarchicalTrainer(
        llm_client=llm_client,
        sampler=sampler,
        retriever=retriever,
        output_dir=config.output_dir,
    )

    trainer.train_all_levels(
        n_rounds=config.rounds,
        n_samples_per_class=config.samples_per_class,
        max_workers=config.max_workers,
    )
    trainer.save_best_prompts()

    artifact_path = Path(config.output_dir) / "prompt_artifact.json"
    artifact = PromptArtifact.from_mapping(
        {"prompts": trainer.best_prompts, "scores": trainer.best_scores}
    )
    artifact.save(artifact_path)

    summary = {
        "timestamp": datetime.now().isoformat(),
        "train_file": config.train_file,
        "kb_path": config.kb_path,
        "rounds": config.rounds,
        "samples_per_class": config.samples_per_class,
        "prompt_artifact": str(artifact_path),
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
    llm_client = create_llm_client(llm_type=config.llm_type)
    ablation_config = apply_ablation_presets(config.ablations, AblationConfig())
    retriever = (
        MulVulRetriever(knowledge_base_path=config.kb_path)
        if config.kb_path and ablation_config.use_retrieval
        else None
    )
    artifact = PromptArtifact.load(config.prompts_path)
    system = MainlineDetectorSystem(
        llm_client=llm_client,
        artifact=artifact,
        ablations=ablation_config,
        retriever=retriever,
    )

    samples = load_jsonl(config.eval_file)
    if config.balanced:
        samples = balanced_sample(samples, config.seed)
    if config.max_samples is not None:
        samples = samples[: config.max_samples]

    start = time.time()
    records = []
    metrics = {
        "major": {"correct": 0, "total": 0},
        "middle": {"correct": 0, "total": 0},
        "cwe": {"correct": 0, "total": 0},
        "binary": {"correct": 0, "total": 0},
    }
    per_major = defaultdict(lambda: {"total": 0, "correct": 0})

    for item in samples:
        gt_cwe, gt_middle, gt_major = get_ground_truth(item)
        result = system.detect(item.get("func", ""))
        pred_binary = "Vulnerable" if result.is_vulnerable else "Benign"
        gt_binary = "Vulnerable" if gt_major != "Benign" else "Benign"

        metrics["major"]["total"] += 1
        metrics["middle"]["total"] += 1
        metrics["cwe"]["total"] += 1
        metrics["binary"]["total"] += 1

        if result.major == gt_major:
            metrics["major"]["correct"] += 1
        if result.middle == gt_middle:
            metrics["middle"]["correct"] += 1
        if result.cwe == gt_cwe:
            metrics["cwe"]["correct"] += 1
        if pred_binary == gt_binary:
            metrics["binary"]["correct"] += 1

        per_major[gt_major]["total"] += 1
        if result.major == gt_major:
            per_major[gt_major]["correct"] += 1

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
    summary = {
        "timestamp": datetime.now().isoformat(),
        "eval_file": config.eval_file,
        "prompts_path": config.prompts_path,
        "ablations": list(config.ablations),
        "samples": len(samples),
        "elapsed_seconds": elapsed,
        "accuracy": {
            level: (
                values["correct"] / values["total"] if values["total"] else 0.0
            )
            for level, values in metrics.items()
        },
        "counts": metrics,
        "per_major": {key: dict(value) for key, value in per_major.items()},
        "records": records[:100],
    }

    output_dir = Path(config.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = output_dir / "summary.json"
    with summary_path.open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2, ensure_ascii=False)
    return summary
