#!/usr/bin/env python3
"""Run the full-sample CWD cascade with sibling-ranking leaf prompts.

Major and middle stages keep the current ``ranking_v2`` prompts.
The CWD leaf stage makes one LLM call per sibling group and ranks all
children under the accepted middle node in one shot, using the evolved
per-node prompts from ``node_evolution_runs`` as candidate guidance.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]

# Load .env before anything else
from dotenv import load_dotenv
load_dotenv(REPO_ROOT / ".env")

SOURCE_ROOT = Path("/Users/zihanwu/.config/superpowers/worktrees/Mulvul/analyze-cwe-cwd-migration")
MULVUL_SRC = REPO_ROOT / "src"
if str(REPO_ROOT) not in sys.path:
    sys.path.append(str(REPO_ROOT))
if str(SOURCE_ROOT) not in sys.path:
    sys.path.append(str(SOURCE_ROOT))
if str(MULVUL_SRC) not in sys.path:
    sys.path.append(str(MULVUL_SRC))

from cwd_optimized_cascade_experiment import (  # noqa: E402
    CWDDataset,
    OptimizedBundleFactory,
    PrototypeSimilarityIndex,
    _pick_benign,
    _pick_vulnerable,
    grid_search_thresholds,
    to_eval_samples,
)
from mulvul.llm.client import OpenAICompatibleClient  # noqa: E402
from mulvul.mainline.bundle import NodeScoreResult  # noqa: E402
from mulvul.mainline.evaluator import EvaluationSample, MainlineEvaluator  # noqa: E402
from mulvul.mainline.policy import BeamCascadePolicy, GreedyCascadePolicy  # noqa: E402
from mulvul.mainline.scorer import LLMNodeScorer  # noqa: E402

NODE_RE = re.compile(r"CWD-\d+")
BENIGN_GUIDANCE = (
    "Rank Benign first when the visible snippet does not clearly match any leaf "
    "candidate, when the code is visibly guarded/safe, or when the evidence only "
    "supports the broader parent family but not a specific leaf."
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the full-sample CWD cascade with sibling-ranking leaf prompts."
    )
    parser.add_argument(
        "--dataset",
        default=str(SOURCE_ROOT / "cwd_native_dataset.json"),
    )
    parser.add_argument(
        "--output-root",
        default=str(REPO_ROOT / "cwd_optimized_experiment_results"),
    )
    parser.add_argument(
        "--run-prefix",
        default="all_samples_sibling_leaf",
    )
    parser.add_argument(
        "--node-results-root",
        default=str(REPO_ROOT / "node_evolution_runs"),
    )
    parser.add_argument(
        "--baseline-results",
        default=str(
            REPO_ROOT
            / "cwd_optimized_experiment_results"
            / "all_samples_hybrid_20260415_021603"
            / "results.json"
        ),
    )
    parser.add_argument("--dev-samples", type=int, default=200)
    parser.add_argument("--vulnerable-ratio", type=float, default=0.75)
    parser.add_argument("--min-cwe-vuln-samples", type=int, default=6)
    parser.add_argument("--sample-workers", type=int, default=4)
    parser.add_argument("--progress-every", type=int, default=20)
    parser.add_argument("--checkpoint-every", type=int, default=50)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--model-name", default=os.getenv("MODEL_NAME", "gpt-5.4"))
    parser.add_argument(
        "--api-base",
        default=os.getenv("OPENAI_API_BASE", os.getenv("API_BASE_URL", "https://openrouter.ai/api/v1")),
    )
    parser.add_argument(
        "--policy",
        choices=["greedy", "beam"],
        default="beam",
        help="Cascade policy: greedy (top-1 commit) or beam (top-k retention + benign gate + margin reject).",
    )
    parser.add_argument("--major-beam-width", type=int, default=2)
    parser.add_argument("--middle-beam-width", type=int, default=2)
    parser.add_argument("--benign-gate-threshold", type=float, default=0.3,
                        help="Major confidence below this → classify as Benign (Stage 0 gate).")
    parser.add_argument("--margin-threshold", type=float, default=0.05,
                        help="If top1-top2 confidence gap < this at major/middle → reject as Benign.")
    return parser.parse_args()


def save_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def build_dev_subset(
    dataset: CWDDataset,
    *,
    dev_samples: int,
    vulnerable_ratio: float,
) -> tuple[list[Any], list[Any], list[Any]]:
    vuln_target = min(len(dataset.vulnerable_records), int(round(dev_samples * vulnerable_ratio)))
    benign_target = max(0, dev_samples - vuln_target)
    dev_vuln = _pick_vulnerable(dataset.vulnerable_records, vuln_target)
    preferred_cwds = {record.cwe for record in dev_vuln}
    dev_benign = _pick_benign(
        dataset.benign_records,
        benign_target,
        preferred_cwds=preferred_cwds,
    )
    dev_records = sorted(dev_vuln + dev_benign, key=lambda record: record.sample_id)
    used_ids = {record.sample_id for record in dev_records}
    support_records = [record for record in dataset.records if record.sample_id not in used_ids]
    eval_records = sorted(dataset.records, key=lambda record: record.sample_id)
    return dev_records, support_records, eval_records


def summarize_records(records: Sequence[Any]) -> dict[str, Any]:
    total = len(records)
    vulnerable = sum(1 for record in records if getattr(record, "final_label", None) != "Benign")
    benign = total - vulnerable
    major_counts: dict[str, int] = {}
    cwe_counts: dict[str, int] = {}
    for record in records:
        major = getattr(record, "major", None) or "Benign"
        cwe = getattr(record, "cwe", None) or "Benign"
        major_counts[major] = major_counts.get(major, 0) + 1
        cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
    return {
        "total": total,
        "vulnerable": vulnerable,
        "benign": benign,
        "major_counts": dict(sorted(major_counts.items())),
        "cwe_count": len(cwe_counts) - (1 if "Benign" in cwe_counts else 0),
    }


def extract_holdout_accuracy(item: Mapping[str, Any]) -> float:
    holdout = item.get("holdout_metric")
    if isinstance(holdout, Mapping):
        value = holdout.get("accuracy")
        if isinstance(value, (int, float)):
            return float(value)
    if isinstance(holdout, (int, float)):
        return float(holdout)
    value = item.get("holdout_accuracy")
    if isinstance(value, (int, float)):
        return float(value)
    return -1.0


def sort_prompt_candidate(candidate: Mapping[str, Any]) -> tuple[int, float, str]:
    status = str(candidate.get("status") or "")
    keep_rank = 1 if status == "keep" else 0
    return (
        keep_rank,
        float(candidate.get("holdout_accuracy", -1.0)),
        str(candidate.get("source_path", "")),
    )


def load_best_leaf_prompts(root: Path) -> dict[str, dict[str, Any]]:
    best: dict[str, dict[str, Any]] = {}
    for path in sorted(root.rglob("results.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue

        entries: list[tuple[str | None, Mapping[str, Any]]] = []
        if isinstance(payload, dict) and isinstance(payload.get("nodes"), dict):
            entries.extend((str(k), v) for k, v in payload["nodes"].items() if isinstance(v, Mapping))
        elif isinstance(payload, dict) and isinstance(payload.get("results"), dict):
            entries.extend((str(k), v) for k, v in payload["results"].items() if isinstance(v, Mapping))
        elif isinstance(payload, dict):
            entries.append((None, payload))
        elif isinstance(payload, list):
            entries.extend((None, item) for item in payload if isinstance(item, Mapping))

        for key, item in entries:
            prompt = item.get("best_prompt")
            if not isinstance(prompt, str):
                continue
            if "{node}" in prompt or "{label}" in prompt or "{negative_label}" in prompt:
                continue

            node_match = NODE_RE.search(prompt)
            if node_match is None and isinstance(key, str):
                node_match = NODE_RE.search(key)
            if node_match is None:
                run_name = item.get("run_name") or payload.get("run_name")
                if isinstance(run_name, str):
                    node_match = NODE_RE.search(run_name)
            if node_match is None:
                continue

            node_label = node_match.group(0)
            candidate = {
                "prompt": prompt.strip(),
                "holdout_accuracy": extract_holdout_accuracy(item),
                "source_path": str(path.relative_to(REPO_ROOT)),
                "status": item.get("status") or item.get("final_status"),
            }
            previous = best.get(node_label)
            if previous is None or sort_prompt_candidate(candidate) > sort_prompt_candidate(previous):
                best[node_label] = candidate
    return best


def normalize_guidance(prompt: str, label: str) -> str:
    lines: list[str] = []
    for raw_line in prompt.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.lower().startswith("return exactly"):
            continue
        if line.lower().startswith("output exactly"):
            continue
        lines.append(line)

    text = "\n".join(lines).strip()
    target_prefix = f"Target node: {label}"
    if text.startswith(target_prefix):
        text = text[len(target_prefix) :].strip()
    if len(text) > 1400:
        text = text[:1400].rsplit(" ", 1)[0].strip() + " ..."
    return text


def load_baseline_metrics(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return {
        "path": str(path.relative_to(REPO_ROOT) if path.is_relative_to(REPO_ROOT) else path),
        "backend_used": payload.get("backend_used"),
        "end_to_end_metrics": payload.get("cascade", {}).get("aggregate", {}).get("end_to_end_metrics", {}),
        "route_metrics": payload.get("cascade", {}).get("aggregate", {}).get("route_metrics", {}),
    }


class LeafSiblingRankingScorer:
    """Use one sibling-ranking call per accepted middle node."""

    def __init__(
        self,
        *,
        llm_client: OpenAICompatibleClient,
        bundle,
        cwd_definitions: Mapping[str, Mapping[str, Any]],
        evolved_leaf_prompts: Mapping[str, Mapping[str, Any]],
    ):
        self.llm_client = llm_client
        self.bundle = bundle
        self.cwd_definitions = cwd_definitions
        self.evolved_leaf_prompts = dict(evolved_leaf_prompts)
        self.base_scorer = LLMNodeScorer(llm_client, bundle)
        self._cache: dict[tuple[str, str, tuple[str, ...]], dict[str, Any]] = {}
        self._cache_lock = threading.Lock()

    def score(self, node, ctx) -> NodeScoreResult:
        if node.stage != "cwe":
            return self.base_scorer.score(node, ctx)

        key = (
            ctx.parent_result.target_label if ctx.parent_result else "",
            ctx.code[:4000],
            tuple(ctx.candidate_labels),
        )
        with self._cache_lock:
            cached = self._cache.get(key)

        if cached is None:
            cached = self._score_leaf_group(ctx)
            with self._cache_lock:
                self._cache[key] = cached

        if cached["kind"] != "ranking":
            return self.base_scorer.score(node, ctx)

        ranking = cached["ranking"]
        parse_status = cached["parse_status"]
        raw_response = cached["raw_response"]
        predicted_label, top_confidence = ranking[0]
        target_confidence = next(
            (confidence for label, confidence in ranking if label == node.target_label),
            0.0,
        )
        matched_target = predicted_label == node.target_label
        effective_threshold = self.base_scorer._effective_threshold(node)

        if parse_status == "fallback" and self.bundle.defaults.distrust_fallback:
            decision = "abstain"
            reject_label = None
        elif top_confidence < effective_threshold:
            decision = "abstain"
            reject_label = None
        elif matched_target:
            decision = "accept"
            reject_label = None
        else:
            decision = "reject"
            reject_label = predicted_label

        return NodeScoreResult(
            node_id=node.node_id,
            stage=node.stage,
            target_label=node.target_label,
            predicted_label=predicted_label,
            top_confidence=top_confidence,
            target_confidence=target_confidence,
            ranking=ranking,
            matched_target=matched_target,
            decision=decision,
            reject_label=reject_label,
            parse_status=parse_status,
            effective_threshold=effective_threshold,
            raw_response=raw_response,
            metadata={
                "backend": "openrouter-leaf-sibling-ranking",
                "candidate_labels": list(ctx.candidate_labels),
                "parent_middle": ctx.parent_result.target_label if ctx.parent_result else None,
                "leaf_prompt_source_labels": [
                    label for label in ctx.candidate_labels if label in self.evolved_leaf_prompts
                ],
            },
        )

    def _score_leaf_group(self, ctx) -> dict[str, Any]:
        prompt = self._render_leaf_prompt(
            parent_middle=ctx.parent_result.target_label if ctx.parent_result else "",
            candidate_labels=ctx.candidate_labels,
            code=ctx.code[:4000],
        )
        try:
            response = self.llm_client.generate(prompt, temperature=0.0, max_tokens=240)
        except Exception as exc:
            return {
                "kind": "fallback",
                "reason": f"exception:{exc.__class__.__name__}",
                "raw_response": str(exc),
            }

        ranking, parse_status = self.base_scorer._parse_ranking(response, ctx.candidate_labels)
        if not ranking:
            return {
                "kind": "fallback",
                "reason": "parse_error",
                "raw_response": response,
            }
        return {
            "kind": "ranking",
            "ranking": ranking,
            "parse_status": parse_status,
            "raw_response": response,
        }

    def _render_leaf_prompt(
        self,
        *,
        parent_middle: str,
        candidate_labels: Sequence[str],
        code: str,
    ) -> str:
        blocks: list[str] = []
        for label in candidate_labels:
            if label == self.bundle.taxonomy.benign_label:
                guidance = BENIGN_GUIDANCE
            else:
                prompt_info = self.evolved_leaf_prompts.get(label)
                if prompt_info is not None:
                    guidance = normalize_guidance(prompt_info["prompt"], label)
                else:
                    definition = self.cwd_definitions.get(label, {})
                    name = str(definition.get("name", "")).strip()
                    description = str(definition.get("description", "")).strip()
                    guidance = f"{name}\n{description[:1200]}".strip()
            blocks.append(f"### {label}\n{guidance}")

        joined_blocks = "\n\n".join(blocks)
        return f"""You are classifying code at the CWD leaf stage.

The parent middle family `{parent_middle}` has already been accepted.
Rank the sibling leaf candidates below. Use the candidate guidance as the
decision boundary for each label.

Rules:
- Choose only from the candidate labels listed below.
- Rank `Benign` first when the visible snippet does not clearly match any
  leaf candidate, or when the evidence only supports the broader parent
  family but not a specific leaf.
- Prefer exact sibling boundaries over generic memory/injection intuition.
- Use only the visible code. Do not assume unseen caller guarantees.

Candidate guidance:
{joined_blocks}

Code:
```
{code}
```

Output JSON only:
{{
  "predictions": [
    {{"cwe": "<candidate label>", "confidence": 0.0, "reason": "<short reason>"}},
    {{"cwe": "<candidate label>", "confidence": 0.0, "reason": "<short reason>"}},
    {{"cwe": "<candidate label>", "confidence": 0.0, "reason": "<short reason>"}}
  ]
}}
"""


def trace_for_sample(sample: EvaluationSample, inference, elapsed_seconds: float) -> dict[str, Any]:
    return {
        "sample_id": sample.sample_id,
        "truth": {
            "final": sample.final_label,
            "major": sample.major_label,
            "middle": sample.middle_label,
            "cwe": sample.cwe_label,
        },
        "prediction": inference.prediction,
        "best_path": (
            {
                "labels": [
                    {
                        "stage": result.stage,
                        "target": result.target_label,
                        "confidence": result.target_confidence,
                        "decision": result.decision,
                    }
                    for result in inference.best_path.stage_results
                ],
                "score": inference.best_path.score,
            }
            if inference.best_path is not None
            else None
        ),
        "stage_results": {
            stage: [
                {
                    "target": result.target_label,
                    "predicted_label": result.predicted_label,
                    "decision": result.decision,
                    "target_confidence": round(result.target_confidence, 6),
                    "top_confidence": round(result.top_confidence, 6),
                    "backend": result.metadata.get("backend") if isinstance(result.metadata, Mapping) else None,
                }
                for result in stage_results[:8]
            ]
            for stage, stage_results in inference.stage_results.items()
        },
        "candidate_path_count": len(inference.candidate_paths),
        "nodes_scored": inference.nodes_scored,
        "elapsed_seconds": elapsed_seconds,
    }


def stage_activity(traces: Sequence[Mapping[str, Any]]) -> dict[str, float]:
    if not traces:
        return {
            "major_accept_rate": 0.0,
            "middle_stage_trigger_rate": 0.0,
            "cwe_stage_trigger_rate": 0.0,
            "non_benign_prediction_rate": 0.0,
        }
    total = float(len(traces))
    major_accept = sum(
        1.0
        for trace in traces
        if any(item["decision"] == "accept" for item in trace["stage_results"]["major"])
    )
    middle_trigger = sum(1.0 for trace in traces if trace["stage_results"]["middle"])
    cwe_trigger = sum(1.0 for trace in traces if trace["stage_results"]["cwe"])
    non_benign = sum(1.0 for trace in traces if trace["prediction"] != "Benign")
    return {
        "major_accept_rate": major_accept / total,
        "middle_stage_trigger_rate": middle_trigger / total,
        "cwe_stage_trigger_rate": cwe_trigger / total,
        "non_benign_prediction_rate": non_benign / total,
    }


def render_report(results: Mapping[str, Any]) -> str:
    metrics = results["cascade"]["aggregate"]["end_to_end_metrics"]
    route = results["cascade"]["aggregate"]["route_metrics"]
    stage = results["cascade"]["stage_activity"]
    calibration = results["calibration"]["best"]
    question_bank_filter = results["question_bank_filter"]
    excluded_nodes = question_bank_filter["excluded_cwds"]
    excluded_text = ", ".join(excluded_nodes) if excluded_nodes else "none"
    baseline = results.get("baseline_comparison")
    baseline_lines = ""
    if baseline:
        prev = baseline["previous"]
        delta = baseline["delta"]
        baseline_lines = f"""
## Previous Full-Run Delta
- Baseline: {prev["path"]}
- Previous CWD accuracy: {prev["end_to_end_metrics"].get("cwe_accuracy", 0.0):.3f}
- Previous final exact match: {prev["end_to_end_metrics"].get("final_exact_match", 0.0):.3f}
- Delta CWD accuracy: {delta.get("cwe_accuracy", 0.0):+.3f}
- Delta final exact match: {delta.get("final_exact_match", 0.0):+.3f}
"""

    return f"""# Full-Sample CWD Sibling-Leaf Ranking Run

## Summary
- Timestamp: {results["timestamp"]}
- Backend: {results["backend_used"]}
- Model: {results["model_name"]}
- Eval variants: {results["sample_selection"]["eval"]["total"]}
- Dev variants for threshold calibration: {results["sample_selection"]["dev"]["total"]}
- Support variants for prototype calibration: {results["sample_selection"]["support"]["total"]}
- Minimum vulnerable samples per CWD: {question_bank_filter["min_cwe_vulnerable_samples"]}
- Active CWD nodes in question bank/cascade: {question_bank_filter["active_cwd_count"]}
- Excluded low-sample CWD nodes: {question_bank_filter["excluded_cwd_count"]}
- Excluded labels: {excluded_text}
- Evolved leaf prompts loaded into taxonomy: {results["leaf_prompt_coverage"]["loaded"]} / {results["leaf_prompt_coverage"]["total_cwe_nodes"]}
- Missing evolved leaf prompts: {", ".join(results["leaf_prompt_coverage"]["missing_in_bundle"]) if results["leaf_prompt_coverage"]["missing_in_bundle"] else "none"}
- Sample workers: {results["config"]["sample_workers"]}

## Calibration
- Thresholds: major={calibration["major_threshold"]:.2f}, middle={calibration["middle_threshold"]:.2f}, cwe={calibration["cwe_threshold"]:.2f}
- Dev exact match: {calibration["metrics"]["final_exact_match"]:.3f}
- Dev path coverage: {calibration["route_metrics"]["path_coverage"]:.3f}

## Final Metrics
| Metric | Value |
|---|---:|
| Final exact match | {metrics["final_exact_match"]:.3f} |
| Major accuracy | {metrics["major_accuracy"]:.3f} |
| Middle accuracy | {metrics["middle_accuracy"]:.3f} |
| CWD accuracy | {metrics["cwe_accuracy"]:.3f} |
| Vulnerable vs Benign F1 | {metrics["vuln_vs_benign_f1"]:.3f} |
| Macro F1 | {metrics["macro_f1"]:.3f} |
| Path coverage | {route["path_coverage"]:.3f} |
| Major route recall@1 | {route["major_route_recall_at_1"]:.3f} |
| Middle route recall@1 | {route["middle_route_recall_at_1"]:.3f} |
| Avg nodes scored/sample | {results["cascade"]["aggregate"]["cost_metrics"]["avg_nodes_scored_per_sample"]:.2f} |

## Stage Activity
- Major accept rate: {stage["major_accept_rate"]:.3f}
- Middle trigger rate: {stage["middle_stage_trigger_rate"]:.3f}
- CWD trigger rate: {stage["cwe_stage_trigger_rate"]:.3f}
- Non-benign prediction rate: {stage["non_benign_prediction_rate"]:.3f}
{baseline_lines}
## Notes
- Major and middle stages still use the current `ranking_v2` cascade prompts.
- CWD leaf scoring now makes one sibling-ranking call under the accepted middle node.
- Candidate guidance is sourced from evolved leaf prompts when available, otherwise from the taxonomy definition text.
"""


def run_one_sample(sample: EvaluationSample, bundle, scorer, policy) -> tuple[EvaluationSample, Any, float]:
    started = time.time()
    inference = policy.run(bundle, scorer, sample.code)
    return sample, inference, time.time() - started


def baseline_delta(current: Mapping[str, Any], previous: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if previous is None:
        return None
    current_metrics = current["cascade"]["aggregate"]["end_to_end_metrics"]
    prev_metrics = previous.get("end_to_end_metrics", {})
    return {
        "previous": previous,
        "delta": {
            "final_exact_match": current_metrics.get("final_exact_match", 0.0) - prev_metrics.get("final_exact_match", 0.0),
            "cwe_accuracy": current_metrics.get("cwe_accuracy", 0.0) - prev_metrics.get("cwe_accuracy", 0.0),
            "middle_accuracy": current_metrics.get("middle_accuracy", 0.0) - prev_metrics.get("middle_accuracy", 0.0),
            "major_accuracy": current_metrics.get("major_accuracy", 0.0) - prev_metrics.get("major_accuracy", 0.0),
        },
    }


def main() -> None:
    args = parse_args()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = Path(args.output_root) / f"{args.run_prefix}_{timestamp}"
    output_dir.mkdir(parents=True, exist_ok=True)

    dataset = CWDDataset(
        Path(args.dataset),
        min_cwe_vulnerable_samples=args.min_cwe_vuln_samples,
    )
    dev_records, support_records, eval_records = build_dev_subset(
        dataset,
        dev_samples=args.dev_samples,
        vulnerable_ratio=args.vulnerable_ratio,
    )
    if args.limit and args.limit > 0:
        eval_records = eval_records[: args.limit]

    evolved_leaf_prompts = load_best_leaf_prompts(Path(args.node_results_root))
    bundle_factory = OptimizedBundleFactory(
        dataset.cwd_definitions,
        active_cwds=dataset.active_cwds,
    )

    # P0-3: disable major nodes that contribute near-zero TP but massive FP.
    # Based on full-run analysis: Logic/Input/Resource/Other合计4186 FP / 1 TP.
    disabled_majors_str = getattr(args, "disabled_majors", "").strip()
    disabled_majors = set(m.strip() for m in disabled_majors_str.split(",") if m.strip()) if disabled_majors_str else set()
    index = PrototypeSimilarityIndex(
        support_records=support_records,
        cwd_definitions=dataset.cwd_definitions,
        support_top_k=3,
        char_ngram_range=(3, 5),
        max_features=60000,
    )
    calibration = grid_search_thresholds(
        bundle_factory=bundle_factory,
        index=index,
        dev_samples=to_eval_samples(dev_records),
    )
    best = calibration["best"]
    bundle = bundle_factory.build(
        major_threshold=best["major_threshold"],
        middle_threshold=best["middle_threshold"],
        cwe_threshold=best["cwe_threshold"],
    )

    # No hardcoded major disabling. Data-driven pruning via
    # min_cwe_vulnerable_samples already removes CWD nodes with too few
    # samples, and _prune_bundle() removes orphaned middle/major nodes.

    api_key = os.getenv("OPENROUTER_API_KEY") or os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENROUTER_API_KEY or OPENAI_API_KEY is required")
    api_base = args.api_base or os.getenv("OPENAI_API_BASE", "https://openrouter.ai/api/v1")

    llm_client = OpenAICompatibleClient(
        model_name=args.model_name,
        api_base=api_base,
        api_key=api_key,
    )
    scorer = LeafSiblingRankingScorer(
        llm_client=llm_client,
        bundle=bundle,
        cwd_definitions=dataset.cwd_definitions,
        evolved_leaf_prompts=evolved_leaf_prompts,
    )

    evaluator = MainlineEvaluator()
    if args.policy == "beam":
        policy = BeamCascadePolicy(
            parallel=False,
            major_beam_width=args.major_beam_width,
            middle_beam_width=args.middle_beam_width,
            benign_gate_threshold=args.benign_gate_threshold,
            margin_threshold=args.margin_threshold,
        )
    else:
        policy = GreedyCascadePolicy(parallel=False, major_top_k=1, middle_top_k=1)
    samples = to_eval_samples(eval_records)
    acc = evaluator._new_accumulator(policy)
    processed_samples: list[EvaluationSample] = []
    traces: list[dict[str, Any]] = []
    started_at = time.time()

    with ThreadPoolExecutor(max_workers=max(1, args.sample_workers)) as executor:
        futures = [executor.submit(run_one_sample, sample, bundle, scorer, policy) for sample in samples]
        total = len(futures)
        for index_num, future in enumerate(as_completed(futures), start=1):
            sample, inference, elapsed = future.result()
            evaluator._record_prediction_pairs(bundle, sample, inference, acc)
            evaluator._record_route_metrics(bundle, sample, inference, acc)
            evaluator._record_node_metrics(bundle, sample, inference, acc)
            processed_samples.append(sample)
            traces.append(trace_for_sample(sample, inference, elapsed))

            if index_num % args.progress_every == 0 or index_num == total:
                partial = evaluator._build_result(processed_samples, acc)
                print(
                    f"[{index_num}/{total}] exact={partial.end_to_end_metrics['final_exact_match']:.3f} "
                    f"cwe={partial.end_to_end_metrics['cwe_accuracy']:.3f} "
                    f"avg_nodes={partial.cost_metrics['avg_nodes_scored_per_sample']:.2f} "
                    f"last_sample_s={elapsed:.2f} total_min={(time.time() - started_at) / 60.0:.1f}",
                    flush=True,
                )

            if index_num % args.checkpoint_every == 0 or index_num == total:
                partial = evaluator._build_result(processed_samples, acc)
                checkpoint = {
                    "processed": index_num,
                    "total": total,
                    "elapsed_seconds": time.time() - started_at,
                    "metrics": {
                        "end_to_end_metrics": partial.end_to_end_metrics,
                        "route_metrics": partial.route_metrics,
                        "cost_metrics": partial.cost_metrics,
                    },
                }
                save_json(output_dir / "checkpoint.json", checkpoint)

    traces.sort(key=lambda item: item["sample_id"])
    aggregate = evaluator._build_result(samples, acc)
    cwe_nodes = sorted(node.target_label for node in bundle.nodes.values() if node.stage == "cwe")
    loaded_in_bundle = sorted(label for label in cwe_nodes if label in evolved_leaf_prompts)
    missing_in_bundle = sorted(label for label in cwe_nodes if label not in evolved_leaf_prompts)
    extra_loaded = sorted(label for label in evolved_leaf_prompts if label not in set(cwe_nodes))
    mispredictions = [trace for trace in traces if trace["truth"]["final"] != trace["prediction"]]

    results = {
        "timestamp": timestamp,
        "backend_used": "openrouter_sibling_leaf_ranking",
        "model_name": args.model_name,
        "api_base": api_base,
        "config": {
            **vars(args),
            "policy": args.policy,
            "major_beam_width": args.major_beam_width if args.policy == "beam" else 1,
            "middle_beam_width": args.middle_beam_width if args.policy == "beam" else 1,
            "benign_gate_threshold": args.benign_gate_threshold if args.policy == "beam" else None,
            "margin_threshold": args.margin_threshold if args.policy == "beam" else None,
        },
        "sample_selection": {
            "dev": summarize_records(dev_records),
            "support": summarize_records(support_records),
            "eval": summarize_records(eval_records),
        },
        "question_bank_filter": dataset.filter_summary,
        "calibration": calibration,
        "leaf_prompt_coverage": {
            "loaded": len(loaded_in_bundle),
            "total_cwe_nodes": len(cwe_nodes),
            "missing_in_bundle": missing_in_bundle,
            "extra_loaded_not_in_bundle": extra_loaded,
            "sources": {label: evolved_leaf_prompts[label] for label in loaded_in_bundle},
        },
        "cascade": {
            "aggregate": {
                "route_metrics": aggregate.route_metrics,
                "end_to_end_metrics": aggregate.end_to_end_metrics,
                "cost_metrics": aggregate.cost_metrics,
            },
            "node_metrics": {node_id: asdict(metrics) for node_id, metrics in aggregate.node_metrics.items()},
            "stage_activity": stage_activity(traces),
        },
        "runtime": {"elapsed_seconds": time.time() - started_at},
    }
    baseline = load_baseline_metrics(Path(args.baseline_results))
    comparison = baseline_delta(results, baseline)
    if comparison is not None:
        results["baseline_comparison"] = comparison

    save_json(output_dir / "results.json", results)
    save_json(output_dir / "cascade_traces.json", traces)
    save_json(output_dir / "mispredictions.json", mispredictions)
    (output_dir / "report.md").write_text(render_report(results), encoding="utf-8")
    print(f"Artifacts saved to: {output_dir}", flush=True)


if __name__ == "__main__":
    main()
