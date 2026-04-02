#!/usr/bin/env python3
"""MulVul 全量训练与评估脚本

整合所有已实现功能:
- 层级检测器 (Major → Middle → CWE)
- RAG 知识库检索
- 1:1:1 采样策略 (target/other_vul/benign)
- 迭代训练 + 错误反馈
- 并发评估
- 详细统计输出

Usage:
    # 全量训练 + 评估
    uv run python scripts/ablations/run_full_pipeline.py

    # 仅训练
    uv run python scripts/ablations/run_full_pipeline.py --train-only

    # 仅评估 (使用已训练的 prompts)
    uv run python scripts/ablations/run_full_pipeline.py --eval-only
"""

import os
import sys
import json
import time
import random
import argparse
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any, Optional, Tuple

sys.path.insert(0, "src")

from tqdm import tqdm
from evoprompt.llm.client import create_llm_client, load_env_vars
from evoprompt.rag.retriever import MulVulRetriever
from evoprompt.agents.hierarchical_detector import (
    HierarchicalDetector, HierarchicalResult, LevelDetector,
    MAJOR_TO_MIDDLE, MIDDLE_TO_CWE, CWE_TO_MIDDLE, MIDDLE_TO_MAJOR,
    VALID_CWES, CWE_FALLBACK_MAP, MIN_CWE_SAMPLES
)
from evoprompt.agents.hierarchical_sampler import HierarchicalSampler, TrainingSample
from evoprompt.data.cwe_hierarchy import cwe_to_major, cwe_to_middle


# ============================================================================
# Data Loading
# ============================================================================

def load_jsonl(path: str) -> List[Dict]:
    samples = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                try:
                    samples.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return samples


def get_ground_truth(item: Dict) -> Tuple[str, str, str]:
    """Get (cwe, middle, major) ground truth.

    For CWEs with < MIN_CWE_SAMPLES, fallback to Middle level.
    """
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

    # Fallback: if CWE has < MIN_CWE_SAMPLES, use Middle as CWE target
    if cwe not in VALID_CWES:
        cwe = middle  # Fallback to middle category

    return cwe, middle, major


# ============================================================================
# Training
# ============================================================================

class FullPipelineTrainer:
    """Full pipeline trainer with all features."""

    def __init__(
        self,
        llm_client,
        sampler: HierarchicalSampler,
        retriever: MulVulRetriever,
        output_dir: str,
    ):
        self.llm_client = llm_client
        self.sampler = sampler
        self.retriever = retriever
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

        self.prompts = {}
        self.scores = {}
        self.training_history = []

    def train_all(
        self,
        n_rounds: int = 3,
        n_samples_per_class: int = 100,
        max_workers: int = 4,
    ):
        """Train all level detectors."""
        print("\n" + "=" * 70)
        print("🎯 PHASE 1: Training All Detectors")
        print("=" * 70)

        for round_num in range(1, n_rounds + 1):
            print(f"\n{'#' * 70}")
            print(f"# Training Round {round_num}/{n_rounds}")
            print(f"{'#' * 70}")

            round_results = {}

            # 1. Train Major detectors
            print("\n📊 [1/3] Training Major Detectors...")
            for major in self.sampler.get_all_majors():
                result = self._train_detector(
                    level="major", target=major,
                    n_samples=n_samples_per_class,
                    round_num=round_num,
                )
                round_results[f"major_{major}"] = result
                print(f"   ✓ {major}: F1={result['f1']:.2%}, Acc={result['accuracy']:.2%}")

            # 2. Train Middle detectors
            print("\n📊 [2/3] Training Middle Detectors...")
            for middle in self.sampler.get_all_middles():
                result = self._train_detector(
                    level="middle", target=middle,
                    n_samples=n_samples_per_class,
                    round_num=round_num,
                )
                round_results[f"middle_{middle}"] = result
                print(f"   ✓ {middle}: F1={result['f1']:.2%}, Acc={result['accuracy']:.2%}")

            # 3. Train CWE detectors (only for CWEs with >= 50 samples)
            print("\n📊 [3/3] Training CWE Detectors (>= 50 samples)...")
            cwes = self.sampler.get_all_cwes(min_samples=50)
            print(f"   Training {len(cwes)} CWEs (skipping {len(self.sampler.by_cwe) - len(cwes)} with < 50 samples)")
            for cwe in cwes:
                result = self._train_detector(
                    level="cwe", target=cwe,
                    n_samples=min(n_samples_per_class, 50),
                    round_num=round_num,
                )
                round_results[f"cwe_{cwe}"] = result
                print(f"   ✓ {cwe}: F1={result['f1']:.2%}, Acc={result['accuracy']:.2%}")

            # Generate feedback
            feedback = self._generate_round_feedback(round_results)
            self.training_history.append({
                "round": round_num,
                "results": round_results,
                "feedback": feedback,
            })

            # Save round
            self._save_round(round_num, round_results, feedback)

            print(f"\n📝 Round {round_num} Summary:")
            self._print_round_summary(round_results)

        # Save final prompts
        self._save_prompts()
        print(f"\n✅ Training complete! Prompts saved to {self.output_dir}/best_prompts.json")

    def _train_detector(
        self,
        level: str,
        target: str,
        n_samples: int,
        round_num: int,
    ) -> Dict:
        """Train a single detector."""
        # Get candidates
        if level == "major":
            samples = self.sampler.sample_for_major(target, n_samples)
            candidates = list(MAJOR_TO_MIDDLE.keys()) + ["Benign"]
        elif level == "middle":
            samples = self.sampler.sample_for_middle(target, n_samples)
            major = MIDDLE_TO_MAJOR.get(target, "Logic")
            candidates = MAJOR_TO_MIDDLE.get(major, []) + ["Benign"]
        else:
            samples = self.sampler.sample_for_cwe(target, n_samples)
            middle = CWE_TO_MIDDLE.get(target, "Other")
            candidates = MIDDLE_TO_CWE.get(middle, []) + ["Benign"]

        if not samples:
            return {"accuracy": 0, "f1": 0, "errors": []}

        # Get or evolve prompt
        key = f"{level}_{target}"
        if round_num == 1 or key not in self.prompts:
            prompt = self._create_prompt(level, target, candidates)
        else:
            prev_errors = self.training_history[-1]["results"].get(key, {}).get("errors", [])
            prompt = self._evolve_prompt(self.prompts[key], prev_errors, level, target, candidates)

        # Create detector
        detector = LevelDetector(
            level=level, target=target,
            llm_client=self.llm_client,
            prompt=prompt,
            candidates=candidates,
            retriever=self.retriever,
        )

        # Evaluate
        result = self._evaluate_detector(detector, samples, level, target)
        result["prompt"] = prompt

        # Update best
        if key not in self.scores or result["f1"] > self.scores[key]:
            self.scores[key] = result["f1"]
            self.prompts[key] = prompt

        return result

    def _create_prompt(self, level: str, target: str, candidates: List[str]) -> str:
        """Create initial prompt with RAG emphasis."""
        candidates_str = ", ".join(candidates)

        base = f"""You are a security expert specializing in {target} vulnerabilities.

## CRITICAL: Compare with Known Vulnerable Patterns
Below are CONFIRMED vulnerable code examples. You MUST compare the target code against these patterns:

{{evidence}}

## Target Code to Analyze:
```
{{code}}
```

## Categories: {candidates_str}

## Analysis Instructions:
1. FIRST, identify which patterns from the evidence examples appear in the target code
2. If the code shares vulnerable patterns with the examples, classify accordingly
3. Only mark as Benign if NO similar patterns exist

## Output (JSON):
{{{{
  "predictions": [
    {{{{"category": "...", "confidence": 0.85, "reason": "Pattern match with example X"}}}}
  ]
}}}}"""
        return base

    def _evolve_prompt(self, current: str, errors: List[Dict], level: str, target: str, candidates: List[str]) -> str:
        """Evolve prompt based on errors."""
        if not errors:
            return current

        error_summary = "\n".join([
            f"- Expected {e['expected']}, got {e['predicted']}: {e.get('reason', '')[:100]}"
            for e in errors[:5]
        ])

        evolution_prompt = f"""Improve this vulnerability detection prompt to avoid these errors:

## Current Prompt:
{current[:2000]}

## Errors:
{error_summary}

## Requirements:
1. Keep JSON output format
2. Add specific hints to avoid the errors
3. Keep concise

Output the improved prompt only:"""

        try:
            improved = self.llm_client.generate(evolution_prompt)
            if len(improved) > 200:
                return improved
        except Exception:
            pass
        return current

    def _evaluate_detector(
        self,
        detector: LevelDetector,
        samples: List[TrainingSample],
        level: str,
        target: str,
    ) -> Dict:
        """Evaluate detector on samples."""
        confusion = defaultdict(lambda: defaultdict(int))
        errors = []

        for sample in samples:
            try:
                results = detector.detect(sample.code, top_k=1)
                pred = results[0][0] if results else "Unknown"
            except Exception:
                pred = "Error"

            # Ground truth
            if sample.label == "target":
                gt = target
            elif sample.label == "benign":
                gt = "Benign"
            else:
                gt = getattr(sample, level, "Unknown")

            confusion[gt][pred] += 1

            if pred != gt and len(errors) < 10:
                errors.append({
                    "expected": gt,
                    "predicted": pred,
                    "code": sample.code[:300],
                })

        # Metrics
        tp = confusion[target][target]
        fp = sum(confusion[gt][target] for gt in confusion if gt != target)
        fn = sum(confusion[target][pred] for pred in confusion[target] if pred != target)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        total = sum(sum(p.values()) for p in confusion.values())
        correct = sum(confusion[gt][gt] for gt in confusion)
        accuracy = correct / total if total > 0 else 0

        return {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "errors": errors,
        }

    def _generate_round_feedback(self, results: Dict) -> str:
        """Generate feedback for the round."""
        lines = []
        by_level = defaultdict(list)
        for key, result in results.items():
            level = key.split("_")[0]
            by_level[level].append((key, result))

        for level in ["major", "middle", "cwe"]:
            level_results = by_level.get(level, [])
            if not level_results:
                continue
            avg_f1 = sum(r["f1"] for _, r in level_results) / len(level_results)
            lines.append(f"{level.upper()}: avg F1={avg_f1:.2%}")

        return "\n".join(lines)

    def _print_round_summary(self, results: Dict):
        """Print round summary."""
        by_level = defaultdict(list)
        for key, result in results.items():
            level = key.split("_")[0]
            by_level[level].append(result["f1"])

        for level in ["major", "middle", "cwe"]:
            scores = by_level.get(level, [])
            if scores:
                avg = sum(scores) / len(scores)
                print(f"   {level.upper():8s}: avg F1={avg:.2%} (n={len(scores)})")

    def _save_round(self, round_num: int, results: Dict, feedback: str):
        """Save round results."""
        path = os.path.join(self.output_dir, f"round_{round_num}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({
                "round": round_num,
                "feedback": feedback,
                "results": {k: {kk: vv for kk, vv in v.items() if kk != "prompt"} for k, v in results.items()},
            }, f, indent=2, ensure_ascii=False)

    def _save_prompts(self):
        """Save best prompts."""
        path = os.path.join(self.output_dir, "best_prompts.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"prompts": self.prompts, "scores": self.scores}, f, indent=2, ensure_ascii=False)


# ============================================================================
# Evaluation
# ============================================================================

class FullPipelineEvaluator:
    """Full pipeline evaluator with detailed statistics."""

    def __init__(
        self,
        llm_client,
        retriever: MulVulRetriever,
        prompts: Dict[str, str],
        output_dir: str,
    ):
        self.llm_client = llm_client
        self.retriever = retriever
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

        # Build detector
        major_prompt = None
        middle_prompts = {}
        cwe_prompts = {}

        for key, prompt in prompts.items():
            if key.startswith("major_"):
                major_prompt = prompt
            elif key.startswith("middle_"):
                middle_prompts[key.replace("middle_", "")] = prompt
            elif key.startswith("cwe_"):
                cwe_prompts[key.replace("cwe_", "")] = prompt

        self.detector = HierarchicalDetector(
            llm_client=llm_client,
            retriever=retriever,
            major_prompt=major_prompt,
            middle_prompts=middle_prompts,
            cwe_prompts=cwe_prompts,
            top_k=2,
        )

    def evaluate_all(
        self,
        eval_file: str,
        max_samples: int = None,
        max_workers: int = 16,
        balanced: bool = True,
        seed: int = 42,
    ):
        """Evaluate on all samples with detailed statistics."""
        print("\n" + "=" * 70)
        print("📊 PHASE 2: Full Evaluation")
        print("=" * 70)

        # Load data
        print(f"\n📂 Loading: {eval_file}")
        samples = load_jsonl(eval_file)
        print(f"   Total: {len(samples)}")

        # Balance if requested
        if balanced:
            random.seed(seed)
            benign = [s for s in samples if int(s.get("target", 0)) == 0]
            vuls = [s for s in samples if int(s.get("target", 0)) == 1]
            n = min(len(benign), len(vuls))
            samples = random.sample(benign, n) + random.sample(vuls, n)
            random.shuffle(samples)
            print(f"   Balanced: {len(samples)} (benign:vul = 1:1)")

        if max_samples:
            samples = samples[:max_samples]
            print(f"   Using: {len(samples)}")

        # Statistics structures
        stats = {
            "major": {"correct": 0, "total": 0, "by_class": defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})},
            "middle": {"correct": 0, "total": 0, "by_class": defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})},
            "cwe": {"correct": 0, "total": 0, "by_class": defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})},
        }
        confusion_major = defaultdict(lambda: defaultdict(int))
        confusion_middle = defaultdict(lambda: defaultdict(int))
        confusion_cwe = defaultdict(lambda: defaultdict(int))

        results = []
        errors = []

        # Evaluate
        print(f"\n🚀 Evaluating (workers={max_workers})...")
        start_time = time.time()

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            def eval_single(item):
                code = item.get("func", "")
                gt_cwe, gt_middle, gt_major = get_ground_truth(item)

                try:
                    result = self.detector.detect(code)
                except Exception as e:
                    result = HierarchicalResult(
                        major="Error", major_confidence=0,
                        middle="Error", middle_confidence=0,
                        cwe="Error", cwe_confidence=0,
                        evidence=str(e),
                    )

                return {
                    "gt_major": gt_major,
                    "gt_middle": gt_middle,
                    "gt_cwe": gt_cwe,
                    "pred_major": result.major,
                    "pred_middle": result.middle,
                    "pred_cwe": result.cwe,
                    "confidence": result.cwe_confidence,
                    "code": code[:500],
                }

            futures = {executor.submit(eval_single, s): s for s in samples}

            with tqdm(total=len(samples), desc="Evaluating", unit="sample") as pbar:
                for future in as_completed(futures):
                    try:
                        r = future.result()
                        results.append(r)

                        # Update stats
                        for level in ["major", "middle", "cwe"]:
                            gt = r[f"gt_{level}"]
                            pred = r[f"pred_{level}"]
                            stats[level]["total"] += 1

                            if gt == pred:
                                stats[level]["correct"] += 1
                                stats[level]["by_class"][gt]["tp"] += 1
                            else:
                                stats[level]["by_class"][gt]["fn"] += 1
                                stats[level]["by_class"][pred]["fp"] += 1

                        # Confusion matrices
                        confusion_major[r["gt_major"]][r["pred_major"]] += 1
                        confusion_middle[r["gt_middle"]][r["pred_middle"]] += 1
                        confusion_cwe[r["gt_cwe"]][r["pred_cwe"]] += 1

                        # Collect errors
                        if r["gt_cwe"] != r["pred_cwe"] and len(errors) < 50:
                            errors.append(r)

                    except Exception as e:
                        tqdm.write(f"Error: {e}")

                    pbar.update(1)

        elapsed = time.time() - start_time

        # Print results
        self._print_results(stats, confusion_major, confusion_middle, confusion_cwe, elapsed, len(results))

        # Save results
        self._save_results(stats, confusion_major, confusion_middle, confusion_cwe, results, errors)

        return stats

    def _print_results(self, stats, conf_major, conf_middle, conf_cwe, elapsed, total):
        """Print detailed results."""
        print("\n" + "=" * 70)
        print("📊 EVALUATION RESULTS")
        print("=" * 70)

        # Overall accuracy
        print("\n🎯 Overall Accuracy:")
        for level in ["major", "middle", "cwe"]:
            acc = stats[level]["correct"] / stats[level]["total"] if stats[level]["total"] > 0 else 0
            print(f"   {level.upper():8s}: {acc:.2%} ({stats[level]['correct']}/{stats[level]['total']})")

        # Per-class F1 for Major
        print("\n📈 Major Category Performance:")
        print(f"   {'Category':<12} {'Precision':>10} {'Recall':>10} {'F1':>10} {'Support':>10}")
        print("   " + "-" * 54)
        for cat in ["Memory", "Injection", "Logic", "Input", "Crypto", "Benign"]:
            s = stats["major"]["by_class"][cat]
            tp, fp, fn = s["tp"], s["fp"], s["fn"]
            prec = tp / (tp + fp) if (tp + fp) > 0 else 0
            rec = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0
            support = tp + fn
            if support > 0:
                print(f"   {cat:<12} {prec:>10.2%} {rec:>10.2%} {f1:>10.2%} {support:>10}")

        # Top CWE performance
        print("\n📈 Top 10 CWE Performance:")
        cwe_stats = [(cwe, s) for cwe, s in stats["cwe"]["by_class"].items() if s["tp"] + s["fn"] > 5]
        cwe_stats.sort(key=lambda x: x[1]["tp"] + x[1]["fn"], reverse=True)

        print(f"   {'CWE':<12} {'Precision':>10} {'Recall':>10} {'F1':>10} {'Support':>10}")
        print("   " + "-" * 54)
        for cwe, s in cwe_stats[:10]:
            tp, fp, fn = s["tp"], s["fp"], s["fn"]
            prec = tp / (tp + fp) if (tp + fp) > 0 else 0
            rec = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0
            support = tp + fn
            print(f"   {cwe:<12} {prec:>10.2%} {rec:>10.2%} {f1:>10.2%} {support:>10}")

        # Confusion matrix for Major
        print("\n📊 Major Confusion Matrix:")
        cats = ["Memory", "Injection", "Logic", "Input", "Crypto", "Benign"]
        print("   " + " " * 12 + "".join(f"{c[:6]:>8}" for c in cats))
        for gt in cats:
            row = "".join(f"{conf_major[gt][pred]:>8}" for pred in cats)
            print(f"   {gt:<12}{row}")

        # Performance
        print(f"\n⏱️  Performance:")
        print(f"   Time: {elapsed:.1f}s")
        print(f"   Throughput: {total / elapsed:.1f} samples/sec")

    def _save_results(self, stats, conf_major, conf_middle, conf_cwe, results, errors):
        """Save results to file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(self.output_dir, f"full_eval_{timestamp}.json")

        # Convert defaultdicts
        def convert(d):
            if isinstance(d, defaultdict):
                return {k: convert(v) for k, v in d.items()}
            return d

        with open(path, "w", encoding="utf-8") as f:
            json.dump({
                "timestamp": timestamp,
                "stats": {
                    level: {
                        "accuracy": s["correct"] / s["total"] if s["total"] > 0 else 0,
                        "correct": s["correct"],
                        "total": s["total"],
                        "by_class": convert(s["by_class"]),
                    }
                    for level, s in stats.items()
                },
                "confusion_major": convert(conf_major),
                "confusion_middle": convert(conf_middle),
                "sample_errors": errors[:20],
            }, f, indent=2, ensure_ascii=False)

        print(f"\n💾 Results saved to: {path}")


# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="MulVul Full Pipeline")
    parser.add_argument("--train-only", action="store_true", help="Only train")
    parser.add_argument("--eval-only", action="store_true", help="Only evaluate")
    parser.add_argument("--train-data", default="./data/primevul/primevul/primevul_train.jsonl")
    parser.add_argument("--eval-data", default="./data/primevul/primevul/primevul_valid.jsonl")
    parser.add_argument("--kb", default="./data/knowledge_base_hierarchical.json")
    parser.add_argument("--output", default="./outputs/full_pipeline")
    parser.add_argument("--prompts", default="./outputs/full_pipeline/best_prompts.json")
    parser.add_argument("--rounds", type=int, default=3, help="Training rounds")
    parser.add_argument("--train-samples", type=int, default=100, help="Samples per class for training")
    parser.add_argument("--eval-samples", type=int, default=None, help="Max eval samples")
    parser.add_argument("--workers", type=int, default=16, help="Parallel workers")
    parser.add_argument("--balanced", action="store_true", default=True, help="Balance eval data")
    parser.add_argument("--seed", type=int, default=42)

    args = parser.parse_args()

    load_env_vars()

    print("=" * 70)
    print("🔥 MulVul Full Pipeline - Train & Evaluate")
    print("=" * 70)
    print(f"   Train data: {args.train_data}")
    print(f"   Eval data: {args.eval_data}")
    print(f"   Knowledge base: {args.kb}")
    print(f"   Output: {args.output}")
    print("=" * 70)

    # Load knowledge base
    retriever = None
    if os.path.exists(args.kb):
        retriever = MulVulRetriever(knowledge_base_path=args.kb)

    # Training
    if not args.eval_only:
        if not os.path.exists(args.train_data):
            print(f"❌ Train data not found: {args.train_data}")
            return 1

        llm_client = create_llm_client()
        sampler = HierarchicalSampler(args.train_data, seed=args.seed)

        trainer = FullPipelineTrainer(
            llm_client=llm_client,
            sampler=sampler,
            retriever=retriever,
            output_dir=args.output,
        )

        trainer.train_all(
            n_rounds=args.rounds,
            n_samples_per_class=args.train_samples,
        )

    # Evaluation
    if not args.train_only:
        if not os.path.exists(args.eval_data):
            print(f"❌ Eval data not found: {args.eval_data}")
            return 1

        # Load prompts
        prompts = {}
        prompts_path = args.prompts if args.eval_only else os.path.join(args.output, "best_prompts.json")
        if os.path.exists(prompts_path):
            with open(prompts_path, "r") as f:
                data = json.load(f)
                prompts = data.get("prompts", {})
            print(f"\n📚 Loaded {len(prompts)} prompts")

        llm_client = create_llm_client()

        evaluator = FullPipelineEvaluator(
            llm_client=llm_client,
            retriever=retriever,
            prompts=prompts,
            output_dir=args.output,
        )

        evaluator.evaluate_all(
            eval_file=args.eval_data,
            max_samples=args.eval_samples,
            max_workers=args.workers,
            balanced=args.balanced,
            seed=args.seed,
        )

    print("\n✅ Pipeline complete!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
