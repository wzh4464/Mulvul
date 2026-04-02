#!/usr/bin/env python3
"""Hierarchical detector training and evaluation script.

Usage:
    # Train all detectors
    uv run python scripts/ablations/run_hierarchical_train.py --train

    # Evaluate trained detectors
    uv run python scripts/ablations/run_hierarchical_train.py --eval

    # Both
    uv run python scripts/ablations/run_hierarchical_train.py --train --eval
"""

import os
import sys
import json
import argparse
from datetime import datetime
from collections import defaultdict

sys.path.insert(0, "src")

from evoprompt.llm.client import create_llm_client, load_env_vars
from evoprompt.rag.retriever import MulVulRetriever
from evoprompt.agents.hierarchical_detector import HierarchicalDetector, HierarchicalResult
from evoprompt.agents.hierarchical_sampler import HierarchicalSampler
from evoprompt.agents.hierarchical_trainer import HierarchicalTrainer
from evoprompt.data.cwe_hierarchy import cwe_to_major, cwe_to_middle


def load_jsonl(path: str):
    samples = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                try:
                    samples.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return samples


def train_hierarchical(
    train_file: str,
    kb_path: str,
    output_dir: str,
    n_rounds: int = 3,
    n_samples: int = 50,
):
    """Train hierarchical detectors."""
    load_env_vars()

    print("=" * 70)
    print("🎯 Hierarchical Detector Training")
    print("=" * 70)

    # Create components
    llm_client = create_llm_client()
    retriever = MulVulRetriever(knowledge_base_path=kb_path) if kb_path else None
    sampler = HierarchicalSampler(train_file)

    # Create trainer
    trainer = HierarchicalTrainer(
        llm_client=llm_client,
        sampler=sampler,
        retriever=retriever,
        output_dir=output_dir,
    )

    # Train
    best_prompts = trainer.train_all_levels(
        n_rounds=n_rounds,
        n_samples_per_class=n_samples,
    )

    # Save
    trainer.save_best_prompts()

    print("\n✅ Training complete!")
    print(f"   Best prompts saved to: {output_dir}/best_prompts.json")

    return best_prompts


def evaluate_hierarchical(
    eval_file: str,
    kb_path: str,
    prompts_path: str,
    output_dir: str,
    max_samples: int = None,
):
    """Evaluate hierarchical detector."""
    load_env_vars()

    print("=" * 70)
    print("📊 Hierarchical Detector Evaluation")
    print("=" * 70)

    # Load prompts
    prompts = {}
    if prompts_path and os.path.exists(prompts_path):
        with open(prompts_path, "r") as f:
            data = json.load(f)
            prompts = data.get("prompts", {})
        print(f"📚 Loaded {len(prompts)} prompts from {prompts_path}")

    # Create detector
    llm_client = create_llm_client()
    retriever = MulVulRetriever(knowledge_base_path=kb_path) if kb_path else None

    # Parse prompts into major/middle/cwe
    major_prompt = None
    middle_prompts = {}
    cwe_prompts = {}

    for key, prompt in prompts.items():
        if key.startswith("major_"):
            major_prompt = prompt  # Use any major prompt as base
        elif key.startswith("middle_"):
            middle = key.replace("middle_", "")
            middle_prompts[middle] = prompt
        elif key.startswith("cwe_"):
            cwe = key.replace("cwe_", "")
            cwe_prompts[cwe] = prompt

    detector = HierarchicalDetector(
        llm_client=llm_client,
        retriever=retriever,
        major_prompt=major_prompt,
        middle_prompts=middle_prompts,
        cwe_prompts=cwe_prompts,
        top_k=2,
    )

    # Load eval data
    print(f"\n📂 Loading eval data: {eval_file}")
    samples = load_jsonl(eval_file)
    print(f"   Total samples: {len(samples)}")

    if max_samples:
        samples = samples[:max_samples]
        print(f"   Using: {len(samples)}")

    # Evaluate
    results = []
    stats = {
        "major": {"correct": 0, "total": 0},
        "middle": {"correct": 0, "total": 0},
        "cwe": {"correct": 0, "total": 0},
    }

    from tqdm import tqdm
    for item in tqdm(samples, desc="Evaluating"):
        code = item.get("func", "")
        target = int(item.get("target", 0))

        # Get ground truth
        if target == 0:
            gt_cwe, gt_middle, gt_major = "Benign", "Benign", "Benign"
        else:
            cwe_codes = item.get("cwe", [])
            if isinstance(cwe_codes, str):
                cwe_codes = [cwe_codes] if cwe_codes else []
            gt_cwe = cwe_codes[0] if cwe_codes else "Unknown"
            gt_middle = cwe_to_middle(cwe_codes)
            gt_major = cwe_to_major(cwe_codes)

        # Detect
        try:
            result = detector.detect(code)
        except Exception as e:
            result = HierarchicalResult(
                major="Error", major_confidence=0,
                middle="Error", middle_confidence=0,
                cwe="Error", cwe_confidence=0,
                evidence=str(e),
            )

        # Check accuracy
        major_correct = result.major == gt_major
        middle_correct = result.middle == gt_middle
        cwe_correct = result.cwe == gt_cwe

        stats["major"]["total"] += 1
        stats["middle"]["total"] += 1
        stats["cwe"]["total"] += 1

        if major_correct:
            stats["major"]["correct"] += 1
        if middle_correct:
            stats["middle"]["correct"] += 1
        if cwe_correct:
            stats["cwe"]["correct"] += 1

        results.append({
            "gt_major": gt_major,
            "gt_middle": gt_middle,
            "gt_cwe": gt_cwe,
            "pred_major": result.major,
            "pred_middle": result.middle,
            "pred_cwe": result.cwe,
            "major_correct": major_correct,
            "middle_correct": middle_correct,
            "cwe_correct": cwe_correct,
        })

    # Print results
    print("\n" + "=" * 70)
    print("📊 Evaluation Results")
    print("=" * 70)

    for level in ["major", "middle", "cwe"]:
        acc = stats[level]["correct"] / stats[level]["total"] if stats[level]["total"] > 0 else 0
        print(f"   {level.upper():8s} Accuracy: {acc:.2%} ({stats[level]['correct']}/{stats[level]['total']})")

    # Save results
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"hierarchical_eval_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump({
            "stats": stats,
            "results": results[:100],  # Save first 100 for analysis
        }, f, indent=2, ensure_ascii=False)

    print(f"\n💾 Results saved to: {output_file}")

    return stats


def main():
    parser = argparse.ArgumentParser(description="Hierarchical Detector Training & Evaluation")
    parser.add_argument("--train", action="store_true", help="Run training")
    parser.add_argument("--eval", action="store_true", help="Run evaluation")
    parser.add_argument("--train-data", default="./data/primevul/primevul/primevul_train.jsonl")
    parser.add_argument("--eval-data", default="./data/primevul/primevul/primevul_valid.jsonl")
    parser.add_argument("--kb", default="./data/knowledge_base_hierarchical.json")
    parser.add_argument("--prompts", default="./outputs/hierarchical_training/best_prompts.json")
    parser.add_argument("--output", default="./outputs/hierarchical_training")
    parser.add_argument("--rounds", type=int, default=3, help="Training rounds")
    parser.add_argument("--samples", type=int, default=50, help="Samples per class")
    parser.add_argument("--max-eval", type=int, default=None, help="Max eval samples")

    args = parser.parse_args()

    if not args.train and not args.eval:
        print("Please specify --train and/or --eval")
        return 1

    if args.train:
        if not os.path.exists(args.train_data):
            print(f"❌ Training data not found: {args.train_data}")
            return 1

        train_hierarchical(
            train_file=args.train_data,
            kb_path=args.kb if os.path.exists(args.kb) else None,
            output_dir=args.output,
            n_rounds=args.rounds,
            n_samples=args.samples,
        )

    if args.eval:
        if not os.path.exists(args.eval_data):
            print(f"❌ Eval data not found: {args.eval_data}")
            return 1

        evaluate_hierarchical(
            eval_file=args.eval_data,
            kb_path=args.kb if os.path.exists(args.kb) else None,
            prompts_path=args.prompts if os.path.exists(args.prompts) else None,
            output_dir=args.output,
            max_samples=args.max_eval,
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
