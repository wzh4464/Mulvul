#!/usr/bin/env python3
"""MulVul CWE 级别评估脚本

评估三个层级的检测准确率:
- Major (5类): Memory, Injection, Logic, Input, Crypto
- Middle (10类): Buffer Errors, Memory Management, etc.
- CWE (具体): CWE-119, CWE-416, etc.
"""

import os
import sys
import json
import time
import random
import argparse
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict

sys.path.insert(0, "src")

from tqdm import tqdm
from evoprompt.llm.client import create_llm_client, load_env_vars
from evoprompt.agents import MulVulDetector, DetectionResult
from evoprompt.rag.retriever import MulVulRetriever
from evoprompt.data.cwe_hierarchy import cwe_to_major, cwe_to_middle, extract_cwe_id


def load_jsonl_data(data_file: str) -> List[Dict]:
    samples = []
    with open(data_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                try:
                    samples.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return samples


def get_ground_truth(item: Dict) -> Tuple[str, str, str]:
    """获取样本的真实类别 (cwe, middle, major)"""
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


def evaluate_single_sample(
    item: Dict,
    detector: MulVulDetector,
    expected: Tuple[str, str, str],
) -> Dict:
    """评估单个样本，返回三层级结果"""
    code = item.get("func", "")
    expected_cwe, expected_middle, expected_major = expected

    try:
        details = detector.detect_with_details(code)

        routing = details["routing"]
        top_k_categories = routing["top_k"]
        final = details["final"]

        # 检查各层级准确率
        top_k_cats = [c[0] for c in top_k_categories]
        routing_correct = expected_major in top_k_cats
        major_correct = final["category"] == expected_major

        # 从 prediction 中提取 CWE
        pred_cwe = final["prediction"] if final["prediction"].startswith("CWE") else ""

        return {
            "expected_cwe": expected_cwe,
            "expected_middle": expected_middle,
            "expected_major": expected_major,
            "routing_top_k": top_k_categories,
            "routing_correct": routing_correct,
            "pred_cwe": pred_cwe,
            "pred_category": final["category"],
            "pred_confidence": final["confidence"],
            "major_correct": major_correct,
            "cwe_correct": pred_cwe == expected_cwe,
            "error": None,
        }

    except Exception as e:
        return {
            "expected_cwe": expected_cwe,
            "expected_middle": expected_middle,
            "expected_major": expected_major,
            "routing_top_k": [],
            "routing_correct": False,
            "pred_cwe": "",
            "pred_category": "Error",
            "pred_confidence": 0.0,
            "major_correct": False,
            "cwe_correct": False,
            "error": str(e),
        }


def run_cwe_evaluation(
    data_file: str,
    max_workers: int = 32,
    max_samples: Optional[int] = None,
    output_dir: str = "./outputs",
    max_agents: int = 3,
    balanced: bool = False,
    seed: int = 42,
    kb_path: str = None,
    adaptive_agents: bool = True,
) -> Dict[str, Any]:
    """运行 CWE 级别评估"""

    load_env_vars()

    print("=" * 70)
    print("🔥 MulVul CWE 级别评估")
    print("=" * 70)
    routing_mode = "Adaptive" if adaptive_agents else "Fixed"
    print(f"   🔀 Router: {routing_mode} routing (max_agents={max_agents})")
    print(f"   📊 评估层级: Major → Middle → CWE")
    if kb_path:
        print(f"   📚 Knowledge Base: {kb_path}")
    print("=" * 70)

    # 加载知识库
    retriever = None
    if kb_path and os.path.exists(kb_path):
        retriever = MulVulRetriever(knowledge_base_path=kb_path)

    # 加载数据
    print(f"\n📂 加载数据: {data_file}")
    samples = load_jsonl_data(data_file)
    print(f"   总样本数: {len(samples)}")

    # 平衡采样
    if balanced:
        random.seed(seed)
        benign = [s for s in samples if int(s.get("target", 0)) == 0]
        vuls = [s for s in samples if int(s.get("target", 0)) == 1]
        n = min(len(benign), len(vuls))
        samples = random.sample(benign, n) + random.sample(vuls, n)
        random.shuffle(samples)
        print(f"   平衡采样后: {len(samples)}")

    if max_samples:
        samples = samples[:max_samples]
        print(f"   评估样本数: {len(samples)}")

    # 统计分布
    cwe_counts = defaultdict(int)
    major_counts = defaultdict(int)
    for item in samples:
        cwe, middle, major = get_ground_truth(item)
        cwe_counts[cwe] += 1
        major_counts[major] += 1

    print("\n📊 Major 分布:")
    for cat, count in sorted(major_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"   {cat:12s}: {count:5d}")

    print("\n📊 Top 10 CWE 分布:")
    for cwe, count in sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"   {cwe:12s}: {count:5d}")

    # 创建评估任务
    eval_tasks = [(item, get_ground_truth(item)) for item in samples]

    print(f"\n🚀 启动并发评估 (workers={max_workers})")

    start_time = time.time()
    results = []

    # 并发评估
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        def evaluate_with_detector(args):
            item, expected = args
            llm_client = create_llm_client()
            detector = MulVulDetector.create_default(
                llm_client,
                retriever=retriever,
                max_agents=max_agents,
                parallel=False,
                adaptive=adaptive_agents,
            )
            return evaluate_single_sample(item, detector, expected)

        futures = {
            executor.submit(evaluate_with_detector, task): task
            for task in eval_tasks
        }

        with tqdm(total=len(eval_tasks), desc="CWE 评估", unit="样本") as pbar:
            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    tqdm.write(f"❌ 评估失败: {e}")
                pbar.update(1)

    elapsed = time.time() - start_time

    # 计算指标
    total = len(results)
    routing_correct = sum(1 for r in results if r["routing_correct"])
    major_correct = sum(1 for r in results if r["major_correct"])
    cwe_correct = sum(1 for r in results if r["cwe_correct"])

    # 分 CWE 统计
    cwe_stats = defaultdict(lambda: {"total": 0, "correct": 0})
    for r in results:
        cwe = r["expected_cwe"]
        cwe_stats[cwe]["total"] += 1
        if r["cwe_correct"]:
            cwe_stats[cwe]["correct"] += 1

    # 打印结果
    print("\n" + "=" * 70)
    print("📊 CWE 级别评估结果")
    print("=" * 70)

    print(f"\n🔀 Router (Recall@{max_agents}): {routing_correct/total:.2%} ({routing_correct}/{total})")
    print(f"🎯 Major Accuracy: {major_correct/total:.2%} ({major_correct}/{total})")
    print(f"🎯 CWE Accuracy: {cwe_correct/total:.2%} ({cwe_correct}/{total})")

    print(f"\n⏱️  耗时: {elapsed:.1f}秒, 吞吐量: {total/elapsed:.1f} 样本/秒")

    # Top CWE 准确率
    print("\n📈 Top 10 CWE 准确率:")
    sorted_cwe_stats = sorted(cwe_stats.items(), key=lambda x: x[1]["total"], reverse=True)
    for cwe, stats in sorted_cwe_stats[:10]:
        if stats["total"] > 0:
            acc = stats["correct"] / stats["total"]
            print(f"   {cwe:12s}: {acc:6.2%} ({stats['correct']}/{stats['total']})")

    # 保存结果
    os.makedirs(output_dir, exist_ok=True)
    summary = {
        "timestamp": datetime.now().isoformat(),
        "data_file": data_file,
        "k": max_agents,
        "max_agents": max_agents,
        "adaptive_agents": adaptive_agents,
        "total_samples": total,
        "elapsed_seconds": elapsed,
        "routing_recall_k": routing_correct / total,
        "major_accuracy": major_correct / total,
        "cwe_accuracy": cwe_correct / total,
        "cwe_stats": {k: dict(v) for k, v in cwe_stats.items()},
    }

    output_file = Path(output_dir) / f"mulvul_cwe_eval_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    print(f"\n💾 结果已保存: {output_file}")

    return summary


def main():
    parser = argparse.ArgumentParser(description="MulVul CWE 级别评估")
    parser.add_argument("--data", default="./data/primevul/primevul/primevul_valid.jsonl")
    parser.add_argument("--workers", type=int, default=32)
    parser.add_argument("--max-samples", type=int, default=None)
    parser.add_argument("--output", default="./outputs")
    parser.add_argument(
        "--max-agents",
        "--k",
        dest="max_agents",
        type=int,
        default=3,
        help="Adaptive routing的最大 detector agent 数",
    )
    parser.add_argument(
        "--fixed-agents",
        action="store_true",
        help="禁用自适应 routing，始终运行 max_agents 个 detector",
    )
    parser.add_argument("--balanced", action="store_true", help="Balance benign:vul = 1:1")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--kb", default="./data/knowledge_base_hierarchical.json", help="Knowledge base path")

    args = parser.parse_args()

    if not os.path.exists(args.data):
        print(f"❌ 数据文件不存在: {args.data}")
        return 1

    run_cwe_evaluation(
        args.data,
        max_workers=args.workers,
        max_samples=args.max_samples,
        output_dir=args.output,
        max_agents=args.max_agents,
        balanced=args.balanced,
        seed=args.seed,
        kb_path=args.kb,
        adaptive_agents=not args.fixed_agents,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
