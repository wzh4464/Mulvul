#!/usr/bin/env python3
"""并发全量评估三层检测器

支持:
- 全量 Primevul JSONL 数据
- 并发加速 + 进度条
- 三层检测 (Major → Middle → CWE)
- 1:1:1 平衡采样 (vul/other_vul/benign)
- 上级分类统计
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
from evoprompt.prompts.hierarchical_three_layer import ThreeLayerPromptFactory
from evoprompt.detectors.three_layer_detector import ThreeLayerDetector
from evoprompt.data.cwe_categories import CWE_MAJOR_CATEGORIES, map_cwe_to_major

# 上级分类映射
CATEGORY_TO_MAJOR = {
    "Buffer Errors": "Memory",
    "Memory Management": "Memory",
    "Pointer Dereference": "Memory",
    "Integer Errors": "Memory",
    "Injection": "Injection",
    "Concurrency Issues": "Logic",
    "Path Traversal": "Input",
    "Cryptography Issues": "Crypto",
    "Information Exposure": "Logic",
    "Other": "Logic",
    "Benign": "Benign",
}


def load_jsonl_data(data_file: str) -> List[Dict]:
    """加载 JSONL 数据"""
    samples = []
    with open(data_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                try:
                    samples.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return samples


def get_ground_truth_category(item: Dict) -> Tuple[str, bool]:
    """获取样本的真实类别"""
    target = int(item.get("target", 0))
    if target == 0:
        return "Benign", False

    cwe_codes = item.get("cwe", [])
    if isinstance(cwe_codes, str):
        cwe_codes = [cwe_codes] if cwe_codes else []

    category = map_cwe_to_major(cwe_codes) if cwe_codes else "Other"
    return category, True


def get_sample_id(item: Dict) -> str:
    """获取样本唯一ID"""
    if "idx" in item:
        return str(item["idx"])
    return str(hash(item.get("func", "")[:200]))


def balanced_sample(
    category_samples: Dict[str, List[Dict]],
    target_category: str,
    n_per_type: int
) -> List[Tuple[Dict, str]]:
    """1:1:1 平衡采样: target_vul / other_vul / benign"""
    result = []

    # 1. Target category samples
    target_samples = category_samples.get(target_category, [])
    sampled = random.sample(target_samples, min(n_per_type, len(target_samples)))
    result.extend([(s, target_category) for s in sampled])

    # 2. Other vulnerable samples
    other_vul = []
    for cat, samples in category_samples.items():
        if cat != target_category and cat != "Benign":
            other_vul.extend([(s, cat) for s in samples])
    if other_vul:
        sampled = random.sample(other_vul, min(n_per_type, len(other_vul)))
        result.extend(sampled)

    # 3. Benign samples
    benign = category_samples.get("Benign", [])
    sampled = random.sample(benign, min(n_per_type, len(benign)))
    result.extend([(s, "Benign") for s in sampled])

    random.shuffle(result)
    return result


def evaluate_single_sample(
    item: Dict,
    prompt_set,
    expected_category: str,
    use_scale: bool = False
) -> Dict:
    """评估单个样本"""
    llm_client = create_llm_client()
    detector = ThreeLayerDetector(
        prompt_set=prompt_set,
        llm_client=llm_client,
        use_scale_enhancement=use_scale
    )

    code = item.get("func", "")
    expected_major = CATEGORY_TO_MAJOR.get(expected_category, "Logic")

    try:
        _, details = detector.detect(code, return_intermediate=True)

        layer1_pred = details.get("layer1", "Unknown")
        layer2_pred = details.get("layer2", "Unknown")
        layer3_pred = details.get("layer3", "Unknown")

        layer1_correct = layer1_pred == expected_major

        return {
            "expected_category": expected_category,
            "expected_major": expected_major,
            "layer1_pred": layer1_pred,
            "layer2_pred": layer2_pred,
            "layer3_pred": layer3_pred,
            "layer1_correct": layer1_correct,
            "error": None
        }

    except Exception as e:
        return {
            "expected_category": expected_category,
            "expected_major": expected_major,
            "layer1_pred": None,
            "layer2_pred": None,
            "layer3_pred": None,
            "layer1_correct": False,
            "error": str(e)
        }


def load_checkpoint(checkpoint_file: str) -> Dict[str, Dict]:
    """加载检查点"""
    completed = {}
    if os.path.exists(checkpoint_file):
        with open(checkpoint_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        record = json.loads(line)
                        completed[record["sample_id"]] = record
                    except Exception:
                        continue
    return completed


def save_checkpoint(checkpoint_file: str, sample_id: str, result: Dict):
    """追加保存检查点"""
    record = {"sample_id": sample_id, **result}
    with open(checkpoint_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def run_concurrent_evaluation(
    data_file: str,
    max_workers: int = 64,
    max_samples_per_category: Optional[int] = None,
    output_dir: str = "./outputs",
    use_scale: bool = False,
    resume: bool = False,
    balanced: bool = False,
    n_per_type: int = 100
) -> Dict[str, Any]:
    """并发全量评估"""

    load_env_vars()

    print("=" * 70)
    print("🔥 三层检测器并发全量评估")
    if use_scale:
        print("   📊 SCALE Enhancement: ENABLED")
    if balanced:
        print(f"   ⚖️  Balanced Sampling: {n_per_type} per type (1:1:1)")
    print("=" * 70)

    # 检查点
    os.makedirs(output_dir, exist_ok=True)
    checkpoint_file = Path(output_dir) / "eval_checkpoint.jsonl"

    completed_ids = set()
    completed_results = {}
    if resume and checkpoint_file.exists():
        completed_results = load_checkpoint(str(checkpoint_file))
        completed_ids = set(completed_results.keys())
        print(f"   🔄 Resume: 已加载 {len(completed_ids)} 个已完成样本")
    elif not resume and checkpoint_file.exists():
        checkpoint_file.unlink()
        print("   🗑️  清空旧检查点")

    # 加载数据
    print(f"\n📂 加载数据: {data_file}")
    samples = load_jsonl_data(data_file)
    print(f"   总样本数: {len(samples)}")

    # 按类别分组
    category_samples: Dict[str, List[Dict]] = defaultdict(list)
    for item in samples:
        category, _ = get_ground_truth_category(item)
        category_samples[category].append(item)

    print("\n📊 数据分布:")
    for cat, cat_samples in sorted(category_samples.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"   {cat:25s}: {len(cat_samples):5d} 样本")

    # 创建 prompt set
    prompt_set = ThreeLayerPromptFactory.create_default_prompt_set()

    # 准备评估任务
    eval_tasks = []
    if balanced:
        # 对每个漏洞类别做 1:1:1 采样
        for target_cat in category_samples.keys():
            if target_cat != "Benign":
                sampled = balanced_sample(category_samples, target_cat, n_per_type)
                eval_tasks.extend(sampled)
    else:
        # 全量评估
        for cat, cat_samples in category_samples.items():
            samples_to_eval = cat_samples[:max_samples_per_category] if max_samples_per_category else cat_samples
            eval_tasks.extend([(s, cat) for s in samples_to_eval])

    # 过滤已完成
    pending_tasks = [(item, cat) for item, cat in eval_tasks if get_sample_id(item) not in completed_ids]

    print(f"\n🚀 启动并发评估 (workers={max_workers})")
    print(f"   待评估: {len(pending_tasks)} / 总任务: {len(eval_tasks)}")

    # 统计结构
    major_stats = defaultdict(lambda: {"total": 0, "correct": 0})
    category_stats = defaultdict(lambda: {"total": 0, "correct": 0})

    # 加载已完成的统计
    for record in completed_results.values():
        cat = record.get("expected_category", "Unknown")
        major = record.get("expected_major", CATEGORY_TO_MAJOR.get(cat, "Logic"))
        correct = record.get("layer1_correct", False)

        category_stats[cat]["total"] += 1
        category_stats[cat]["correct"] += 1 if correct else 0
        major_stats[major]["total"] += 1
        major_stats[major]["correct"] += 1 if correct else 0

    start_time = time.time()

    # 并发评估 + 进度条
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {}
        for item, cat in pending_tasks:
            future = executor.submit(evaluate_single_sample, item, prompt_set, cat, use_scale)
            futures[future] = (item, cat)

        with tqdm(total=len(pending_tasks), desc="评估进度", unit="样本") as pbar:
            for future in as_completed(futures):
                item, cat = futures[future]
                sample_id = get_sample_id(item)

                try:
                    result = future.result()

                    # 更新统计
                    major = result.get("expected_major", "Logic")
                    correct = result.get("layer1_correct", False)

                    category_stats[cat]["total"] += 1
                    category_stats[cat]["correct"] += 1 if correct else 0
                    major_stats[major]["total"] += 1
                    major_stats[major]["correct"] += 1 if correct else 0

                    # 保存检查点
                    save_checkpoint(str(checkpoint_file), sample_id, result)

                    # 更新进度条描述
                    total_correct = sum(s["correct"] for s in major_stats.values())
                    total_eval = sum(s["total"] for s in major_stats.values())
                    acc = total_correct / total_eval if total_eval > 0 else 0
                    pbar.set_postfix({"acc": f"{acc:.1%}"})

                except Exception as e:
                    tqdm.write(f"❌ 样本 {sample_id} 失败: {e}")

                pbar.update(1)

    elapsed = time.time() - start_time

    # 汇总结果
    total_evaluated = sum(s["total"] for s in category_stats.values())
    total_correct = sum(s["correct"] for s in category_stats.values())
    overall_accuracy = total_correct / total_evaluated if total_evaluated > 0 else 0

    # 计算各类准确率
    category_accuracies = []
    for cat, stats in category_stats.items():
        if stats["total"] > 0:
            category_accuracies.append(stats["correct"] / stats["total"])
    macro_accuracy = sum(category_accuracies) / len(category_accuracies) if category_accuracies else 0

    # 打印结果
    print("\n" + "=" * 70)
    print("📊 三层检测评估结果")
    print("=" * 70)
    print(f"总样本数: {total_evaluated}")
    print(f"Layer1 正确数: {total_correct}")
    print(f"Layer1 准确率 (Micro): {overall_accuracy:.2%}")
    print(f"Layer1 宏平均准确率 (Macro): {macro_accuracy:.2%}")
    print(f"耗时: {elapsed:.1f}秒")
    if elapsed > 0:
        print(f"吞吐量: {len(pending_tasks) / elapsed:.1f} 样本/秒")

    # 上级分类统计
    print("\n📈 上级分类 (Major) 准确率:")
    for major in ["Memory", "Injection", "Input", "Crypto", "Logic", "Benign"]:
        stats = major_stats.get(major, {"total": 0, "correct": 0})
        if stats["total"] > 0:
            acc = stats["correct"] / stats["total"]
            print(f"   {major:12s}: {acc:6.2%} ({stats['correct']:4d}/{stats['total']:4d})")

    # 细分类别统计
    print("\n📈 细分类别准确率:")
    sorted_cats = sorted(category_stats.items(), key=lambda x: x[1]["correct"] / max(x[1]["total"], 1), reverse=True)
    for cat, stats in sorted_cats:
        if stats["total"] > 0:
            acc = stats["correct"] / stats["total"]
            print(f"   {cat:25s}: {acc:6.2%} ({stats['correct']:4d}/{stats['total']:4d})")

    # 保存结果
    summary = {
        "timestamp": datetime.now().isoformat(),
        "data_file": data_file,
        "use_scale": use_scale,
        "balanced": balanced,
        "elapsed_seconds": elapsed,
        "total_samples": total_evaluated,
        "total_correct": total_correct,
        "overall_accuracy": overall_accuracy,
        "macro_accuracy": macro_accuracy,
        "major_stats": {k: dict(v) for k, v in major_stats.items()},
        "category_stats": {k: dict(v) for k, v in category_stats.items()},
    }

    output_file = Path(output_dir) / f"three_layer_eval_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    print(f"\n💾 结果已保存: {output_file}")

    return summary


def main():
    parser = argparse.ArgumentParser(description="三层检测器并发评估")
    parser.add_argument("--data", default="./data/primevul/primevul/primevul_valid.jsonl", help="JSONL 数据文件")
    parser.add_argument("--workers", type=int, default=64, help="并发线程数")
    parser.add_argument("--max-samples", type=int, default=None, help="每类最大样本数")
    parser.add_argument("--output", default="./outputs", help="输出目录")
    parser.add_argument("--use-scale", action="store_true", help="启用 SCALE Enhancement")
    parser.add_argument("--resume", action="store_true", help="从检查点恢复")
    parser.add_argument("--balanced", action="store_true", help="启用 1:1:1 平衡采样")
    parser.add_argument("--n-per-type", type=int, default=100, help="平衡采样时每类样本数")

    args = parser.parse_args()

    if not os.path.exists(args.data):
        print(f"❌ 数据文件不存在: {args.data}")
        return 1

    run_concurrent_evaluation(
        args.data,
        max_workers=args.workers,
        max_samples_per_category=args.max_samples,
        output_dir=args.output,
        use_scale=args.use_scale,
        resume=args.resume,
        balanced=args.balanced,
        n_per_type=args.n_per_type
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
