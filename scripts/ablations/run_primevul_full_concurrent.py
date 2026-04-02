#!/usr/bin/env python3
"""并发全量评估 Primevul 每个 CWE 类别

支持:
- 全量 JSONL 数据
- 自定义 prompt
- 并发加速
- 详细结果输出
"""

import os
import sys
import json
import time
import argparse
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any, Optional

sys.path.insert(0, "src")

from evoprompt.llm.client import create_llm_client, load_env_vars
from evoprompt.data.cwe_categories import CWE_MAJOR_CATEGORIES, map_cwe_to_major, canonicalize_category


def load_jsonl_by_category(data_file: str) -> Dict[str, List[Dict]]:
    """从 JSONL 文件按 CWE 大类加载数据"""
    print(f"📂 加载 JSONL 数据: {data_file}")

    category_samples: Dict[str, List[Dict]] = {cat: [] for cat in CWE_MAJOR_CATEGORIES}
    category_samples["Benign"] = []

    total = 0
    with open(data_file, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                item = json.loads(line)
                total += 1

                target = int(item.get("target", 0))
                cwe_codes = item.get("cwe", [])
                if isinstance(cwe_codes, str):
                    cwe_codes = [cwe_codes] if cwe_codes else []

                if target == 0:
                    category_samples["Benign"].append(item)
                else:
                    category = map_cwe_to_major(cwe_codes) if cwe_codes else "Other"
                    if category in category_samples:
                        category_samples[category].append(item)
                    else:
                        category_samples["Other"].append(item)

            except json.JSONDecodeError:
                continue

    print(f"   总样本数: {total}")
    return category_samples


def evaluate_single_sample(sample, prompt: str, llm_client, expected_category: str) -> Dict:
    """评估单个样本"""
    code = sample.input_text
    query = prompt.replace("{input}", code)

    try:
        response = llm_client.generate(query, temperature=0.1, max_tokens=50)

        # 规范化预测结果
        predicted = canonicalize_category(response)
        if predicted is None:
            if any(w in response.lower() for w in ["vulnerable", "vuln", "exploit"]):
                predicted = "Other"
            else:
                predicted = "Benign"

        is_correct = predicted == expected_category

        return {
            "expected": expected_category,
            "predicted": predicted,
            "raw_response": response[:100],
            "correct": is_correct,
            "error": None
        }
    except Exception as e:
        return {
            "expected": expected_category,
            "predicted": None,
            "raw_response": None,
            "correct": False,
            "error": str(e)
        }


def evaluate_category_batch(
    category: str,
    samples: List[Dict],
    prompt: str,
    max_samples: Optional[int] = None,
    batch_size: int = 10
) -> Dict[str, Any]:
    """批量评估单个类别 (支持 dict 格式样本)"""
    if not samples:
        return {"category": category, "total": 0, "correct": 0, "accuracy": 0.0, "results": []}

    eval_samples = samples[:max_samples] if max_samples else samples
    llm_client = create_llm_client()

    results = []
    correct = 0

    # 批量处理
    for i in range(0, len(eval_samples), batch_size):
        batch = eval_samples[i:i + batch_size]
        # 支持 dict 格式: 使用 "func" 字段
        queries = [prompt.replace("{input}", s.get("func", "")) for s in batch]

        try:
            responses = llm_client.batch_generate(
                queries, temperature=0.1, max_tokens=50, batch_size=batch_size
            )

            for sample, response in zip(batch, responses):
                predicted = canonicalize_category(response) if response != "error" else None
                if predicted is None:
                    if response and any(w in response.lower() for w in ["vulnerable", "vuln"]):
                        predicted = "Other"
                    else:
                        predicted = "Benign"

                is_correct = predicted == category
                if is_correct:
                    correct += 1

                results.append({
                    "expected": category,
                    "predicted": predicted,
                    "correct": is_correct
                })

        except Exception as e:
            # 回退到单个处理
            for sample in batch:
                code = sample.get("func", "")
                query = prompt.replace("{input}", code)
                try:
                    response = llm_client.generate(query, temperature=0.1, max_tokens=50)
                    predicted = canonicalize_category(response)
                    if predicted is None:
                        predicted = "Benign"
                    is_correct = predicted == category
                    if is_correct:
                        correct += 1
                    results.append({"expected": category, "predicted": predicted, "correct": is_correct})
                except:
                    results.append({"expected": category, "predicted": None, "correct": False})

    accuracy = correct / len(eval_samples) if eval_samples else 0

    return {
        "category": category,
        "total": len(eval_samples),
        "correct": correct,
        "accuracy": accuracy,
        "results": results
    }


def run_full_concurrent_evaluation(
    data_file: str,
    prompt: str,
    max_workers: int = 8,
    max_samples_per_category: Optional[int] = None,
    output_dir: str = "./outputs"
) -> Dict[str, Any]:
    """并发全量评估"""

    load_env_vars()

    print("=" * 70)
    print("🔥 Primevul 并发全量 CWE 类别评估")
    print("=" * 70)

    # 加载数据
    category_samples = load_jsonl_by_category(data_file)

    total_samples = sum(len(s) for s in category_samples.values())
    print(f"   总样本数: {total_samples}")

    print("\n📊 数据分布:")
    for cat, samples in sorted(category_samples.items(), key=lambda x: len(x[1]), reverse=True):
        if samples:
            print(f"   {cat:25s}: {len(samples):5d} 样本")

    # 并发评估
    print(f"\n🚀 启动并发评估 (workers={max_workers})")
    if max_samples_per_category:
        print(f"   每类最大样本: {max_samples_per_category}")

    start_time = time.time()
    results = {}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {}

        for category, samples in category_samples.items():
            if samples:
                future = executor.submit(
                    evaluate_category_batch,
                    category, samples, prompt, max_samples_per_category
                )
                futures[future] = category

        for future in as_completed(futures):
            category = futures[future]
            try:
                result = future.result()
                results[category] = result
                print(f"   ✅ {category:25s}: {result['accuracy']:6.2%} ({result['correct']:4d}/{result['total']:4d})")
            except Exception as e:
                print(f"   ❌ {category:25s}: 失败 - {e}")
                results[category] = {"category": category, "error": str(e)}

    elapsed = time.time() - start_time

    # 汇总
    total_evaluated = sum(r.get("total", 0) for r in results.values())
    total_correct = sum(r.get("correct", 0) for r in results.values())
    overall_accuracy = total_correct / total_evaluated if total_evaluated > 0 else 0

    # 计算 Macro-F1 (简化版)
    category_accuracies = [r.get("accuracy", 0) for r in results.values() if r.get("total", 0) > 0]
    macro_accuracy = sum(category_accuracies) / len(category_accuracies) if category_accuracies else 0

    summary = {
        "timestamp": datetime.now().isoformat(),
        "data_file": data_file,
        "elapsed_seconds": elapsed,
        "total_samples": total_evaluated,
        "total_correct": total_correct,
        "overall_accuracy": overall_accuracy,
        "macro_accuracy": macro_accuracy,
        "num_categories": len([r for r in results.values() if r.get("total", 0) > 0]),
        "category_results": {k: {kk: vv for kk, vv in v.items() if kk != "results"}
                            for k, v in results.items()},
        "prompt_used": prompt
    }

    # 打印结果
    print("\n" + "=" * 70)
    print("📊 评估结果汇总")
    print("=" * 70)
    print(f"总样本数: {total_evaluated}")
    print(f"正确数: {total_correct}")
    print(f"总体准确率 (Micro): {overall_accuracy:.2%}")
    print(f"宏平均准确率 (Macro): {macro_accuracy:.2%}")
    print(f"耗时: {elapsed:.1f}秒")
    print(f"吞吐量: {total_evaluated / elapsed:.1f} 样本/秒")

    print("\n📈 各类别准确率 (按准确率排序):")
    for cat, res in sorted(results.items(), key=lambda x: x[1].get('accuracy', 0), reverse=True):
        if res.get('total', 0) > 0:
            print(f"   {cat:25s}: {res['accuracy']:6.2%} ({res['correct']:4d}/{res['total']:4d})")

    # 保存结果
    os.makedirs(output_dir, exist_ok=True)
    output_file = Path(output_dir) / f"category_eval_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    print(f"\n💾 结果已保存: {output_file}")

    return summary


def main():
    parser = argparse.ArgumentParser(description="并发评估 Primevul CWE 类别")
    parser.add_argument("--data", default="./data/primevul/primevul/primevul_valid.jsonl", help="JSONL 数据文件路径")
    parser.add_argument("--prompt-file", help="Prompt 文件路径 (包含 {input} 占位符)")
    parser.add_argument("--workers", type=int, default=8, help="并发线程数")
    parser.add_argument("--max-samples", type=int, default=None, help="每类最大样本数 (None=全量)")
    parser.add_argument("--output", default="./outputs", help="输出目录")

    args = parser.parse_args()

    # 加载 prompt
    if args.prompt_file and os.path.exists(args.prompt_file):
        with open(args.prompt_file, "r", encoding="utf-8") as f:
            prompt = f.read()
        print(f"📝 从文件加载 Prompt: {args.prompt_file}")
    else:
        prompt = """Analyze this code for security vulnerabilities. Classify into one of these CWE major categories:
- Buffer Errors, Injection, Memory Management, Pointer Dereference, Integer Errors
- Concurrency Issues, Path Traversal, Cryptography Issues, Information Exposure, Other
- Benign (no vulnerabilities)

Code:
{input}

Category:"""

    # 检查数据文件
    if not os.path.exists(args.data):
        print(f"❌ 数据文件不存在: {args.data}")
        return 1

    # 运行评估
    run_full_concurrent_evaluation(
        args.data,
        prompt,
        max_workers=args.workers,
        max_samples_per_category=args.max_samples,
        output_dir=args.output
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
