#!/usr/bin/env python3
"""并发评估 Primevul 每个 CWE 类别的 LLM Prompt

按 CWE 大类并发运行检测，汇总每个类别的性能。
"""

import os
import sys
import json
import time
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any

sys.path.insert(0, "src")

from evoprompt.llm.client import create_llm_client, load_env_vars
from evoprompt.data.dataset import PrimevulDataset
from evoprompt.data.cwe_categories import CWE_MAJOR_CATEGORIES, map_cwe_to_major


def load_dataset_by_category(data_file: str) -> Dict[str, List[Dict]]:
    """按 CWE 大类加载数据集"""
    print(f"📂 加载数据: {data_file}")

    dataset = PrimevulDataset(data_file, "eval")
    samples = dataset.get_samples()

    # 按类别分组
    category_samples: Dict[str, List] = {cat: [] for cat in CWE_MAJOR_CATEGORIES}
    category_samples["Benign"] = []

    for sample in samples:
        target = int(sample.target)
        cwe_codes = sample.metadata.get("cwe", [])

        if target == 0:
            category_samples["Benign"].append(sample)
        else:
            category = map_cwe_to_major(cwe_codes) if cwe_codes else "Other"
            if category in category_samples:
                category_samples[category].append(sample)
            else:
                category_samples["Other"].append(sample)

    # 打印统计
    print("\n📊 数据分布:")
    for cat, samples_list in category_samples.items():
        if samples_list:
            print(f"   {cat}: {len(samples_list)} 样本")

    return category_samples


def evaluate_category(
    category: str,
    samples: List,
    prompt: str,
    llm_client,
    max_samples: int = None
) -> Dict[str, Any]:
    """评估单个类别"""
    if not samples:
        return {"category": category, "total": 0, "correct": 0, "accuracy": 0.0}

    # 限制样本数
    eval_samples = samples[:max_samples] if max_samples else samples

    correct = 0
    results = []

    for sample in eval_samples:
        code = sample.input_text
        ground_truth = "Benign" if int(sample.target) == 0 else category

        # 构建查询
        query = prompt.replace("{input}", code)

        try:
            response = llm_client.generate(query, temperature=0.1, max_tokens=50)
            response_lower = response.lower()

            # 判断预测结果
            if category == "Benign":
                is_correct = "benign" in response_lower or "safe" in response_lower
            else:
                # 检查是否预测为该类别
                is_correct = category.lower() in response_lower or (
                    "vulnerable" in response_lower and category != "Benign"
                )

            if is_correct:
                correct += 1

            results.append({
                "ground_truth": ground_truth,
                "prediction": response[:100],
                "correct": is_correct
            })

        except Exception as e:
            results.append({
                "ground_truth": ground_truth,
                "prediction": f"ERROR: {e}",
                "correct": False
            })

    accuracy = correct / len(eval_samples) if eval_samples else 0

    return {
        "category": category,
        "total": len(eval_samples),
        "correct": correct,
        "accuracy": accuracy,
        "sample_results": results[:5]  # 只保留前5个示例
    }


def run_concurrent_evaluation(
    category_samples: Dict[str, List],
    prompt: str,
    max_workers: int = 8,
    max_samples_per_category: int = 50
) -> Dict[str, Any]:
    """并发评估所有类别"""

    load_env_vars()

    print(f"\n🚀 启动并发评估 (workers={max_workers}, max_samples={max_samples_per_category})")
    print(f"📝 使用 Prompt:\n{prompt[:200]}...")

    results = {}
    start_time = time.time()

    # 为每个类别创建独立的 LLM 客户端
    def eval_task(category: str, samples: List):
        client = create_llm_client()
        return evaluate_category(
            category, samples, prompt, client, max_samples_per_category
        )

    # 并发执行
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {}

        for category, samples in category_samples.items():
            if samples:  # 只处理有样本的类别
                future = executor.submit(eval_task, category, samples)
                futures[future] = category

        # 收集结果
        for future in as_completed(futures):
            category = futures[future]
            try:
                result = future.result()
                results[category] = result
                print(f"   ✅ {category}: {result['accuracy']:.2%} ({result['correct']}/{result['total']})")
            except Exception as e:
                print(f"   ❌ {category}: 失败 - {e}")
                results[category] = {"category": category, "error": str(e)}

    elapsed = time.time() - start_time

    # 汇总统计
    total_samples = sum(r.get("total", 0) for r in results.values())
    total_correct = sum(r.get("correct", 0) for r in results.values())
    overall_accuracy = total_correct / total_samples if total_samples > 0 else 0

    summary = {
        "timestamp": datetime.now().isoformat(),
        "elapsed_seconds": elapsed,
        "total_samples": total_samples,
        "total_correct": total_correct,
        "overall_accuracy": overall_accuracy,
        "category_results": results,
        "prompt_used": prompt
    }

    return summary


def main():
    """主函数"""
    print("=" * 60)
    print("🔥 Primevul 并发 CWE 类别评估")
    print("=" * 60)

    # 配置
    DATA_FILE = "./data/primevul_1percent_sample/dev.txt"
    MAX_WORKERS = 8  # 并发线程数
    MAX_SAMPLES_PER_CATEGORY = 30  # 每类最大样本数

    # 默认 prompt (可以替换为你的 prompt)
    DEFAULT_PROMPT = """You are a security expert. Analyze this code and classify it into one of these CWE major categories:
- Buffer Errors: buffer overflow, out-of-bounds access
- Injection: SQL injection, command injection, XSS
- Memory Management: use-after-free, double-free, memory leak
- Pointer Dereference: null pointer, invalid pointer
- Integer Errors: integer overflow/underflow
- Concurrency Issues: race conditions
- Path Traversal: directory traversal
- Cryptography Issues: weak crypto
- Information Exposure: data leaks
- Other: other security issues
- Benign: no vulnerabilities

Code:
{input}

Category:"""

    # 检查数据文件
    if not os.path.exists(DATA_FILE):
        print(f"❌ 数据文件不存在: {DATA_FILE}")
        print("请先运行采样脚本生成数据")
        return 1

    # 加载数据
    category_samples = load_dataset_by_category(DATA_FILE)

    # 运行并发评估
    results = run_concurrent_evaluation(
        category_samples,
        DEFAULT_PROMPT,
        max_workers=MAX_WORKERS,
        max_samples_per_category=MAX_SAMPLES_PER_CATEGORY
    )

    # 打印结果
    print("\n" + "=" * 60)
    print("📊 评估结果汇总")
    print("=" * 60)
    print(f"总样本数: {results['total_samples']}")
    print(f"正确数: {results['total_correct']}")
    print(f"总体准确率: {results['overall_accuracy']:.2%}")
    print(f"耗时: {results['elapsed_seconds']:.1f}秒")

    print("\n📈 各类别准确率:")
    for cat, res in sorted(results['category_results'].items(),
                           key=lambda x: x[1].get('accuracy', 0), reverse=True):
        if 'accuracy' in res:
            print(f"   {cat:25s}: {res['accuracy']:6.2%} ({res['correct']:3d}/{res['total']:3d})")

    # 保存结果
    output_file = f"./outputs/category_eval_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    os.makedirs("./outputs", exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\n💾 结果已保存: {output_file}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
