#!/usr/bin/env python3
"""
测试最佳prompt在训练集上的泛化性能
"""

import os
import sys
import json
import time
from typing import List, Dict, Any
from dotenv import load_dotenv

# 添加src路径
sys.path.insert(0, "src")

from mulvul.data.cwe_categories import (
    map_cwe_to_major,
    canonicalize_category,
    CWE_MAJOR_CATEGORIES,
)
from mulvul.llm.client import create_default_client
from mulvul.llm.async_client import AsyncLLMClient
import asyncio
from mulvul.utils.text import safe_format


def load_sampling_stats(stats_file: str) -> Dict[str, Any]:
    """加载采样统计信息"""
    with open(stats_file, "r", encoding="utf-8") as f:
        return json.load(f)


def load_train_samples(train_file: str) -> List[Dict[str, Any]]:
    """加载训练样本"""
    samples = []
    with open(train_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                samples.append(json.loads(line))
    return samples


async def evaluate_prompt_on_samples_async(
    prompt: str,
    samples: List[Dict[str, Any]],
    async_client: AsyncLLMClient,
    sample_limit: int = None,
) -> Dict[str, Any]:
    """在样本上异步评估prompt性能"""
    if sample_limit:
        samples = samples[:sample_limit]

    print(f"🔍 开始异步评估 {len(samples)} 个样本...")
    print(f"🚀 使用并发客户端，最大并发数: {async_client.max_concurrency}")

    correct = 0
    total = len(samples)
    category_results = {}
    cwe_results = {}

    # 初始化类别统计
    for category in CWE_MAJOR_CATEGORIES + ["Benign"]:
        category_results[category] = {
            "total": 0,
            "correct": 0,
            "accuracy": 0.0,
            "predictions": {},
        }

    start_time = time.time()

    # 准备批量查询
    batch_queries = []
    batch_samples = []
    batch_metadata = []

    for idx, sample in enumerate(samples):
        code = sample.get("input_text", "")
        ground_truth_binary = int(sample.get("target", 0))

        # 获取CWE代码和真实类别
        cwe_codes = sample.get("metadata", {}).get("cwe", [])
        if ground_truth_binary == 1 and cwe_codes:
            ground_truth_category = map_cwe_to_major(cwe_codes)
        else:
            ground_truth_category = "Benign"

        # 构建查询
        query = safe_format(prompt, input=code)
        batch_queries.append(query)
        batch_samples.append(sample)
        batch_metadata.append(
            {
                "idx": idx,
                "ground_truth_binary": ground_truth_binary,
                "ground_truth_category": ground_truth_category,
                "cwe_codes": cwe_codes,
            }
        )

    # 分批处理，每批8个并发请求
    batch_size = 8
    total_batches = (total + batch_size - 1) // batch_size

    print(f"📦 分批处理: {total} 个样本，{total_batches} 批，每批 {batch_size} 个")

    for batch_idx in range(total_batches):
        start_idx = batch_idx * batch_size
        end_idx = min(start_idx + batch_size, total)

        print(
            f"   🔄 处理批次 {batch_idx + 1}/{total_batches} (样本 {start_idx + 1}-{end_idx})"
        )

        # 获取当前批次的查询
        current_queries = batch_queries[start_idx:end_idx]
        current_samples = batch_samples[start_idx:end_idx]
        current_metadata = batch_metadata[start_idx:end_idx]

        try:
            # 并发调用LLM
            prediction_texts = await async_client.batch_generate_async(
                current_queries, temperature=0.1, max_tokens=50
            )

            # 处理当前批次的结果
            for i, (sample, metadata, prediction_text) in enumerate(
                zip(current_samples, current_metadata, prediction_texts)
            ):
                if prediction_text == "error":
                    print(f"     ⚠️ 样本 {metadata['idx'] + 1} 预测失败")
                    continue

                # 规范化预测结果
                predicted_category = canonicalize_category(prediction_text)
                if predicted_category is None:
                    if any(
                        word in prediction_text.lower()
                        for word in ["vulnerable", "vulnerability", "vuln", "exploit"]
                    ):
                        predicted_category = "Other"
                    else:
                        predicted_category = "Benign"

                # 判断是否正确
                is_correct = predicted_category == metadata["ground_truth_category"]
                if is_correct:
                    correct += 1

                # 更新类别统计
                ground_truth_category = metadata["ground_truth_category"]
                if ground_truth_category not in category_results:
                    category_results[ground_truth_category] = {
                        "total": 0,
                        "correct": 0,
                        "accuracy": 0.0,
                        "predictions": {},
                    }

                cat_stats = category_results[ground_truth_category]
                cat_stats["total"] += 1
                if is_correct:
                    cat_stats["correct"] += 1

                # 记录预测分布
                if predicted_category not in cat_stats["predictions"]:
                    cat_stats["predictions"][predicted_category] = 0
                cat_stats["predictions"][predicted_category] += 1

                # 更新CWE统计
                for cwe in metadata["cwe_codes"]:
                    if cwe not in cwe_results:
                        cwe_results[cwe] = {"total": 0, "correct": 0, "accuracy": 0.0}
                    cwe_results[cwe]["total"] += 1
                    if is_correct:
                        cwe_results[cwe]["correct"] += 1

                # 显示一些错误案例
                if not is_correct and metadata["idx"] < 100:  # 只显示前100个错误案例
                    print(f"     ❌ 样本 {metadata['idx'] + 1} 预测错误:")
                    print(
                        f"        真实: {ground_truth_category} | 预测: {predicted_category}"
                    )
                    print(f"        CWE: {metadata['cwe_codes']}")
                    print(f"        代码片段: {sample.get('input_text', '')[:100]}...")
                    print(f"        LLM输出: {prediction_text}")
                    print()

            # 显示批次进度
            processed_samples = (batch_idx + 1) * batch_size
            if processed_samples > total:
                processed_samples = total

            elapsed = time.time() - start_time
            avg_time = elapsed / processed_samples
            remaining = (total - processed_samples) * avg_time

            print(
                f"     📊 批次完成: {processed_samples}/{total} ({processed_samples/total*100:.1f}%) "
                f"| 已用: {elapsed:.1f}s | 预计剩余: {remaining:.1f}s"
            )

        except Exception as e:
            print(f"     ❌ 批次 {batch_idx + 1} 处理失败: {e}")
            # 继续处理下一批
            continue

    # 计算最终统计
    total_time = time.time() - start_time
    overall_accuracy = correct / total if total > 0 else 0

    # 计算各类别准确率
    for category in category_results:
        cat_stats = category_results[category]
        if cat_stats["total"] > 0:
            cat_stats["accuracy"] = cat_stats["correct"] / cat_stats["total"]

    # 计算CWE准确率
    for cwe in cwe_results:
        cwe_stats = cwe_results[cwe]
        if cwe_stats["total"] > 0:
            cwe_stats["accuracy"] = cwe_stats["correct"] / cwe_stats["total"]

    return {
        "overall_accuracy": overall_accuracy,
        "correct_predictions": correct,
        "total_samples": total,
        "evaluation_time": total_time,
        "avg_time_per_sample": total_time / total if total > 0 else 0,
        "category_results": category_results,
        "cwe_results": cwe_results,
        "category_summary": {
            "best_categories": sorted(
                [
                    (cat, stats)
                    for cat, stats in category_results.items()
                    if stats["total"] > 0
                ],
                key=lambda x: x[1]["accuracy"],
                reverse=True,
            )[:5],
            "worst_categories": sorted(
                [
                    (cat, stats)
                    for cat, stats in category_results.items()
                    if stats["total"] > 0
                ],
                key=lambda x: x[1]["accuracy"],
            )[:5],
            "most_common_categories": sorted(
                [
                    (cat, stats)
                    for cat, stats in category_results.items()
                    if stats["total"] > 0
                ],
                key=lambda x: x[1]["total"],
                reverse=True,
            )[:5],
        },
        "cwe_summary": {
            "best_cwes": sorted(
                [
                    (cwe, stats)
                    for cwe, stats in cwe_results.items()
                    if stats["total"] > 0
                ],
                key=lambda x: x[1]["accuracy"],
                reverse=True,
            )[:10],
            "worst_cwes": sorted(
                [
                    (cwe, stats)
                    for cwe, stats in cwe_results.items()
                    if stats["total"] > 0
                ],
                key=lambda x: x[1]["accuracy"],
            )[:10],
        },
    }


def evaluate_prompt_on_samples(
    prompt: str, samples: List[Dict[str, Any]], llm_client, sample_limit: int = None
) -> Dict[str, Any]:
    """在样本上评估prompt性能（同步版本，保持兼容性）"""
    if sample_limit:
        samples = samples[:sample_limit]

    print(f"🔍 开始评估 {len(samples)} 个样本...")

    correct = 0
    total = len(samples)
    category_results = {}
    cwe_results = {}

    # 初始化类别统计
    for category in CWE_MAJOR_CATEGORIES + ["Benign"]:
        category_results[category] = {
            "total": 0,
            "correct": 0,
            "accuracy": 0.0,
            "predictions": {},
        }

    start_time = time.time()

    for idx, sample in enumerate(samples):
        try:
            # 获取样本信息
            code = sample.get("input_text", "")
            ground_truth_binary = int(sample.get("target", 0))

            # 获取CWE代码和真实类别
            cwe_codes = sample.get("metadata", {}).get("cwe", [])
            if ground_truth_binary == 1 and cwe_codes:
                ground_truth_category = map_cwe_to_major(cwe_codes)
            else:
                ground_truth_category = "Benign"

            # 构建查询
            query = safe_format(prompt, input=code)

            # 调用LLM
            prediction_text = llm_client.generate(query, temperature=0.1, max_tokens=50)

            # 规范化预测结果
            predicted_category = canonicalize_category(prediction_text)
            if predicted_category is None:
                if any(
                    word in prediction_text.lower()
                    for word in ["vulnerable", "vulnerability", "vuln", "exploit"]
                ):
                    predicted_category = "Other"
                else:
                    predicted_category = "Benign"

            # 判断是否正确
            is_correct = predicted_category == ground_truth_category
            if is_correct:
                correct += 1

            # 更新类别统计
            if ground_truth_category not in category_results:
                category_results[ground_truth_category] = {
                    "total": 0,
                    "correct": 0,
                    "accuracy": 0.0,
                    "predictions": {},
                }

            cat_stats = category_results[ground_truth_category]
            cat_stats["total"] += 1
            if is_correct:
                cat_stats["correct"] += 1

            # 记录预测分布
            if predicted_category not in cat_stats["predictions"]:
                cat_stats["predictions"][predicted_category] = 0
            cat_stats["predictions"][predicted_category] += 1

            # 更新CWE统计
            for cwe in cwe_codes:
                if cwe not in cwe_results:
                    cwe_results[cwe] = {"total": 0, "correct": 0, "accuracy": 0.0}
                cwe_results[cwe]["total"] += 1
                if is_correct:
                    cwe_results[cwe]["correct"] += 1

            # 显示进度
            if (idx + 1) % 20 == 0:
                elapsed = time.time() - start_time
                avg_time = elapsed / (idx + 1)
                remaining = (total - idx - 1) * avg_time
                print(
                    f"   📊 进度: {idx + 1}/{total} ({((idx + 1)/total)*100:.1f}%) "
                    f"| 已用: {elapsed:.1f}s | 预计剩余: {remaining:.1f}s"
                )

            # 显示一些错误案例
            if not is_correct and idx < 100:  # 只显示前100个错误案例
                print(f"   ❌ 样本 {idx + 1} 预测错误:")
                print(
                    f"      真实: {ground_truth_category} | 预测: {predicted_category}"
                )
                print(f"      CWE: {cwe_codes}")
                print(f"      代码片段: {code[:100]}...")
                print(f"      LLM输出: {prediction_text}")
                print()

        except Exception as e:
            print(f"   ⚠️ 样本 {idx + 1} 处理失败: {e}")
            continue

    # 计算最终统计
    total_time = time.time() - start_time
    overall_accuracy = correct / total if total > 0 else 0

    # 计算各类别准确率
    for category in category_results:
        cat_stats = category_results[category]
        if cat_stats["total"] > 0:
            cat_stats["accuracy"] = cat_stats["correct"] / cat_stats["total"]

    # 计算CWE准确率
    for cwe in cwe_results:
        cwe_stats = cwe_results[cwe]
        if cwe_stats["total"] > 0:
            cwe_stats["accuracy"] = cwe_stats["correct"] / cwe_stats["total"]

    return {
        "overall_accuracy": overall_accuracy,
        "correct_predictions": correct,
        "total_samples": total,
        "evaluation_time": total_time,
        "avg_time_per_sample": total_time / total if total > 0 else 0,
        "category_results": category_results,
        "cwe_results": cwe_results,
        "category_summary": {
            "best_categories": sorted(
                [
                    (cat, stats)
                    for cat, stats in category_results.items()
                    if stats["total"] > 0
                ],
                key=lambda x: x[1]["accuracy"],
                reverse=True,
            )[:5],
            "worst_categories": sorted(
                [
                    (cat, stats)
                    for cat, stats in category_results.items()
                    if stats["total"] > 0
                ],
                key=lambda x: x[1]["accuracy"],
            )[:5],
            "most_common_categories": sorted(
                [
                    (cat, stats)
                    for cat, stats in category_results.items()
                    if stats["total"] > 0
                ],
                key=lambda x: x[1]["total"],
                reverse=True,
            )[:5],
        },
        "cwe_summary": {
            "best_cwes": sorted(
                [
                    (cwe, stats)
                    for cwe, stats in cwe_results.items()
                    if stats["total"] > 0
                ],
                key=lambda x: x[1]["accuracy"],
                reverse=True,
            )[:10],
            "worst_cwes": sorted(
                [
                    (cwe, stats)
                    for cwe, stats in cwe_results.items()
                    if stats["total"] > 0
                ],
                key=lambda x: x[1]["accuracy"],
            )[:10],
        },
    }

    # 计算最终统计
    total_time = time.time() - start_time
    overall_accuracy = correct / total if total > 0 else 0

    # 计算各类别准确率
    for category in category_results:
        cat_stats = category_results[category]
        if cat_stats["total"] > 0:
            cat_stats["accuracy"] = cat_stats["correct"] / cat_stats["total"]

    # 计算CWE准确率
    for cwe in cwe_results:
        cwe_stats = cwe_results[cwe]
        if cwe_stats["total"] > 0:
            cwe_stats["accuracy"] = cwe_stats["correct"] / cwe_stats["total"]

    return {
        "overall_accuracy": overall_accuracy,
        "correct_predictions": correct,
        "total_samples": total,
        "evaluation_time": total_time,
        "avg_time_per_sample": total_time / total if total > 0 else 0,
        "category_results": category_results,
        "cwe_results": cwe_results,
        "category_summary": {
            "best_categories": sorted(
                [
                    (cat, stats)
                    for cat, stats in category_results.items()
                    if stats["total"] > 0
                ],
                key=lambda x: x[1]["accuracy"],
                reverse=True,
            )[:5],
            "worst_categories": sorted(
                [
                    (cat, stats)
                    for cat, stats in category_results.items()
                    if stats["total"] > 0
                ],
                key=lambda x: x[1]["accuracy"],
            )[:5],
            "most_common_categories": sorted(
                [
                    (cat, stats)
                    for cat, stats in category_results.items()
                    if stats["total"] > 0
                ],
                key=lambda x: x[1]["total"],
                reverse=True,
            )[:5],
        },
        "cwe_summary": {
            "best_cwes": sorted(
                [
                    (cwe, stats)
                    for cwe, stats in cwe_results.items()
                    if stats["total"] > 0
                ],
                key=lambda x: x[1]["accuracy"],
                reverse=True,
            )[:10],
            "worst_cwes": sorted(
                [
                    (cwe, stats)
                    for cwe, stats in cwe_results.items()
                    if stats["total"] > 0
                ],
                key=lambda x: x[1]["accuracy"],
            )[:10],
        },
    }


def print_evaluation_results(results: Dict[str, Any]):
    """打印评估结果"""
    print("\n" + "=" * 80)
    print("🎯 PROMPT 泛化性能评估结果")
    print("=" * 80)

    print("\n📊 总体性能:")
    print(
        f"   准确率: {results['overall_accuracy']:.4f} ({results['correct_predictions']}/{results['total_samples']})"
    )
    print(f"   评估时间: {results['evaluation_time']:.2f}秒")
    print(f"   平均每样本: {results['avg_time_per_sample']:.3f}秒")

    print("\n🏆 表现最佳的CWE大类 (前5名):")
    for i, (category, stats) in enumerate(
        results["category_summary"]["best_categories"], 1
    ):
        print(
            f"   {i}. {category}: {stats['accuracy']:.4f} ({stats['correct']}/{stats['total']})"
        )

    print("\n❌ 表现最差的CWE大类 (前5名):")
    for i, (category, stats) in enumerate(
        results["category_summary"]["worst_categories"], 1
    ):
        print(
            f"   {i}. {category}: {stats['accuracy']:.4f} ({stats['correct']}/{stats['total']})"
        )

    print("\n📈 样本最多的CWE大类 (前5名):")
    for i, (category, stats) in enumerate(
        results["category_summary"]["most_common_categories"], 1
    ):
        print(
            f"   {i}. {category}: {stats['total']} 样本, 准确率 {stats['accuracy']:.4f}"
        )

    print("\n🔍 各类别详细结果:")
    for category, stats in sorted(results["category_results"].items()):
        if stats["total"] > 0:
            print(
                f"   {category}: {stats['accuracy']:.4f} ({stats['correct']}/{stats['total']})"
            )
            if stats["predictions"]:
                pred_str = ", ".join(
                    [f"{pred}:{count}" for pred, count in stats["predictions"].items()]
                )
                print(f"     预测分布: {pred_str}")

    print("\n🎯 表现最佳的CWE代码 (前10名):")
    for i, (cwe, stats) in enumerate(results["cwe_summary"]["best_cwes"], 1):
        print(
            f"   {i}. {cwe}: {stats['accuracy']:.4f} ({stats['correct']}/{stats['total']})"
        )

    print("\n❌ 表现最差的CWE代码 (前10名):")
    for i, (cwe, stats) in enumerate(results["cwe_summary"]["worst_cwes"], 1):
        print(
            f"   {i}. {cwe}: {stats['accuracy']:.4f} ({stats['correct']}/{stats['total']})"
        )


def save_evaluation_results(results: Dict[str, Any], output_file: str):
    """保存评估结果到文件"""
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\n💾 评估结果已保存到: {output_file}")


async def main_async():
    """异步主函数"""
    print("🎮 Prompt 泛化性能测试 Playground (异步并发版本)")
    print("=" * 60)

    # 加载环境变量
    print("🔧 加载环境变量...")
    load_dotenv()

    # 配置路径
    stats_file = "data/primevul_1percent_sample/sampling_stats.json"
    train_file = "data/primevul_1percent_sample/dev_sample.jsonl"

    # 检查文件是否存在
    if not os.path.exists(stats_file):
        print(f"❌ 采样统计文件不存在: {stats_file}")
        return 1

    if not os.path.exists(train_file):
        print(f"❌ 训练样本文件不存在: {train_file}")
        return 1

    # 加载采样统计
    print("📊 加载采样统计...")
    stats = load_sampling_stats(stats_file)
    print(f"   总样本数: {stats['total_samples']}")
    print(f"   采样比例: {stats['sample_ratio']:.3f}")
    print(f"   训练样本: {stats['sampled_total']}")

    # 加载训练样本
    print("📁 加载训练样本...")
    train_samples = load_train_samples(train_file)
    print(f"   已加载: {len(train_samples)} 个样本")

    # 检查API配置
    api_key = os.getenv("API_KEY")
    if not api_key:
        print("❌ 请设置 API_KEY 环境变量")
        print("   在.env文件中设置: API_KEY='your-api-key-here'")
        return 1

    # 创建异步LLM客户端
    print("🤖 初始化异步LLM客户端...")
    async_client = AsyncLLMClient(
        api_key=api_key,
        max_concurrency=8,  # 设置8个并发请求
        timeout=30,
    )

    print(f"   ✅ 并发客户端已创建，最大并发数: {async_client.max_concurrency}")

    # 最佳prompt
    best_prompt = """You are an expert cybersecurity analyst with deep knowledge of CWE patterns and vulnerability detection. Conduct a comprehensive security assessment using a systematic multi-phase approach:

**Phase 1 - Attacker Mindset & Entry Point Analysis:**
- Identify the most attractive attack vectors and entry points an attacker would target first
- Examine user-controlled inputs, external interfaces, and data sources that could be weaponized
- Consider how vulnerabilities might be chained for maximum exploitation impact

**Phase 2 - CWE Pattern Recognition & Static Analysis:**
Systematically detect vulnerability patterns across major CWE categories:
- **Buffer Errors (CWE-120,119,787)**: overflows, underflows, bounds violations, memory corruption
- **Injection Flaws (CWE-78,79,89)**: SQL injection, command injection, XSS, code injection, format string attacks
- **Memory Management (CWE-416,415,401)**: use-after-free, double-free, memory leaks, improper cleanup
- **Pointer Dereference (CWE-476)**: null pointer dereference, invalid pointer usage, dangling pointers
- **Integer Errors (CWE-190,191)**: integer overflow, underflow, wraparound, signedness issues
- **Concurrency Issues (CWE-362)**: race conditions, synchronization problems, deadlocks
- **Path Traversal (CWE-22)**: directory traversal, path manipulation, file inclusion attacks
- **Cryptography Issues (CWE-327,326)**: weak algorithms, broken crypto, improper key management
- **Information Exposure (CWE-200)**: data leaks, privacy violations, sensitive info disclosure
- **Other Security Issues**: logic flaws, design weaknesses, implementation errors

**Phase 3 - Classification Decision:**
Based on the analysis, classify the code into the most appropriate CWE major category above. If no vulnerability is found, respond with 'Benign'.

Code: {input}

Security assessment:"""

    print("\n🎯 开始评估最佳prompt...")
    print(f"Prompt长度: {len(best_prompt)} 字符")

    # 询问是否限制样本数量
    sample_limit = input("\n🔢 输入要评估的样本数量 (直接回车评估全部): ").strip()
    if sample_limit:
        try:
            sample_limit = int(sample_limit)
            print(f"   将评估前 {sample_limit} 个样本")
        except ValueError:
            sample_limit = None
            print("   输入无效，将评估全部样本")
    else:
        sample_limit = None
        print("   将评估全部样本")

    # 执行异步评估
    print("\n🚀 启动异步并发评估...")
    results = await evaluate_prompt_on_samples_async(
        best_prompt, train_samples, async_client, sample_limit
    )

    # 显示结果
    print_evaluation_results(results)

    # 保存结果
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    output_file = f"playground_results_async_{timestamp}.json"
    save_evaluation_results(results, output_file)

    print("\n✅ 异步泛化性能测试完成!")
    return 0


def main():
    """主函数（同步版本，保持兼容性）"""
    print("🎮 Prompt 泛化性能测试 Playground (同步版本)")
    print("=" * 50)

    # 配置路径
    stats_file = "data/primevul_1percent_sample/sampling_stats.json"
    train_file = "data/primevul_1percent_sample/dev_sample.jsonl"

    # 检查文件是否存在
    if not os.path.exists(stats_file):
        print(f"❌ 采样统计文件不存在: {stats_file}")
        return 1

    if not os.path.exists(train_file):
        print(f"❌ 训练样本文件不存在: {train_file}")
        return 1

    # 加载采样统计
    print("📊 加载采样统计...")
    stats = load_sampling_stats(stats_file)
    print(f"   总样本数: {stats['total_samples']}")
    print(f"   采样比例: {stats['sample_ratio']:.3f}")
    print(f"   训练样本: {stats['sampled_total']}")

    # 加载训练样本
    print("📁 加载训练样本...")
    train_samples = load_train_samples(train_file)
    print(f"   已加载: {len(train_samples)} 个样本")

    # 检查API配置
    api_key = os.getenv("API_KEY")
    if not api_key:
        print("❌ 请设置 API_KEY 环境变量")
        print("   在.env文件中设置: API_KEY='your-api-key-here'")
        return 1

    # 创建LLM客户端
    print("🤖 初始化LLM客户端...")
    llm_client = create_default_client()

    # 最佳prompt
    best_prompt = """You are an expert cybersecurity analyst with deep knowledge of CWE patterns and vulnerability detection. Conduct a comprehensive security assessment using a systematic multi-phase approach:

**Phase 1 - Attacker Mindset & Entry Point Analysis:**
- Identify the most attractive attack vectors and entry points an attacker would target first
- Examine user-controlled inputs, external interfaces, and data sources that could be weaponized
- Consider how vulnerabilities might be chained for maximum exploitation impact

**Phase 2 - CWE Pattern Recognition & Static Analysis:**
Systematically detect vulnerability patterns across major CWE categories:
- **Buffer Errors (CWE-120,119,787)**: overflows, underflows, bounds violations, memory corruption
- **Injection Flaws (CWE-78,79,89)**: SQL injection, command injection, XSS, code injection, format string attacks

Code: {input}

Security assessment:"""

    print("\n🎯 开始评估最佳prompt...")
    print(f"Prompt长度: {len(best_prompt)} 字符")

    # 询问是否限制样本数量
    sample_limit = input("\n🔢 输入要评估的样本数量 (直接回车评估全部): ").strip()
    if sample_limit:
        try:
            sample_limit = int(sample_limit)
            print(f"   将评估前 {sample_limit} 个样本")
        except ValueError:
            sample_limit = None
            print("   输入无效，将评估全部样本")
    else:
        sample_limit = None
        print("   将评估全部样本")

    # 执行评估
    results = evaluate_prompt_on_samples(
        best_prompt, train_samples, llm_client, sample_limit
    )

    # 显示结果
    print_evaluation_results(results)

    # 保存结果
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    output_file = f"playground_results_{timestamp}.json"
    save_evaluation_results(results, output_file)

    print("\n✅ 泛化性能测试完成!")
    return 0


if __name__ == "__main__":
    # 询问用户选择运行模式
    print("🎮 选择运行模式:")
    print("1. 异步并发模式 (推荐，8个并发请求)")
    print("2. 同步模式 (兼容性)")

    choice = input("\n请选择 (1/2，默认1): ").strip()

    if choice == "2":
        # 同步模式
        sys.exit(main())
    else:
        # 异步模式（默认）
        try:
            exit_code = asyncio.run(main_async())
            sys.exit(exit_code)
        except KeyboardInterrupt:
            print("\n\n⚠️ 用户中断执行")
            sys.exit(1)
        except Exception as e:
            print(f"\n❌ 异步执行失败: {e}")
            import traceback

            traceback.print_exc()
            sys.exit(1)
