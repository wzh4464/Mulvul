#!/usr/bin/env python3
"""RAG 增强的 Primevul 并发评估

1. 从 Primevul 数据集为每个 CWE 大类构建 one-shot 知识库
2. 使用 top-k RAG 检索相似案例
3. 将案例作为上下文输入 LLM 辅助判断
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
from typing import Dict, List, Any, Optional

sys.path.insert(0, "src")

from evoprompt.llm.client import create_llm_client, load_env_vars
from evoprompt.data.cwe_categories import CWE_MAJOR_CATEGORIES, map_cwe_to_major, canonicalize_category
from evoprompt.rag.knowledge_base import KnowledgeBase, CodeExample
from evoprompt.rag.retriever import CodeSimilarityRetriever


def build_kb_from_primevul(
    data_file: str,
    samples_per_category: int = 2,
    max_code_length: int = 1000
) -> KnowledgeBase:
    """从 Primevul JSONL 构建知识库，每个 CWE 大类至少一个案例"""

    print(f"📚 从 {data_file} 构建知识库...")

    # 按类别收集样本
    category_samples: Dict[str, List[Dict]] = {cat: [] for cat in CWE_MAJOR_CATEGORIES}

    with open(data_file, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                item = json.loads(line)
                target = int(item.get("target", 0))

                # 只收集漏洞样本
                if target != 1:
                    continue

                cwe_codes = item.get("cwe", [])
                if isinstance(cwe_codes, str):
                    cwe_codes = [cwe_codes] if cwe_codes else []

                category = map_cwe_to_major(cwe_codes) if cwe_codes else "Other"

                if category in category_samples:
                    # 限制代码长度
                    code = item.get("func", "")[:max_code_length]
                    if len(code) > 100:  # 过滤太短的代码
                        category_samples[category].append({
                            "code": code,
                            "cwe": cwe_codes,
                            "category": category
                        })

            except json.JSONDecodeError:
                continue

    # 构建知识库
    kb = KnowledgeBase()

    for category, samples in category_samples.items():
        if not samples:
            print(f"   ⚠️ {category}: 无样本")
            continue

        # 随机选择样本
        selected = random.sample(samples, min(samples_per_category, len(samples)))

        for sample in selected:
            kb.major_examples.setdefault(category, []).append(
                CodeExample(
                    code=sample["code"],
                    category=category,
                    description=f"{category} vulnerability example",
                    cwe=sample["cwe"][0] if sample["cwe"] else None
                )
            )

        print(f"   ✅ {category}: {len(selected)} 个案例")

    # 添加 Benign 案例
    kb.major_examples["Benign"] = [
        CodeExample(
            code="int add(int a, int b) { return a + b; }",
            category="Benign",
            description="Safe arithmetic operation"
        )
    ]

    print(f"\n📊 知识库统计: {kb.statistics()}")
    return kb


def evaluate_with_rag(
    code: str,
    category: str,
    retriever: CodeSimilarityRetriever,
    llm_client,
    base_prompt: str,
    top_k: int = 3
) -> Dict:
    """使用 RAG 增强评估单个样本"""

    # 检索相似案例
    retrieval = retriever.retrieve_for_major_category(code, top_k=top_k)

    # 构建增强 prompt
    if retrieval.formatted_text:
        enhanced_prompt = f"{retrieval.formatted_text}\n\n{base_prompt}"
    else:
        enhanced_prompt = base_prompt

    query = enhanced_prompt.replace("{input}", code[:2000])  # 限制代码长度

    try:
        response = llm_client.generate(query, temperature=0.1, max_tokens=50)

        predicted = canonicalize_category(response)
        if predicted is None:
            if any(w in response.lower() for w in ["vulnerable", "vuln"]):
                predicted = "Other"
            else:
                predicted = "Benign"

        is_correct = predicted == category

        return {
            "expected": category,
            "predicted": predicted,
            "correct": is_correct,
            "num_examples_used": len(retrieval.examples),
            "raw_response": response[:100]
        }

    except Exception as e:
        return {
            "expected": category,
            "predicted": None,
            "correct": False,
            "error": str(e)
        }


def evaluate_category_with_rag(
    category: str,
    samples: List[Dict],
    retriever: CodeSimilarityRetriever,
    base_prompt: str,
    max_samples: Optional[int] = None,
    top_k: int = 3
) -> Dict[str, Any]:
    """使用 RAG 评估单个类别"""

    if not samples:
        return {"category": category, "total": 0, "correct": 0, "accuracy": 0.0}

    eval_samples = samples[:max_samples] if max_samples else samples
    llm_client = create_llm_client()

    correct = 0
    results = []

    for sample in eval_samples:
        code = sample.get("func", "")
        result = evaluate_with_rag(code, category, retriever, llm_client, base_prompt, top_k)

        if result.get("correct"):
            correct += 1
        results.append(result)

    accuracy = correct / len(eval_samples) if eval_samples else 0

    return {
        "category": category,
        "total": len(eval_samples),
        "correct": correct,
        "accuracy": accuracy,
        "results": results[:5]  # 只保留前5个示例
    }


def run_rag_concurrent_evaluation(
    data_file: str,
    kb: KnowledgeBase,
    base_prompt: str,
    max_workers: int = 8,
    max_samples_per_category: Optional[int] = None,
    top_k: int = 3,
    output_dir: str = "./outputs",
    debug_rag: bool = False
) -> Dict[str, Any]:
    """并发 RAG 增强评估"""

    load_env_vars()

    print("=" * 70)
    print("🔥 RAG 增强 Primevul 并发评估")
    print("=" * 70)

    # 创建 retriever (with debug flag)
    retriever = CodeSimilarityRetriever(kb, debug=debug_rag)

    # 加载数据
    print(f"\n📂 加载数据: {data_file}")
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

    print("\n📊 数据分布:")
    for cat, samples in sorted(category_samples.items(), key=lambda x: len(x[1]), reverse=True):
        if samples:
            print(f"   {cat:25s}: {len(samples):5d} 样本")

    # 并发评估
    print(f"\n🚀 启动 RAG 并发评估 (workers={max_workers}, top_k={top_k})")

    start_time = time.time()
    results = {}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {}

        for category, samples in category_samples.items():
            if samples:
                future = executor.submit(
                    evaluate_category_with_rag,
                    category, samples, retriever, base_prompt,
                    max_samples_per_category, top_k
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

    category_accuracies = [r.get("accuracy", 0) for r in results.values() if r.get("total", 0) > 0]
    macro_accuracy = sum(category_accuracies) / len(category_accuracies) if category_accuracies else 0

    summary = {
        "timestamp": datetime.now().isoformat(),
        "data_file": data_file,
        "rag_top_k": top_k,
        "kb_stats": kb.statistics(),
        "elapsed_seconds": elapsed,
        "total_samples": total_evaluated,
        "total_correct": total_correct,
        "overall_accuracy": overall_accuracy,
        "macro_accuracy": macro_accuracy,
        "category_results": {k: {kk: vv for kk, vv in v.items() if kk != "results"}
                            for k, v in results.items()},
        "prompt_used": base_prompt
    }

    # 打印结果
    print("\n" + "=" * 70)
    print("📊 RAG 增强评估结果")
    print("=" * 70)
    print(f"RAG top-k: {top_k}")
    print(f"总样本数: {total_evaluated}")
    print(f"正确数: {total_correct}")
    print(f"总体准确率 (Micro): {overall_accuracy:.2%}")
    print(f"宏平均准确率 (Macro): {macro_accuracy:.2%}")
    print(f"耗时: {elapsed:.1f}秒")

    print("\n📈 各类别准确率:")
    for cat, res in sorted(results.items(), key=lambda x: x[1].get('accuracy', 0), reverse=True):
        if res.get('total', 0) > 0:
            print(f"   {cat:25s}: {res['accuracy']:6.2%} ({res['correct']:4d}/{res['total']:4d})")

    # 保存结果
    os.makedirs(output_dir, exist_ok=True)
    output_file = Path(output_dir) / f"rag_eval_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    print(f"\n💾 结果已保存: {output_file}")

    return summary


def main():
    parser = argparse.ArgumentParser(description="RAG 增强 Primevul 评估")
    parser.add_argument("--data", default="./data/primevul/primevul/primevul_valid.jsonl", help="评估数据")
    parser.add_argument("--kb-data", default="./data/primevul/primevul/primevul_train.jsonl", help="知识库数据源")
    parser.add_argument("--kb-file", help="已有知识库文件 (跳过构建)")
    parser.add_argument("--samples-per-cat", type=int, default=2, help="每类知识库样本数")
    parser.add_argument("--top-k", type=int, default=3, help="RAG 检索 top-k")
    parser.add_argument("--workers", type=int, default=8, help="并发线程数")
    parser.add_argument("--max-samples", type=int, default=None, help="每类最大评估样本数")
    parser.add_argument("--output", default="./outputs", help="输出目录")
    parser.add_argument("--save-kb", help="保存知识库到文件")
    parser.add_argument("--debug-rag", action="store_true", help="打印 RAG 检索调试信息")

    args = parser.parse_args()

    random.seed(42)

    # 构建或加载知识库
    if args.kb_file and os.path.exists(args.kb_file):
        print(f"📖 加载已有知识库: {args.kb_file}")
        kb = KnowledgeBase.load(args.kb_file)
    else:
        kb = build_kb_from_primevul(args.kb_data, args.samples_per_cat)

        if args.save_kb:
            kb.save(args.save_kb)
            print(f"💾 知识库已保存: {args.save_kb}")

    # 基础 prompt
    base_prompt = """Based on the examples above, classify this code into one of these CWE major categories:
- Buffer Errors, Injection, Memory Management, Pointer Dereference, Integer Errors
- Concurrency Issues, Path Traversal, Cryptography Issues, Information Exposure, Other
- Benign (no vulnerabilities)

Code to analyze:
{input}

Category:"""

    # 运行评估
    run_rag_concurrent_evaluation(
        args.data,
        kb,
        base_prompt,
        max_workers=args.workers,
        max_samples_per_category=args.max_samples,
        top_k=args.top_k,
        output_dir=args.output,
        debug_rag=args.debug_rag
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
