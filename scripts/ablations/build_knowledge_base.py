#!/usr/bin/env python3
"""从 primevul 训练集构建层级知识库

支持三层结构:
- Major (5类): Memory, Injection, Logic, Input, Crypto
- Middle (10类): Buffer Errors, Memory Management, etc.
- CWE (具体): CWE-119, CWE-416, etc.
"""

import os
import sys
import json
import random
from collections import defaultdict

sys.path.insert(0, "src")

from evoprompt.data.cwe_hierarchy import (
    cwe_to_major, cwe_to_middle, extract_cwe_id,
    MAJOR_CATEGORIES, MIDDLE_CATEGORIES
)


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


def build_hierarchical_kb(train_file, output_file, samples_per_category=100, seed=42):
    """构建层级知识库，按 Major 和 CWE 两个维度组织"""
    random.seed(seed)

    print(f"📂 加载训练数据: {train_file}")
    samples = load_jsonl(train_file)
    print(f"   总样本数: {len(samples)}")

    # 按 Major 和 CWE 分类
    major_samples = defaultdict(list)
    cwe_samples = defaultdict(list)
    middle_samples = defaultdict(list)

    for item in samples:
        if int(item.get("target", 0)) == 0:
            continue  # Skip benign

        code = item.get("func", "")
        if len(code) < 50 or len(code) > 3000:
            continue

        cwe_codes = item.get("cwe", [])
        if isinstance(cwe_codes, str):
            cwe_codes = [cwe_codes] if cwe_codes else []
        if not cwe_codes:
            continue

        cwe = cwe_codes[0]
        major = cwe_to_major(cwe_codes)
        middle = cwe_to_middle(cwe_codes)

        sample = {
            "code": code,
            "cwe": cwe,
            "major": major,
            "middle": middle,
            "description": item.get("cve_desc", "")[:300],
        }

        major_samples[major].append(sample)
        middle_samples[middle].append(sample)
        cwe_samples[cwe].append(sample)

    # 打印统计
    print("\n📊 Major 类别分布:")
    for cat in ["Memory", "Injection", "Logic", "Input", "Crypto"]:
        print(f"   {cat:12s}: {len(major_samples[cat]):5d}")

    print("\n📊 Middle 类别分布 (top 10):")
    sorted_middle = sorted(middle_samples.items(), key=lambda x: len(x[1]), reverse=True)
    for cat, samples_list in sorted_middle[:10]:
        print(f"   {cat:20s}: {len(samples_list):5d}")

    print("\n📊 CWE 分布 (top 15):")
    sorted_cwe = sorted(cwe_samples.items(), key=lambda x: len(x[1]), reverse=True)
    for cwe, samples_list in sorted_cwe[:15]:
        print(f"   {cwe:12s}: {len(samples_list):5d}")

    # 构建知识库
    knowledge_base = {
        "by_major": {},
        "by_middle": {},
        "by_cwe": {},
    }

    # 按 Major 采样
    print("\n✅ 按 Major 采样:")
    for major, samples_list in major_samples.items():
        n = min(samples_per_category, len(samples_list))
        knowledge_base["by_major"][major] = random.sample(samples_list, n)
        print(f"   {major}: {n}")

    # 按 Middle 采样
    print("\n✅ 按 Middle 采样:")
    for middle, samples_list in middle_samples.items():
        n = min(samples_per_category // 2, len(samples_list))
        if n > 0:
            knowledge_base["by_middle"][middle] = random.sample(samples_list, n)
            print(f"   {middle}: {n}")

    # 按 CWE 采样 (top 30)
    print("\n✅ 按 CWE 采样 (top 30):")
    for cwe, samples_list in sorted_cwe[:30]:
        n = min(20, len(samples_list))
        knowledge_base["by_cwe"][cwe] = random.sample(samples_list, n)
        print(f"   {cwe}: {n}")

    # 保存
    os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(knowledge_base, f, indent=2, ensure_ascii=False)

    total_major = sum(len(v) for v in knowledge_base["by_major"].values())
    total_middle = sum(len(v) for v in knowledge_base["by_middle"].values())
    total_cwe = sum(len(v) for v in knowledge_base["by_cwe"].values())

    print(f"\n💾 知识库已保存: {output_file}")
    print(f"   by_major: {total_major} samples")
    print(f"   by_middle: {total_middle} samples")
    print(f"   by_cwe: {total_cwe} samples")

    return knowledge_base


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--train", default="./data/primevul/primevul/primevul_train.jsonl")
    parser.add_argument("--output", default="./data/knowledge_base_hierarchical.json")
    parser.add_argument("--samples-per-category", type=int, default=100)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    if not os.path.exists(args.train):
        print(f"❌ 训练文件不存在: {args.train}")
        return 1

    build_hierarchical_kb(args.train, args.output, args.samples_per_category, args.seed)
    return 0


if __name__ == "__main__":
    sys.exit(main())
