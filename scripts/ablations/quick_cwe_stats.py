#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
快速CWE统计程序
简化版本，快速统计JSONL文件中的CWE类型和数量
"""

import json
from collections import Counter


def quick_cwe_stats(file_path):
    """快速统计CWE数据"""
    cwe_counter = Counter()
    total = 0

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
                total += 1

                if "cwe" in data and data["cwe"]:
                    for cwe in data["cwe"]:
                        if cwe:
                            cwe_counter[cwe] += 1

            except json.JSONDecodeError:
                continue

    return cwe_counter, total


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("用法: python3 quick_cwe_stats.py <jsonl_file>")
        sys.exit(1)

    file_path = sys.argv[1]

    try:
        cwe_counts, total = quick_cwe_stats(file_path)

        print(f"文件: {file_path}")
        print(f"总记录数: {total}")
        print(f"唯一CWE类型数: {len(cwe_counts)}")
        print("\nCWE类型统计:")
        print("-" * 30)

        # 按数量降序排列
        for cwe, count in sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total) * 100
            print(f"{cwe:<20} : {count:4d} ({percentage:5.1f}%)")

    except FileNotFoundError:
        print(f"错误: 文件 '{file_path}' 不存在")
    except Exception as e:
        print(f"错误: {e}")
