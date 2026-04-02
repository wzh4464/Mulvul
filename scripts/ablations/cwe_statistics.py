#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CWE统计程序
统计JSONL文件中所有的CWE类型和数量
"""

import json
from collections import Counter
import argparse
from pathlib import Path


def analyze_cwe_data(file_path):
    """
    分析JSONL文件中的CWE数据

    Args:
        file_path (str): JSONL文件路径

    Returns:
        dict: CWE统计结果
    """
    cwe_counter = Counter()
    total_records = 0
    records_with_cwe = 0
    records_without_cwe = 0

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                try:
                    data = json.loads(line)
                    total_records += 1

                    # 检查是否有CWE字段
                    if "cwe" in data:
                        cwe_list = data["cwe"]
                        if isinstance(cwe_list, list) and cwe_list:
                            records_with_cwe += 1
                            # 统计每个CWE类型
                            for cwe in cwe_list:
                                if cwe:  # 确保CWE不为空
                                    cwe_counter[cwe] += 1
                        else:
                            records_without_cwe += 1
                    else:
                        records_without_cwe += 1

                except json.JSONDecodeError as e:
                    print(f"警告: 第{line_num}行JSON解析失败: {e}")
                    continue

    except FileNotFoundError:
        print(f"错误: 文件 '{file_path}' 不存在")
        return None
    except Exception as e:
        print(f"错误: 读取文件时发生异常: {e}")
        return None

    return {
        "cwe_counts": dict(cwe_counter),
        "total_records": total_records,
        "records_with_cwe": records_with_cwe,
        "records_without_cwe": records_without_cwe,
        "unique_cwe_types": len(cwe_counter),
    }


def print_statistics(stats):
    """
    打印统计结果

    Args:
        stats (dict): 统计结果字典
    """
    if not stats:
        return

    print("=" * 60)
    print("CWE漏洞类型统计报告")
    print("=" * 60)

    print("\n总体统计:")
    print(f"  总记录数: {stats['total_records']:,}")
    print(f"  包含CWE的记录数: {stats['records_with_cwe']:,}")
    print(f"  不包含CWE的记录数: {stats['records_without_cwe']:,}")
    print(f"  唯一CWE类型数: {stats['unique_cwe_types']:,}")

    if stats["cwe_counts"]:
        print("\nCWE类型分布 (按数量降序排列):")
        print("-" * 40)

        # 按数量降序排列
        sorted_cwes = sorted(
            stats["cwe_counts"].items(), key=lambda x: x[1], reverse=True
        )

        for i, (cwe, count) in enumerate(sorted_cwes, 1):
            percentage = (count / stats["total_records"]) * 100
            print(f"{i:2d}. {cwe:<15} : {count:6,} ({percentage:5.1f}%)")

    print("\n" + "=" * 60)


def save_statistics_to_file(stats, output_file):
    """
    将统计结果保存到文件

    Args:
        stats (dict): 统计结果字典
        output_file (str): 输出文件路径
    """
    if not stats:
        return

    try:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write("CWE漏洞类型统计报告\n")
            f.write("=" * 50 + "\n\n")

            f.write("总体统计:\n")
            f.write(f"  总记录数: {stats['total_records']:,}\n")
            f.write(f"  包含CWE的记录数: {stats['records_with_cwe']:,}\n")
            f.write(f"  不包含CWE的记录数: {stats['records_without_cwe']:,}\n")
            f.write(f"  唯一CWE类型数: {stats['unique_cwe_types']:,}\n\n")

            if stats["cwe_counts"]:
                f.write("CWE类型分布 (按数量降序排列):\n")
                f.write("-" * 40 + "\n")

                sorted_cwes = sorted(
                    stats["cwe_counts"].items(), key=lambda x: x[1], reverse=True
                )

                for i, (cwe, count) in enumerate(sorted_cwes, 1):
                    percentage = (count / stats["total_records"]) * 100
                    f.write(f"{i:2d}. {cwe:<15} : {count:6,} ({percentage:5.1f}%)\n")

        print(f"\n统计结果已保存到: {output_file}")

    except Exception as e:
        print(f"保存文件时发生错误: {e}")


def main():
    parser = argparse.ArgumentParser(description="统计JSONL文件中的CWE类型和数量")
    parser.add_argument("input_file", help="输入的JSONL文件路径")
    parser.add_argument("-o", "--output", help="输出文件路径（可选）")
    parser.add_argument("-v", "--verbose", action="store_true", help="显示详细信息")

    args = parser.parse_args()

    # 检查输入文件是否存在
    if not Path(args.input_file).exists():
        print(f"错误: 输入文件 '{args.input_file}' 不存在")
        return

    print(f"正在分析文件: {args.input_file}")

    # 分析数据
    stats = analyze_cwe_data(args.input_file)

    if stats:
        # 打印统计结果
        print_statistics(stats)

        # 如果指定了输出文件，保存结果
        if args.output:
            save_statistics_to_file(stats, args.output)

        # 详细模式显示
        if args.verbose and stats["cwe_counts"]:
            print("\n详细CWE信息:")
            print("-" * 40)
            for cwe, count in sorted(stats["cwe_counts"].items()):
                print(f"{cwe}: {count:,} 次出现")
    else:
        print("分析失败，请检查文件格式和内容")


if __name__ == "__main__":
    main()
