#!/usr/bin/env python3
"""
替换CSV文件中Top-Level Category列，用CWE ID替换类别名称
"""

import csv
import re
from pathlib import Path


def extract_cwe_from_category(category):
    """从Top-Level Category中提取CWE ID"""
    # 匹配形如 "Improper Control of a Resource Through its Lifetime (CWE-664)" 的模式
    match = re.search(r"\(CWE-(\d+)\)", category)
    if match:
        return f"CWE-{match.group(1)}"
    return category


def replace_categories_in_csv(input_file, output_file):
    """替换CSV文件中的Top-Level Category列"""
    rows = []

    with open(input_file, "r", encoding="utf-8") as infile:
        reader = csv.DictReader(infile)
        fieldnames = reader.fieldnames

        for row in reader:
            # 替换Top-Level Category列
            if "Top-Level Category" in row:
                old_category = row["Top-Level Category"]
                new_category = extract_cwe_from_category(old_category)
                row["Top-Level Category"] = new_category
                print(f"替换: {old_category} -> {new_category}")

            rows.append(row)

    # 写入新文件
    with open(output_file, "w", encoding="utf-8", newline="") as outfile:
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print("\n处理完成！")
    print(f"输入文件: {input_file}")
    print(f"输出文件: {output_file}")
    print(f"处理了 {len(rows)} 行数据")


def main():
    input_file = "data/primevul_1percent_sample/cwesimple.csv"
    output_file = "data/primevul_1percent_sample/cwesimple_replaced.csv"

    # 检查输入文件是否存在
    if not Path(input_file).exists():
        print(f"错误: 输入文件 {input_file} 不存在")
        return

    try:
        replace_categories_in_csv(input_file, output_file)
    except Exception as e:
        print(f"处理过程中出现错误: {e}")


if __name__ == "__main__":
    main()
