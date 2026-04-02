#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PrimeVul完整数据集统计程序
统计所有训练、验证、测试集的CWE分布
"""

import json
from collections import Counter
from pathlib import Path


def analyze_cwe_data(file_path):
    """分析JSONL文件中的CWE数据"""
    cwe_counter = Counter()
    total_records = 0
    records_with_cwe = 0

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
                total_records += 1

                if "cwe" in data:
                    cwe_list = data["cwe"]
                    if isinstance(cwe_list, list) and cwe_list:
                        records_with_cwe += 1
                        for cwe in cwe_list:
                            if cwe:
                                cwe_counter[cwe] += 1

            except json.JSONDecodeError:
                continue

    return {
        "cwe_counts": dict(cwe_counter),
        "total_records": total_records,
        "records_with_cwe": records_with_cwe,
    }


def main():
    # 数据集路径
    base_path = Path("data/primevul/primevul")
    
    files = {
        "训练集": base_path / "primevul_train.jsonl",
        "验证集": base_path / "primevul_valid.jsonl",
        "测试集": base_path / "primevul_test.jsonl",
    }
    
    total_cwe_counter = Counter()
    total_records = 0
    total_records_with_cwe = 0
    
    print("=" * 80)
    print("PrimeVul完整数据集统计报告")
    print("=" * 80)
    
    # 统计各个数据集
    for name, file_path in files.items():
        if not file_path.exists():
            print(f"警告: 文件 {file_path} 不存在，跳过")
            continue
            
        stats = analyze_cwe_data(file_path)
        total_records += stats["total_records"]
        total_records_with_cwe += stats["records_with_cwe"]
        
        for cwe, count in stats["cwe_counts"].items():
            total_cwe_counter[cwe] += count
        
        print(f"\n{name} ({file_path.name}):")
        print(f"  总记录数: {stats['total_records']:,}")
        print(f"  包含CWE的记录数: {stats['records_with_cwe']:,}")
        print(f"  唯一CWE类型数: {len(stats['cwe_counts']):,}")
    
    # 汇总统计
    print("\n" + "=" * 80)
    print("汇总统计")
    print("=" * 80)
    print(f"总记录数: {total_records:,}")
    print(f"包含CWE的记录数: {total_records_with_cwe:,}")
    print(f"唯一CWE类型数: {len(total_cwe_counter):,}")
    
    # CWE分布
    print("\nCWE类型分布 (按数量降序排列):")
    print("-" * 80)
    
    sorted_cwes = sorted(total_cwe_counter.items(), key=lambda x: x[1], reverse=True)
    
    for i, (cwe, count) in enumerate(sorted_cwes, 1):
        percentage = (count / total_records) * 100
        print(f"{i:3d}. {cwe:<20} : {count:7,} ({percentage:5.1f}%)")
    
    print("\n" + "=" * 80)
    
    # 保存到文件
    output_file = "primevul_full_stats.txt"
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write("PrimeVul完整数据集统计报告\n")
        f.write("=" * 80 + "\n\n")
        
        f.write("汇总统计\n")
        f.write("-" * 80 + "\n")
        f.write(f"总记录数: {total_records:,}\n")
        f.write(f"包含CWE的记录数: {total_records_with_cwe:,}\n")
        f.write(f"唯一CWE类型数: {len(total_cwe_counter):,}\n\n")
        
        f.write("CWE类型分布 (按数量降序排列):\n")
        f.write("-" * 80 + "\n")
        
        for i, (cwe, count) in enumerate(sorted_cwes, 1):
            percentage = (count / total_records) * 100
            f.write(f"{i:3d}. {cwe:<20} : {count:7,} ({percentage:5.1f}%)\n")
        
        f.write("\n" + "=" * 80 + "\n")
    
    print(f"\n统计结果已保存到: {output_file}")


if __name__ == "__main__":
    main()

