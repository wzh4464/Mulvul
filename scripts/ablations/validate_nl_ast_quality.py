#!/usr/bin/env python3
"""验证 Natural Language AST 数据质量"""

import json
import sys
from pathlib import Path
from collections import Counter


def analyze_nl_ast_file(filepath: Path):
    """分析单个 NL AST 文件的质量"""
    total = 0
    with_comments_original = 0
    nl_differs = 0
    error_samples = 0
    cwe_counter = Counter()

    print(f"\n{'='*80}")
    print(f"分析文件: {filepath}")
    print(f"{'='*80}")

    with open(filepath) as f:
        for line in f:
            try:
                d = json.loads(line)
                total += 1

                # 检查原始代码是否有注释
                func = d.get('func', '')
                if '//' in func or '/*' in func:
                    with_comments_original += 1

                # 检查 NL AST 是否有变化
                nl_ast = d.get('natural_language_ast', '')
                if func != nl_ast:
                    nl_differs += 1

                # 统计 CWE 分布
                for cwe in d.get('cwe', []):
                    cwe_counter[cwe] += 1

            except Exception as e:
                error_samples += 1
                print(f"  ⚠️  样本 {total} 解析错误: {e}")

    print(f"\n📊 统计结果:")
    print(f"  总样本数: {total:,}")
    print(f"  包含注释: {with_comments_original:,} ({100*with_comments_original/total:.1f}%)")
    print(f"  NL AST 有变化: {nl_differs:,} ({100*nl_differs/total:.1f}%)")
    print(f"  处理错误: {error_samples}")

    if cwe_counter:
        print(f"\n🔍 CWE 分布 (Top 10):")
        for cwe, count in cwe_counter.most_common(10):
            print(f"  {cwe}: {count:,} ({100*count/total:.1f}%)")

    return {
        'total': total,
        'with_comments': with_comments_original,
        'nl_differs': nl_differs,
        'errors': error_samples,
        'cwe_dist': dict(cwe_counter),
    }


def show_example_transformations(filepath: Path, n_examples: int = 3):
    """显示注释转换示例"""
    print(f"\n{'='*80}")
    print(f"注释转换示例 (来自 {filepath.name})")
    print(f"{'='*80}")

    shown = 0
    with open(filepath) as f:
        for i, line in enumerate(f, 1):
            if shown >= n_examples:
                break

            try:
                d = json.loads(line)
                func = d.get('func', '')
                nl_ast = d.get('natural_language_ast', '')

                # 只显示有注释且有变化的样本
                if ('//' in func or '/*' in func) and func != nl_ast:
                    shown += 1
                    print(f"\n--- 示例 {shown} (样本 #{i}) ---")

                    # 找到变化的行
                    func_lines = func.split('\n')
                    nl_lines = nl_ast.split('\n')

                    for j, (orig, transformed) in enumerate(zip(func_lines, nl_lines)):
                        if orig != transformed:
                            print(f"原始:    {orig[:100]}")
                            print(f"转换后:  {transformed[:100]}")
                            if len(orig) > 100 or len(transformed) > 100:
                                print("  (行太长，已截断)")
                            break  # 只显示第一个不同的行

            except Exception as e:
                continue

    if shown == 0:
        print("  ⚠️  未找到带注释转换的样本")


if __name__ == "__main__":
    nl_ast_dir = Path("outputs/primevul_nl_ast")

    if not nl_ast_dir.exists():
        print(f"❌ 错误: 目录不存在: {nl_ast_dir}")
        print("请先运行预处理脚本生成 NL AST 数据")
        sys.exit(1)

    # 分析所有文件
    files = list(nl_ast_dir.glob("*.jsonl"))
    if not files:
        print(f"❌ 错误: {nl_ast_dir} 中没有 JSONL 文件")
        sys.exit(1)

    results = {}
    for filepath in sorted(files):
        results[filepath.name] = analyze_nl_ast_file(filepath)

    # 显示一些转换示例
    if files:
        show_example_transformations(files[0], n_examples=3)

    # 总结
    print(f"\n{'='*80}")
    print("✅ 质量验证完成")
    print(f"{'='*80}")
