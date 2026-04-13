#!/usr/bin/env python3
"""
CWD 分类分析工具
分析 CWD 数据集中的代码示例，尝试推断与 CWE 的映射关系
"""

import json
import re
from pathlib import Path
from collections import defaultdict, Counter
from typing import Dict, List, Any

def load_cwd_data(data_dir: str) -> Dict[str, Any]:
    """加载 CWD 数据集"""
    data_path = Path(data_dir)

    all_data = {}

    # 加载 cwd_benchmark_2.json
    cwd_file = data_path / "cwd_benchmark_2.json"
    if cwd_file.exists():
        with open(cwd_file, 'r', encoding='utf-8') as f:
            all_data.update(json.load(f))

    # 加载 checked_codehub_benchmark.json
    codehub_file = data_path / "checked_codehub_benchmark.json"
    if codehub_file.exists():
        with open(codehub_file, 'r', encoding='utf-8') as f:
            codehub_data = json.load(f)
            # 合并数据
            for lang in codehub_data:
                if lang in all_data:
                    for cwd_id in codehub_data[lang]:
                        if cwd_id in all_data[lang]:
                            all_data[lang][cwd_id].extend(codehub_data[lang][cwd_id])
                        else:
                            all_data[lang][cwd_id] = codehub_data[lang][cwd_id]
                else:
                    all_data[lang] = codehub_data[lang]

    return all_data

def analyze_cwd_patterns(data: Dict[str, Any]) -> Dict[str, Dict]:
    """分析 CWD 分类的代码模式"""

    analysis = {}

    for lang in data:
        print(f"\n=== 分析 {lang} 语言的 CWD 分类 ===")
        lang_stats = {
            'total_cwds': len(data[lang]),
            'total_examples': 0,
            'patterns': defaultdict(list)
        }

        for cwd_id in sorted(data[lang].keys()):
            examples = data[lang][cwd_id]
            lang_stats['total_examples'] += len(examples)

            # 分析代码模式
            patterns = analyze_code_patterns(cwd_id, examples)
            lang_stats['patterns'][cwd_id] = patterns

            # 打印前几个分类的分析
            if int(cwd_id.split('-')[1]) <= 1010:  # 只显示前面的一些
                print(f"\n{cwd_id}: {len(examples)} 个示例")
                if patterns['keywords']:
                    print(f"  关键词: {', '.join(patterns['keywords'][:5])}")
                if patterns['functions']:
                    print(f"  函数: {', '.join(patterns['functions'][:3])}")
                if patterns['suggested_cwe']:
                    print(f"  推测 CWE 类型: {patterns['suggested_cwe']}")

        analysis[lang] = lang_stats
        print(f"\n{lang} 总计: {lang_stats['total_cwds']} 个 CWD 分类, {lang_stats['total_examples']} 个代码示例")

    return analysis

def analyze_code_patterns(cwd_id: str, examples: List[Dict]) -> Dict:
    """分析单个 CWD 分类的代码模式"""

    all_code = []
    functions = []
    keywords = []

    for example in examples:
        # 收集漏洞代码
        vuln_code = example.get('vulnerable_code', {})
        if vuln_code.get('func'):
            all_code.append(vuln_code['func'])
            functions.append(extract_function_name(vuln_code['func']))

        if vuln_code.get('context'):
            all_code.append(vuln_code['context'])

        # 收集良性代码
        benign_code = example.get('benign_code', {})
        if benign_code.get('func'):
            all_code.append(benign_code['func'])

    # 提取关键词
    code_text = ' '.join(all_code).lower()
    keywords = extract_security_keywords(code_text)

    # 基于模式推测可能的 CWE 分类
    suggested_cwe = suggest_cwe_mapping(cwd_id, keywords, code_text)

    return {
        'keywords': keywords,
        'functions': [f for f in functions if f],
        'suggested_cwe': suggested_cwe,
        'code_patterns': analyze_code_structure(code_text)
    }

def extract_function_name(func_code: str) -> str:
    """提取函数名"""
    # 简单的函数名提取
    match = re.search(r'(\w+)\s*\(', func_code)
    return match.group(1) if match else ""

def extract_security_keywords(code_text: str) -> List[str]:
    """提取安全相关关键词"""

    security_patterns = {
        'memory': ['malloc', 'free', 'kmalloc', 'kfree', 'buffer', 'memcpy', 'strcpy', 'alloc'],
        'injection': ['sql', 'query', 'exec', 'eval', 'command', 'script', 'injection'],
        'overflow': ['overflow', 'size', 'length', 'bounds', 'check'],
        'validation': ['validate', 'sanitize', 'filter', 'input', 'param'],
        'crypto': ['encrypt', 'decrypt', 'hash', 'key', 'cipher', 'crypto'],
        'file': ['file', 'path', 'directory', 'read', 'write', 'open'],
        'network': ['url', 'http', 'request', 'response', 'web', 'api'],
        'concurrency': ['thread', 'lock', 'race', 'sync', 'atomic']
    }

    found_keywords = []
    for category, patterns in security_patterns.items():
        for pattern in patterns:
            if pattern in code_text:
                found_keywords.append(pattern)

    return list(set(found_keywords))

def suggest_cwe_mapping(cwd_id: str, keywords: List[str], code_text: str) -> str:
    """基于代码模式推测可能的 CWE 映射"""

    # 基于关键词的简单映射规则
    if any(kw in keywords for kw in ['malloc', 'free', 'buffer', 'memcpy', 'strcpy']):
        if 'overflow' in keywords or 'size' in keywords:
            return "Buffer Errors (CWE-119系列)"
        else:
            return "Memory Management (CWE-401系列)"

    if any(kw in keywords for kw in ['sql', 'query', 'injection']):
        return "Injection (CWE-89系列)"

    if any(kw in keywords for kw in ['command', 'exec', 'eval']):
        return "Command Injection (CWE-78系列)"

    if any(kw in keywords for kw in ['script', 'web', 'html', 'xss']):
        return "XSS (CWE-79系列)"

    if any(kw in keywords for kw in ['file', 'path', 'directory']):
        return "Path Traversal (CWE-22系列)"

    if any(kw in keywords for kw in ['validate', 'input', 'param']):
        return "Input Validation (CWE-20系列)"

    return "Unknown"

def analyze_code_structure(code_text: str) -> Dict:
    """分析代码结构特征"""

    return {
        'has_loops': bool(re.search(r'\b(for|while|do)\b', code_text)),
        'has_conditionals': bool(re.search(r'\b(if|else|switch)\b', code_text)),
        'has_functions': bool(re.search(r'\w+\s*\(', code_text)),
        'has_arrays': bool(re.search(r'\[\s*\]|\[\s*\d+\s*\]', code_text)),
        'has_pointers': bool(re.search(r'\*\w+|\w+\*', code_text)),
        'line_count': len(code_text.split('\n'))
    }

def main():
    """主函数"""

    print("开始分析 CWD 数据集...")

    # 数据路径
    data_dir = "/Users/zihanwu/codes/Mulvul/data/enter"

    try:
        # 加载数据
        data = load_cwd_data(data_dir)

        # 分析模式
        analysis = analyze_cwd_patterns(data)

        # 生成统计报告
        print(f"\n=== 总体统计 ===")
        total_cwds = sum(lang_data['total_cwds'] for lang_data in analysis.values())
        total_examples = sum(lang_data['total_examples'] for lang_data in analysis.values())

        print(f"总计: {total_cwds} 个 CWD 分类, {total_examples} 个代码示例")

        for lang, lang_data in analysis.items():
            print(f"{lang}: {lang_data['total_cwds']} 个分类, {lang_data['total_examples']} 个示例")

    except Exception as e:
        print(f"分析失败: {e}")

if __name__ == "__main__":
    main()