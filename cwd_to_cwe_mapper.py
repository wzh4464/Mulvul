#!/usr/bin/env python3
"""
CWD 到 CWE 映射工具
将 CWD 数据格式转换为 Mulvul 项目兼容的格式
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass

@dataclass
class CodeExample:
    """代码示例数据结构"""
    vulnerable_code: str
    benign_code: str
    context: str
    language: str
    cwd_id: str
    mapped_cwe: Optional[str] = None
    mapped_middle: Optional[str] = None
    mapped_major: Optional[str] = None
    confidence: float = 0.0
    metadata: Dict[str, Any] = None

class CWDToCWEMapper:
    """CWD 到 CWE 映射器"""

    def __init__(self):
        # 基于当前 Mulvul 项目的 CWE 分类体系
        self.cwe_hierarchy = {
            # Memory 相关
            "Memory": {
                "Buffer Errors": ["CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-131", "CWE-787", "CWE-805"],
                "Memory Management": ["CWE-401", "CWE-415", "CWE-416", "CWE-772"],
                "Pointer Dereference": ["CWE-476", "CWE-617"],
                "Integer Errors": ["CWE-189", "CWE-190", "CWE-191", "CWE-369"]
            },
            # Injection 相关
            "Injection": {
                "Injection": ["CWE-74", "CWE-77", "CWE-78", "CWE-79", "CWE-89", "CWE-94"]
            },
            # Logic 相关
            "Logic": {
                "Concurrency Issues": ["CWE-362", "CWE-667"],
                "Information Exposure": ["CWE-200", "CWE-209"],
                "Resource Management": ["CWE-399", "CWE-400", "CWE-770", "CWE-835"],
                "Access Control": ["CWE-264", "CWE-269", "CWE-284"],
                "Other": []
            },
            # Input 相关
            "Input": {
                "Path Traversal": ["CWE-22", "CWE-59"],
                "Input Validation": ["CWE-20", "CWE-703"]
            },
            # Crypto 相关
            "Crypto": {
                "Cryptography Issues": ["CWE-254", "CWE-310", "CWE-311", "CWE-312", "CWE-326", "CWE-327", "CWE-330"]
            }
        }

        # 映射规则 (基于关键词和模式)
        self.mapping_rules = [
            # 内存管理相关
            {
                "keywords": ["malloc", "kmalloc", "alloc", "free", "kfree"],
                "patterns": [r"malloc|alloc|free"],
                "major": "Memory",
                "middle": "Memory Management",
                "cwe": "CWE-401",  # 默认映射到内存泄漏
                "confidence": 0.8
            },
            # 缓冲区溢出
            {
                "keywords": ["overflow", "buffer", "bounds", "size", "length", "memcpy", "strcpy"],
                "patterns": [r"overflow|buffer.*over|bounds", r"memcpy|strcpy|strcat"],
                "major": "Memory",
                "middle": "Buffer Errors",
                "cwe": "CWE-119",
                "confidence": 0.9
            },
            # 整数错误
            {
                "keywords": ["overflow", "underflow", "integer", "multiplication", "division"],
                "patterns": [r"overflow.*by.*multi", r"integer.*overflow", r"divide.*by.*zero"],
                "major": "Memory",
                "middle": "Integer Errors",
                "cwe": "CWE-190",
                "confidence": 0.8
            },
            # SQL 注入
            {
                "keywords": ["sql", "query", "database", "injection"],
                "patterns": [r"sql.*inject", r"query.*exec", r"database.*query"],
                "major": "Injection",
                "middle": "Injection",
                "cwe": "CWE-89",
                "confidence": 0.9
            },
            # 命令注入
            {
                "keywords": ["command", "exec", "eval", "shell", "system"],
                "patterns": [r"exec|system|shell", r"eval.*command"],
                "major": "Injection",
                "middle": "Injection",
                "cwe": "CWE-78",
                "confidence": 0.9
            },
            # XSS
            {
                "keywords": ["script", "html", "web", "xss", "javascript"],
                "patterns": [r"script.*inject", r"html.*inject", r"xss"],
                "major": "Injection",
                "middle": "Injection",
                "cwe": "CWE-79",
                "confidence": 0.8
            },
            # 路径遍历
            {
                "keywords": ["file", "path", "directory", "../", "..\\"],
                "patterns": [r"\.\.\/|\.\.\\", r"path.*traversal", r"directory.*traversal"],
                "major": "Input",
                "middle": "Path Traversal",
                "cwe": "CWE-22",
                "confidence": 0.8
            },
            # 输入验证
            {
                "keywords": ["validate", "sanitize", "input", "filter", "param"],
                "patterns": [r"input.*valid", r"param.*check", r"validate.*input"],
                "major": "Input",
                "middle": "Input Validation",
                "cwe": "CWE-20",
                "confidence": 0.7
            },
            # 空指针解引用
            {
                "keywords": ["null", "nullptr", "pointer", "dereference"],
                "patterns": [r"null.*pointer", r"pointer.*null", r"nullptr"],
                "major": "Memory",
                "middle": "Pointer Dereference",
                "cwe": "CWE-476",
                "confidence": 0.8
            },
            # 竞争条件
            {
                "keywords": ["race", "thread", "concurrent", "lock", "sync"],
                "patterns": [r"race.*condition", r"thread.*safe", r"concurrent.*access"],
                "major": "Logic",
                "middle": "Concurrency Issues",
                "cwe": "CWE-362",
                "confidence": 0.7
            }
        ]

    def map_cwd_to_cwe(self, cwd_id: str, code_text: str, metadata: Dict = None) -> Tuple[str, str, str, float]:
        """
        将 CWD 映射到 CWE 分类

        返回: (major, middle, cwe, confidence)
        """

        code_lower = code_text.lower()
        best_match = None
        best_confidence = 0.0

        for rule in self.mapping_rules:
            confidence = 0.0

            # 检查关键词匹配
            keyword_matches = sum(1 for keyword in rule["keywords"] if keyword in code_lower)
            if keyword_matches > 0:
                confidence += (keyword_matches / len(rule["keywords"])) * 0.6

            # 检查正则表达式模式
            pattern_matches = sum(1 for pattern in rule["patterns"] if re.search(pattern, code_lower))
            if pattern_matches > 0:
                confidence += (pattern_matches / len(rule["patterns"])) * 0.4

            # 调整置信度
            total_confidence = confidence * rule["confidence"]

            if total_confidence > best_confidence:
                best_confidence = total_confidence
                best_match = rule

        if best_match and best_confidence > 0.3:  # 最低置信度阈值
            return (
                best_match["major"],
                best_match["middle"],
                best_match["cwe"],
                best_confidence
            )
        else:
            # 默认分类
            return ("Logic", "Other", "", 0.1)

    def convert_cwd_example(self, cwd_id: str, example: Dict, language: str) -> CodeExample:
        """转换单个 CWD 示例为标准格式"""

        # 提取代码
        vuln_code = example.get("vulnerable_code", {})
        benign_code = example.get("benign_code", {})

        vulnerable_text = ""
        benign_text = ""
        context_text = ""

        # 组合漏洞代码
        if vuln_code.get("func"):
            vulnerable_text += vuln_code["func"]
        if vuln_code.get("context"):
            context_text += vuln_code["context"]

        # 组合良性代码
        if benign_code.get("func"):
            benign_text += benign_code["func"]
        if benign_code.get("context") and not context_text:
            context_text += benign_code["context"]

        # 整合所有代码用于分析
        all_code = f"{vulnerable_text} {benign_text} {context_text}"

        # 映射到 CWE
        major, middle, cwe, confidence = self.map_cwd_to_cwe(cwd_id, all_code, example)

        # 保留原始元数据
        metadata = {
            "source": example.get("source", "unknown"),
            "commit_url": example.get("commit_url"),
            "quality": example.get("quality"),
            "review_comment": example.get("review_comment"),
            "other_cwds": example.get("other_CWDs", []),
            "other_cwes": example.get("other_CWEs", []),
            "original_lines": {
                "vulnerable": vuln_code.get("lines", []),
                "benign": benign_code.get("lines", [])
            }
        }

        return CodeExample(
            vulnerable_code=vulnerable_text,
            benign_code=benign_text,
            context=context_text,
            language=language,
            cwd_id=cwd_id,
            mapped_cwe=cwe,
            mapped_middle=middle,
            mapped_major=major,
            confidence=confidence,
            metadata=metadata
        )

    def load_and_convert_cwd_data(self, data_dir: str) -> List[CodeExample]:
        """加载并转换 CWD 数据"""

        data_path = Path(data_dir)
        all_examples = []

        # 处理文件列表
        files_to_process = [
            data_path / "cwd_benchmark_2.json",
            data_path / "checked_codehub_benchmark.json"
        ]

        for file_path in files_to_process:
            if not file_path.exists():
                print(f"警告: 文件不存在 {file_path}")
                continue

            print(f"处理文件: {file_path}")

            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            for language in data:
                print(f"  处理语言: {language}")
                lang_examples = 0

                for cwd_id in data[language]:
                    examples = data[language][cwd_id]

                    for example in examples:
                        converted = self.convert_cwd_example(cwd_id, example, language)
                        all_examples.append(converted)
                        lang_examples += 1

                print(f"    转换了 {lang_examples} 个示例")

        return all_examples

    def generate_mapping_report(self, examples: List[CodeExample]) -> str:
        """生成映射报告"""

        from collections import Counter

        # 统计信息
        total_examples = len(examples)
        by_language = Counter(ex.language for ex in examples)
        by_major = Counter(ex.mapped_major for ex in examples)
        by_middle = Counter(ex.mapped_middle for ex in examples)
        by_confidence = Counter(f"{ex.confidence:.1f}" for ex in examples)

        # 高质量映射 (置信度 > 0.7)
        high_conf_examples = [ex for ex in examples if ex.confidence > 0.7]
        high_conf_by_cwe = Counter(ex.mapped_cwe for ex in high_conf_examples)

        report = f"""
# CWD 到 CWE 映射报告

## 总体统计
- 总示例数: {total_examples:,}
- 高质量映射 (置信度 > 0.7): {len(high_conf_examples):,} ({len(high_conf_examples)/total_examples*100:.1f}%)

## 按语言分布
{chr(10).join(f"- {lang}: {count:,}" for lang, count in by_language.most_common())}

## 按主要分类分布
{chr(10).join(f"- {major}: {count:,}" for major, count in by_major.most_common())}

## 按中间分类分布
{chr(10).join(f"- {middle}: {count:,}" for middle, count in by_middle.most_common(10))}

## 置信度分布
{chr(10).join(f"- {conf}: {count:,}" for conf, count in by_confidence.most_common())}

## 高质量 CWE 映射 (置信度 > 0.7)
{chr(10).join(f"- {cwe}: {count:,}" for cwe, count in high_conf_by_cwe.most_common(10))}

## 示例 CWD 映射
"""

        # 添加一些具体的映射示例
        for major in ["Memory", "Injection", "Input"]:
            major_examples = [ex for ex in high_conf_examples if ex.mapped_major == major][:3]
            if major_examples:
                report += f"\n### {major} 分类示例:\n"
                for ex in major_examples:
                    report += f"- {ex.cwd_id} -> {ex.mapped_cwe} ({ex.confidence:.2f})\n"
                    if ex.vulnerable_code:
                        code_snippet = ex.vulnerable_code[:100].replace('\n', ' ') + "..."
                        report += f"  代码: {code_snippet}\n"

        return report

    def export_to_mulvul_format(self, examples: List[CodeExample], output_file: str):
        """导出为 Mulvul 兼容的格式"""

        # 按 CWE 分类组织数据
        mulvul_data = {}

        for example in examples:
            if not example.mapped_cwe:  # 跳过无法映射的示例
                continue

            key = f"{example.language}_{example.mapped_cwe}"
            if key not in mulvul_data:
                mulvul_data[key] = {
                    "language": example.language,
                    "cwe": example.mapped_cwe,
                    "middle": example.mapped_middle,
                    "major": example.mapped_major,
                    "examples": []
                }

            mulvul_data[key]["examples"].append({
                "cwd_id": example.cwd_id,
                "vulnerable_code": example.vulnerable_code,
                "benign_code": example.benign_code,
                "context": example.context,
                "confidence": example.confidence,
                "metadata": example.metadata
            })

        # 保存到文件
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(mulvul_data, f, indent=2, ensure_ascii=False)

        print(f"导出 {len(mulvul_data)} 个 CWE 分类到 {output_file}")


def main():
    """主函数"""

    print("开始 CWD 到 CWE 映射转换...")

    # 初始化映射器
    mapper = CWDToCWEMapper()

    # 数据目录
    data_dir = "/Users/zihanwu/codes/Mulvul/data/enter"

    # 输出目录
    output_dir = Path("./")

    try:
        # 加载并转换数据
        print("加载 CWD 数据...")
        examples = mapper.load_and_convert_cwd_data(data_dir)

        print(f"成功转换 {len(examples)} 个代码示例")

        # 生成报告
        print("生成映射报告...")
        report = mapper.generate_mapping_report(examples)

        report_file = output_dir / "cwd_mapping_report.md"
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"报告保存到: {report_file}")

        # 导出为 Mulvul 格式
        print("导出 Mulvul 兼容格式...")
        output_file = output_dir / "cwd_converted_data.json"
        mapper.export_to_mulvul_format(examples, str(output_file))

        print("转换完成!")

    except Exception as e:
        print(f"转换失败: {e}")
        raise


if __name__ == "__main__":
    main()