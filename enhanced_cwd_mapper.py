#!/usr/bin/env python3
"""
基于 CWD 字典的精确映射工具
使用 CWD代码缺陷字典 V1.5.md 中的语义定义进行精确映射
"""

import re
import json
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass

@dataclass
class CWDDefinition:
    """CWD 分类定义"""
    id: str
    name: str
    description: str
    languages: List[str]
    severity: str
    mapped_cwe: Optional[str] = None
    mapped_middle: Optional[str] = None
    mapped_major: Optional[str] = None
    confidence: float = 0.0

class EnhancedCWDMapper:
    """基于语义的 CWD 映射器"""

    def __init__(self):
        # 加载 CWD 字典定义
        self.cwd_definitions = self._load_cwd_definitions()

        # 基于语义的精确映射规则
        self.semantic_mappings = {
            # 内存管理相关
            "CWD-1002": ("Memory", "Memory Management", "CWE-770", 0.95),  # 内存分配大小未受限 -> 资源管理
            "CWD-1003": ("Memory", "Buffer Errors", "CWE-131", 0.95),      # 缓冲区大小计算错误 -> 缓冲区大小计算错误
            "CWD-1007": ("Memory", "Buffer Errors", "CWE-119", 0.90),      # 不正确的逐位操作 -> 缓冲区溢出
            "CWD-1009": ("Memory", "Buffer Errors", "CWE-120", 0.90),      # 未受认可的内存安全函数 -> 经典缓冲区溢出
            "CWD-1015": ("Memory", "Buffer Errors", "CWE-125", 0.95),      # 源缓冲区访问长度设置不正确 -> 越界读
            "CWD-1016": ("Memory", "Buffer Errors", "CWE-787", 0.95),      # 目的缓冲区访问长度设置不正确 -> 越界写
            "CWD-1017": ("Memory", "Buffer Errors", "CWE-119", 0.95),      # 内存拷贝重叠 -> 缓冲区溢出
            "CWD-1021": ("Memory", "Memory Management", "CWE-415", 0.95),  # 释放非堆内存 -> 双重释放
            "CWD-1022": ("Memory", "Memory Management", "CWE-401", 0.90),  # 申请释放函数未配对 -> 内存泄漏
            "CWD-1023": ("Memory", "Memory Management", "CWE-415", 0.95),  # 释放未在缓冲区起始处的指针 -> 双重释放
            "CWD-1025": ("Memory", "Memory Management", "CWE-415", 0.95),  # 双重释放内存 -> 双重释放
            "CWD-1026": ("Memory", "Memory Management", "CWE-416", 0.95),  # 访问已释放内存 -> 释放后使用
            "CWD-1027": ("Memory", "Memory Management", "CWE-401", 0.95),  # 内存泄漏 -> 内存泄漏
            "CWD-1028": ("Memory", "Buffer Errors", "CWE-125", 0.95),      # 数组索引越界 -> 越界读
            "CWD-1029": ("Memory", "Buffer Errors", "CWE-119", 0.90),      # 指针偏移量超出范围 -> 缓冲区溢出
            "CWD-1030": ("Memory", "Pointer Dereference", "CWE-476", 0.95), # 访问未初始化的指针 -> 空指针解引用
            "CWD-1019": ("Memory", "Pointer Dereference", "CWE-476", 0.85), # 返回栈变量地址 -> 空指针解引用相关

            # 字节序和数据处理
            "CWD-1005": ("Logic", "Other", "", 0.80),                      # 不正确的字节序
            "CWD-1006": ("Logic", "Other", "", 0.80),                      # 依赖带位域的结构体的内存布局
            "CWD-1008": ("Logic", "Other", "", 0.80),                      # std::vector<bool>兼容性问题

            # 整数错误相关
            "CWD-1031": ("Memory", "Integer Errors", "CWE-190", 0.95),     # 整数溢出
            "CWD-1034": ("Memory", "Integer Errors", "CWE-369", 0.95),     # 除零错误

            # 注入攻击相关
            "CWD-1068": ("Injection", "Injection", "CWE-89", 0.95),       # SQL注入
            "CWD-1070": ("Injection", "Injection", "CWE-79", 0.95),       # XSS攻击
            "CWD-1071": ("Injection", "Injection", "CWE-94", 0.95),       # 代码注入
            "CWD-1081": ("Injection", "Injection", "CWE-78", 0.95),       # 命令注入
            "CWD-1082": ("Injection", "Injection", "CWE-77", 0.90),       # 命令注入变体

            # 输入验证相关
            "CWD-1038": ("Input", "Input Validation", "CWE-20", 0.90),    # 输入验证不当
            "CWD-1039": ("Input", "Path Traversal", "CWE-22", 0.95),      # 路径遍历
            "CWD-1040": ("Input", "Input Validation", "CWE-703", 0.85),   # 异常处理不当

            # 访问控制相关
            "CWD-1042": ("Logic", "Access Control", "CWE-284", 0.90),     # 访问控制不当
            "CWD-1043": ("Logic", "Access Control", "CWE-269", 0.90),     # 权限管理不当

            # 并发相关
            "CWD-1084": ("Logic", "Concurrency Issues", "CWE-362", 0.90), # 竞争条件
            "CWD-1093": ("Logic", "Concurrency Issues", "CWE-667", 0.85), # 不当锁定

            # 信息泄露相关
            "CWD-1096": ("Logic", "Information Exposure", "CWE-200", 0.90), # 信息泄露
            "CWD-1101": ("Logic", "Information Exposure", "CWE-209", 0.85), # 错误信息泄露

            # 资源管理相关
            "CWD-1113": ("Logic", "Resource Management", "CWE-400", 0.90), # 资源消耗不受控
            "CWD-1114": ("Logic", "Resource Management", "CWE-770", 0.85), # 功能限制不当
            "CWD-1115": ("Logic", "Resource Management", "CWE-835", 0.80), # 无限循环

            # 加密相关
            "CWD-1044": ("Crypto", "Cryptography Issues", "CWE-327", 0.90), # 加密算法不当
            "CWD-1045": ("Crypto", "Cryptography Issues", "CWE-330", 0.85), # 随机数生成不当
        }

    def _load_cwd_definitions(self) -> Dict[str, CWDDefinition]:
        """从字典文件加载 CWD 定义"""
        definitions = {}

        try:
            dict_file = "/Users/zihanwu/codes/Mulvul/data/enter/CWD代码缺陷字典 V1.5.md"
            with open(dict_file, 'r', encoding='utf-8') as f:
                content = f.read()

            # 解析 CWD 定义
            cwd_sections = re.split(r'^# (CWD-\d+)\s+(.+)$', content, flags=re.MULTILINE)

            for i in range(1, len(cwd_sections), 3):
                if i + 2 < len(cwd_sections):
                    cwd_id = cwd_sections[i]
                    cwd_name = cwd_sections[i + 1]
                    section_content = cwd_sections[i + 2]

                    # 提取描述
                    desc_match = re.search(r'\*\*描述\*\*\s*\n(.*?)(?=\n\*\*|$)', section_content, re.DOTALL)
                    description = desc_match.group(1).strip() if desc_match else ""

                    # 提取支持的语言
                    lang_match = re.search(r'\*\*语言:\s*\*\*(.*?)(?=\n|\*\*)', section_content)
                    languages = []
                    if lang_match:
                        lang_str = lang_match.group(1).strip()
                        languages = [lang.strip() for lang in lang_str.split(',')]

                    # 提取严重等级
                    severity_match = re.search(r'\*\*严重等级\*\*\s*\n(.*?)(?=\n|\*\*)', section_content)
                    severity = severity_match.group(1).strip() if severity_match else "未知"

                    definitions[cwd_id] = CWDDefinition(
                        id=cwd_id,
                        name=cwd_name,
                        description=description,
                        languages=languages,
                        severity=severity
                    )

        except Exception as e:
            print(f"加载 CWD 字典失败: {e}")

        return definitions

    def get_precise_mapping(self, cwd_id: str) -> Tuple[str, str, str, float]:
        """获取精确的映射结果"""

        if cwd_id in self.semantic_mappings:
            major, middle, cwe, confidence = self.semantic_mappings[cwd_id]
            return major, middle, cwe, confidence
        else:
            # 未知的 CWD，返回默认分类
            return "Logic", "Other", "", 0.1

    def analyze_cwd_coverage(self) -> Dict:
        """分析 CWD 映射覆盖率"""

        total_cwds = len(self.cwd_definitions)
        mapped_cwds = len(self.semantic_mappings)

        # 按分类统计
        major_stats = {}
        middle_stats = {}
        cwe_stats = {}

        for cwd_id, (major, middle, cwe, conf) in self.semantic_mappings.items():
            major_stats[major] = major_stats.get(major, 0) + 1
            middle_stats[middle] = middle_stats.get(middle, 0) + 1
            if cwe:
                cwe_stats[cwe] = cwe_stats.get(cwe, 0) + 1

        # 按严重等级统计
        severity_stats = {}
        for cwd_id, defn in self.cwd_definitions.items():
            severity_stats[defn.severity] = severity_stats.get(defn.severity, 0) + 1

        return {
            "coverage": {
                "total_cwds": total_cwds,
                "mapped_cwds": mapped_cwds,
                "coverage_rate": mapped_cwds / total_cwds * 100
            },
            "mapping_distribution": {
                "by_major": major_stats,
                "by_middle": middle_stats,
                "by_cwe": cwe_stats
            },
            "severity_distribution": severity_stats,
            "unmapped_cwds": [cwd_id for cwd_id in self.cwd_definitions.keys()
                             if cwd_id not in self.semantic_mappings]
        }

    def generate_enhanced_mapping_report(self) -> str:
        """生成增强的映射报告"""

        analysis = self.analyze_cwd_coverage()

        report = f"""
# 基于 CWD 字典的精确映射报告

## 映射覆盖率
- CWD 字典总数: {analysis['coverage']['total_cwds']}
- 已映射数量: {analysis['coverage']['mapped_cwds']}
- 覆盖率: {analysis['coverage']['coverage_rate']:.1f}%

## 映射分布

### 按主要分类
{chr(10).join(f"- {major}: {count} 个" for major, count in analysis['mapping_distribution']['by_major'].items())}

### 按中间分类
{chr(10).join(f"- {middle}: {count} 个" for middle, count in analysis['mapping_distribution']['by_middle'].items())}

### 按 CWE 分类
{chr(10).join(f"- {cwe}: {count} 个" for cwe, count in sorted(analysis['mapping_distribution']['by_cwe'].items()))}

## 严重等级分布
{chr(10).join(f"- {severity}: {count} 个" for severity, count in analysis['severity_distribution'].items())}

## 详细映射列表

### 高置信度映射 (置信度 ≥ 0.9)
"""

        # 添加高置信度映射详情
        for cwd_id, (major, middle, cwe, conf) in self.semantic_mappings.items():
            if conf >= 0.9:
                cwd_def = self.cwd_definitions.get(cwd_id)
                if cwd_def:
                    report += f"\n**{cwd_id}: {cwd_def.name}** ({conf:.2f})\n"
                    report += f"- 映射: {major} -> {middle} -> {cwe}\n"
                    report += f"- 语言: {', '.join(cwd_def.languages)}\n"
                    report += f"- 严重等级: {cwd_def.severity}\n"
                    if cwd_def.description:
                        desc_short = cwd_def.description[:100] + "..." if len(cwd_def.description) > 100 else cwd_def.description
                        report += f"- 描述: {desc_short}\n"

        # 添加未映射的 CWD 列表
        if analysis['unmapped_cwds']:
            report += f"\n## 未映射的 CWD 分类 ({len(analysis['unmapped_cwds'])} 个)\n"
            for cwd_id in analysis['unmapped_cwds'][:10]:  # 只显示前10个
                cwd_def = self.cwd_definitions.get(cwd_id)
                if cwd_def:
                    report += f"- {cwd_id}: {cwd_def.name}\n"

        return report

    def export_enhanced_mapping(self, output_file: str):
        """导出增强的映射结果"""

        mapping_data = {
            "metadata": {
                "version": "1.5_enhanced",
                "total_cwds": len(self.cwd_definitions),
                "mapped_cwds": len(self.semantic_mappings),
                "coverage_rate": len(self.semantic_mappings) / len(self.cwd_definitions) * 100
            },
            "cwd_definitions": {},
            "semantic_mappings": {}
        }

        # 导出 CWD 定义
        for cwd_id, defn in self.cwd_definitions.items():
            mapping_data["cwd_definitions"][cwd_id] = {
                "name": defn.name,
                "description": defn.description,
                "languages": defn.languages,
                "severity": defn.severity
            }

        # 导出映射关系
        for cwd_id, (major, middle, cwe, conf) in self.semantic_mappings.items():
            cwd_def = self.cwd_definitions.get(cwd_id)
            definition_dict = {}
            if cwd_def:
                definition_dict = {
                    "name": cwd_def.name,
                    "description": cwd_def.description,
                    "languages": cwd_def.languages,
                    "severity": cwd_def.severity
                }

            mapping_data["semantic_mappings"][cwd_id] = {
                "major": major,
                "middle": middle,
                "cwe": cwe,
                "confidence": conf,
                "definition": definition_dict
            }

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(mapping_data, f, indent=2, ensure_ascii=False)

        print(f"增强映射导出到: {output_file}")

def main():
    """主函数"""

    print("开始基于 CWD 字典的精确映射分析...")

    try:
        # 初始化增强映射器
        mapper = EnhancedCWDMapper()

        print(f"加载了 {len(mapper.cwd_definitions)} 个 CWD 定义")
        print(f"配置了 {len(mapper.semantic_mappings)} 个精确映射")

        # 生成增强报告
        report = mapper.generate_enhanced_mapping_report()

        # 保存报告
        report_file = "enhanced_cwd_mapping_report.md"
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"增强报告保存到: {report_file}")

        # 导出映射数据
        mapping_file = "enhanced_cwd_mappings.json"
        mapper.export_enhanced_mapping(mapping_file)

        # 分析覆盖率
        analysis = mapper.analyze_cwd_coverage()
        print(f"\n映射覆盖率: {analysis['coverage']['coverage_rate']:.1f}%")

        print("\n增强映射分析完成！")

    except Exception as e:
        print(f"分析失败: {e}")
        raise

if __name__ == "__main__":
    main()