#!/usr/bin/env python3
"""
创建 CWD 原生数据集
抛弃 CWE 映射，直接构建基于 CWD 的原生漏洞检测数据集
"""

import json
import re
from pathlib import Path
from collections import defaultdict, Counter
from typing import Dict, List, Any, Optional

class CWDNativeDatasetCreator:
    """CWD 原生数据集创建器"""

    def __init__(self):
        # 加载 CWD 字典定义
        self.cwd_definitions = self._load_cwd_definitions()

    def _load_cwd_definitions(self) -> Dict[str, Dict]:
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
                        languages = [lang.strip().lower() for lang in lang_str.split(',')]

                    # 提取严重等级
                    severity_match = re.search(r'\*\*严重等级\*\*\s*\n(.*?)(?=\n|\*\*)', section_content)
                    severity = severity_match.group(1).strip() if severity_match else "未知"

                    # 提取 CleanCode 特征
                    cleancode_match = re.search(r'\*\*cleancode特征\*\*\s*\n(.*?)(?=\n|\*\*)', section_content)
                    cleancode = cleancode_match.group(1).strip() if cleancode_match else ""

                    definitions[cwd_id] = {
                        'id': cwd_id,
                        'name': cwd_name,
                        'description': description,
                        'languages': languages,
                        'severity': severity,
                        'cleancode': cleancode,
                        'full_section': section_content
                    }

            print(f"加载了 {len(definitions)} 个 CWD 定义")

        except Exception as e:
            print(f"加载 CWD 字典失败: {e}")

        return definitions

    def load_raw_cwd_data(self, data_dir: str) -> Dict[str, Any]:
        """加载原始 CWD 数据"""

        data_path = Path(data_dir)
        all_data = {}

        # 处理数据文件
        data_files = [
            data_path / "cwd_benchmark_2.json",
            data_path / "checked_codehub_benchmark.json"
        ]

        for file_path in data_files:
            if not file_path.exists():
                print(f"警告: 文件不存在 {file_path}")
                continue

            print(f"加载文件: {file_path}")

            with open(file_path, 'r', encoding='utf-8') as f:
                file_data = json.load(f)

            # 合并数据
            for language in file_data:
                if language not in all_data:
                    all_data[language] = {}

                for cwd_id in file_data[language]:
                    if cwd_id not in all_data[language]:
                        all_data[language][cwd_id] = []

                    all_data[language][cwd_id].extend(file_data[language][cwd_id])

        return all_data

    def create_native_examples(self, raw_data: Dict[str, Any]) -> List[Dict]:
        """创建 CWD 原生示例"""

        examples = []
        example_id = 1

        print("创建 CWD 原生示例...")

        for language in raw_data:
            print(f"  处理语言: {language}")

            for cwd_id in raw_data[language]:
                if cwd_id not in self.cwd_definitions:
                    print(f"    警告: CWD {cwd_id} 未在字典中找到")
                    continue

                cwd_def = self.cwd_definitions[cwd_id]
                raw_examples = raw_data[language][cwd_id]

                for raw_example in raw_examples:
                    # 提取代码内容
                    example = self._process_single_example(
                        example_id, raw_example, cwd_id, cwd_def, language
                    )

                    if example:
                        examples.append(example)
                        example_id += 1

        print(f"创建了 {len(examples)} 个原生示例")
        return examples

    def _process_single_example(self, example_id: int, raw_example: Dict,
                               cwd_id: str, cwd_def: Dict, language: str) -> Optional[Dict]:
        """处理单个示例"""

        # 提取漏洞代码和良性代码
        vuln_code = raw_example.get('vulnerable_code', {})
        benign_code = raw_example.get('benign_code', {})

        # 构建代码内容
        vulnerable_text = self._extract_code_text(vuln_code)
        benign_text = self._extract_code_text(benign_code)

        # 至少需要有一个代码
        if not vulnerable_text and not benign_text:
            return None

        # 构建示例
        example = {
            'id': f"cwd_{example_id:06d}",
            'code': {
                'vulnerable': vulnerable_text,
                'benign': benign_text,
                'context': vuln_code.get('context', '') or benign_code.get('context', '')
            },
            'labels': {
                'cwd_id': cwd_id,
                'cwd_name': cwd_def['name'],
                'cwd_description': cwd_def['description'][:200] + "..." if len(cwd_def['description']) > 200 else cwd_def['description'],
                'language': language,
                'severity': cwd_def['severity'],
                'cleancode': cwd_def['cleancode']
            },
            'metadata': {
                'source': raw_example.get('source', 'unknown'),
                'commit_url': raw_example.get('commit_url'),
                'quality': raw_example.get('quality'),
                'review_comment': raw_example.get('review_comment'),
                'other_cwds': raw_example.get('other_CWDs', []),
                'other_cwes': raw_example.get('other_CWEs', []),
                'lines': {
                    'vulnerable': vuln_code.get('lines', []),
                    'benign': benign_code.get('lines', [])
                }
            }
        }

        return example

    def _extract_code_text(self, code_data: Dict) -> str:
        """提取代码文本"""
        if not code_data:
            return ""

        parts = []
        if code_data.get('func'):
            parts.append(code_data['func'])
        if code_data.get('class'):
            parts.append(code_data['class'])

        return '\n\n'.join(parts)

    def analyze_dataset(self, examples: List[Dict]) -> Dict:
        """分析数据集统计信息"""

        stats = {
            'total_examples': len(examples),
            'by_language': Counter(),
            'by_cwd': Counter(),
            'by_severity': Counter(),
            'by_source': Counter(),
            'code_length_stats': {'vulnerable': [], 'benign': []},
            'quality_stats': {'with_quality': 0, 'avg_quality': {}},
            'cwd_distribution': []
        }

        for example in examples:
            labels = example['labels']
            metadata = example['metadata']
            code = example['code']

            # 基础统计
            stats['by_language'][labels['language']] += 1
            stats['by_cwd'][labels['cwd_id']] += 1
            stats['by_severity'][labels['severity']] += 1
            stats['by_source'][metadata['source']] += 1

            # 代码长度统计
            if code['vulnerable']:
                stats['code_length_stats']['vulnerable'].append(len(code['vulnerable']))
            if code['benign']:
                stats['code_length_stats']['benign'].append(len(code['benign']))

            # 质量统计
            if metadata.get('quality'):
                stats['quality_stats']['with_quality'] += 1
                quality = metadata['quality']
                for metric, value in quality.items():
                    if metric not in stats['quality_stats']['avg_quality']:
                        stats['quality_stats']['avg_quality'][metric] = []
                    stats['quality_stats']['avg_quality'][metric].append(value)

        # 计算平均质量分数
        for metric, values in stats['quality_stats']['avg_quality'].items():
            stats['quality_stats']['avg_quality'][metric] = sum(values) / len(values)

        # CWD 分布详情
        for cwd_id, count in stats['by_cwd'].most_common():
            cwd_def = self.cwd_definitions.get(cwd_id, {})
            stats['cwd_distribution'].append({
                'cwd_id': cwd_id,
                'cwd_name': cwd_def.get('name', 'Unknown'),
                'count': count,
                'percentage': count / stats['total_examples'] * 100
            })

        return stats

    def save_dataset(self, examples: List[Dict], stats: Dict, output_file: str):
        """保存数据集"""

        dataset = {
            'metadata': {
                'version': '1.0_native_cwd',
                'total_examples': len(examples),
                'cwd_classes': len(stats['by_cwd']),
                'languages': list(stats['by_language'].keys()),
                'creation_date': '2026-04-13',
                'source': 'CWD代码缺陷字典 V1.5',
                'description': 'Native CWD detection dataset without CWE mapping'
            },
            'cwd_definitions': self.cwd_definitions,
            'statistics': stats,
            'examples': examples
        }

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(dataset, f, indent=2, ensure_ascii=False)

        print(f"数据集保存到: {output_file}")

    def generate_report(self, stats: Dict, output_file: str):
        """生成分析报告"""

        report = f"""# CWD 原生数据集分析报告

## 总体统计
- 示例总数: {stats['total_examples']:,}
- CWD 分类: {len(stats['by_cwd'])} 个
- 支持语言: {len(stats['by_language'])} 种
- 数据源: {len(stats['by_source'])} 个

## 语言分布
{chr(10).join(f"- {lang}: {count:,} 个 ({count/stats['total_examples']*100:.1f}%)" for lang, count in stats['by_language'].most_common())}

## 严重等级分布
{chr(10).join(f"- {severity}: {count:,} 个 ({count/stats['total_examples']*100:.1f}%)" for severity, count in stats['by_severity'].most_common())}

## 数据源分布
{chr(10).join(f"- {source}: {count:,} 个 ({count/stats['total_examples']*100:.1f}%)" for source, count in stats['by_source'].most_common())}

## CWD 分类分布 (Top 20)

| CWD ID | 名称 | 示例数 | 占比 |
|--------|------|--------|------|"""

        for item in stats['cwd_distribution'][:20]:
            report += f"\n| {item['cwd_id']} | {item['cwd_name'][:30]}... | {item['count']:,} | {item['percentage']:.2f}% |"

        # 代码长度统计
        vuln_lengths = stats['code_length_stats']['vulnerable']
        benign_lengths = stats['code_length_stats']['benign']

        if vuln_lengths:
            report += f"""

## 代码长度统计

### 漏洞代码
- 平均长度: {sum(vuln_lengths)/len(vuln_lengths):.0f} 字符
- 中位数: {sorted(vuln_lengths)[len(vuln_lengths)//2]:,} 字符
- 最短: {min(vuln_lengths):,} 字符
- 最长: {max(vuln_lengths):,} 字符

### 良性代码
- 平均长度: {sum(benign_lengths)/len(benign_lengths):.0f} 字符 (如果有)
- 总计: {len(benign_lengths):,} 个良性示例"""

        # 质量统计
        if stats['quality_stats']['with_quality'] > 0:
            report += f"""

## 质量评估统计
- 包含质量评估的示例: {stats['quality_stats']['with_quality']:,} 个
- 质量指标平均分:"""
            for metric, avg_score in stats['quality_stats']['avg_quality'].items():
                report += f"\n  - {metric}: {avg_score:.2f}"

        # 数据质量分析
        report += f"""

## 数据质量分析

### 优势 ✅
- **规模充足**: {stats['total_examples']:,} 个示例，足够训练深度学习模型
- **分类丰富**: {len(stats['by_cwd'])} 个 CWD 分类，提供细粒度检测
- **多语言**: 支持 {', '.join(stats['by_language'].keys())} 等编程语言
- **工程实践**: 基于企业真实代码审查经验

### 挑战 ⚠️
- **类别不平衡**: 不同 CWD 分类的示例数量差异很大
- **长尾分布**: 部分 CWD 分类样本较少 (<10 个)
- **语言偏向**: 某些语言的数据可能更多

### 建议策略
1. **分层训练**: 先训练高频 CWD，再逐步加入低频 CWD
2. **数据增强**: 对样本较少的 CWD 进行代码变换增强
3. **类别权重**: 使用加权损失函数处理不平衡问题
4. **层次分类**: 考虑按语义相似性构建层次分类器

## 下一步建议

1. **数据预处理**:
   - 清理和标准化代码格式
   - 移除过短或过长的代码片段
   - 验证 CWD 标签的准确性

2. **模型设计**:
   - 使用预训练的代码模型 (CodeBERT, CodeT5)
   - 设计处理类别不平衡的损失函数
   - 考虑多任务学习 (CWD + 严重等级)

3. **评估策略**:
   - 建立分层评估指标 (按频率、语言、严重等级)
   - 设计 CWD 特定的评估基准
   - 与人工标注进行一致性验证
"""

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report)

        print(f"分析报告保存到: {output_file}")

def main():
    """主函数"""

    print("🚀 创建 CWD 原生检测数据集")
    print("=" * 50)

    # 初始化创建器
    creator = CWDNativeDatasetCreator()

    # 数据目录
    data_dir = "/Users/zihanwu/codes/Mulvul/data/enter"

    try:
        # 加载原始数据
        print("📂 加载原始 CWD 数据...")
        raw_data = creator.load_raw_cwd_data(data_dir)

        if not raw_data:
            print("❌ 没有找到任何数据")
            return

        # 创建原生示例
        print("🔄 创建 CWD 原生示例...")
        examples = creator.create_native_examples(raw_data)

        if not examples:
            print("❌ 没有创建任何示例")
            return

        # 分析数据集
        print("📊 分析数据集统计...")
        stats = creator.analyze_dataset(examples)

        # 保存数据集
        print("💾 保存数据集...")
        creator.save_dataset(examples, stats, "cwd_native_dataset.json")

        # 生成报告
        print("📋 生成分析报告...")
        creator.generate_report(stats, "cwd_native_analysis.md")

        # 显示结果
        print(f"\n✅ 数据集创建完成!")
        print(f"   示例总数: {stats['total_examples']:,}")
        print(f"   CWD 分类: {len(stats['by_cwd'])}")
        print(f"   支持语言: {', '.join(stats['by_language'].keys())}")
        print(f"   输出文件: cwd_native_dataset.json ({len(examples)*1000//1024//1024}MB)")

        # 显示下一步
        print(f"\n📋 下一步:")
        print(f"   1. 查看 cwd_native_analysis.md 了解数据详情")
        print(f"   2. 开发 CWD 原生分类器")
        print(f"   3. 训练和评估模型")

    except Exception as e:
        print(f"❌ 创建失败: {e}")
        raise

if __name__ == "__main__":
    main()