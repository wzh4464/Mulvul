#!/usr/bin/env python3
"""
第一阶段：提取高置信度 CWD 数据
从原始 CWD 数据中提取 41 个高置信度映射的示例
"""

import json
import os
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Any

def load_mappings(mapping_file: str) -> Dict:
    """加载映射配置"""
    with open(mapping_file, 'r', encoding='utf-8') as f:
        return json.load(f)

def extract_high_confidence_examples(
    mappings: Dict,
    confidence_threshold: float = 0.8
) -> Dict[str, Any]:
    """提取高置信度 CWD 示例"""

    print(f"开始提取置信度 ≥ {confidence_threshold} 的 CWD 数据...")

    # 筛选高置信度映射
    high_conf_cwds = []
    for cwd_id, data in mappings['semantic_mappings'].items():
        if data['confidence'] >= confidence_threshold:
            high_conf_cwds.append(cwd_id)

    print(f"找到 {len(high_conf_cwds)} 个高置信度 CWD 分类")

    # CWD 数据源文件
    cwd_data_files = [
        "/Users/zihanwu/codes/Mulvul/data/enter/cwd_benchmark_2.json",
        "/Users/zihanwu/codes/Mulvul/data/enter/checked_codehub_benchmark.json"
    ]

    extracted_data = {}
    total_examples = 0

    for file_path in cwd_data_files:
        if not os.path.exists(file_path):
            print(f"警告: 文件不存在 {file_path}")
            continue

        print(f"处理文件: {file_path}")

        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        for lang in data:
            for cwd_id in high_conf_cwds:
                if cwd_id in data[lang]:
                    key = f"{lang}_{cwd_id}"
                    examples = data[lang][cwd_id]

                    extracted_data[key] = {
                        'cwd_id': cwd_id,
                        'language': lang,
                        'examples': examples,
                        'mapping': mappings['semantic_mappings'][cwd_id],
                        'example_count': len(examples)
                    }

                    total_examples += len(examples)
                    print(f"  {key}: {len(examples)} 个示例")

    print(f"\n提取完成:")
    print(f"  数据集数量: {len(extracted_data)}")
    print(f"  示例总数: {total_examples}")

    return extracted_data

def analyze_extracted_data(extracted_data: Dict) -> Dict:
    """分析提取的数据"""

    stats = {
        'total_datasets': len(extracted_data),
        'total_examples': sum(d['example_count'] for d in extracted_data.values()),
        'by_language': defaultdict(int),
        'by_major': defaultdict(int),
        'by_middle': defaultdict(int),
        'by_cwe': defaultdict(int),
        'by_confidence': defaultdict(int),
        'example_distribution': []
    }

    for key, data in extracted_data.items():
        lang = data['language']
        mapping = data['mapping']
        count = data['example_count']

        stats['by_language'][lang] += count
        stats['by_major'][mapping['major']] += count
        stats['by_middle'][mapping['middle']] += count
        if mapping['cwe']:
            stats['by_cwe'][mapping['cwe']] += count

        # 置信度分组
        conf_group = f"{mapping['confidence']:.1f}"
        stats['by_confidence'][conf_group] += count

        stats['example_distribution'].append({
            'dataset': key,
            'cwd_id': data['cwd_id'],
            'language': lang,
            'examples': count,
            'major': mapping['major'],
            'middle': mapping['middle'],
            'cwe': mapping['cwe'],
            'confidence': mapping['confidence']
        })

    # 排序示例分布
    stats['example_distribution'].sort(key=lambda x: x['examples'], reverse=True)

    return stats

def generate_quality_report(stats: Dict) -> str:
    """生成数据质量报告"""

    report = f"""# 第一阶段 CWD 数据提取报告

## 总体统计
- 提取数据集: {stats['total_datasets']} 个
- 代码示例总数: {stats['total_examples']:,} 个
- 平均每数据集: {stats['total_examples'] / stats['total_datasets']:.1f} 个示例

## 语言分布
{chr(10).join(f"- {lang}: {count:,} 个示例" for lang, count in sorted(stats['by_language'].items()))}

## 分类映射分布

### 按主要分类
{chr(10).join(f"- {major}: {count:,} 个示例" for major, count in sorted(stats['by_major'].items(), key=lambda x: x[1], reverse=True))}

### 按中间分类
{chr(10).join(f"- {middle}: {count:,} 个示例" for middle, count in sorted(stats['by_middle'].items(), key=lambda x: x[1], reverse=True))}

### 按 CWE 分类
{chr(10).join(f"- {cwe}: {count:,} 个示例" for cwe, count in sorted(stats['by_cwe'].items(), key=lambda x: x[1], reverse=True) if cwe)}

## 置信度分布
{chr(10).join(f"- {conf}: {count:,} 个示例" for conf, count in sorted(stats['by_confidence'].items(), key=lambda x: float(x[0]), reverse=True))}

## 数据集详细分布

| 数据集 | CWD ID | 语言 | 示例数 | 主分类 | 中分类 | CWE | 置信度 |
|--------|--------|------|--------|--------|--------|-----|--------|"""

    for item in stats['example_distribution'][:20]:  # 显示前20个
        report += f"""
| {item['dataset']} | {item['cwd_id']} | {item['language']} | {item['examples']} | {item['major']} | {item['middle']} | {item['cwe']} | {item['confidence']:.2f} |"""

    if len(stats['example_distribution']) > 20:
        report += f"\n\n... 省略了 {len(stats['example_distribution']) - 20} 个数据集"

    # 添加质量评估
    report += f"""

## 数据质量评估

### 优点 ✅
- **高置信度**: 所有映射置信度 ≥ 0.8
- **数据丰富**: {stats['total_examples']:,} 个示例，足够训练使用
- **分类覆盖**: 覆盖 {len(stats['by_major'])} 个主分类，{len(stats['by_cwe'])} 个 CWE
- **多语言**: 支持 {len(stats['by_language'])} 种编程语言

### 注意事项 ⚠️
- **分布不均**: 某些分类的示例数量较少，可能需要平衡
- **语言偏向**: 检查是否存在语言分布偏差
- **质量验证**: 建议对前 10% 的数据进行人工验证

### 推荐的下一步
1. 对示例数量 > 100 的数据集进行抽样验证
2. 检查代码示例的完整性和正确性
3. 验证漏洞代码与良性代码的配对关系
4. 确认映射分类的准确性

## 数据使用建议

### 训练策略
- **分层采样**: 按分类比例进行平衡采样
- **质量筛选**: 优先使用高质量评分的示例
- **渐进集成**: 先使用示例数量最多的前 10 个分类进行验证

### 风险控制
- **baseline 对比**: 与现有训练数据进行对比测试
- **A/B 测试**: 使用部分数据验证效果后再全量使用
- **监控指标**: 重点监控映射分类的检测准确率变化
"""

    return report

def save_results(extracted_data: Dict, stats: Dict, output_dir: str = "."):
    """保存提取结果"""

    output_path = Path(output_dir)

    # 保存提取的数据
    data_file = output_path / "phase1_cwd_data.json"
    with open(data_file, 'w', encoding='utf-8') as f:
        json.dump(extracted_data, f, indent=2, ensure_ascii=False)
    print(f"高置信度数据保存到: {data_file}")

    # 保存质量报告
    report = generate_quality_report(stats)
    report_file = output_path / "data_quality_report.md"
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(report)
    print(f"质量报告保存到: {report_file}")

    # 保存统计数据
    stats_file = output_path / "extraction_stats.json"
    with open(stats_file, 'w', encoding='utf-8') as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)
    print(f"统计数据保存到: {stats_file}")

def main():
    """主函数"""

    print("=" * 60)
    print("第一阶段：CWD 高置信度数据提取")
    print("=" * 60)

    # 检查必需文件
    mapping_file = "enhanced_cwd_mappings.json"
    if not os.path.exists(mapping_file):
        print(f"错误: 找不到映射文件 {mapping_file}")
        print("请先运行 enhanced_cwd_mapper.py 生成映射文件")
        return

    try:
        # 加载映射配置
        mappings = load_mappings(mapping_file)

        # 提取高置信度数据
        extracted_data = extract_high_confidence_examples(mappings)

        if not extracted_data:
            print("警告: 没有提取到任何数据")
            return

        # 分析数据质量
        stats = analyze_extracted_data(extracted_data)

        # 保存结果
        save_results(extracted_data, stats)

        print(f"\n✅ 提取完成!")
        print(f"   数据集: {stats['total_datasets']} 个")
        print(f"   示例: {stats['total_examples']:,} 个")
        print(f"   主分类: {len(stats['by_major'])} 个")
        print(f"   CWE: {len([c for c in stats['by_cwe'] if c])} 个")

        # 显示下一步建议
        print(f"\n📋 下一步:")
        print(f"   1. 查看 data_quality_report.md 了解数据详情")
        print(f"   2. 运行 convert_to_prompt_bundle.py 进行格式转换")
        print(f"   3. 进行人工抽样验证")

    except Exception as e:
        print(f"❌ 提取失败: {e}")
        raise

if __name__ == "__main__":
    main()