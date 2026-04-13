#!/usr/bin/env python3
"""
第一阶段快速启动脚本
自动化执行第一阶段的关键步骤
"""

import os
import subprocess
import sys
from pathlib import Path

def check_prerequisites():
    """检查先决条件"""
    print("🔍 检查先决条件...")

    required_files = [
        "enhanced_cwd_mappings.json",
        "enhanced_cwd_mapper.py",
        "extract_high_confidence_data.py"
    ]

    missing_files = []
    for file in required_files:
        if not os.path.exists(file):
            missing_files.append(file)

    if missing_files:
        print(f"❌ 缺少必需文件: {', '.join(missing_files)}")
        print("请先运行 enhanced_cwd_mapper.py 生成所需文件")
        return False

    # 检查 CWD 数据源
    cwd_data_files = [
        "/Users/zihanwu/codes/Mulvul/data/enter/cwd_benchmark_2.json",
        "/Users/zihanwu/codes/Mulvul/data/enter/checked_codehub_benchmark.json"
    ]

    missing_data = []
    for file in cwd_data_files:
        if not os.path.exists(file):
            missing_data.append(file)

    if missing_data:
        print(f"❌ 缺少 CWD 数据文件: {', '.join(missing_data)}")
        return False

    print("✅ 先决条件检查通过")
    return True

def run_command(cmd, description):
    """运行命令并处理错误"""
    print(f"🔄 {description}...")
    try:
        result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description}完成")
        if result.stdout:
            print(f"输出: {result.stdout[:200]}...")  # 显示前200个字符
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description}失败: {e}")
        if e.stderr:
            print(f"错误: {e.stderr}")
        return False

def execute_phase1():
    """执行第一阶段步骤"""

    steps = [
        {
            'cmd': 'python3 extract_high_confidence_data.py',
            'desc': '提取高置信度 CWD 数据',
            'output_files': ['phase1_cwd_data.json', 'data_quality_report.md']
        }
    ]

    for step in steps:
        success = run_command(step['cmd'], step['desc'])
        if not success:
            print(f"❌ 步骤失败: {step['desc']}")
            return False

        # 检查输出文件
        missing_outputs = []
        for output_file in step['output_files']:
            if not os.path.exists(output_file):
                missing_outputs.append(output_file)

        if missing_outputs:
            print(f"⚠️ 警告: 未生成预期文件 {missing_outputs}")

    return True

def show_results():
    """显示结果和下一步建议"""
    print("\n📊 第一阶段执行结果:")

    # 检查生成的文件
    generated_files = [
        ('phase1_cwd_data.json', '高置信度 CWD 数据'),
        ('data_quality_report.md', '数据质量报告'),
        ('extraction_stats.json', '提取统计数据')
    ]

    for filename, description in generated_files:
        if os.path.exists(filename):
            size = os.path.getsize(filename)
            size_mb = size / 1024 / 1024
            print(f"  ✅ {filename} ({description}) - {size_mb:.1f}MB")
        else:
            print(f"  ❌ {filename} ({description}) - 未生成")

    # 显示数据统计
    try:
        import json
        with open('extraction_stats.json', 'r') as f:
            stats = json.load(f)

        print(f"\n📈 数据统计:")
        print(f"  数据集数量: {stats['total_datasets']}")
        print(f"  代码示例: {stats['total_examples']:,} 个")
        print(f"  覆盖语言: {len(stats['by_language'])} 种")
        print(f"  CWE 分类: {len([c for c in stats['by_cwe'] if c])} 个")

        # 显示分类分布
        print(f"\n🎯 主要分类分布:")
        for category, count in sorted(stats['by_major'].items(), key=lambda x: x[1], reverse=True):
            percentage = count / stats['total_examples'] * 100
            print(f"  {category}: {count:,} 个 ({percentage:.1f}%)")

    except Exception as e:
        print(f"⚠️ 无法读取统计数据: {e}")

def show_next_steps():
    """显示下一步建议"""
    print(f"\n🚀 下一步建议:")

    print(f"\n1️⃣ 数据质量检查:")
    print(f"   查看 data_quality_report.md 了解数据详情")
    print(f"   cat data_quality_report.md")

    print(f"\n2️⃣ 人工验证 (推荐):")
    print(f"   抽样检查前20个数据集的映射准确性")
    print(f"   重点验证示例数量最多的分类")

    print(f"\n3️⃣ 格式转换:")
    print(f"   开发 convert_to_prompt_bundle.py 工具")
    print(f"   将数据转换为 Mulvul PromptBundle 格式")

    print(f"\n4️⃣ 集成测试:")
    print(f"   修改 src/mulvul/mainline/workflows.py")
    print(f"   建立 baseline 性能基准")

    print(f"\n5️⃣ 性能评估:")
    print(f"   运行对比实验")
    print(f"   分析检测性能提升效果")

    print(f"\n📋 详细计划:")
    print(f"   参考 phase1_implementation_plan.md")

def main():
    """主函数"""
    print("🚀 第一阶段：精确映射数据增强")
    print("=" * 50)

    # 检查先决条件
    if not check_prerequisites():
        sys.exit(1)

    # 执行第一阶段步骤
    if not execute_phase1():
        print("\n❌ 第一阶段执行失败")
        sys.exit(1)

    # 显示结果
    show_results()

    # 显示下一步建议
    show_next_steps()

    print(f"\n🎉 第一阶段数据提取完成！")
    print(f"准备好进行格式转换和集成测试。")

if __name__ == "__main__":
    main()