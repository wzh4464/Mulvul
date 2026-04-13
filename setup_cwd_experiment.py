#!/usr/bin/env python3
"""
CWD 检测实验环境配置和启动脚本
"""

import os
import sys
import json
import subprocess
from pathlib import Path

def setup_environment():
    """设置实验环境"""

    print("🔧 设置 CWD 检测实验环境...")

    # 1. 检查 OpenRouter API Key
    api_key = os.getenv('OPENROUTER_API_KEY')

    if not api_key:
        print("⚠️  需要设置 OPENROUTER_API_KEY")
        print("请在用户环境中获取或设置:")
        print("export OPENROUTER_API_KEY='your-api-key'")

        # 尝试从用户内存中读取
        try:
            with open('/Users/zihanwu/.claude/projects/-Users-zihanwu-Public-codes-Mulvul/memory/ref_datasets_and_api.md', 'r') as f:
                content = f.read()
                if 'OpenRouter' in content:
                    print("💡 在内存文件中找到 OpenRouter 配置信息")
        except:
            pass

        return False

    print(f"✅ OpenRouter API Key 已配置: {api_key[:8]}...")

    # 2. 检查必要的数据文件
    required_files = [
        'enhanced_cwd_mappings.json',
        'cwd_native_dataset.json'
    ]

    missing_files = []
    for file in required_files:
        if not os.path.exists(file):
            missing_files.append(file)

    if missing_files:
        print(f"❌ 缺少必要文件: {missing_files}")
        print("请先运行数据准备脚本")
        return False

    print("✅ 必要数据文件已就绪")

    # 3. 检查 Python 环境
    try:
        import openai
        import asyncio
        print("✅ Python 依赖已安装")
    except ImportError as e:
        print(f"❌ 缺少 Python 依赖: {e}")
        print("请运行: uv add openai")
        return False

    return True

def run_quick_test():
    """运行快速测试"""

    print("\n🧪 运行 OpenRouter 连接测试...")

    test_script = """
import openai
import os

client = openai.OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=os.getenv('OPENROUTER_API_KEY')
)

try:
    response = client.chat.completions.create(
        model="anthropic/claude-3.5-sonnet",  # 测试模型
        messages=[
            {"role": "user", "content": "Test message"}
        ],
        max_tokens=50
    )
    print("✅ OpenRouter 连接成功")
    print(f"模型响应: {response.choices[0].message.content[:100]}...")
except Exception as e:
    print(f"❌ OpenRouter 连接失败: {e}")
"""

    try:
        result = subprocess.run([sys.executable, "-c", test_script],
                               capture_output=True, text=True, timeout=30)
        print(result.stdout)
        if result.stderr:
            print(f"错误: {result.stderr}")

        return result.returncode == 0
    except subprocess.TimeoutExpired:
        print("❌ 连接测试超时")
        return False
    except Exception as e:
        print(f"❌ 测试失败: {e}")
        return False

def display_baseline_summary():
    """显示现有 baseline 结果摘要"""

    print("\n📊 现有 Mulvul Baseline 结果 (v0.2.0)")
    print("=" * 50)

    baseline_info = """
🎯 关键指标:
├── 端到端准确率: 0.227 (22.7%)
├── Major 准确率: 0.63 (63%)
├── Middle 准确率: 0.57 (57%)
├── CWE 准确率: 0.37 (37%)
└── Binary 准确率: 0.68 (68%)

🏗️ 架构:
├── 模型: GPT-5.4 (OpenRouter)
├── 方法: 协同进化算法优化提示
├── 分类: 三级级联 (6→13→46)
└── 数据: PrimeVul (175,797 样本)

⚠️  核心瓶颈:
└── 级联乘法效应: 0.63 × 0.57 × 0.37 ≈ 0.133
   (实际 0.227 因 Benign 快捷路径)
"""

    print(baseline_info)

def create_experiment_config():
    """创建实验配置文件"""

    config = {
        "experiment_name": "CWD_vs_CWE_Baseline_Comparison",
        "timestamp": "2026-04-13",
        "models": {
            "cwd_detection": {
                "model": "gpt-5.4",
                "provider": "openrouter",
                "api_base": "https://openrouter.ai/api/v1",
                "temperature": 0.1,
                "max_tokens": 2048
            }
        },
        "datasets": {
            "cwd_test": {
                "source": "cwd_native_dataset.json",
                "max_samples": 200,
                "balance_classes": True
            }
        },
        "methods": {
            "cwd_hierarchical": {
                "enabled": True,
                "description": "层次化 CWD 检测 (类别→具体CWD)"
            },
            "cwd_direct": {
                "enabled": True,
                "description": "直接 CWD 检测 (扁平化)"
            }
        },
        "baseline_comparison": {
            "mulvul_v0_2_0": {
                "e2e_accuracy": 0.227,
                "major_accuracy": 0.63,
                "middle_accuracy": 0.57,
                "cwe_accuracy": 0.37,
                "architecture": "三级级联",
                "num_classes": 65,
                "dataset": "PrimeVul (175K samples)"
            }
        },
        "evaluation_metrics": [
            "accuracy",
            "precision",
            "recall",
            "f1_score",
            "confidence_distribution",
            "processing_time",
            "error_analysis"
        ]
    }

    with open('cwd_experiment_config.json', 'w') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)

    print("📁 实验配置已保存: cwd_experiment_config.json")

def main():
    """主函数"""

    print("🚀 CWD 检测实验环境配置")
    print("=" * 60)

    # 1. 设置环境
    if not setup_environment():
        print("\n❌ 环境配置失败，请解决上述问题后重试")
        return

    # 2. 显示 baseline 信息
    display_baseline_summary()

    # 3. 运行连接测试
    if not run_quick_test():
        print("\n⚠️  连接测试失败，但可以继续进行实验")

    # 4. 创建配置文件
    create_experiment_config()

    print("\n✅ 环境配置完成！")
    print("\n📋 下一步操作:")
    print("1. 运行 CWD 检测实验:")
    print("   python3 cwd_detection_implementation.py")
    print("")
    print("2. 分析结果:")
    print("   查看生成的 cwd_detection_results.json")
    print("   查看对比报告 cwd_vs_baseline_comparison.md")
    print("")
    print("3. 调整参数:")
    print("   编辑 cwd_experiment_config.json")

if __name__ == "__main__":
    main()