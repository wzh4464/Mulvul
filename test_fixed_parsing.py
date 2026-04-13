#!/usr/bin/env python3
"""
测试修复后的解析逻辑
"""

import sys
import os
import json
import asyncio

# 添加 Mulvul 路径
sys.path.append('/Users/zihanwu/Public/codes/Mulvul/src')

from cwd_detection_implementation import CWDDetectionSystem, CWDExperimentConfig

def test_parsing():
    """测试解析逻辑"""

    # 模拟配置
    config = CWDExperimentConfig(
        model_name="gpt-5.4",
        api_base="https://openrouter.ai/api/v1",
        max_samples=1,
        temperature=0.1,
        max_tokens=100
    )

    # 创建检测系统
    detection_system = CWDDetectionSystem(config, {})

    # 测试 markdown 包装的 JSON 响应
    test_response = '''```json
{
  "primary_cwd": "CWD-1002",
  "confidence": 0.98,
  "reasoning": "代码分析显示内存分配大小未受限的问题",
  "alternative_cwds": [],
  "is_vulnerable": true,
  "severity_assessment": "一般"
}
```'''

    print("🔍 测试修复后的解析逻辑...\n")
    print(f"原始响应:\n{test_response}\n")

    try:
        result = detection_system._parse_detection_response(test_response)
        print("✅ 解析成功!")
        print(f"Primary CWD: {result.get('primary_cwd')}")
        print(f"Confidence: {result.get('confidence')}")
        print(f"Reasoning: {result.get('reasoning', '')[:100]}...")

        if result.get('primary_cwd') == 'CWD-1002':
            print("\n🎉 修复成功！现在能正确解析 markdown 包装的 JSON!")
        else:
            print(f"\n❌ 仍有问题，得到: {result.get('primary_cwd')}")

    except Exception as e:
        print(f"❌ 解析失败: {e}")

    # 测试类别响应
    print("\n" + "="*50)
    category_response = '''```json
{
  "category": "Memory Safety"
}
```'''

    print(f"测试类别响应解析:\n{category_response}\n")

    try:
        category = detection_system._parse_category_response(category_response)
        print(f"✅ 类别解析成功: {category}")
        if category == "Memory Safety":
            print("🎉 类别解析修复成功!")
        else:
            print(f"❌ 类别解析仍有问题: {category}")
    except Exception as e:
        print(f"❌ 类别解析失败: {e}")

if __name__ == "__main__":
    test_parsing()