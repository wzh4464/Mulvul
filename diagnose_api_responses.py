#!/usr/bin/env python3
"""
诊断 OpenRouter API 响应格式
"""

import sys
import os
import json
import asyncio

# 添加 Mulvul 路径
sys.path.append('/Users/zihanwu/Public/codes/Mulvul/src')

from mulvul.llm.client import OpenAICompatibleClient

async def test_api_response():
    """测试 API 响应格式"""

    print("🔍 开始诊断 OpenRouter API 响应格式...\n")

    # 获取 API 密钥
    api_key = os.getenv('OPENROUTER_API_KEY')
    if not api_key:
        print("❌ 需要设置 OPENROUTER_API_KEY")
        return

    # 创建客户端
    client = OpenAICompatibleClient(
        model_name="gpt-5.4",
        api_base="https://openrouter.ai/api/v1",
        api_key=api_key
    )

    # 测试简单提示
    simple_prompt = """请返回一个简单的 JSON 对象：
{
    "test": "success",
    "number": 42
}"""

    print("📝 测试简单 JSON 提示:")
    print(f"提示: {simple_prompt[:100]}...")

    try:
        response = await asyncio.to_thread(
            client.generate,
            simple_prompt,
            temperature=0.1,
            max_tokens=100
        )

        print(f"✅ 响应 (前500字符):\n{'-'*50}")
        print(response[:500])
        print(f"{'-'*50}\n")

        # 尝试解析 JSON
        try:
            parsed = json.loads(response.strip())
            print("✅ JSON 解析成功!")
            print(f"解析结果: {parsed}")
        except Exception as e:
            print(f"❌ JSON 解析失败: {e}")

    except Exception as e:
        print(f"❌ API 调用失败: {e}")
        return

    # 测试 CWD 检测提示
    print("\n" + "="*60)
    cwd_prompt = """你是一个代码安全分析专家，专门识别企业 CWD (Code Weakness Dictionary) 分类的漏洞。

## 任务
分析以下代码，从候选的 CWD 分类中识别最可能的漏洞类型。

## 候选 CWD 分类
CWD-1002: 内存分配大小未受限
-- 描述: 内存分配大小未受限，可能导致资源耗尽...
-- 严重等级: 一般

## 待分析代码
```c
void allocateMemory(size_t size) {
    char *buffer = (char*)malloc(size);  // 未检查size参数
    // 使用buffer...
    free(buffer);
}
```

## 分析要求
1. 仔细分析代码的逻辑和潜在安全问题
2. 基于企业 CWD 标准进行分类
3. 提供详细的推理过程
4. 给出置信度评分 (0.0-1.0)

## 输出格式 (JSON)
```json
{
    "primary_cwd": "CWD-xxxx",
    "confidence": 0.85,
    "reasoning": "详细的分析推理过程...",
    "alternative_cwds": [
        {"cwd": "CWD-yyyy", "confidence": 0.65}
    ],
    "is_vulnerable": true,
    "severity_assessment": "严重"
}
```"""

    print("📝 测试 CWD 检测提示:")
    print(f"提示长度: {len(cwd_prompt)} 字符")

    try:
        response = await asyncio.to_thread(
            client.generate,
            cwd_prompt,
            temperature=0.1,
            max_tokens=2048
        )

        print(f"✅ CWD 响应:\n{'-'*50}")
        print(response)
        print(f"{'-'*50}\n")

        # 尝试解析 JSON
        try:
            # 尝试提取 JSON 部分
            if '```json' in response:
                json_start = response.find('```json') + 7
                json_end = response.find('```', json_start)
                json_content = response[json_start:json_end].strip()
            else:
                json_content = response.strip()

            parsed = json.loads(json_content)
            print("✅ CWD JSON 解析成功!")
            print(f"Primary CWD: {parsed.get('primary_cwd')}")
            print(f"Confidence: {parsed.get('confidence')}")
            print(f"Reasoning: {parsed.get('reasoning', '')[:100]}...")

        except Exception as e:
            print(f"❌ CWD JSON 解析失败: {e}")
            print("尝试的 JSON 内容:")
            if '```json' in response:
                json_start = response.find('```json') + 7
                json_end = response.find('```', json_start)
                print(repr(response[json_start:json_end]))
            else:
                print(repr(response[:200]))

    except Exception as e:
        print(f"❌ CWD API 调用失败: {e}")

async def main():
    await test_api_response()

if __name__ == "__main__":
    asyncio.run(main())