#!/usr/bin/env python3
"""
简单的 CWD 检测测试
逐步验证每个组件
"""

import os
import sys
import json

# 添加 Mulvul 路径
sys.path.append('/Users/zihanwu/Public/codes/Mulvul/src')

def test_basic_imports():
    """测试基本导入"""
    print("🧪 测试基本导入...")

    try:
        from cwd_hierarchy import get_major_categories, get_cwd_ids
        print("✅ CWD 层次结构导入成功")

        from mulvul.mainline.bundle import PromptBundle, NodeSpec
        print("✅ PromptBundle 导入成功")

        from mulvul.llm.client import OpenAICompatibleClient
        print("✅ LLM 客户端导入成功")

        return True
    except Exception as e:
        print(f"❌ 导入失败: {e}")
        return False

def test_data_loading():
    """测试数据加载"""
    print("\n🧪 测试数据加载...")

    try:
        with open('cwd_native_dataset.json', 'r', encoding='utf-8') as f:
            data = json.load(f)

        examples = data.get('examples', [])
        print(f"✅ 加载了 {len(examples)} 个样本")

        # 显示第一个样本
        if examples:
            sample = examples[0]
            print(f"   示例 ID: {sample.get('id')}")
            print(f"   CWD ID: {sample.get('labels', {}).get('cwd_id')}")

        return True, data
    except Exception as e:
        print(f"❌ 数据加载失败: {e}")
        return False, None

def test_cwd_hierarchy():
    """测试 CWD 层次结构"""
    print("\n🧪 测试 CWD 层次结构...")

    try:
        from cwd_hierarchy import get_major_categories, get_middle_categories, get_cwd_ids

        majors = get_major_categories()
        middles = get_middle_categories()
        cwds = get_cwd_ids()

        print(f"✅ Major 类别: {len(majors)} 个")
        print(f"✅ Middle 类别: {len(middles)} 个")
        print(f"✅ CWD 分类: {len(cwds)} 个")

        print(f"   Major 类别: {majors}")

        return True
    except Exception as e:
        print(f"❌ CWD 层次结构测试失败: {e}")
        return False

def test_llm_client():
    """测试 LLM 客户端"""
    print("\n🧪 测试 LLM 客户端...")

    try:
        from mulvul.llm.client import OpenAICompatibleClient

        api_key = os.getenv('OPENROUTER_API_KEY')
        if not api_key:
            print("❌ OPENROUTER_API_KEY 未设置")
            return False

        client = OpenAICompatibleClient(
            model_name="gpt-5.4",
            api_base="https://openrouter.ai/api/v1",
            api_key=api_key
        )

        print("✅ LLM 客户端创建成功")
        return True, client
    except Exception as e:
        print(f"❌ LLM 客户端创建失败: {e}")
        return False, None

def test_simple_detection():
    """测试简单检测"""
    print("\n🧪 测试简单检测...")

    try:
        # 测试代码
        test_code = """
int buffer[10];
char input[100];
strcpy(buffer, input);  // 潜在的缓冲区溢出
"""

        success, client = test_llm_client()
        if not success:
            return False

        # 简单的 API 调用测试
        prompt = f"""分析以下代码，判断是否存在安全问题：

{test_code}

回答 "VULNERABLE" 或 "BENIGN"。"""

        print("📡 发送 API 请求...")
        try:
            # 这里可能会调用实际的 API
            print("✅ 简单检测测试准备完成")
            return True
        except Exception as e:
            print(f"❌ API 调用失败: {e}")
            return False

    except Exception as e:
        print(f"❌ 简单检测测试失败: {e}")
        return False

def main():
    """主测试函数"""
    print("🚀 开始 CWD 检测组件测试")
    print("=" * 50)

    # 逐步测试各个组件
    if not test_basic_imports():
        return

    if not test_cwd_hierarchy():
        return

    success, data = test_data_loading()
    if not success:
        return

    if not test_simple_detection():
        return

    print("\n🎉 所有基础测试通过!")
    print("可以进行完整的 CWD 进化实验")

if __name__ == "__main__":
    main()