#!/usr/bin/env python3
"""
简单测试无限制token生成
"""

import sys
sys.path.insert(0, 'src')

def test_simple():
    """简单测试"""
    
    instruction = """Create a detailed security analysis prompt that includes at least 5 phases of analysis. Make it comprehensive but not excessive."""
    
    try:
        from evoprompt.llm.client import create_default_client
        client = create_default_client()
        
        print("测试无max_tokens限制...")
        result = client.generate(instruction, temperature=0.5)
        
        print(f"生成长度: {len(result)} 字符")
        print(f"前200字符: {result[:200]}...")
        print(f"后100字符: ...{result[-100:]}")
        
        # 检查是否被截断
        if len(result) > 500 and not result.endswith('...'):
            print("✅ 成功生成较长内容，无明显截断")
        else:
            print("⚠️ 内容可能被截断或过短")
            
    except Exception as e:
        print(f"❌ 错误: {e}")


if __name__ == "__main__":
    test_simple()