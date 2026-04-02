#!/usr/bin/env python3
"""
测试移除max_tokens限制后的效果
"""

import sys
sys.path.insert(0, 'src')

def test_unlimited_tokens():
    """测试无限制token生成"""
    
    # 创建一个复杂的prompt改进指令
    complex_instruction = """
Create a comprehensive security analysis prompt that can accurately classify code vulnerabilities into CWE major categories. The prompt should be extremely detailed and thorough, including:

1. Multiple analysis phases
2. Specific detection patterns for each vulnerability type
3. Real-world examples and common patterns
4. Step-by-step reasoning methodology
5. Common pitfalls and edge cases to consider
6. Integration with automated tools and manual review
7. Performance optimization techniques
8. Cross-platform considerations
9. Language-specific nuances
10. Detailed output format requirements

The prompt should be production-ready and suitable for enterprise-level security analysis. Please create the most comprehensive prompt possible without any length constraints.

Enhanced prompt:
"""
    
    print("测试无限制token生成:")
    print("=" * 60)
    
    try:
        from evoprompt.llm.client import create_default_client
        client = create_default_client()
        
        print("🚀 正在生成无限制长度的prompt...")
        result = client.generate(complex_instruction, temperature=0.7)
        
        print(f"\n✅ 生成成功!")
        print(f"📏 生成长度: {len(result)} 字符")
        print(f"📄 行数: {len(result.splitlines())} 行")
        print(f"🔤 包含{{input}}占位符: {'{input}' in result}")
        
        # 检查是否有常见的截断标志
        truncation_indicators = [
            result.endswith('...'),
            result.endswith('"'),
            result.rstrip().endswith(','),
            len(result.split()[-1]) > 50  # 最后一个词异常长
        ]
        
        print(f"🔍 截断指标检查:")
        print(f"   以...结尾: {truncation_indicators[0]}")
        print(f"   以引号结尾: {truncation_indicators[1]}")  
        print(f"   以逗号结尾: {truncation_indicators[2]}")
        print(f"   最后词异常: {truncation_indicators[3]}")
        
        is_truncated = any(truncation_indicators)
        print(f"🎯 可能被截断: {is_truncated}")
        
        # 显示前后部分
        print(f"\n📖 前300字符:")
        print(result[:300] + "...")
        
        print(f"\n📖 后300字符:")
        print("..." + result[-300:])
        
        if not is_truncated and len(result) > 1000:
            print(f"\n🎉 成功！生成了长度为 {len(result)} 字符的完整prompt")
        else:
            print(f"\n⚠️ 可能仍存在限制，长度: {len(result)}")
            
    except Exception as e:
        print(f"❌ 测试失败: {e}")


if __name__ == "__main__":
    test_unlimited_tokens()