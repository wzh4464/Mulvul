#!/usr/bin/env python3
"""
测试prompt生成时的token截断问题
"""

import sys
sys.path.insert(0, 'src')

def test_token_truncation():
    """测试max_tokens参数对prompt生成的影响"""
    
    # 模拟一个复杂的prompt改进指令
    feedback_instruction = """
The current prompt made an incorrect CWE major category classification. Please improve it based on the specific vulnerability information.

Current Prompt:
You are an expert cybersecurity analyst conducting a comprehensive security assessment. Analyze the provided code using a systematic multi-phase approach to detect vulnerabilities across all major security categories:

**Phase 1 - Attacker Mindset Analysis:**
- What would an attacker target first? Identify the most attractive attack surfaces and entry points
- Examine user-controlled inputs, external interfaces, and data flow paths
- Consider how vulnerabilities could be chained together for maximum exploitation impact
- Trace potential attack paths from input sources to sensitive operations

**Phase 2 - Systematic Vulnerability Detection:**
Methodically examine each category using static analysis patterns:
- **Buffer/Memory Errors (CWE-120,119,787)**: buffer overflows, underflows, bounds violations, use-after-free, double-free, memory corruption, uninitialized memory
- **Injection Vulnerabilities**: SQL injection, command injection, XSS, code injection, LDAP injection

Code: {input}

Security assessment:

Code Sample:
int main() {
    char buffer[10];
    strcpy(buffer, argv[1]);  // potential buffer overflow
    return 0;
}

Ground Truth Category: Buffer Errors
Predicted Category: Injection
Project: test-project
CWE Categories: CWE-120, CWE-787

Create an improved prompt that would correctly classify this sample into the correct CWE major category. Focus on:
1. The specific CWE categories: Buffer Errors characteristics
2. The vulnerability patterns that distinguish Buffer Errors from other categories
3. Common Buffer Errors issues in test-project code
4. Ensure the prompt can distinguish between all CWE major categories: Benign, Buffer Errors, Injection, Memory Management, Pointer Dereference, Integer Errors, Concurrency Issues, Path Traversal, Cryptography Issues, Information Exposure, Other

Improved prompt:
"""
    
    print("测试不同max_tokens设置对prompt生成的影响:")
    print("=" * 60)
    
    # 测试不同的max_tokens值
    test_values = [100, 250, 500, 1000]
    
    try:
        from evoprompt.llm.client import create_default_client
        client = create_default_client()
        
        for max_tokens in test_values:
            print(f"\n测试 max_tokens={max_tokens}:")
            print("-" * 40)
            
            try:
                result = client.generate(
                    feedback_instruction, 
                    temperature=0.7, 
                    max_tokens=max_tokens
                )
                
                print(f"生成长度: {len(result)} 字符")
                print(f"包含{{input}}: {'{input}' in result}")
                print(f"结尾是否完整: {not result.endswith('...')}")
                print(f"前200字符: {result[:200]}...")
                
                # 检查是否被截断
                if len(result) > 0:
                    last_sentence = result.split('.')[-1].strip()
                    is_truncated = len(last_sentence) > 20 and not last_sentence.endswith(('.', '!', '?', ':'))
                    print(f"可能被截断: {is_truncated}")
                    if is_truncated:
                        print(f"最后片段: ...{last_sentence}")
                
            except Exception as e:
                print(f"生成失败: {e}")
    
    except Exception as e:
        print(f"创建客户端失败: {e}")
        return
    
    print("\n结论:")
    print("- max_tokens=250 可能导致复杂prompt生成时被截断")
    print("- 建议增加到500或更多以确保prompt完整性")


if __name__ == "__main__":
    test_token_truncation()