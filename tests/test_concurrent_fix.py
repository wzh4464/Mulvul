#!/usr/bin/env python3
"""
测试修改后的并发批处理功能
"""

import sys
from pathlib import Path

sys.path.insert(0, 'src')
# 添加项目根目录到路径，以便导入scripts模块
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

def test_openai_client_concurrent():
    """测试OpenAI客户端并发功能"""
    print("🧪 测试OpenAI客户端并发功能...")
    
    from evoprompt.llm.client import create_default_client
    import time
    
    client = create_default_client()
    
    # 检查是否有并发方法
    if not hasattr(client, '_process_batch_concurrent'):
        print("   ❌ 客户端缺少_process_batch_concurrent方法")
        return False
    
    print("   ✅ 客户端包含并发处理方法")
    
    # 创建测试数据
    test_prompts = [
        f"What is vulnerability {i}? One word answer." 
        for i in range(1, 6)  # 5个prompt
    ]
    
    print(f"   📝 准备了 {len(test_prompts)} 个测试prompt")
    
    # 测试顺序处理
    print("   🔄 测试顺序处理...")
    start_time = time.time()
    
    try:
        sequential_results = client.batch_generate(
            test_prompts,
            batch_size=8,
            concurrent=False,  # 顺序处理
            max_tokens=10
        )
        sequential_time = time.time() - start_time
        sequential_success = sum(1 for r in sequential_results if r != "error")
        
        print(f"      ⏱️ 顺序处理耗时: {sequential_time:.2f}秒")
        print(f"      ✅ 成功: {sequential_success}/{len(test_prompts)}")
        
        # 测试并发处理
        print("   🚀 测试并发处理...")
        start_time = time.time()
        
        concurrent_results = client.batch_generate(
            test_prompts,
            batch_size=8, 
            concurrent=True,   # 并发处理
            max_tokens=10
        )
        concurrent_time = time.time() - start_time
        concurrent_success = sum(1 for r in concurrent_results if r != "error")
        
        print(f"      ⏱️ 并发处理耗时: {concurrent_time:.2f}秒")
        print(f"      ✅ 成功: {concurrent_success}/{len(test_prompts)}")
        
        # 性能对比
        if sequential_time > 0 and concurrent_time > 0:
            speedup = sequential_time / concurrent_time
            print(f"      📈 加速比: {speedup:.2f}x")
            
            if speedup > 1.2:
                print("      🎉 并发处理明显更快！")
            else:
                print("      ℹ️ 性能提升不明显（可能由于API或网络限制）")
        
        return True
        
    except Exception as e:
        print(f"   ❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_config_and_params():
    """测试配置和参数传递"""
    print("\n⚙️ 测试配置和参数传递...")
    
    from scripts.ablations.run_primevul_concurrent_optimized import create_optimized_config
    
    config = create_optimized_config()
    
    # 检查关键配置
    enable_batch = config.get('enable_batch_processing', False)
    batch_size = config.get('llm_batch_size', 8)
    enable_concurrent = config.get('enable_concurrent', True)
    
    print(f"   📊 配置检查:")
    print(f"      批处理启用: {enable_batch}")
    print(f"      批大小: {batch_size}")
    print(f"      并发启用: {enable_concurrent}")
    
    if enable_batch and batch_size == 8 and enable_concurrent:
        print("   ✅ 配置正确")
        return True
    else:
        print("   ❌ 配置有误")
        return False


def main():
    """运行测试"""
    print("=== 并发功能修复验证 ===")
    print("验证OpenAI客户端现在支持并发批处理")
    print()
    
    tests = [
        ("配置和参数传递", test_config_and_params),
        ("OpenAI客户端并发功能", test_openai_client_concurrent),
    ]
    
    results = {}
    
    for test_name, test_func in tests:
        print(f"🧪 执行测试: {test_name}")
        try:
            result = test_func()
            results[test_name] = result
        except Exception as e:
            print(f"   💥 测试异常: {e}")
            results[test_name] = False
        print()
    
    # 总结
    passed = sum(1 for r in results.values() if r)
    total = len(results)
    
    print("=== 测试总结 ===")
    for test_name, result in results.items():
        status = "✅ 通过" if result else "❌ 失败"
        print(f"   {test_name}: {status}")
    
    print()
    print(f"总体结果: {passed}/{total} 个测试通过")
    
    if passed == total:
        print("\n🎉 修复成功！")
        print("✅ OpenAI客户端现在支持并发批处理")
        print("✅ run_primevul_concurrent_optimized.py 将使用并发模式")
        print("\n📝 现在应该看到的日志特征:")
        print("   • 'Using 并发 batch processing' 而不是 'Using sequential'")
        print("   • '🚀 并发处理 X 个请求'")
        print("   • '📊 并发进度: X/Y'")
        print("   • '✅ 并发批次完成: X/Y 成功'")
        print("   • HTTP请求时间重叠而不是连续")
        return 0
    else:
        print("\n⚠️ 部分测试失败，需要进一步修复")
        return 1


if __name__ == "__main__":
    sys.exit(main())