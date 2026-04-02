#!/usr/bin/env python3
"""
测试并发批处理功能
"""

from mulvul.llm.client import sven_llm_init, sven_llm_query
import time


def test_concurrent_vs_sequential():
    """比较并发和顺序处理的性能"""
    print("🔥 测试并发 vs 顺序批处理性能对比...")

    try:
        client = sven_llm_init()

        # 创建测试prompts
        test_prompts = [
            f"What is CWE-{i}? Answer in one sentence."
            for i in range(78, 86)  # 8个prompt，正好一个batch
        ]

        print(f"测试样本: {len(test_prompts)} 个prompts")
        print()

        # 1. 顺序处理测试
        print("1️⃣ 顺序处理模式:")
        start_time = time.time()
        sequential_results = sven_llm_query(
            test_prompts,
            client,
            task=True,
            batch_size=8,
            concurrent=False,  # 顺序处理
        )
        sequential_time = time.time() - start_time
        sequential_success = sum(1 for r in sequential_results if r != "error")

        print(f"   ⏱️ 耗时: {sequential_time:.2f}秒")
        print(f"   ✅ 成功: {sequential_success}/{len(test_prompts)}")
        print()

        # 2. 并发处理测试
        print("2️⃣ 并发处理模式:")
        start_time = time.time()
        concurrent_results = sven_llm_query(
            test_prompts,
            client,
            task=True,
            batch_size=8,
            concurrent=True,  # 并发处理
        )
        concurrent_time = time.time() - start_time
        concurrent_success = sum(1 for r in concurrent_results if r != "error")

        print(f"   ⏱️ 耗时: {concurrent_time:.2f}秒")
        print(f"   ✅ 成功: {concurrent_success}/{len(test_prompts)}")
        print()

        # 3. 性能对比
        if sequential_time > 0 and concurrent_time > 0:
            speedup = sequential_time / concurrent_time
            print("📊 性能对比:")
            print(f"   顺序处理: {sequential_time:.2f}秒")
            print(f"   并发处理: {concurrent_time:.2f}秒")
            print(f"   加速比: {speedup:.2f}x")

            if speedup > 1.5:
                print("   🚀 并发处理显著更快")
            elif speedup > 1.1:
                print("   ⚡ 并发处理稍快")
            else:
                print("   🔄 两种模式性能接近")

        # 4. 结果对比
        print()
        print("🔍 结果样本对比:")
        for i in range(min(3, len(test_prompts))):
            print(f"   Prompt {i+1}:")
            if sequential_results[i] != "error":
                print(f"     顺序: {sequential_results[i][:60]}...")
            else:
                print("     顺序: ERROR")

            if concurrent_results[i] != "error":
                print(f"     并发: {concurrent_results[i][:60]}...")
            else:
                print("     并发: ERROR")
            print()

        return True

    except Exception as e:
        print(f"❌ 测试失败: {e}")
        import traceback

        traceback.print_exc()
        return False


def test_batch_size_options():
    """测试不同批大小的处理"""
    print("📏 测试不同批大小...")

    try:
        client = sven_llm_init()

        # 创建12个prompts来测试不同批大小
        test_prompts = [
            f"Explain vulnerability type {i} briefly." for i in range(1, 13)
        ]

        batch_sizes = [4, 8, 12]

        for batch_size in batch_sizes:
            print(f"\n🔧 批大小 {batch_size} 测试:")
            start_time = time.time()

            results = sven_llm_query(
                test_prompts, client, task=True, batch_size=batch_size, concurrent=True
            )

            elapsed = time.time() - start_time
            success_count = sum(1 for r in results if r != "error")
            expected_batches = (len(test_prompts) + batch_size - 1) // batch_size

            print(f"   📊 结果: {success_count}/{len(test_prompts)} 成功")
            print(f"   ⏱️ 耗时: {elapsed:.2f}秒")
            print(f"   📦 批次数: {expected_batches}")

        return True

    except Exception as e:
        print(f"❌ 批大小测试失败: {e}")
        return False


if __name__ == "__main__":
    print("=== 并发批处理测试 ===")
    print()

    # 测试并发vs顺序
    concurrent_test = test_concurrent_vs_sequential()

    print("\n" + "=" * 50 + "\n")

    # 测试不同批大小
    batch_test = test_batch_size_options()

    print("\n=== 测试总结 ===")
    print(f"并发对比测试: {'✅ 通过' if concurrent_test else '❌ 失败'}")
    print(f"批大小测试: {'✅ 通过' if batch_test else '❌ 失败'}")

    if concurrent_test and batch_test:
        print("\n🎉 所有测试通过！")
        print("\n📝 使用说明:")
        print("   • concurrent=False: 顺序处理（默认，稳定）")
        print("   • concurrent=True: 并发处理（更快，但可能不稳定）")
        print("   • batch_size=8: 每批处理8个请求（默认）")
        print("   • 建议在网络稳定时使用并发模式")
    else:
        print("\n⚠️ 部分测试失败，请检查API配置")
