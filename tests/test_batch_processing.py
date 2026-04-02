#!/usr/bin/env python3
"""
测试批量处理功能，验证batch_size=8的设置
"""

from evoprompt.llm.client import sven_llm_init, sven_llm_query


def test_batch_processing():
    """测试批量处理功能"""
    print("Testing batch processing with batch_size=8...")

    try:
        # 初始化客户端
        client = sven_llm_init()

        # 创建测试prompts - 使用20个prompt来验证批量处理
        test_prompts = [
            f"Explain what vulnerability type CWE-{i} represents in one sentence."
            for i in range(78, 98)  # 20个prompt
        ]

        print(f"Total prompts: {len(test_prompts)}")
        print("Expected: 3 batches (8, 8, 4 prompts each)")
        print()

        # 使用批量查询，默认batch_size=8
        results = sven_llm_query(test_prompts, client, task=True, batch_size=8)

        print(f"Received {len(results)} results")
        print("Sample results:")
        for i, result in enumerate(results[:3]):  # 显示前3个结果
            if result != "error":
                print(f"  {i+1}: {result[:100]}...")
            else:
                print(f"  {i+1}: ERROR")

        # 验证成功
        successful_count = sum(1 for r in results if r != "error")
        print(
            f"\nSuccess rate: {successful_count}/{len(results)} ({successful_count/len(results)*100:.1f}%)"
        )

        return True

    except Exception as e:
        print(f"Test failed: {e}")
        return False


def test_single_query():
    """测试单个查询"""
    print("\nTesting single query...")

    try:
        client = sven_llm_init()

        # 单个查询测试
        single_prompt = "What is a buffer overflow vulnerability?"
        result = sven_llm_query(single_prompt, client, task=True)

        if result and result != "error":
            print(f"Single query result: {result[:100]}...")
            return True
        else:
            print("Single query failed")
            return False

    except Exception as e:
        print(f"Single query test failed: {e}")
        return False


if __name__ == "__main__":
    print("=== Batch Processing Test ===")

    # 测试单个查询
    single_success = test_single_query()

    # 测试批量处理
    batch_success = test_batch_processing()

    print("\n=== Test Results ===")
    print(f"Single query test: {'PASSED' if single_success else 'FAILED'}")
    print(f"Batch processing test: {'PASSED' if batch_success else 'FAILED'}")

    if single_success and batch_success:
        print("\n✅ All tests passed! Batch size=8 is working correctly.")
    else:
        print("\n❌ Some tests failed. Please check the configuration.")
