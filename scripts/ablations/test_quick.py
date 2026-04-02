#!/usr/bin/env python3
"""快速测试脚本 - 用于验证系统是否正常工作"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from evoprompt.prompts.hierarchical_three_layer import ThreeLayerPromptFactory
from evoprompt.detectors.three_layer_detector import ThreeLayerDetector
from evoprompt.detectors.rag_three_layer_detector import RAGThreeLayerDetector
from evoprompt.rag.knowledge_base import KnowledgeBaseBuilder
from evoprompt.llm.client import load_env_vars, create_llm_client


def test_basic_detection():
    """测试基础三层检测"""
    print("\n" + "="*70)
    print("测试1: 基础三层检测")
    print("="*70)

    # 创建检测器
    prompt_set = ThreeLayerPromptFactory.create_default_prompt_set()
    llm_client = create_llm_client(llm_type=os.getenv("MODEL_NAME", "gpt-4"))
    detector = ThreeLayerDetector(prompt_set, llm_client, use_scale_enhancement=False)

    # 测试代码
    test_code = """
void copy_data(char* input) {
    char buffer[64];
    strcpy(buffer, input);
    printf("%s", buffer);
}
"""

    print(f"\n📝 测试代码:")
    print(test_code)

    print("\n🔍 检测中...")
    cwe, details = detector.detect(test_code, return_intermediate=True)

    print("\n✅ 检测完成!")
    print(f"   Layer 1: {details.get('layer1', 'Unknown')}")
    print(f"   Layer 2: {details.get('layer2', 'Unknown')}")
    print(f"   Layer 3: {details.get('layer3', 'Unknown')}")
    print(f"   Final: {cwe or 'Unknown'}")

    print("\n💡 期望结果:")
    print("   Layer 1: Memory")
    print("   Layer 2: Buffer Overflow")
    print("   Layer 3: CWE-120 或 CWE-787")

    return cwe is not None


def test_rag_detection():
    """测试RAG增强检测"""
    print("\n" + "="*70)
    print("测试2: RAG增强检测")
    print("="*70)

    # 创建知识库
    print("\n📚 构建知识库...")
    kb = KnowledgeBaseBuilder.create_default_kb()
    stats = kb.statistics()
    print(f"   ✅ {stats['total_examples']} 个示例")

    # 创建RAG检测器
    prompt_set = ThreeLayerPromptFactory.create_default_prompt_set()
    llm_client = create_llm_client(llm_type=os.getenv("MODEL_NAME", "gpt-4"))

    detector = RAGThreeLayerDetector(
        prompt_set=prompt_set,
        llm_client=llm_client,
        knowledge_base=kb,
        use_scale_enhancement=False,
        retriever_type="lexical",
        top_k=2
    )

    # 测试代码
    test_code = """
String query = "SELECT * FROM users WHERE id=" + userId;
stmt.executeQuery(query);
"""

    print(f"\n📝 测试代码:")
    print(test_code)

    print("\n🔍 检测中 (含RAG)...")
    cwe, details = detector.detect(test_code, return_intermediate=True)

    print("\n✅ 检测完成!")
    print(f"   Layer 1: {details.get('layer1', 'Unknown')}")
    print(f"   Layer 2: {details.get('layer2', 'Unknown')}")
    print(f"   Layer 3: {details.get('layer3', 'Unknown')}")
    print(f"   Final: {cwe or 'Unknown'}")

    print("\n🔎 RAG检索信息:")
    for layer in [1, 2, 3]:
        key = f"layer{layer}_retrieval"
        if key in details:
            r = details[key]
            print(f"   Layer {layer}: 检索到 {r.get('num_examples', 0)} 个示例")
            if r.get('similarity_scores'):
                scores = [f"{s:.3f}" for s in r['similarity_scores']]
                print(f"            相似度: {scores}")

    print("\n💡 期望结果:")
    print("   Layer 1: Injection")
    print("   Layer 2: SQL Injection")
    print("   Layer 3: CWE-89")

    return cwe is not None


def test_scale_enhancement():
    """测试Scale增强"""
    print("\n" + "="*70)
    print("测试3: Scale增强")
    print("="*70)

    # 创建带Scale的检测器
    prompt_set = ThreeLayerPromptFactory.create_default_prompt_set()
    llm_client = create_llm_client(llm_type=os.getenv("MODEL_NAME", "gpt-4"))
    detector = ThreeLayerDetector(prompt_set, llm_client, use_scale_enhancement=True)

    # 测试代码
    test_code = "strcpy(buf, input);"

    print(f"\n📝 测试代码: {test_code}")

    print("\n🔍 检测中 (含Scale)...")
    cwe, details = detector.detect(test_code, return_intermediate=True)

    print("\n✅ 检测完成!")
    print(f"   Enhanced: {details.get('enhanced_code', 'N/A')[:100]}...")
    print(f"   Layer 1: {details.get('layer1', 'Unknown')}")
    print(f"   Final: {cwe or 'Unknown'}")

    return cwe is not None


def main():
    """主函数"""
    print("🧪 EvoPrompt 快速测试")
    print("="*70)

    # 加载环境
    load_env_vars()
    api_key = os.getenv("API_KEY")

    if not api_key:
        print("❌ 未找到 API_KEY")
        print("   请确保 .env 文件包含 API_KEY")
        return 1

    print(f"✅ 环境配置:")
    print(f"   Model: {os.getenv('MODEL_NAME', 'gpt-4')}")

    results = []

    # 测试1: 基础检测
    try:
        success = test_basic_detection()
        results.append(("基础检测", success))
    except Exception as e:
        print(f"\n❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()
        results.append(("基础检测", False))

    # 测试2: RAG检测
    try:
        success = test_rag_detection()
        results.append(("RAG检测", success))
    except Exception as e:
        print(f"\n❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()
        results.append(("RAG检测", False))

    # 测试3: Scale增强
    try:
        success = test_scale_enhancement()
        results.append(("Scale增强", success))
    except Exception as e:
        print(f"\n❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()
        results.append(("Scale增强", False))

    # 总结
    print("\n" + "="*70)
    print("📊 测试总结")
    print("="*70)

    for name, success in results:
        status = "✅ 通过" if success else "❌ 失败"
        print(f"   {name}: {status}")

    all_passed = all(s for _, s in results)

    print()
    if all_passed:
        print("🎉 所有测试通过!")
    else:
        print("⚠️  部分测试失败，请检查错误信息")

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
