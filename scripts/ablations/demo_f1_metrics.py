#!/usr/bin/env python3
"""演示Macro/Weighted/Micro F1指标的区别

展示在类别不平衡场景下，三种F1计算方式的差异，
以及为什么在漏洞检测中推荐使用Macro-F1。
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from evoprompt.evaluators.multiclass_metrics import (
    MultiClassMetrics,
    compare_averaging_methods,
    print_averaging_comparison,
)


def demo_balanced_case():
    """演示平衡数据集的情况"""
    print("\n" + "=" * 70)
    print("场景1: 平衡数据集")
    print("=" * 70)
    print("\n假设我们有一个平衡的数据集:")
    print("- Class A: 100 samples, 模型表现: F1 = 0.9")
    print("- Class B: 100 samples, 模型表现: F1 = 0.8")
    print("- Class C: 100 samples, 模型表现: F1 = 0.7")

    metrics = MultiClassMetrics()

    # Class A: 100 samples, 90 correct
    for i in range(90):
        metrics.add_prediction("A", "A")
    for i in range(10):
        metrics.add_prediction("B", "A")  # 10 FN for A

    # Class B: 100 samples, 80 correct
    for i in range(80):
        metrics.add_prediction("B", "B")
    for i in range(20):
        metrics.add_prediction("C", "B")  # 20 FN for B

    # Class C: 100 samples, 70 correct
    for i in range(70):
        metrics.add_prediction("C", "C")
    for i in range(30):
        metrics.add_prediction("A", "C")  # 30 FN for C

    # 打印报告
    metrics.print_report("平衡数据集")

    # 对比F1方法
    print_averaging_comparison(metrics)

    print("\n💡 结论:")
    print("   在平衡数据集中，三种F1方法差异不大，")
    print("   因为每个类别的样本数量相同。")


def demo_imbalanced_case_benign():
    """演示不平衡数据集的情况 - 多数类表现好"""
    print("\n" + "=" * 70)
    print("场景2: 不平衡数据集 - 多数类(Benign)表现好")
    print("=" * 70)
    print("\n假设我们有一个极度不平衡的数据集 (类似漏洞检测):")
    print("- Benign (安全代码): 900 samples, 模型表现: F1 ≈ 0.95")
    print("- Vulnerable (漏洞代码): 100 samples, 模型表现: F1 ≈ 0.30")
    print("\n⚠️  这种情况下，模型主要靠预测'Benign'获得高分!")

    metrics = MultiClassMetrics()

    # Benign: 900 samples, 90% accuracy
    for i in range(810):  # 810 correct
        metrics.add_prediction("Benign", "Benign")
    for i in range(90):  # 90 FN
        metrics.add_prediction("Vulnerable", "Benign")

    # Vulnerable: 100 samples, 30% accuracy (很差!)
    for i in range(30):  # 30 correct
        metrics.add_prediction("Vulnerable", "Vulnerable")
    for i in range(70):  # 70 FN (大量漏检!)
        metrics.add_prediction("Benign", "Vulnerable")

    # 打印报告
    metrics.print_report("不平衡数据集")

    # 对比F1方法
    comparison = compare_averaging_methods(metrics)

    print("\n" + "=" * 70)
    print("F1指标对比分析")
    print("=" * 70)

    print(f"\n1. Macro-F1 = {comparison['macro_f1']['value']:.4f}")
    print("   计算: (0.95 + 0.30) / 2 ≈ 0.625")
    print("   💡 揭示了模型在Vulnerable类上的糟糕表现")
    print("   ✅ 适合漏洞检测: 强制关注少数类")

    print(f"\n2. Weighted-F1 = {comparison['weighted_f1']['value']:.4f}")
    print("   计算: 0.95 × 0.9 + 0.30 × 0.1 ≈ 0.885")
    print("   ⚠️  被多数类主导，掩盖了少数类的失败")
    print("   ❌ 不适合漏洞检测: 会产生误导性的高分")

    print(f"\n3. Micro-F1 = {comparison['micro_f1']['value']:.4f}")
    print("   计算: (810 + 30) / 1000 = 0.84")
    print("   ℹ️  等同于准确率，反映整体表现")

    print("\n" + "=" * 70)
    print("💡 关键洞察")
    print("=" * 70)
    print("""
在漏洞检测场景中:
1. 如果只看Weighted-F1 (0.88)，会误以为模型很好
2. 但Macro-F1 (0.62) 揭示了真相: 模型在检测漏洞上很差
3. Vulnerable类只有30%的F1，意味着70%的漏洞被漏检!

结论: 必须使用Macro-F1，确保模型在所有类别上都表现好
""")


def demo_imbalanced_case_vulnerable():
    """演示不平衡数据集的情况 - 少数类表现好"""
    print("\n" + "=" * 70)
    print("场景3: 不平衡数据集 - 少数类(Vulnerable)表现好")
    print("=" * 70)
    print("\n这次假设模型在少数类上表现很好:")
    print("- Benign: 900 samples, F1 ≈ 0.60")
    print("- Vulnerable: 100 samples, F1 ≈ 0.95")
    print("\n💡 这是一个好模型! 能准确识别漏洞")

    metrics = MultiClassMetrics()

    # Benign: 900 samples, 60% correct
    for i in range(540):
        metrics.add_prediction("Benign", "Benign")
    for i in range(360):
        metrics.add_prediction("Vulnerable", "Benign")

    # Vulnerable: 100 samples, 95% correct
    for i in range(95):
        metrics.add_prediction("Vulnerable", "Vulnerable")
    for i in range(5):
        metrics.add_prediction("Benign", "Vulnerable")

    # 打印报告
    metrics.print_report("少数类表现好")

    # 对比F1方法
    comparison = compare_averaging_methods(metrics)

    print("\n" + "=" * 70)
    print("F1指标对比分析")
    print("=" * 70)

    print(f"\n1. Macro-F1 = {comparison['macro_f1']['value']:.4f}")
    print("   计算: (0.60 + 0.95) / 2 ≈ 0.775")
    print("   💡 准确反映了模型在两个类别上的平均表现")

    print(f"\n2. Weighted-F1 = {comparison['weighted_f1']['value']:.4f}")
    print("   计算: 0.60 × 0.9 + 0.95 × 0.1 ≈ 0.635")
    print("   ⚠️  被多数类拉低，没有体现少数类的优秀表现")

    print(f"\n3. Micro-F1 = {comparison['micro_f1']['value']:.4f}")
    print("   计算: (540 + 95) / 1000 = 0.635")

    print("\n" + "=" * 70)
    print("💡 对比场景2和场景3")
    print("=" * 70)
    print("""
场景2 (多数类好):
- Macro-F1: 0.62 → 揭示少数类很差
- Weighted-F1: 0.88 → 掩盖少数类失败

场景3 (少数类好):
- Macro-F1: 0.78 → 肯定少数类的优秀表现
- Weighted-F1: 0.64 → 忽视少数类的贡献

结论: Macro-F1是唯一能公平对待所有类别的指标
""")


def demo_three_layer_example():
    """演示三层检测中的实际应用"""
    print("\n" + "=" * 70)
    print("场景4: 三层漏洞检测实际应用")
    print("=" * 70)

    print("""
假设Layer 1 (大类分类) 的结果:
- Memory:    50 samples, F1 = 0.85
- Injection: 30 samples, F1 = 0.75
- Logic:     10 samples, F1 = 0.45  ← 少数类表现差!
- Input:     8 samples,  F1 = 0.30  ← 更少，更差!
- Crypto:    2 samples,  F1 = 0.50

如果使用Weighted-F1:
    0.85×0.50 + 0.75×0.30 + 0.45×0.10 + 0.30×0.08 + 0.50×0.02
    = 0.425 + 0.225 + 0.045 + 0.024 + 0.010
    = 0.729  ← 看起来不错!

但Macro-F1会揭示真相:
    (0.85 + 0.75 + 0.45 + 0.30 + 0.50) / 5
    = 0.57  ← 表明模型在少数类上有严重问题!

💡 在安全领域，我们必须关注Logic和Input这些少数类，
   因为它们同样可能包含严重漏洞。

推荐做法:
1. 使用Macro-F1作为主要指标
2. 同时报告Weighted-F1作为参考
3. 分析每个类别的F1，找出需要改进的类别
""")


def main():
    """主函数"""
    print("🎯 Macro/Weighted/Micro F1指标对比演示")
    print("=" * 70)
    print("\n本演示将展示三种F1计算方式在不同场景下的表现,")
    print("并解释为什么在漏洞检测中必须使用Macro-F1。")

    # 场景1: 平衡数据集
    demo_balanced_case()

    input("\n按Enter继续下一个场景...")

    # 场景2: 不平衡数据集 - 多数类好
    demo_imbalanced_case_benign()

    input("\n按Enter继续下一个场景...")

    # 场景3: 不平衡数据集 - 少数类好
    demo_imbalanced_case_vulnerable()

    input("\n按Enter继续下一个场景...")

    # 场景4: 三层检测实际应用
    demo_three_layer_example()

    # 总结
    print("\n" + "=" * 70)
    print("📊 最终总结")
    print("=" * 70)
    print("""
1. Macro-F1 (宏平均):
   - "众生平等" - 所有类别同等重要
   - 强制模型在所有类别(包括少数类)上都表现好
   - ✅ 推荐用于漏洞检测

2. Weighted-F1 (加权平均):
   - "按资排辈" - 样本多的类别权重大
   - 容易产生误导性的高分
   - ❌ 不推荐用于漏洞检测

3. Micro-F1 (微平均):
   - 等同于准确率
   - 反映整体表现
   - ℹ️  可作为辅助指标

在EvoPrompt系统中:
- 所有评估默认计算三种F1
- 重点关注Macro-F1
- 结果中会标注推荐指标 ⭐
""")

    print("\n" + "=" * 70)
    print("✅ 演示完成!")
    print("\n下一步:")
    print("   运行: uv run python scripts/ablations/train_three_layer.py --eval-samples 50")
    print("   查看实际三层检测中的Macro-F1表现")
    print("=" * 70)

    return 0


if __name__ == "__main__":
    sys.exit(main())
