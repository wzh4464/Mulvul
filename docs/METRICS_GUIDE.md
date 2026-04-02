# 评估指标指南

## 为什么在漏洞检测中必须使用Macro-F1？

### 核心问题：类别不平衡

在漏洞检测数据集中，典型分布如下：

```
Benign (安全代码):     ~90% (900/1000 samples)
Vulnerable (漏洞代码): ~10% (100/1000 samples)
```

在三层检测中更加不平衡：

```
Layer 1 (大类):
- Memory:    50 samples
- Injection: 30 samples
- Logic:     10 samples  ← 少数类
- Input:     8 samples   ← 更少
- Crypto:    2 samples   ← 极少
```

### 三种F1计算方式

#### 1. **Macro-F1** ⭐ 推荐

**公式**:
$$\text{Macro-F1} = \frac{1}{N} \sum_{i=1}^{N} F1_i$$

**特点**:
- "众生平等" - 所有类别同等重要
- 不考虑样本数量
- 强制模型在所有类别上都表现好

**示例**:
```python
Class A (900 samples): F1 = 0.95
Class B (100 samples): F1 = 0.30

Macro-F1 = (0.95 + 0.30) / 2 = 0.625
```

**解读**: 0.625的分数清楚地揭示了模型在Class B上的糟糕表现

---

#### 2. **Weighted-F1** ⚠️ 不推荐

**公式**:
$$\text{Weighted-F1} = \frac{\sum_{i=1}^{N} (F1_i \times S_i)}{S_{total}}$$

**特点**:
- "按资排辈" - 样本多的类别权重大
- 被多数类主导
- 容易产生误导性的高分

**示例**:
```python
Class A (900 samples): F1 = 0.95
Class B (100 samples): F1 = 0.30

Weighted-F1 = (0.95 × 0.9) + (0.30 × 0.1) = 0.885
```

**解读**: 0.885的高分掩盖了模型无法检测Class B的事实！

---

#### 3. **Micro-F1** ℹ️ 辅助参考

**公式**:
$$\text{Micro-F1} = \frac{TP_{global}}{TP_{global} + \frac{1}{2}(FP_{global} + FN_{global})}$$

**特点**:
- 全局计算
- 在多分类中等同于Accuracy
- 反映整体表现

**示例**:
```python
Total correct: 840/1000
Micro-F1 = 0.84 (= Accuracy)
```

---

## 实际案例对比

### 场景1: 多数类表现好 (常见的坏模型)

```
Benign (900 samples):     F1 = 0.95 ✅
Vulnerable (100 samples): F1 = 0.30 ❌ (70%的漏洞被漏检!)

指标对比:
- Macro-F1:    0.625 ← 揭示真相
- Weighted-F1: 0.885 ← 误导性高分!
- Micro-F1:    0.840

结论: 如果只看Weighted-F1，会误以为这是个好模型
```

### 场景2: 少数类表现好 (好模型)

```
Benign (900 samples):     F1 = 0.60
Vulnerable (100 samples): F1 = 0.95 ✅ (能准确检测漏洞!)

指标对比:
- Macro-F1:    0.775 ← 肯定少数类的贡献
- Weighted-F1: 0.635 ← 忽视少数类的优秀表现
- Micro-F1:    0.635

结论: Weighted-F1没有体现模型在关键类别上的优秀表现
```

---

## EvoPrompt中的实现

### 1. 自动计算三种F1

所有评估都会自动计算：

```python
metrics = {
    "layer1": {
        "accuracy": 0.80,
        "macro_f1": 0.65,      # ⭐ 推荐关注
        "weighted_f1": 0.75,
        "micro_f1": 0.80,
        "macro_precision": 0.63,
        "macro_recall": 0.67,
    },
    ...
}
```

### 2. 每个类别的详细指标

```python
"layer1_per_class": {
    "Memory": {
        "precision": 0.85,
        "recall": 0.80,
        "f1_score": 0.825,
        "support": 50
    },
    "Logic": {
        "precision": 0.40,
        "recall": 0.30,
        "f1_score": 0.343,
        "support": 10  # ← 少数类表现差!
    },
    ...
}
```

### 3. 可视化报告

```bash
uv run python scripts/ablations/train_three_layer.py --eval-samples 50
```

输出示例：

```
======================================================================
EVALUATION RESULTS
======================================================================

Total Samples: 50
Full Path Accuracy: 0.4200

----------------------------------------------------------------------
Layer 1 (Major Category)
----------------------------------------------------------------------
  Accuracy:        0.8000
  Macro-F1:        0.6500 ⭐ (推荐)
  Weighted-F1:     0.7500
  Micro-F1:        0.8000
  Macro-Precision: 0.6300
  Macro-Recall:    0.6700

----------------------------------------------------------------------
Layer 2 (Middle Category)
----------------------------------------------------------------------
  Accuracy:        0.7000
  Macro-F1:        0.5500 ⭐ (推荐)
  Weighted-F1:     0.6500
  Micro-F1:        0.7000
  Macro-Precision: 0.5200
  Macro-Recall:    0.5800

----------------------------------------------------------------------
Layer 3 (CWE)
----------------------------------------------------------------------
  Accuracy:        0.6000
  Macro-F1:        0.4500 ⭐ (推荐)
  Weighted-F1:     0.5500
  Micro-F1:        0.6000
  Macro-Precision: 0.4300
  Macro-Recall:    0.4700

======================================================================
💡 推荐关注指标: Macro-F1
   原因: 漏洞检测中类别不平衡，Macro-F1确保所有类别都被重视
======================================================================
```

---

## 使用建议

### 1. 主要指标

✅ **Macro-F1** - 主要优化目标

```python
# 训练时的适应度函数
fitness = metrics["layer1"]["macro_f1"] * 0.4 + \
          metrics["layer2"]["macro_f1"] * 0.3 + \
          metrics["layer3"]["macro_f1"] * 0.3
```

### 2. 辅助指标

📊 **Weighted-F1** - 参考整体表现
📊 **Per-class F1** - 找出需要改进的类别

### 3. 错误分析

通过Per-class指标识别问题：

```python
for class_name, metrics in layer1_per_class.items():
    if metrics["f1_score"] < 0.5:
        print(f"⚠️  {class_name} 表现差: F1 = {metrics['f1_score']}")
        print(f"   Support: {metrics['support']} samples")
        print(f"   建议: 增加该类别的训练样本或优化prompt")
```

---

## 演示脚本

### 查看F1指标对比

```bash
uv run python scripts/ablations/demo_f1_metrics.py
```

这个脚本展示：
1. 平衡数据集中三种F1的表现
2. 不平衡数据集中的误导性问题
3. 为什么必须使用Macro-F1

### 实际评估

```bash
# 基础评估 (会打印详细指标)
uv run python scripts/ablations/train_three_layer.py --eval-samples 50

# RAG增强评估
uv run python scripts/ablations/train_three_layer.py --use-rag --eval-samples 50
```

---

## 论文中的报告

### 推荐格式

在论文中报告所有三种F1，但强调Macro-F1：

| 配置 | Macro-F1 (⭐) | Weighted-F1 | Micro-F1 |
|------|--------------|-------------|----------|
| 基线 | 0.45 | 0.65 | 0.70 |
| + RAG | 0.55 (+22%) | 0.72 (+11%) | 0.78 (+11%) |
| + 训练 | 0.65 (+44%) | 0.80 (+23%) | 0.85 (+21%) |

**说明**: 我们使用Macro-F1作为主要指标，因为漏洞检测数据集存在严重的类别不平衡问题。Macro-F1能够确保模型在所有CWE类别(包括罕见但关键的少数类)上都保持良好性能。

---

## 相关文献

1. **Sokolova & Lapalme (2009)**: "A systematic analysis of performance measures for classification tasks"
   - 详细分析了各种F1计算方式的适用场景

2. **Grandini et al. (2020)**: "Metrics for Multi-Class Classification: an Overview"
   - 多分类场景下的指标选择指南

3. **Ling & Li (1998)**: "Data Mining for Direct Marketing: Problems and Solutions"
   - 不平衡数据集的评估方法

---

## 快速参考

| 指标 | 公式 | 适用场景 | 推荐度 |
|------|------|----------|--------|
| Macro-F1 | mean(F1_i) | 类别不平衡 + 所有类别都重要 | ⭐⭐⭐ |
| Weighted-F1 | sum(F1_i × support_i) / total | 样本分布代表真实情况 | ⚠️ |
| Micro-F1 | global TP / total | 整体准确性 | ℹ️ |

**漏洞检测场景**: 必须使用 **Macro-F1** ⭐

---

## 总结

1. **使用Macro-F1作为主要指标** - 确保所有类别都被公平对待
2. **报告所有三种F1** - 提供完整的性能视图
3. **分析Per-class F1** - 找出需要改进的类别
4. **避免被Weighted-F1误导** - 它会掩盖少数类的失败

记住：**在安全领域，我们不能忽视任何一个类别，哪怕它只有1个样本！**
