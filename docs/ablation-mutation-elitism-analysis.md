# Constrained Mutation & Elitism Ablation 分析报告

## 实验配置

| 参数 | 值 |
|------|-----|
| 数据集 | PrimeVul-Balanced-20 (2000 samples) |
| 进化轮数 | 5 (当前完成 Gen 2) |
| Population | 5 per node |
| 节点数 | 64 (5 major + 13 middle + 46 CWE) |

## 四组实验对比

| 方法 | Elitism | Constrained | Gen 0 | Gen 2 | 提升% | vs Baseline |
|------|---------|-------------|-------|-------|-------|-------------|
| **no_constrained** | ✓ | ✗ | 0.3077 | **0.3180** | +3.35% | **+0.0028** |
| baseline | ✓ | ✓ | 0.3003 | 0.3152 | +4.96% | — |
| no_elitism | ✗ | ✓ | 0.2900 | 0.3099 | **+6.86%** | -0.0053 |
| no_both | ✗ | ✗ | 0.2959 | 0.3037 | +2.64% | -0.0115 |

**结论**: `no_constrained` 达到最高 F1，`no_elitism` 提升速度最快，`no_both` 最差。

---

## 成功案例分析

### Top 5 提升节点

| 节点 | 方法 | Seed F1 | Best F1 | 提升 | 进化方式 |
|------|------|---------|---------|------|----------|
| cwe_CWE-399 | no_elitism | 0.000 | 0.435 | **+0.435** | crossover |
| middle_Memory Management | no_constrained | 0.190 | 0.561 | **+0.371** | crossover |
| middle_Memory Management | baseline | 0.205 | 0.478 | +0.273 | mutation |
| cwe_CWE-189 | baseline | 0.176 | 0.444 | +0.268 | crossover |
| cwe_CWE-200 | no_elitism | 0.065 | 0.229 | +0.164 | crossover |

### 成功的 Prompt 改写模式

**1. 添加语义定义** (最有效)

```diff
- Identify if this code has CWE-399.
- Possible CWEs: CWE-399, CWE-400, CWE-770, CWE-835, Benign.
+ - CWE-399 — Resource Management Errors (general/other): Use this when 
+   the code has a resource-management problem but it is NOT more 
+   specifically best described as uncontrolled consumption (CWE-400)...
+ - CWE-400 — Uncontrolled Resource Consumption: Choose only when the 
+   main issue is that attacker influence can drive excessive consumption...
```

**2. 添加决策边界** (解决相邻类别混淆)

```diff
- Classify the code into one of: Buffer Errors, Memory Management...
+ - Buffer Errors: out-of-bounds read/write, overflow, underflow
+ - Memory Management: double free, use-after-free, memory leaks
+ - Pointer Dereference: null, uninitialized, wild pointer dereference
+ Choose the single best match even if multiple seem plausible.
```

**3. 层次化排除法**

```
Use CWE-399 when the problem is NOT more specifically:
- CWE-400 (uncontrolled consumption)
- CWE-770 (missing limits)
- CWE-835 (infinite loop)
```

---

## 失败案例分析

### 进化失败统计

| 方法 | 失败数 | 失败率 |
|------|--------|--------|
| baseline | 92 | 28.8% |
| no_elitism | 94 | 29.4% |
| no_constrained | 104 | 32.5% |
| **no_both** | **129** | **40.3%** |

**no_both 失败最多**，说明同时去掉两个保护机制会导致进化失控。

### 失败模式

**1. 结构性破坏** (no_both 最常见)
- 进化后的 prompt 丢失了 `{code}` 或 `{evidence}` 占位符
- 输出格式被改坏，无法解析 JSON

**2. 过度泛化**
- 原本针对特定 CWE 的 prompt 被改写成通用描述
- 失去了区分相邻 CWE 的能力

**3. 训练数据不足的节点**
- `major_Injection` 在所有方法中 F1=0
- 原因：数据集中 Injection 样本极少，进化无法学到有效模式

---

## 机制效果分解

### Elitism 的作用

| 比较 | 结果 | 解释 |
|------|------|------|
| baseline vs no_elitism | F1 +0.0053 | Elitism 保护好的 prompt |
| no_constrained vs no_both | F1 +0.0143 | 无 Elitism 时更多节点被破坏 |

**Elitism 提供稳定性**：防止高分 prompt 被进化操作破坏。

### Constrained Mutation 的作用

| 比较 | 结果 | 解释 |
|------|------|------|
| baseline vs no_constrained | F1 **-0.0028** | Constrained 反而限制改进 |
| no_elitism vs no_both | F1 +0.0062 | 无 Elitism 时 Constrained 有保护作用 |

**Constrained Mutation 有负面效果**（当有 Elitism 保护时）：
- 只允许改 header，限制了结构性重写
- 最成功的改进都需要添加语义定义，这需要更大的改写空间

---

## 核心发现

### 1. Seed Prompt 过于简洁

大多数 seed prompt 只是：
```
Identify if this code has CWE-XXX.
Possible CWEs: CWE-XXX, CWE-YYY, Benign.
```

**缺少**：语义定义、决策边界、区分标准。

### 2. 进化成功的关键是"添加"而非"修改"

| 操作 | 成功率 | 原因 |
|------|--------|------|
| 添加 CWE 语义描述 | 高 | 帮助 LLM 理解类别含义 |
| 添加决策边界 | 高 | 解决相邻类别混淆 |
| 重写指令结构 | 中 | 有风险但可能大幅改进 |
| 删除内容 | 低 | 通常导致信息丢失 |

### 3. 最佳策略

```
保留 Elitism (保护高分节点) + 放开 Constrained (允许结构性重写)
```

这让：
- 高分节点保持稳定
- 低分节点可以进行激进改写
- 实现最高的最终 F1 (0.3180)

---

## 下一步建议

1. **改进 Seed Prompt**：在初始 prompt 中就添加 CWE 语义描述
2. **自适应 Elitism**：根据节点 F1 动态调整阈值，而非固定 0.5
3. **结构化 Mutation**：允许在特定位置（如候选列表后）插入内容
4. **Cascade 感知进化**：优化节点组合而非单独节点

---

*生成时间: 2026-04-12 | 数据截至 Generation 2*
