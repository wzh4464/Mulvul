# NL AST 生成限制和解决方案

## 问题说明

当前生成的 `natural_language_ast` 字段与原始 `func` 字段**内容相同**。

### 原因

comment4vul 的 NL AST 生成需要**两个步骤**:

```
步骤 1: 原始代码 → [LLM] → 带语义注释的代码
步骤 2: 带注释代码 → [symbolic.py] → Natural Language AST
```

**当前实现仅完成步骤 2**,但输入是无注释的原始代码,因此 `symbolic.py` 无法将注释插入 AST,输出几乎等于输入。

### 示例

**理想流程**:
```c
// 输入(原始代码)
if (ptr == NULL)
    return -1;

// LLM 生成注释
// Check if pointer is NULL
if (ptr == NULL)
    return -1;

// symbolic.py 生成 NL AST
if (Check if pointer is NULL)
    return -1;
```

**当前实际流程**:
```c
// 输入(无注释)
if (ptr == NULL)
    return -1;

// symbolic.py 输出(无变化)
if (ptr == NULL)
    return -1;
```

---

## 解决方案对比

### 方案 1: 使用当前"伪 NL AST"(快速,已可用)

**优点**:
- ✅ 无需额外工作,数据已生成
- ✅ 系统架构完整,所有集成已完成
- ✅ 可以立即开始实验
- ✅ 即使 NL AST 与原始代码相同,进化算法仍能工作

**缺点**:
- ❌ 没有语义增强,NL AST 无实际价值
- ❌ 无法体现 comment4vul 的核心优势

**适用场景**:
- 验证系统架构和集成是否正确
- 作为 baseline 对比实验
- 快速原型验证

**使用方法**:
```bash
# 直接使用已生成的数据
uv run python run_primevul_1percent.py \
    --data-path data/primevul/primevul_nl_ast/train_nl_ast.jsonl
```

---

### 方案 2: 生成真正的 NL AST(完整,推荐)

**优点**:
- ✅ 真正的语义增强
- ✅ 完整实现 comment4vul 方法
- ✅ 可能显著提升检测性能

**缺点**:
- ❌ 需要大量 LLM API 调用(成本和时间)
- ❌ 对于 PrimeVul 训练集(~21K样本),可能需要数小时

**实施步骤**:

#### 步骤 1: 生成语义注释
```bash
# 测试(10个样本)
uv run python scripts/ablations/generate_semantic_comments.py \
    --input data/primevul/primevul/primevul_train.jsonl \
    --output data/primevul/primevul_commented/train_commented.jsonl \
    --limit 10

# 完整数据集(慎用,需要大量API调用)
uv run python scripts/ablations/generate_semantic_comments.py \
    --input data/primevul/primevul/primevul_train.jsonl \
    --output data/primevul/primevul_commented/train_commented.jsonl
```

#### 步骤 2: 生成 NL AST
```bash
uv run python scripts/ablations/preprocess_primevul_comment4vul.py \
    --primevul-path data/primevul/primevul_commented/train_commented.jsonl \
    --output data/primevul/primevul_nl_ast_true/train_nl_ast.jsonl \
    --use-adapter
```

#### 步骤 3: 运行实验
```bash
uv run python run_primevul_1percent.py \
    --data-path data/primevul/primevul_nl_ast_true/train_nl_ast.jsonl
```

---

## 成本估算(方案 2)

### LLM API 调用成本

**假设**:
- 训练集样本数: 21,000
- 平均代码长度: 150 tokens
- 平均注释长度: 50 tokens
- 总输入 tokens: 21,000 × 150 = 3,150,000
- 总输出 tokens: 21,000 × 50 = 1,050,000

**估算成本** (使用 Qwen3-Coder-480B-A35B-Instruct):
- 输入: 3.15M tokens × $价格 ≈ $X
- 输出: 1.05M tokens × $价格 ≈ $Y
- **总计**: 根据您的 API 定价

**时间估算**:
- 假设每次 API 调用 1 秒
- 21,000 样本 ≈ 5-6 小时

### 优化建议

1. **批量处理**: 修改脚本支持并发 API 调用
2. **缓存**: 避免重复处理相同代码
3. **增量处理**: 支持断点续跑
4. **采样**: 先在 1% 数据上验证效果

---

## 推荐方案

### 情况 1: 快速验证系统
→ **使用方案 1**,验证集成是否正确

### 情况 2: 科学实验
→ **使用方案 2**,在小规模数据(100-1000样本)上对比:
  - Baseline: 无 NL AST
  - Pseudo: "伪 NL AST"(当前数据)
  - True: 真正的 NL AST

### 情况 3: 生产使用
→ **使用方案 2**,完整生成并评估 ROI

---

## 快速测试(推荐)

先在小规模上测试完整流程:

```bash
# 1. 为 100 个样本生成注释(测试 LLM 效果)
uv run python scripts/ablations/generate_semantic_comments.py \
    --input data/primevul_1percent_sample/train_sample.jsonl \
    --output data/primevul_commented_test/train.jsonl \
    --limit 100

# 2. 生成真正的 NL AST
uv run python scripts/ablations/preprocess_primevul_comment4vul.py \
    --primevul-path data/primevul_commented_test/train.jsonl \
    --output data/primevul_nl_ast_test/train.jsonl \
    --use-adapter

# 3. 检查结果
head -1 data/primevul_nl_ast_test/train.jsonl | python -m json.tool | grep -A 5 natural_language_ast

# 4. 如果效果好,再处理完整数据集
```

---

## 当前系统状态

虽然 NL AST 内容与原始代码相同,但**系统架构是完整的**:

✅ **已完成**:
- Dataset 可以加载 NL AST 字段
- Evaluator 支持 `{nl_ast}` 占位符
- 初始 prompts 包含 NL AST 感知模板
- 进化算子保持 NL AST 意识
- 完全向后兼容

⏳ **缺失**:
- LLM 注释生成(方案 2 的步骤 1)

---

## 结论

**短期**: 使用方案 1 验证系统,或在小样本上测试方案 2

**长期**: 如果小规模测试显示 NL AST 有价值,再投入资源处理完整数据集

**关键问题**: 是否值得花费 LLM API 成本来生成真正的 NL AST?
→ 建议先在 100-1000 样本上 A/B 测试

---

## 参考

- comment4vul 论文: 说明了 LLM 注释的重要性
- 注释生成脚本: `scripts/ablations/generate_semantic_comments.py`
- 完整集成报告: `docs/NL_AST_INTEGRATION_COMPLETE.md`
