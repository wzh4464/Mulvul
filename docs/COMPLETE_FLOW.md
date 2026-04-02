# 完整系统流程说明

## 系统流程概览

```
┌─────────────────────────────────────────────────────────────────┐
│ 阶段0: 准备                                                      │
│ - 环境配置 (.env文件)                                            │
│ - 数据集准备 (train/dev/test)                                    │
│ - 快速测试验证 (test_quick.py)                                   │
└────────────────────────┬────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────────────┐
│ 阶段1: 知识库构建 (可选, --use-rag)                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  选项A: 使用默认知识库                                            │
│  - 预置示例 (每类1-2个)                                          │
│  - 快速，适合测试                                                 │
│                                                                  │
│  选项B: 从数据集构建 (--kb-from-dataset)                         │
│  - 从训练集采样                                                   │
│  - 更真实，适合生产                                               │
│  - 可配置每类采样数量                                             │
│                                                                  │
│  输出:                                                           │
│  ✅ knowledge_base.json (保存知识库)                             │
│  ✅ 统计信息 (总示例数、各类分布)                                 │
│                                                                  │
└────────────────────────┬────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────────────┐
│ 阶段2: 检测器创建                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  基础检测器:                                                      │
│  - 三层Prompt集合 (默认prompt)                                   │
│  - LLM客户端 (GPT-4/Qwen)                                       │
│  - Scale增强 (可选, --use-scale)                                │
│                                                                  │
│  RAG检测器 (--use-rag):                                          │
│  - 基础检测器 + 知识库                                            │
│  - 检索器 (lexical/embedding)                                    │
│  - top-k配置 (默认2)                                             │
│                                                                  │
│  输出:                                                           │
│  ✅ 配置好的检测器实例                                            │
│                                                                  │
└────────────────────────┬────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────────────┐
│ 阶段3: 单样本检测流程 (核心)                                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  输入: 代码片段                                                   │
│      ↓                                                           │
│  [可选] Scale增强                                                │
│      ↓                                                           │
│  Layer 1: 大类检测                                               │
│  ┌────────────────────────────────────────────┐                 │
│  │ 1. [RAG] 检索全局相似示例 (top-k=2)        │                 │
│  │ 2. [RAG] 格式化示例并注入prompt            │                 │
│  │ 3. 调用LLM: Prompt1 + RAG示例 + Code       │                 │
│  │ 4. 解析响应: Memory/Injection/Logic/...    │                 │
│  └────────────────────────────────────────────┘                 │
│      ↓                                                           │
│  Layer 2: 中类检测                                               │
│  ┌────────────────────────────────────────────┐                 │
│  │ 1. [RAG] 检索该大类下的相似示例             │                 │
│  │ 2. [RAG] 格式化示例并注入prompt            │                 │
│  │ 3. 调用LLM: Prompt2[大类] + RAG示例 + Code │                 │
│  │ 4. 解析响应: Buffer Overflow/SQL Inj/...   │                 │
│  └────────────────────────────────────────────┘                 │
│      ↓                                                           │
│  Layer 3: CWE检测                                                │
│  ┌────────────────────────────────────────────┐                 │
│  │ 1. [RAG] 检索该中类下的相似示例             │                 │
│  │ 2. [RAG] 格式化示例并注入prompt            │                 │
│  │ 3. 调用LLM: Prompt3[中类] + RAG示例 + Code │                 │
│  │ 4. 解析响应: CWE-120/CWE-89/...            │                 │
│  └────────────────────────────────────────────┘                 │
│      ↓                                                           │
│  输出:                                                           │
│  ✅ CWE (最终分类结果)                                           │
│  ✅ 检测路径 (layer1 → layer2 → layer3)                         │
│  ✅ RAG检索信息 (示例数、相似度分数)                              │
│                                                                  │
│  API调用:                                                        │
│  - 无Scale, 无RAG: 3次 (Layer 1/2/3)                           │
│  - 有Scale, 无RAG: 4次 (Scale + Layer 1/2/3)                   │
│  - 无Scale, 有RAG: 3次 (RAG检索在本地)                          │
│  - 有Scale, 有RAG: 4次                                          │
│                                                                  │
└────────────────────────┬────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────────────┐
│ 阶段4: 批量评估 (仅评估模式)                                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  for each sample in eval_dataset:                               │
│      predicted_cwe, details = detector.detect(code)              │
│                                                                  │
│      # 对比ground truth                                         │
│      actual_major, actual_middle, actual_cwe = get_full_path()  │
│                                                                  │
│      # 统计各层准确率                                            │
│      if details["layer1"] == actual_major:                      │
│          layer1_correct++                                       │
│      if details["layer2"] == actual_middle:                     │
│          layer2_correct++                                       │
│      if predicted_cwe == actual_cwe:                            │
│          layer3_correct++                                       │
│      if all_correct:                                            │
│          full_path_correct++                                    │
│                                                                  │
│  输出:                                                           │
│  ✅ metrics.json (各层准确率)                                    │
│  ✅ prompts.json (使用的prompt)                                 │
│  ✅ config.json (运行配置)                                       │
│                                                                  │
└────────────────────────┬────────────────────────────────────────┘
                         ↓
                   [如果--train]
                         ↓
┌─────────────────────────────────────────────────────────────────┐
│ 阶段5: Multi-Agent训练 (训练模式)                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  初始化:                                                         │
│  - Detection Agent (GPT-4): 批量检测                             │
│  - Meta Agent (Claude 4.5): Prompt优化                          │
│  - 初始种群 (population_size=5)                                  │
│                                                                  │
│  进化循环 (max_generations=20):                                  │
│  ┌──────────────────────────────────────────┐                   │
│  │ Generation N:                            │                   │
│  │                                          │                   │
│  │ 1. 评估种群                              │                   │
│  │    for individual in population:         │                   │
│  │        # 批量检测                        │                   │
│  │        predictions = detection_agent.    │                   │
│  │                      detect_batch(       │                   │
│  │                          individual.     │                   │
│  │                          prompt,         │                   │
│  │                          samples         │                   │
│  │                      )                   │                   │
│  │        # 计算适应度                      │                   │
│  │        individual.fitness = accuracy     │                   │
│  │                                          │                   │
│  │ 2. 收集统计信息                          │                   │
│  │    - 每类准确率                          │                   │
│  │    - 混淆矩阵                            │                   │
│  │    - 错误模式                            │                   │
│  │                                          │                   │
│  │ 3. 选择                                  │                   │
│  │    - 精英保留 (elite_size=1)             │                   │
│  │    - 轮盘赌选择父代                      │                   │
│  │                                          │                   │
│  │ 4. 交叉变异                              │                   │
│  │    - 单点交叉                            │                   │
│  │    - LLM变异 (mutation_rate=0.3)         │                   │
│  │                                          │                   │
│  │ 5. Meta优化 (每meta_improve_interval代)  │                   │
│  │    if generation % 3 == 0:               │                   │
│  │        # 选择需要优化的个体              │                   │
│  │        for individual in select_worst(): │                   │
│  │            # Meta Agent分析并优化        │                   │
│  │            improved = meta_agent.        │                   │
│  │                       improve_prompt(    │                   │
│  │                           current_prompt,│                   │
│  │                           statistics,    │                   │
│  │                           error_patterns │                   │
│  │                       )                  │                   │
│  │            individual.prompt = improved  │                   │
│  │                                          │                   │
│  │ 6. 更新种群                              │                   │
│  │    population = elite + offspring        │                   │
│  │                                          │                   │
│  └──────────────────────────────────────────┘                   │
│                                                                  │
│  输出:                                                           │
│  ✅ 最佳prompt集合                                               │
│  ✅ 训练历史                                                     │
│  ✅ 最终评估结果                                                 │
│                                                                  │
└────────────────────────┬────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────────────┐
│ 阶段6: 最终评估和保存                                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  使用优化后的prompt重新评估:                                      │
│  - 在验证集上评估                                                 │
│  - 计算各层准确率                                                 │
│  - 分析性能提升                                                   │
│                                                                  │
│  保存结果:                                                        │
│  ✅ outputs/<timestamp>/                                        │
│     ├── config.json      (运行配置)                              │
│     ├── metrics.json     (评估指标)                              │
│     ├── prompts.json     (优化后的prompt)                        │
│     └── prompts.txt      (可读格式)                              │
│                                                                  │
│  如果使用RAG:                                                    │
│  ✅ outputs/knowledge_base.json (知识库)                         │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## 参数控制流程

### 评估模式 (不训练)

```bash
uv run python scripts/ablations/train_three_layer.py \
    [--use-rag]              # 可选: 启用RAG
    [--use-scale]            # 可选: 启用Scale
    --eval-samples 50        # 评估样本数
```

**流程**: 阶段0 → 阶段1 (如--use-rag) → 阶段2 → 阶段3 → 阶段4 → 阶段6

**时间**: 5-10分钟

---

### 训练模式

```bash
uv run python scripts/ablations/train_three_layer.py \
    --train                  # 启用训练
    [--use-rag]              # 可选: 启用RAG
    [--kb-from-dataset]      # 可选: 从数据集构建KB
    [--use-scale]            # 可选: 启用Scale
    --population-size 5      # 种群大小
    --max-generations 20     # 最大代数
    --eval-samples 100       # 评估样本数
```

**流程**: 阶段0 → 阶段1 → 阶段2 → 阶段3 → 阶段4 → 阶段5 → 阶段6

**时间**: 2-4小时

---

## RAG自动构建流程

### 场景1: 使用默认知识库

```python
if --use-rag and not kb_path.exists():
    print("构建默认知识库...")
    kb = KnowledgeBaseBuilder.create_default_kb()
    kb.save(kb_path)
    print(f"✅ 知识库已保存: {kb_path}")
```

**特点**:
- 自动构建
- 使用预置示例
- 快速 (1-2秒)

---

### 场景2: 从数据集构建

```python
if --use-rag and --kb-from-dataset:
    print("从数据集构建知识库...")
    dataset = load_dataset(train_file)
    kb = create_knowledge_base_from_dataset(
        dataset,
        samples_per_category=kb_samples_per_category  # 默认3
    )
    kb.save(kb_path)
    print(f"✅ 知识库已保存: {kb_path}")
    print(f"   总示例: {kb.statistics()['total_examples']}")
```

**特点**:
- 自动构建
- 从训练数据采样
- 更真实 (30秒-1分钟)

---

### 场景3: 使用已有知识库

```python
if --use-rag and kb_path.exists():
    print(f"加载已有知识库: {kb_path}")
    kb = KnowledgeBase.load(kb_path)
    print(f"✅ 已加载 {kb.statistics()['total_examples']} 个示例")
```

**特点**:
- 跳过构建
- 直接加载
- 最快 (1秒)

---

## Scale自动启用流程

```python
if --use-scale:
    detector = ThreeLayerDetector(
        prompt_set=prompt_set,
        llm_client=llm_client,
        use_scale_enhancement=True  # Scale已启用
    )

    # 检测时自动调用Scale
    for code in codes:
        # 1. Scale增强
        enhanced_code = scale_enhance(code)

        # 2. 三层检测 (使用增强后的代码)
        cwe, details = detect(enhanced_code)

        # details中包含:
        # - enhanced_code: 增强后的代码
        # - layer1/2/3: 各层结果
```

**特点**:
- 参数控制
- 自动调用
- 每样本+1次API调用

---

## 参数关闭流程

### 关闭RAG

```bash
# 不使用 --use-rag 标志
uv run python scripts/ablations/train_three_layer.py --eval-samples 50
```

**效果**:
- 跳过知识库构建
- 不检索示例
- 使用基础检测器

---

### 关闭Scale

```bash
# 不使用 --use-scale 标志
uv run python scripts/ablations/train_three_layer.py --eval-samples 50
```

**效果**:
- 跳过Scale增强
- 直接使用原始代码
- 减少1次API调用

---

### 关闭训练

```bash
# 不使用 --train 标志
uv run python scripts/ablations/train_three_layer.py --eval-samples 50
```

**效果**:
- 仅评估
- 不运行进化
- 快速得到结果

---

## 完整命令示例

### 最小配置 (基线)

```bash
uv run python scripts/ablations/train_three_layer.py \
    --eval-samples 50
```

**启用**: 基础三层检测
**关闭**: RAG, Scale, 训练
**时间**: ~5分钟

---

### RAG增强评估

```bash
uv run python scripts/ablations/train_three_layer.py \
    --use-rag \
    --eval-samples 50
```

**启用**: 基础检测 + RAG (自动构建默认KB)
**关闭**: Scale, 训练
**时间**: ~5分钟

---

### 完整评估 (RAG + Scale)

```bash
uv run python scripts/ablations/train_three_layer.py \
    --use-rag \
    --use-scale \
    --eval-samples 50
```

**启用**: 基础检测 + RAG + Scale
**关闭**: 训练
**时间**: ~8分钟

---

### 快速训练测试

```bash
uv run python scripts/ablations/train_three_layer.py \
    --train \
    --population-size 3 \
    --max-generations 5 \
    --eval-samples 30
```

**启用**: 基础检测 + 训练 (小规模)
**关闭**: RAG, Scale
**时间**: ~30分钟

---

### 完整训练 (最佳配置)

```bash
uv run python scripts/ablations/train_three_layer.py \
    --train \
    --use-rag \
    --kb-from-dataset \
    --kb-samples-per-category 5 \
    --use-scale \
    --population-size 5 \
    --max-generations 20 \
    --batch-size 20 \
    --eval-samples 100
```

**启用**: 所有功能
**关闭**: 无
**时间**: ~4小时

---

## 输出文件说明

### 评估模式输出

```
outputs/three_layer_eval_rag_20250122_143000/
├── config.json           # 运行配置
│   {
│     "use_rag": true,
│     "use_scale": false,
│     "train": false,
│     ...
│   }
├── metrics.json          # 评估指标
│   {
│     "layer1_accuracy": 0.80,
│     "layer2_accuracy": 0.70,
│     "layer3_accuracy": 0.60,
│     "full_path_accuracy": 0.40
│   }
├── prompts.json          # Prompt集合 (JSON)
└── prompts.txt           # Prompt集合 (可读)
```

### 训练模式输出

```
outputs/three_layer_train_rag_20250122_150000/
├── config.json           # 运行配置
├── metrics.json          # 最终评估指标
├── prompts.json          # 优化后的prompt (JSON)
├── prompts.txt           # 优化后的prompt (可读)
└── training_history.json # 训练历史 (未来实现)
```

### 知识库输出 (如使用RAG)

```
outputs/knowledge_base.json
{
  "major_examples": {...},
  "middle_examples": {...},
  "cwe_examples": {...}
}
```

---

## 总结

### 核心流程

1. **准备**: 环境 + 数据 + 快速测试
2. **构建KB**: 自动构建 (如启用RAG)
3. **检测**: 三层 + RAG检索 + Scale增强
4. **评估**: 批量评估 + 统计指标
5. **训练**: Multi-agent进化 (如启用)
6. **保存**: 结果 + prompt + KB

### 参数控制

- `--use-rag`: 自动构建和使用知识库
- `--use-scale`: 自动启用Scale增强
- `--train`: 启用训练模式
- `--kb-from-dataset`: 从数据集构建KB
- 所有功能都可独立开关

### 推荐配置

- **快速测试**: 无参数 (5分钟)
- **RAG评估**: `--use-rag` (5分钟)
- **完整训练**: `--train --use-rag --kb-from-dataset` (4小时)
