# Mulvul 完整工作流程

## 系统流程图

```
┌─────────────────────────────────────────────────────────────────┐
│                      输入: 漏洞代码                              │
└────────────────────────────┬────────────────────────────────────┘
                             ↓
        ┌────────────────────────────────────────┐
        │  可选: 自动构建知识库 (--use-rag)      │
        │  - 从默认示例构建                       │
        │  - 或从数据集采样构建                   │
        └────────────────┬───────────────────────┘
                         ↓
        ┌────────────────────────────────────────┐
        │  可选: Scale增强 (--use-scale)         │
        │  - 语义增强代码表示                     │
        │  - 提供更丰富的上下文                   │
        └────────────────┬───────────────────────┘
                         ↓
┌────────────────────────────────────────────────────────────────┐
│                    三层层级检测                                 │
├────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Layer 1: 大类分类                                              │
│  ├─ 可选: 检索相似示例 (RAG)                                    │
│  ├─ Prompt 1: 判断大类                                          │
│  └─ 输出: Memory/Injection/Logic/Input/Crypto/Benign           │
│           ↓                                                     │
│  Layer 2: 中类分类                                              │
│  ├─ 可选: 检索该大类下的相似示例 (RAG)                          │
│  ├─ Prompt 2[大类]: 判断中类                                    │
│  └─ 输出: Buffer Overflow/SQL Injection/etc.                    │
│           ↓                                                     │
│  Layer 3: CWE分类                                               │
│  ├─ 可选: 检索该中类下的相似示例 (RAG)                          │
│  ├─ Prompt 3[中类]: 判断CWE                                     │
│  └─ 输出: CWE-120/CWE-89/etc.                                   │
│                                                                 │
└────────────────────────┬───────────────────────────────────────┘
                         ↓
        ┌────────────────────────────────────────┐
        │  输出: CWE + 完整检测路径               │
        │  - 每层的分类结果                       │
        │  - RAG检索信息 (如启用)                 │
        │  - 相似度分数                           │
        └────────────────┬───────────────────────┘
                         ↓
        ┌────────────────────────────────────────┐
        │  可选: Multi-Agent训练 (--train)        │
        │  1. Detection Agent批量检测             │
        │  2. 收集统计信息和错误模式               │
        │  3. Meta Agent分析并优化prompt          │
        │  4. 进化算法迭代优化                     │
        └────────────────┬───────────────────────┘
                         ↓
┌────────────────────────────────────────────────────────────────┐
│                    最终输出                                     │
├────────────────────────────────────────────────────────────────┤
│  - 优化后的prompt集合                                           │
│  - 评估指标 (各层准确率)                                        │
│  - 训练历史 (如训练)                                            │
└────────────────────────────────────────────────────────────────┘
```

## 详细流程

### 阶段1: 准备阶段

```bash
# 1.1 环境检查
load_env_vars()
check_api_key()
```

**输出**: ✅ 环境配置正常

```bash
# 1.2 知识库准备 (如启用RAG)
if --use-rag:
    if kb_exists:
        load_knowledge_base()
    else:
        build_knowledge_base()
        save_knowledge_base()
```

**输出**: 📚 知识库 (X个示例)

```bash
# 1.3 数据集加载
load_dataset(train_file)
load_dataset(eval_file)
```

**输出**: 📊 训练集 (526样本) + 验证集 (50样本)

---

### 阶段2: 检测阶段

```python
# 2.1 创建检测器
if use_rag:
    detector = RAGThreeLayerDetector(
        prompt_set, llm_client, kb,
        use_scale_enhancement=use_scale,
        top_k=2
    )
else:
    detector = ThreeLayerDetector(
        prompt_set, llm_client,
        use_scale_enhancement=use_scale
    )

# 2.2 单样本检测流程
for code in codes:
    # Step 1: Scale增强 (可选)
    if use_scale:
        enhanced_code = enhance_code(code)
    else:
        enhanced_code = code

    # Step 2: Layer 1检测
    if use_rag:
        examples = retrieve_similar(enhanced_code, level="major")
        prompt1 = inject_examples(base_prompt1, examples)
    else:
        prompt1 = base_prompt1

    major_category = llm_classify(prompt1, enhanced_code)

    # Step 3: Layer 2检测
    if use_rag:
        examples = retrieve_similar(enhanced_code, major_category)
        prompt2 = inject_examples(base_prompt2[major_category], examples)
    else:
        prompt2 = base_prompt2[major_category]

    middle_category = llm_classify(prompt2, enhanced_code)

    # Step 4: Layer 3检测
    if use_rag:
        examples = retrieve_similar(enhanced_code, middle_category)
        prompt3 = inject_examples(base_prompt3[middle_category], examples)
    else:
        prompt3 = base_prompt3[middle_category]

    cwe = llm_classify(prompt3, enhanced_code)

    # 返回结果
    return cwe, {
        "layer1": major_category,
        "layer2": middle_category,
        "layer3": cwe,
        "layer1_retrieval": {...},  # 如启用RAG
        "layer2_retrieval": {...},
        "layer3_retrieval": {...}
    }
```

**输出**: 每个样本的CWE + 检测路径

---

### 阶段3: 评估阶段

```python
# 3.1 批量评估
evaluator = ThreeLayerEvaluator(detector, dataset)
metrics = evaluator.evaluate(sample_size=50)

# 3.2 计算指标
for sample in samples:
    predicted_cwe, details = detector.detect(sample.code)
    actual_cwe = sample.cwe

    # 检查各层准确性
    actual_major, actual_middle, _ = get_full_path(actual_cwe)

    if details["layer1"] == actual_major:
        layer1_correct += 1

    if details["layer2"] == actual_middle:
        layer2_correct += 1

    if predicted_cwe == actual_cwe:
        layer3_correct += 1

    if all_layers_correct:
        full_path_correct += 1

# 3.3 输出结果
metrics = {
    "layer1_accuracy": layer1_correct / total,
    "layer2_accuracy": layer2_correct / total,
    "layer3_accuracy": layer3_correct / total,
    "full_path_accuracy": full_path_correct / total
}
```

**输出**: 📈 各层准确率

---

### 阶段4: 训练阶段 (可选)

```python
# 4.1 创建Multi-Agent系统
detection_agent = create_detection_agent("gpt-4")
meta_agent = create_meta_agent("claude-4.5")
coordinator = MultiAgentCoordinator(detection_agent, meta_agent)

# 4.2 创建进化算法
algorithm = CoevolutionaryAlgorithm(
    evaluator=evaluator,
    coordinator=coordinator,
    population_size=5,
    max_generations=20
)

# 4.3 进化循环
for generation in range(max_generations):
    # 4.3.1 评估种群
    for individual in population:
        fitness = evaluate(individual.prompt)
        individual.fitness = fitness

    # 4.3.2 选择
    elite = select_elite(population)
    parents = select_parents(population)

    # 4.3.3 交叉变异
    offspring = crossover(parents)
    offspring = mutate(offspring)

    # 4.3.4 Meta优化 (定期)
    if generation % meta_improve_interval == 0:
        # 收集统计信息
        stats = collect_statistics(population)

        # Meta Agent优化
        for individual in select_for_meta_improve(population):
            improved_prompt = meta_agent.improve_prompt(
                current_prompt=individual.prompt,
                statistics=stats,
                error_patterns=analyze_errors(individual)
            )
            individual.prompt = improved_prompt

    # 4.3.5 更新种群
    population = elite + offspring

# 4.4 返回最佳prompt
best_individual = max(population, key=lambda x: x.fitness)
```

**输出**: 🏆 优化后的prompt集合

---

### 阶段5: 保存阶段

```python
# 5.1 保存配置
save_config(output_dir, {
    "use_rag": use_rag,
    "use_scale": use_scale,
    "train": train,
    ...
})

# 5.2 保存评估结果
save_metrics(output_dir, metrics)

# 5.3 保存prompt
save_prompts(output_dir, prompt_set)

# 5.4 保存知识库 (如使用)
if use_rag:
    save_knowledge_base(kb_path, kb)
```

**输出**: 💾 完整实验结果

---

## 时间流程

### 快速评估 (5-10分钟)

```
环境准备 (10s)
    ↓
加载数据 (5s)
    ↓
创建检测器 (2s)
    ↓
评估50样本 (5-8分钟)
    ↓
保存结果 (2s)
```

### RAG评估 (5-10分钟)

```
环境准备 (10s)
    ↓
构建知识库 (10s)
    ↓
加载数据 (5s)
    ↓
创建RAG检测器 (2s)
    ↓
评估50样本 (5-8分钟)
  每样本:
  - 检索示例 (0.01s) × 3层
  - LLM调用 (2-3s) × 3层
    ↓
保存结果 (2s)
```

### 完整训练 (2-4小时)

```
环境准备 (10s)
    ↓
构建知识库 (30s, 如从数据集)
    ↓
加载数据 (5s)
    ↓
创建Multi-Agent (5s)
    ↓
进化训练 (2-4小时)
  每代 (5-10分钟):
  - 评估种群 (2-5分钟)
  - 选择交叉变异 (1分钟)
  - Meta优化 (2-3分钟, 每3代)
    ↓
最终评估 (10分钟)
    ↓
保存结果 (5s)
```

## 数据流

```
输入代码
    ↓
[Scale] → 增强代码
    ↓
[RAG Layer 1] → 检索示例 → 注入prompt
    ↓
[LLM Layer 1] → 大类
    ↓
[RAG Layer 2] → 检索示例 → 注入prompt
    ↓
[LLM Layer 2] → 中类
    ↓
[RAG Layer 3] → 检索示例 → 注入prompt
    ↓
[LLM Layer 3] → CWE
    ↓
输出: CWE + 路径 + 检索信息
```

## API调用流程

### 单样本检测 (无Scale, 无RAG)

```
API调用次数: 3次
1. Layer 1 LLM调用 → 大类
2. Layer 2 LLM调用 → 中类
3. Layer 3 LLM调用 → CWE

总时间: ~6-9秒
```

### 单样本检测 (有Scale, 有RAG)

```
API调用次数: 4次
1. Scale LLM调用 → 增强代码
2. Layer 1 LLM调用 → 大类 (含RAG示例)
3. Layer 2 LLM调用 → 中类 (含RAG示例)
4. Layer 3 LLM调用 → CWE (含RAG示例)

总时间: ~8-12秒
(RAG检索在本地，不增加API调用)
```

### 训练 (20代, 种群5, 批大小20)

```
总API调用次数估算:
- 每代评估: 5个体 × 20样本/批 × 3层 = 300次
- Meta优化: ~7次 (每3代) × 2个体 × 1次 = 14次
- 总计: 20代 × 300 + 14 = ~6014次

总时间: 2-4小时
(取决于API速度和批处理效率)
```

## 配置决策树

```
开始
 ↓
需要训练? ──No──→ 评估模式
 ↓ Yes           ↓
训练模式        使用RAG? ──No──→ 基础评估 (5分钟)
 ↓               ↓ Yes
使用RAG?        RAG评估 (5分钟)
 ↓ Yes
从数据集构建KB? ──Yes──→ 完整训练+RAG (3-4小时)
 ↓ No
使用默认KB → 快速训练+RAG (2-3小时)
```

## 相关文档

- `QUICKSTART.md` - 快速开始
- `SCRIPTS_GUIDE.md` - 脚本指南
- `INTEGRATION_GUIDE.md` - 集成指南
