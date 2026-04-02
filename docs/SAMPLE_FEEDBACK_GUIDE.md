# 🎯 样本级反馈Prompt进化实验指南

## 新功能特点

### ✨ 核心改进
- **🔄 训练集打乱**: 每次实验都会随机打乱训练数据顺序
- **📊 样本级反馈**: 每个训练样本的结果都会用于改进prompt
- **📝 详细记录**: 记录每个样本的预测结果、正确性和改进过程
- **⚡ 并发优化**: 保持16并发连接的高性能

### 🎨 实验流程
1. **数据准备**: 加载并打乱训练集
2. **初始评估**: 在开发集上评估初始prompt种群
3. **进化循环**: 对每个个体进行以下操作：
   - 使用DE算法创建变异个体
   - 在训练样本上进行样本级反馈训练
   - 对预测错误的样本，使用LLM改进prompt
   - 在开发集上评估改进后的prompt
   - 选择更优的个体进入下一代

## 🚀 使用方法

### 运行实验
```bash
# 运行样本级反馈进化实验
uv run python run_primevul_concurrent_optimized.py
```

### 实验配置
关键参数已优化为样本级反馈：
- `population_size`: 8 (适应样本级反馈的种群大小)
- `max_generations`: 5 (适应更intensive训练的代数)
- `feedback_batch_size`: 10 (每批反馈的样本数)
- `shuffle_training_data`: True (启用训练集打乱)

## 📊 输出文件详解

### 主要输出文件

#### 1. `sample_feedback.jsonl` - 样本级反馈记录
每行记录一个样本的处理结果：
```json
{
  "timestamp": "2025-08-08T10:30:45",
  "prompt_id": "gen1_individual_0_feedback_0", 
  "generation": 1,
  "sample_idx": 0,
  "sample_func": "void unsafe_copy(char* src) { char buf[10]; strcpy(buf, src); }",
  "sample_target": 1,
  "prediction": "vulnerable",
  "correct": true,
  "feedback_applied": true,
  "metadata": {
    "project": "Chrome",
    "cwe": ["CWE-120"],
    "func_hash": "123456789"
  }
}
```

#### 2. `sample_statistics.json` - 样本统计汇总
```json
{
  "total_samples_evaluated": 2340,
  "total_prompts": 12,
  "overall_accuracy": 0.8547,
  "prompt_statistics": {
    "initial_0": {
      "total_samples": 195,
      "correct_samples": 167,
      "accuracy": 0.8564,
      "generations": [0],
      "feedback_applied_count": 0
    }
  },
  "generation_summary": {
    "0": {"total": 780, "correct": 645, "accuracy": 0.8269},
    "1": {"total": 520, "correct": 456, "accuracy": 0.8769}
  }
}
```

#### 3. `prompt_evolution.jsonl` - Prompt进化记录
记录每个prompt的变化历程：
```json
{
  "prompt": "Analyze this code for security vulnerabilities...",
  "fitness": 0.8547,
  "generation": 1,
  "individual_id": "gen1_trial_0",
  "operation": "sample_feedback_evolution",
  "metadata": {
    "target_fitness": 0.8123,
    "improvement": 0.0424,
    "feedback_applied": true
  },
  "timestamp": "2025-08-08T10:31:22"
}
```

#### 4. `generation_X_results.json` - 每代详细结果
```json
{
  "generation": 1,
  "duration": 125.3,
  "best_fitness": 0.8547,
  "best_prompt": "Analyze this code for security vulnerabilities...",
  "fitness_history": [0.8123, 0.8547],
  "sample_batches_processed": 8
}
```

## 📈 结果分析

### 实验成功指标
- **适应度提升**: 从初始代到最终代的准确率提升
- **样本反馈效果**: feedback_applied_count vs 总体性能提升
- **代际改进**: 每一代的平均准确率变化趋势
- **个体差异**: 不同prompt个体的性能分布

### 性能监控
实验过程中会显示：
```
⚡ 第 1 代样本级反馈进化...
   处理个体 1/8
     📝 样本级反馈训练: 10 个样本
       ✅ 样本 1: 预测正确
       ⚡ 样本 2: prompt已改进
       ❌ 样本 3: 处理失败
     📈 反馈训练完成: 3/10 个样本触发改进
     📊 评估完成: 156/195 = 0.8000
     ✅ 接受改进个体: 0.8000 > 0.7692
```

## 🔍 分析工具

### 查看样本级结果
```bash
# 查看样本反馈日志
cat outputs/primevul_concurrent_feedback/实验ID/sample_feedback.jsonl | jq .

# 统计反馈效果
grep '"feedback_applied": true' sample_feedback.jsonl | wc -l
```

### 分析进化趋势
```bash
# 查看每代最佳适应度
cat outputs/*/generation_*_results.json | jq '.best_fitness'

# 查看样本统计
cat sample_statistics.json | jq '.generation_summary'
```

## 🎯 实验价值

### 相比传统方法的优势
1. **精细化反馈**: 每个训练样本都能贡献具体的改进建议
2. **动态调整**: Prompt在训练过程中持续优化
3. **全面记录**: 详细记录每个样本的处理过程
4. **个性化进化**: 不同个体针对不同样本特点进化

### 适用场景
- 需要深度理解样本特征的任务
- 希望最大化利用训练数据的场景  
- 需要详细分析prompt演进过程的研究
- 对准确率有较高要求的实际应用

通过样本级反馈，prompt进化将更加精准和高效！