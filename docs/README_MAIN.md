# EvoPrompt Main Entry - 使用指南

## 概述

`main.py` 是 EvoPrompt 项目的统一入口，专门用于 PrimeVul 数据集的 Layer-1 并发漏洞分类任务。

### 核心特性

✅ **批量处理**: 每 16 条代码为一个 batch，高效批量预测
✅ **Batch 级反馈**: 每个 batch 分析错误模式，指导 prompt 进化
✅ **初始化 Prompts**: 从 `init/layer1_prompts.txt` 读取初始 prompts
✅ **完整指标**: 输出 precision, recall, f1-score 分类报告
✅ **结果存档**: 所有结果保存到 `result/` 文件夹
✅ **Checkpoint 机制**: 自动保存进度，支持断点恢复
✅ **重试机制**: API 失败自动重试（指数退避）
✅ **容错处理**: 网络中断、API 不稳定均可恢复

## 快速开始

### 1. 运行实验

```bash
# 使用默认配置运行
uv run python main.py

# 自定义 batch 大小和进化代数
uv run python main.py --batch-size 16 --max-generations 5

# 指定数据路径
uv run python main.py \
  --primevul-dir ./data/primevul/primevul \
  --sample-dir ./data/primevul_1percent_sample
```

### 2. 命令行参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--batch-size` | 16 | 每个 batch 的样本数 |
| `--max-generations` | 5 | 最大进化代数 |
| `--primevul-dir` | `./data/primevul/primevul` | PrimeVul 原始数据集路径 |
| `--sample-dir` | `./data/primevul_1percent_sample` | 1% 采样数据路径 |
| `--experiment-id` | 自动生成 | 实验 ID（时间戳） |
| `--max-retries` | 3 | API 调用最大重试次数 |
| `--retry-delay` | 1.0 | 重试基础延迟时间（秒） |
| `--no-checkpoint` | False | 禁用 checkpoint 功能 |

## 目录结构

```
EvoPrompt/
├── main.py                          # 统一入口脚本
├── init/                            # 初始化目录
│   └── layer1_prompts.txt          # 初始 prompts（10个）
├── result/                          # 结果输出目录
│   └── layer1_YYYYMMDD_HHMMSS/     # 实验结果子目录
│       ├── final_prompt.txt                # 最终优化的 prompt
│       ├── classification_report.txt       # 易读的分类报告
│       ├── classification_metrics.json     # JSON 格式指标
│       ├── confusion_matrix.json           # 混淆矩阵
│       ├── batch_analyses.jsonl            # 每个 batch 的分析
│       ├── experiment_summary.json         # 完整实验总结
│       ├── checkpoints/                    # Checkpoint 目录
│       │   ├── latest.json                # 最新 checkpoint
│       │   ├── backup.json                # 备份 checkpoint
│       │   ├── state.pkl                  # 完整状态
│       │   └── batches/                   # Batch 级 checkpoint
│       └── recovery.log                    # 恢复日志
├── data/                            # 数据目录
│   └── primevul_1percent_sample/   # 1% 采样数据
└── src/                             # 源代码
```

## 初始化 Prompts

### init/layer1_prompts.txt 格式

```text
# 注释以 # 开头
# 每个 prompt 用 "=" 分隔线分隔
# Prompt 必须包含 {input} 占位符

# Prompt 1
Analyze this code for security vulnerabilities...
{input}
Category:

================================================================================

# Prompt 2
You are a security expert...
{input}
Result:

================================================================================
```

### 编辑初始 Prompts

1. 打开 `init/layer1_prompts.txt`
2. 修改或添加 prompts（保持 `{input}` 占位符）
3. 使用 `=` 分隔线分隔不同 prompts
4. 重新运行 `main.py`

## 输出结果

### 1. final_prompt.txt

包含最终优化的 prompt 和适应度：

```text
# 最终优化的 Prompt (适应度: 0.8750)
# 实验 ID: layer1_20251030_143022
# 生成时间: 2025-10-30T14:35:45

Analyze this code for security vulnerabilities...
```

### 2. classification_report.txt

易读的分类报告：

```text
PrimeVul Layer-1 分类报告
================================================================================
实验 ID: layer1_20251030_143022
最终准确率: 0.8750
总样本数: 240
Batch 大小: 16
Batch 总数: 15

各类别性能指标:
--------------------------------------------------------------------------------
Category                   Precision     Recall  F1-Score    Support
--------------------------------------------------------------------------------
Benign                        0.9200     0.9200    0.9200         50
Buffer Errors                 0.8500     0.8900    0.8700         45
Injection                     0.9000     0.8500    0.8750         40
Memory Management             0.8200     0.8500    0.8350         35
...
```

### 3. classification_metrics.json

JSON 格式的完整指标（便于后续分析）：

```json
{
  "Benign": {
    "precision": 0.92,
    "recall": 0.92,
    "f1-score": 0.92,
    "support": 50
  },
  "Buffer Errors": {
    "precision": 0.85,
    "recall": 0.89,
    "f1-score": 0.87,
    "support": 45
  },
  ...
  "macro avg": {
    "precision": 0.87,
    "recall": 0.86,
    "f1-score": 0.865
  }
}
```

### 4. batch_analyses.jsonl

每个 batch 的详细分析（JSONL 格式）：

```jsonl
{"batch_idx": 0, "batch_size": 16, "correct": 14, "accuracy": 0.875, "error_patterns": {"Buffer Errors -> Injection": 1, "Benign -> Other": 1}, "improvement_suggestions": [...]}
{"batch_idx": 1, "batch_size": 16, "correct": 15, "accuracy": 0.9375, ...}
```

### 5. confusion_matrix.json

混淆矩阵（用于分析误分类模式）：

```json
{
  "labels": ["Benign", "Buffer Errors", "Injection", ...],
  "matrix": [
    [46, 2, 1, 0, ...],
    [1, 40, 2, 1, ...],
    ...
  ]
}
```

## 工作流程

### 完整流程图

```
1. 加载初始 Prompts
   ↓
2. 准备数据集（train/dev split）
   ↓
3. 初始评估（在 dev 集上）
   ├─ 每 16 个样本为一个 batch
   ├─ 批量预测
   └─ Batch 级别分析
   ↓
4. 进化循环（max_generations 代）
   ├─ 选择最佳 prompt
   ├─ 在 train 集上评估
   │  ├─ 每个 batch 分析错误模式
   │  └─ 根据反馈进化 prompt
   ├─ 在 dev 集上验证
   └─ 更新种群
   ↓
5. 保存最终结果
   ├─ 最佳 prompt
   ├─ 分类报告（precision/recall/f1）
   ├─ 混淆矩阵
   └─ Batch 分析历史
```

### Batch 级反馈机制

每个 batch 处理后：

1. **统计准确率**: 计算该 batch 的正确率
2. **分析错误模式**: 识别常见的误分类（如 "Buffer Errors → Injection"）
3. **生成改进建议**: 基于错误模式提出具体改进方向
4. **进化 Prompt**: 如果准确率 < 95%，使用 LLM 生成改进的 prompt
5. **验证改进**: 在后续 batch 中验证改进效果

### Batch 反馈示例

```python
# Batch 分析结果
{
  "batch_idx": 3,
  "accuracy": 0.8125,  # 13/16 正确
  "error_patterns": {
    "Buffer Errors -> Injection": 2,      # 缓冲区错误误判为注入
    "Memory Management -> Other": 1       # 内存管理误判为其他
  },
  "improvement_suggestions": [
    "Improve detection of 'Buffer Errors' (misclassified as 'Injection' 2 times). "
    "Focus on distinguishing Buffer Errors characteristics from Injection.",
    "Category 'Memory Management' has low accuracy (50%). "
    "Emphasize patterns specific to this vulnerability type."
  ]
}
```

## CWE 大类分类

### 支持的类别

| 类别 | 说明 | 典型 CWE |
|------|------|----------|
| `Benign` | 无漏洞 | - |
| `Buffer Errors` | 缓冲区错误 | CWE-119, 120, 787 |
| `Injection` | 注入攻击 | CWE-78, 79, 89 |
| `Memory Management` | 内存管理 | CWE-416, 415, 401 |
| `Pointer Dereference` | 指针解引用 | CWE-476 |
| `Integer Errors` | 整数错误 | CWE-190, 191 |
| `Concurrency Issues` | 并发问题 | CWE-362 |
| `Path Traversal` | 路径遍历 | CWE-22 |
| `Cryptography Issues` | 密码学问题 | CWE-326, 327 |
| `Information Exposure` | 信息泄露 | CWE-200 |
| `Other` | 其他安全问题 | - |

### 自动映射

系统会自动将具体的 CWE ID 映射到大类：

- `CWE-120` (Buffer Overflow) → `Buffer Errors`
- `CWE-89` (SQL Injection) → `Injection`
- `CWE-416` (Use After Free) → `Memory Management`
- ...

## 性能优化

### 批量处理优势

- **减少 API 调用**: 批量请求降低延迟
- **并发执行**: 支持并发预测加速
- **内存效率**: 流式处理避免内存溢出

### 推荐配置

```bash
# 小规模测试（快速验证）
uv run python main.py --batch-size 8 --max-generations 2

# 标准配置（平衡性能和质量）
uv run python main.py --batch-size 16 --max-generations 5

# 高质量配置（更多进化代数）
uv run python main.py --batch-size 16 --max-generations 10
```

## 故障排查

### 常见问题

1. **API 配置错误**
   ```bash
   ❌ 请设置 API_KEY 环境变量
   ```
   **解决**: 在 `.env` 文件中设置 `API_KEY`

2. **数据集不存在**
   ```bash
   ❌ Primevul数据目录不存在
   ```
   **解决**: 下载 PrimeVul 数据集到 `data/primevul/primevul/`

3. **初始 Prompts 格式错误**
   ```bash
   ⚠️ 未找到初始 prompts 文件
   ```
   **解决**: 检查 `init/layer1_prompts.txt` 格式，确保包含 `{input}`

4. **Batch 预测失败**
   ```bash
   ❌ 批量预测失败: ...
   ```
   **解决**: 检查 LLM API 连接，降低 batch_size

## 扩展开发

### 自定义 Batch Analyzer

```python
class CustomBatchAnalyzer(BatchAnalyzer):
    def _generate_improvement_suggestions(self, error_patterns, ground_truths, predictions):
        # 自定义改进建议生成逻辑
        suggestions = []
        # ... 你的逻辑
        return suggestions
```

### 自定义 Prompt Evolver

```python
class CustomPromptEvolver(PromptEvolver):
    def evolve_with_feedback(self, current_prompt, batch_analysis, generation):
        # 自定义进化策略
        # ... 你的逻辑
        return improved_prompt
```

### 集成到现有工作流

```python
from main import PrimeVulLayer1Pipeline

# 创建自定义配置
config = {
    "batch_size": 32,
    "max_generations": 10,
    "custom_param": "value"
}

# 运行 pipeline
pipeline = PrimeVulLayer1Pipeline(config)
results = pipeline.run_evolution()

# 处理结果
print(f"Best fitness: {results['best_fitness']}")
```

## 后续步骤

完成 Layer-1 后，可以：

1. **分析结果**: 查看 `result/` 中的报告，识别弱点
2. **优化 Prompts**: 根据分类报告调整 `init/layer1_prompts.txt`
3. **Layer-2 精调**: 使用最佳 prompt 进行更细粒度的分类
4. **生产部署**: 将最佳 prompt 集成到生产环境

## Checkpoint 和容错

### 自动保存

系统会在以下时机自动保存 checkpoint:
- ✅ 每个 batch 处理后
- ✅ 每代进化完成后
- ✅ 用户中断 (Ctrl+C) 时
- ✅ 发生错误时

### 断点恢复

当检测到未完成的实验时：

```bash
uv run python main.py

🔄 检测到未完成的实验...
是否从 checkpoint 恢复? (y/n): y
✅ 从完整状态恢复
   将从第 3 代继续
```

### API 重试

当 API 调用失败时，自动重试（指数退避）：

```bash
🔍 批量预测 16 个样本...
  ⚠️ API 调用失败 (尝试 1/3): Connection timeout
  ⏳ 等待 1.0秒 后重试...
  ⚠️ API 调用失败 (尝试 2/3): Connection timeout
  ⏳ 等待 2.0秒 后重试...
  ✅ API 调用成功
```

### 配置重试参数

```bash
# 增加重试次数和延迟（适用于不稳定的 API）
uv run python main.py --max-retries 5 --retry-delay 2.0
```

详细信息请参考 [CHECKPOINT_GUIDE.md](./CHECKPOINT_GUIDE.md)

## 相关文档

- [CLAUDE.md](./CLAUDE.md) - 项目整体说明
- [PRIMEVUL_LAYERED_FLOW.md](./PRIMEVUL_LAYERED_FLOW.md) - 分层流程文档
- [CHECKPOINT_GUIDE.md](./CHECKPOINT_GUIDE.md) - Checkpoint 机制详细指南

## 许可证

本项目遵循 MIT 许可证。

### result/ 实验输出目录新增文件说明

- `filled_prompts.jsonl`：每次evaluation记录实际变量填充后的prompt实例，每行为一个JSON对象，包含：
    - `template`：原始prompt模板
    - `filled`：替换所有变量后的完整prompt
    - `sample_id`: 样本编号
    - `generation`：进化代数
    - `target`：目标（如有）

- `meta_prompt.txt`：记录用于指导prompt演化的meta prompt文本（若实验有指定）。
