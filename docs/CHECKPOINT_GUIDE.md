# Checkpoint 机制使用指南

## 概述

EvoPrompt 现在配备了完善的 checkpoint 机制，能够有效应对 API 不稳定、网络中断等问题，确保实验可以随时中断和恢复。

## 核心特性

✅ **自动保存** - 每个 batch、每代进化后自动保存
✅ **断点恢复** - 从上次失败的地方继续实验
✅ **重试机制** - API 失败时自动重试（指数退避）
✅ **多级备份** - latest + backup 双重保护
✅ **错误容错** - KeyboardInterrupt 和 Exception 都能正常保存

## 目录结构

```
result/layer1_YYYYMMDD_HHMMSS/
├── checkpoints/                     # Checkpoint 目录
│   ├── latest.json                  # 最新 checkpoint (JSON)
│   ├── backup.json                  # 备份 checkpoint
│   ├── state.pkl                    # 完整状态 (pickle)
│   ├── gen1_batch0.json            # 历史 checkpoint
│   ├── gen2_batch0.json
│   └── batches/                     # Batch 级 checkpoint
│       ├── gen1_batch0.json
│       ├── gen1_batch1.json
│       └── ...
└── recovery.log                     # 恢复日志
```

## 使用方式

### 1. 基本运行（启用 checkpoint）

```bash
# 默认启用 checkpoint
uv run python main.py
```

### 2. 自定义重试参数

```bash
# 设置最大重试次数和延迟
uv run python main.py --max-retries 5 --retry-delay 2.0
```

### 3. 禁用 checkpoint（不推荐）

```bash
# 如果确实不需要 checkpoint
uv run python main.py --no-checkpoint
```

### 4. 从 checkpoint 恢复

当检测到未完成的实验时，会提示：

```
🔄 检测到未完成的实验...
是否从 checkpoint 恢复? (y/n):
```

输入 `y` 恢复，输入 `n` 重新开始。

## Checkpoint 保存时机

### 1. Batch 级保存

每处理完一个 batch（16 条 code）后自动保存：

```
Batch 3/15 (样本 33-48)
  🔍 批量预测 16 个样本...
  ✓ 准确率: 87.50%
  💾 Batch checkpoint 已保存
```

### 2. 代级保存

每完成一代进化后保存完整状态：

```
📈 第 2 代进化
  当前最佳适应度: 0.8750
  ...
  💾 Checkpoint 已保存 (第 2 代)
```

### 3. 中断保存

用户按 Ctrl+C 中断时：

```
⚠️ 用户中断实验
💾 保存当前进度到 checkpoint...
✅ Checkpoint 已保存，可以稍后恢复
```

### 4. 错误保存

发生异常时自动保存：

```
❌ 第 3 代发生错误: API connection timeout
💾 保存当前进度到 checkpoint...
✅ Checkpoint 已保存，可以稍后恢复
```

## 重试机制

### API 调用重试

当 API 调用失败时，自动重试（指数退避）：

```
🔍 批量预测 16 个样本...
  ⚠️ API 调用失败 (尝试 1/3): Connection timeout
  ⏳ 等待 1.0秒 后重试...
  ⚠️ API 调用失败 (尝试 2/3): Connection timeout
  ⏳ 等待 2.0秒 后重试...
  ✅ API 调用成功
```

### 重试配置

```python
config = {
    "max_retries": 3,           # 最大重试次数
    "retry_delay": 1.0,          # 基础延迟（秒）
    # 使用指数退避: 1s, 2s, 4s, 8s, ...
}
```

### 延迟策略

- **指数退避**: `delay = base_delay * (2 ** attempt)`
  - 第 1 次重试: 1 秒
  - 第 2 次重试: 2 秒
  - 第 3 次重试: 4 秒

- **线性延迟**: `delay = base_delay`（可配置）

## 恢复流程

### 完整恢复

如果完整状态可用（state.pkl 存在）：

```
✅ 从完整状态恢复
   将从第 3 代继续

📈 第 3 代进化
  当前最佳适应度: 0.8750
  ...
```

### 部分恢复

如果只有 JSON checkpoint：

```
⚠️ 只能恢复部分信息，将重新开始实验
```

会从头开始，但可以参考 `checkpoints/` 中的历史数据。

### Batch 级恢复

评估时自动检查已完成的 batch：

```
📊 评估 prompt (共 15 个 batches)
  🔄 从 Batch 8 继续...

  Batch 8/15 (样本 113-128)
    📦 从 checkpoint 加载结果
    ✓ 准确率: 87.50%
```

## 实战场景

### 场景 1: API 不稳定

**问题**: API 经常超时或返回错误

**解决方案**:
```bash
# 增加重试次数和延迟
uv run python main.py --max-retries 5 --retry-delay 3.0
```

**效果**:
- 自动重试最多 5 次
- 每次重试延迟: 3s, 6s, 12s, 24s, 48s
- 成功后继续，失败后保存 checkpoint

### 场景 2: 长时间实验中断

**问题**: 实验运行了 2 小时后网络断开

**解决方案**:
```bash
# 恢复实验（自动检测 checkpoint）
uv run python main.py --experiment-id layer1_20251030_120000
```

**效果**:
- 检测到未完成的实验
- 从第 N 代继续（N 是最后保存的代数）
- 已完成的 batch 从 checkpoint 加载

### 场景 3: 手动中断后继续

**问题**: 需要暂停实验，稍后继续

**操作**:
```bash
# 运行中按 Ctrl+C
^C
⚠️ 用户中断实验
💾 保存当前进度到 checkpoint...
✅ Checkpoint 已保存，可以稍后恢复

# 稍后恢复
uv run python main.py
🔄 检测到未完成的实验...
是否从 checkpoint 恢复? (y/n): y
```

### 场景 4: API 配额限制

**问题**: API 达到速率限制

**解决方案**:
```bash
# 保守配置，减少并发
uv run python main.py \
  --batch-size 8 \
  --max-retries 3 \
  --retry-delay 5.0
```

**效果**:
- 每次请求更少的样本
- 更长的重试延迟
- 降低触发速率限制的概率

## Checkpoint 文件说明

### latest.json

轻量级 checkpoint，包含基本信息：

```json
{
  "timestamp": "2025-10-30T14:30:00",
  "generation": 3,
  "batch_idx": 0,
  "num_individuals": 10,
  "best_fitness": 0.8750,
  "metadata": {
    "stage": "generation_3_complete"
  }
}
```

### state.pkl

完整状态（pickle 格式）：

```python
{
    "generation": 3,
    "batch_idx": 0,
    "population": [...],      # 完整种群
    "best_results": [...],    # 历史最佳结果
    "metadata": {...}
}
```

### batch checkpoint

单个 batch 的详细结果：

```json
{
  "generation": 2,
  "batch_idx": 5,
  "timestamp": "2025-10-30T14:25:00",
  "predictions": ["Benign", "Buffer Errors", ...],
  "ground_truths": ["Benign", "Injection", ...],
  "analysis": {
    "accuracy": 0.875,
    "error_patterns": {...}
  },
  "prompt": "Analyze this code..."
}
```

## 监控和诊断

### 查看重试统计

实验结束时会显示：

```
📊 API 调用统计:
   成功: 245
   失败: 12
   重试成功率: 95.33%
```

### 查看恢复日志

```bash
cat result/layer1_YYYYMMDD_HHMMSS/recovery.log
```

```jsonl
{"timestamp": "2025-10-30T14:30:00", "recovered_state": {"generation": 3, "batch_idx": 0}}
{"timestamp": "2025-10-30T15:00:00", "recovered_state": {"generation": 4, "batch_idx": 8}}
```

### 查看历史 checkpoint

```bash
ls -lh result/layer1_YYYYMMDD_HHMMSS/checkpoints/
```

```
gen1_batch0.json    2KB    2025-10-30 14:15
gen2_batch0.json    2KB    2025-10-30 14:20
gen3_batch0.json    2KB    2025-10-30 14:25
latest.json         2KB    2025-10-30 14:30
backup.json         2KB    2025-10-30 14:25
state.pkl          50KB    2025-10-30 14:30
```

## 清理策略

### 自动清理

每 3 代自动清理旧 checkpoint，保留最近 10 个：

```
第 3 代完成
  💾 Checkpoint 已保存
  🗑️ 清理旧 checkpoint: gen1_batch0.json
  🗑️ 清理旧 checkpoint: gen2_batch0.json
```

### 手动清理

```bash
# 删除所有 checkpoint（谨慎）
rm -rf result/layer1_YYYYMMDD_HHMMSS/checkpoints/

# 只删除 batch checkpoint
rm -rf result/layer1_YYYYMMDD_HHMMSS/checkpoints/batches/
```

## 最佳实践

### 1. 稳定环境

```bash
# 标准配置（推荐）
uv run python main.py \
  --batch-size 16 \
  --max-retries 3 \
  --retry-delay 1.0
```

### 2. 不稳定 API

```bash
# 保守配置
uv run python main.py \
  --batch-size 8 \
  --max-retries 5 \
  --retry-delay 2.0
```

### 3. 快速测试

```bash
# 快速测试（短延迟）
uv run python main.py \
  --batch-size 8 \
  --max-generations 2 \
  --max-retries 2 \
  --retry-delay 0.5
```

### 4. 生产环境

```bash
# 生产配置（长时间运行）
uv run python main.py \
  --batch-size 16 \
  --max-generations 10 \
  --max-retries 5 \
  --retry-delay 3.0
```

## 故障排查

### 问题 1: Checkpoint 加载失败

```
⚠️ Latest checkpoint 加载失败: ...
⚠️ Backup checkpoint 加载失败: ...
```

**原因**: Checkpoint 文件损坏

**解决**:
1. 检查 `checkpoints/` 目录下的历史文件
2. 手动选择最近的有效 checkpoint
3. 或重新开始实验

### 问题 2: 重试次数用尽

```
❌ 批量预测失败 (已达最大重试次数): ...
```

**原因**: API 持续失败

**解决**:
1. 检查 API 密钥和配额
2. 增加 `--max-retries` 和 `--retry-delay`
3. 等待 API 恢复后从 checkpoint 继续

### 问题 3: 磁盘空间不足

**症状**: Checkpoint 保存失败

**解决**:
1. 清理旧的实验结果
2. 减少 checkpoint 保留数量（`keep_last_n`）
3. 或禁用 batch checkpoint

## 高级用法

### 编程式使用

```python
from evoprompt.utils.checkpoint import (
    CheckpointManager,
    RetryManager,
    with_retry
)

# 1. 使用 CheckpointManager
checkpoint_mgr = CheckpointManager(exp_dir, auto_save=True)

# 保存
checkpoint_mgr.save_checkpoint(
    generation=1,
    batch_idx=5,
    population=population,
    best_results=results,
    metadata={"note": "custom checkpoint"}
)

# 加载
state = checkpoint_mgr.load_full_state()

# 2. 使用 RetryManager
retry_mgr = RetryManager(max_retries=3, base_delay=1.0)

def risky_api_call():
    return llm_client.generate(prompt)

result = retry_mgr.retry_with_backoff(risky_api_call)

# 3. 使用装饰器
@with_retry(max_retries=3, base_delay=2.0)
def my_function():
    return some_api_call()
```

### 自定义恢复逻辑

```python
recovery = ExperimentRecovery(exp_dir)

if recovery.can_recover():
    state = recovery.recover_experiment()

    if state and state.get("full_state"):
        # 完整恢复
        start_from = state["generation"]
        population = state["population"]
    else:
        # 部分恢复，使用 checkpoint 信息
        checkpoint = state["checkpoint"]
        print(f"上次运行到第 {checkpoint['generation']} 代")
```

## 总结

Checkpoint 机制为 EvoPrompt 提供了：

✅ **可靠性** - 实验可随时中断和恢复
✅ **容错性** - API 失败自动重试
✅ **高效性** - 避免重复计算
✅ **透明性** - 完整的状态记录和恢复日志

无论是 API 不稳定、网络中断、还是主动暂停，都能确保实验进度不丢失！
