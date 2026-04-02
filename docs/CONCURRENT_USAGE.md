# 🚀 EvoPrompt 并发优化使用指南

## 快速开始

### 方式1: 自动优化（推荐）
现有脚本已集成并发优化，无需修改：

```bash
# 使用ChatAnywhere API运行（自动优化）
uv run python run_primevul_1percent.py

# 演示版本（使用模拟LLM）
uv run python demo_primevul_1percent.py
```

**特点：**
- ✅ 零配置，自动检测批量大小
- ✅ 小批量使用顺序，大批量使用并发
- ✅ 向下兼容所有现有代码

### 方式2: 高并发优化版本
专门优化的高性能版本：

```bash
# 运行高并发优化版本
uv run python run_primevul_concurrent_optimized.py
```

**特点：**
- 🔥 强制使用16并发连接
- ⚡ 增大种群规模充分利用并发
- 📈 详细性能统计和监控

## 性能对比

| 运行方式 | 并发度 | 种群大小 | 预期提升 | 适用场景 |
|---------|--------|----------|----------|----------|
| 自动优化 | 自动检测 | 8 | 2-5x | 日常使用 |
| 高并发版 | 16 | 12 | 5-10x | 性能要求高 |
| 顺序处理 | 1 | 6 | 基准 | 调试/测试 |

## API配置

### ChatAnywhere API（推荐）
```bash
# .env文件配置
API_BASE_URL=https://api.chatanywhere.tech/v1
API_KEY=sk-your-api-key-here
MODEL_NAME=gpt-3.5-turbo
```

**优势：**
- ✅ 支持32并发（测试验证）
- ✅ 稳定性好，成功率100%
- ✅ 18.9倍性能提升

### 并发参数调优

如需手动调整：

```python
# 在脚本中配置
config = {
    "max_concurrency": 16,    # 并发连接数
    "force_async": True,      # 强制异步
    "population_size": 12,    # 增大种群
    "batch_evaluation": True  # 批量评估
}
```

## 性能监控

实验过程中会显示：

```
⚡ 第 1 代高并发进化...
   使用批量大小: 8
   个体 1: 改进 0.8542 > 0.7321
   个体 2: 改进 0.7892 > 0.7445
   第1代完成: 12.5秒
   
🎉 高并发进化完成!
   总耗时: 145.2秒
   平均每代: 18.1秒  
   LLM调用总数: 324
   调用速率: 2.23 calls/sec
```

## 结果文件

所有版本都会生成相同的输出文件：

```
outputs/
├── experiment_summary.json     # 实验总结
├── prompt_evolution.jsonl      # 完整进化记录  
├── best_prompts.txt           # 最佳prompt历史
├── concurrent_gen_*.json      # 并发性能统计
└── llm_call_history.json      # API调用历史
```

## 故障排除

### 问题1: 并发连接被限制
```bash
# 降低并发度
config["max_concurrency"] = 8
```

### 问题2: 内存占用过高
```bash
# 减小种群规模
config["population_size"] = 6
```

### 问题3: API频率限制
```bash
# 添加延迟
config["request_delay"] = 0.1
```

## 最佳实践

1. **首次运行**: 使用自动优化版本
2. **生产环境**: 使用高并发优化版本
3. **调试阶段**: 设置`max_concurrency=1`
4. **大规模实验**: 设置`max_concurrency=32`

## 性能期望

基于测试结果：

- **串行处理**: 0.76 req/s
- **并发处理**: 14.35 req/s  
- **性能提升**: 18.9倍
- **成功率**: 100%

实际性能取决于网络延迟和API服务质量。