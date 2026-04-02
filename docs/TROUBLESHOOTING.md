# Multi-Agent System Troubleshooting Guide

## 常见问题及解决方案

### 问题1: Fitness一直为0.0000

**症状:**
```
🧬 Generation 1/4
   Current best fitness: 0.0000
   ...
🧬 Generation 4/4
   Current best fitness: 0.0000
```

**可能原因和解决方案:**

#### 原因1: 数据集太小
```bash
# 检查数据集大小
wc -l data/*/dev.txt

# 应该看到:
#    526 data/primevul_1percent_sample/dev.txt  ✅ 足够
#      2 data/demo_primevul_1percent_sample/dev.txt  ❌ 太小
```

**解决方案:**
```bash
# 使用正确的数据集
uv run python scripts/ablations/demo_multiagent_coevolution.py
# 现在会自动使用primevul_1percent_sample

# 或使用调试版本
uv run python scripts/ablations/demo_multiagent_debug.py
```

#### 原因2: Detection Agent输出格式不正确

Detection Agent必须输出"vulnerable"或"benign",但可能输出了其他内容。

**诊断:**
```bash
# 运行调试版本查看预测
uv run python scripts/ablations/demo_multiagent_debug.py
```

会显示:
```
🧪 Testing detection agent...
   Test predictions:
   ✅ Sample 1: Predicted 'vulnerable', Actual 'vulnerable'
   ❌ Sample 2: Predicted 'benign', Actual 'vulnerable'
```

**解决方案:**
修改Prompt确保明确要求输出格式:
```python
prompt = """...(your instructions)...

IMPORTANT: Respond with ONLY ONE WORD:
- 'vulnerable' if the code has security issues
- 'benign' if the code is safe

Code:
{input}

Answer:"""
```

#### 原因3: API调用失败

检查API密钥和配置:
```bash
# 检查.env文件
cat .env | grep API_KEY

# 应该看到:
# API_KEY=sk-xxx...
# META_API_KEY=sk-xxx...
```

**解决方案:**
```bash
# 确保.env文件配置正确
echo "API_KEY=your-gpt4-key" >> .env
echo "META_API_KEY=your-claude-key" >> .env
```

#### 原因4: F1计算问题

当TP=0时,F1=0。这通常意味着Prompt完全不work。

**诊断:**
查看统计信息:
```bash
cat outputs/multiagent_*/*/statistics.json | grep -A 5 "category_stats"
```

**解决方案:**
- 改进初始Prompt质量
- 增加种群多样性
- 使用更多训练样本

### 问题2: Meta Agent不生成改进

**症状:**
Prompt在多代之间没有变化,或者变化很小。

**解决方案:**

#### 提高Meta Agent的temperature
```python
meta_agent = create_meta_agent(
    model_name="claude-sonnet-4-5-20250929-thinking",
    temperature=0.9  # 增加创造性(默认0.7)
)
```

#### 增加meta_improvement_rate
```python
coevo_config = {
    "meta_improvement_rate": 0.7,  # 提高到70%(默认50%)
    ...
}
```

#### 检查Meta Agent输出
在`src/evoprompt/optimization/meta_optimizer.py`添加debug:
```python
def optimize_prompt(self, context, optimization_type="improve"):
    meta_prompt = self._create_improvement_meta_prompt(context)

    # Debug: 打印Meta prompt
    print(f"\n🔍 Meta Prompt:\n{meta_prompt[:500]}...")

    response = self.meta_llm_client.generate(meta_prompt, temperature=self.temperature)

    # Debug: 打印响应
    print(f"\n🔍 Meta Response:\n{response[:500]}...")

    return self._extract_prompt_from_response(response)
```

### 问题3: 运行时间太长

**症状:**
每代需要10+分钟。

**解决方案:**

#### 减小population_size和generations
```python
coevo_config = {
    "population_size": 4,  # 从6减到4
    "max_generations": 3,  # 从4减到3
}
```

#### 减小batch_size加快单次评估
```python
coordinator_config = CoordinatorConfig(
    batch_size=8,  # 从16减到8
)
```

#### 限制样本数量
```python
# 在demo脚本中
max_samples = 50  # 只用前50个样本进行快速测试
```

### 问题4: Out of Memory错误

**症状:**
```
RuntimeError: CUDA out of memory
```
或
```
MemoryError: Unable to allocate...
```

**解决方案:**

#### 使用API而非本地模型
```python
# 不要用LocalLLMClient
# 使用API客户端
detection_client = create_llm_client(llm_type="gpt-4")
```

#### 减小batch_size
```python
coordinator_config = CoordinatorConfig(
    batch_size=4,  # 减小batch
)
```

#### 减小population_size
```python
coevo_config = {
    "population_size": 3,  # 最小值
}
```

### 问题5: API Rate Limit错误

**症状:**
```
Error: Rate limit exceeded
```

**解决方案:**

#### 添加延时
在`src/evoprompt/llm/client.py`的batch_generate中:
```python
# 在API调用之间添加延时
import time
time.sleep(1)  # 1秒延时
```

#### 使用更小的batch_size
```python
coordinator_config = CoordinatorConfig(
    batch_size=4,  # 减小并发请求
)
```

#### 使用备用API
在.env中配置:
```bash
BACKUP_API_BASE_URL=https://your-backup-api.com/v1
```

### 问题6: 统计信息不准确

**症状:**
Accuracy和F1 score波动很大。

**解决方案:**

#### 使用更多样本
```bash
# 确保使用完整的1%数据集(~500样本)
ls -lh data/primevul_1percent_sample/dev.txt
```

#### 启用batch feedback
```python
coordinator_config = CoordinatorConfig(
    enable_batch_feedback=True,  # 确保启用
    statistics_window=5,  # 增加历史窗口
)
```

#### 检查标签分布
```bash
# 查看采样统计
cat data/primevul_1percent_sample/sampling_stats.json
```

应该看到均衡的分布:
```json
{
  "sampled_0": 263,  // benign
  "sampled_1": 263,  // vulnerable
  ...
}
```

## 调试工作流

### 推荐的调试流程:

1. **先运行调试版本**
   ```bash
   uv run python scripts/ablations/demo_multiagent_debug.py
   ```

2. **检查测试预测**
   看Detection Agent的3个测试预测是否正确

3. **查看统计信息**
   ```bash
   cat outputs/multiagent_debug/*/debug_statistics.json | jq .
   ```

4. **分析错误模式**
   重点关注:
   - `category_stats`: 哪些CWE类型错误率高?
   - `confusion_matrix`: FP还是FN更多?
   - `improvement_suggestions`: 自动建议

5. **调整配置**
   根据分析结果调整Prompt或算法参数

6. **运行完整实验**
   ```bash
   uv run python scripts/ablations/demo_multiagent_coevolution.py
   ```

## 性能优化建议

### 快速测试配置
```python
# 用于快速迭代和调试
coevo_config = {
    "population_size": 3,
    "max_generations": 2,
    "meta_improvement_rate": 0.5,
}

coordinator_config = CoordinatorConfig(
    batch_size=8,
)

max_samples = 50  # 限制样本数
```

### 生产配置
```python
# 用于论文实验
coevo_config = {
    "population_size": 10,
    "max_generations": 8,
    "meta_improvement_rate": 0.3,
}

coordinator_config = CoordinatorConfig(
    batch_size=32,
)

max_samples = None  # 使用所有样本
```

## 获取帮助

如果问题仍未解决:

1. 查看完整文档: `MULTIAGENT_README.md`
2. 检查日志输出中的警告和错误
3. 在GitHub提交issue并附带:
   - 完整错误信息
   - 配置文件(`experiment_config.json`)
   - 统计文件(`statistics.json`)
   - 运行日志

## 常用调试命令

```bash
# 查看数据集大小
wc -l data/*/dev.txt

# 检查API配置
cat .env | grep API

# 查看最近实验结果
ls -lt outputs/multiagent_*/

# 查看统计摘要
cat outputs/multiagent_*/*/statistics.json | jq '.generation_stats'

# 查看最佳Prompt
cat outputs/multiagent_*/*/final_population.txt | head -20

# 查看改进建议
cat outputs/multiagent_*/*/statistics.json | jq '.improvement_suggestions'
```

## 验证系统健康

运行验证脚本:
```bash
uv run python verify_multiagent.py
```

应该看到:
```
🎉 All verification tests passed!
```

如果失败,说明安装有问题,需要重新检查依赖。
