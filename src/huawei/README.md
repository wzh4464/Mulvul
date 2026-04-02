# 华为安全检测数据集 Prompt 管理系统

本模块为华为安全缺陷检测数据集实现了完整的 prompt 初始化、更新和进化功能，支持基于配置文件的灵活定制。

## 功能特性

- ✅ **配置驱动**: 所有 prompt 模板、类别定义和参数都通过配置文件管理，无硬编码
- ✅ **数据集支持**: 完整支持华为数据集格式，包含漏洞检测和误报处理
- ✅ **Prompt 进化**: 实现多种 prompt 变异和交叉策略
- ✅ **均衡采样**: 智能处理不平衡数据集
- ✅ **完整测试**: 包含单元测试、集成测试和演示脚本
- ✅ **兼容性**: 与现有 EvoPrompt 框架完全兼容

## 项目结构

```
src/huawei/
├── __init__.py                 # 包初始化
├── README.md                   # 本文档
├── config/
│   └── huawei_config.json     # 配置文件
├── dataset.py                  # 数据集实现
├── prompt_manager.py           # Prompt 管理器
├── workflow.py                 # 完整工作流程
├── demo.py                     # 演示脚本
├── run_tests.py               # 快速测试脚本
└── tests/                     # 测试用例
    ├── __init__.py
    ├── test_dataset.py        # 数据集测试
    ├── test_prompt_manager.py # Prompt 管理器测试
    └── test_integration.py    # 集成测试
```

## 核心组件

### 1. HuaweiDataset (dataset.py)

华为安全检测数据集的专用实现，支持：

- 自动加载和解析华为数据集格式
- 漏洞样本和干净样本的分类管理
- 按类别筛选和统计
- 均衡采样功能

```python
from huawei import HuaweiDataset

# 初始化数据集
dataset = HuaweiDataset(
    data_path="data/huawei/benchmark.json",
    config_path="src/huawei/config/huawei_config.json"
)

# 加载数据
samples = dataset.load_data("data/huawei/benchmark.json")

# 获取统计信息
stats = dataset.get_statistics()
print(f"总样本数: {stats['total_samples']}")
print(f"漏洞样本数: {stats['vulnerable_samples']}")

# 均衡采样
balanced_samples = dataset.sample_balanced(n_samples=100)
```

### 2. HuaweiPromptManager (prompt_manager.py)

Prompt 管理和进化的核心组件，支持：

- 基于配置文件的 prompt 模板管理
- 种群初始化和多样化
- 多种变异策略（语义变异、结构变异、模板融合）
- 交叉操作和进化算法支持

```python
from huawei import HuaweiPromptManager

# 初始化管理器
prompt_manager = HuaweiPromptManager("src/huawei/config/huawei_config.json")

# 初始化 prompt 种群
prompts = prompt_manager.initialize_prompts(population_size=8)

# 构建完整 prompt
full_prompt = prompt_manager.build_prompt(
    template=prompts[0],
    code="int x = 0;",
    lang="cpp"
)

# Prompt 进化操作
mutated = prompt_manager.mutate_prompt(prompts[0], mutation_rate=0.3)
child1, child2 = prompt_manager.crossover_prompts(prompts[0], prompts[1])
```

### 3. HuaweiWorkflow (workflow.py)

完整的端到端工作流程，包含：

- 数据加载和预处理
- LLM 客户端集成
- 进化算法执行
- 评估和结果保存

```python
from huawei import HuaweiWorkflow

# 初始化工作流程
workflow = HuaweiWorkflow(
    config_path="src/huawei/config/huawei_config.json",
    data_path="data/huawei/benchmark.json"
)

# 加载和准备数据
workflow.load_and_prepare_data(sample_size=100)

# 运行进化过程
best_result = workflow.run_evolution()
print(f"最佳 F1 分数: {best_result['metrics']['f1_score']}")
```

## 配置文件说明

配置文件 `config/huawei_config.json` 包含以下部分：

### 数据集配置
```json
{
  "dataset": {
    "name": "huawei_security_benchmark",
    "description": "华为安全缺陷检测数据集",
    "language": "cpp",
    "task_type": "vulnerability_detection"
  }
}
```

### 类别定义
```json
{
  "categories": {
    "函数指针参数未校验": {
      "cwe_id": 476,
      "description": "对函数指针参数未进行空指针检查",
      "severity": "high"
    }
  }
}
```

### Prompt 模板
```json
{
  "prompt_templates": {
    "base_template": "你是一个专业的静态代码安全分析师...",
    "detailed_template": "作为资深的安全代码审计专家..."
  }
}
```

### 进化参数
```json
{
  "evolution_config": {
    "population_size": 8,
    "max_generations": 10,
    "mutation_rate": 0.3,
    "crossover_rate": 0.7
  }
}
```

## 快速开始

### 1. 运行快速测试

```bash
# 运行基本功能测试
uv run python src/huawei/run_tests.py
```

### 2. 运行演示

```bash
# 运行完整演示（需要数据文件）
uv run python src/huawei/demo.py
```

### 3. 运行完整测试套件

```bash
# 运行所有测试
uv run pytest src/huawei/tests/ -v

# 运行特定测试
uv run pytest src/huawei/tests/test_dataset.py -v
uv run pytest src/huawei/tests/test_prompt_manager.py -v
uv run pytest src/huawei/tests/test_integration.py -v
```

### 4. 自定义使用

```python
import sys
sys.path.append('src')

from huawei import HuaweiDataset, HuaweiPromptManager

# 使用自己的配置
config_path = "my_config.json"
data_path = "my_data.json"

# 初始化组件
dataset = HuaweiDataset(data_path, config_path)
prompt_manager = HuaweiPromptManager(config_path)

# 自定义使用...
```

## 进化策略详解

### 变异策略

1. **语义变异**: 改变表达方式但保持含义
   - 词汇替换（"代码片段" → "代码段"）
   - 语气调整（"分析" → "深入分析"）

2. **结构变异**: 改变 prompt 的组织结构
   - 段落重排
   - 指令顺序调整

3. **模板融合**: 融合不同模板的特点
   - 从其他模板借用有用的表达
   - 组合不同的分析角度

### 交叉策略

- **语义块交叉**: 按语义单位进行交换
- **保持核心逻辑**: 确保交叉后的 prompt 仍然合理
- **多点交叉**: 支持多个交换点

### 多样化技术

1. **添加强调**: 增加强调性词汇
2. **改变语气**: 调整专业性和正式程度
3. **添加示例**: 插入相关的说明示例
4. **格式调整**: 修改输出格式要求

## 评估指标

系统支持多种评估指标：

- **准确率 (Accuracy)**: 整体预测正确性
- **精确率 (Precision)**: 漏洞检测的精确性
- **召回率 (Recall)**: 漏洞检测的完整性
- **F1 分数**: 精确率和召回率的调和平均

## 扩展性

### 添加新的类别

在配置文件中添加：

```json
{
  "categories": {
    "新类别名称": {
      "cwe_id": 123,
      "description": "类别描述",
      "severity": "high"
    }
  }
}
```

### 添加新的 Prompt 模板

```json
{
  "prompt_templates": {
    "新模板名": "模板内容使用 {code}, {lang}, {category_list} 等占位符"
  }
}
```

### 自定义变异策略

继承 `HuaweiPromptManager` 并重写相关方法：

```python
class CustomPromptManager(HuaweiPromptManager):
    def _custom_mutation(self, prompt: str) -> str:
        # 实现自定义变异逻辑
        return modified_prompt
```

## 注意事项

1. **文件路径**: 确保数据文件和配置文件路径正确
2. **编码格式**: 所有文件使用 UTF-8 编码
3. **内存使用**: 大数据集时注意内存管理
4. **API 限制**: 使用真实 LLM 时注意速率限制

## 故障排除

### 常见问题

1. **配置文件不存在**
   ```
   解决: 检查路径，使用提供的示例配置文件
   ```

2. **数据格式错误**
   ```
   解决: 确保数据文件符合华为数据集格式规范
   ```

3. **导入错误**
   ```
   解决: 确保 PYTHONPATH 包含 src 目录
   ```

### 调试技巧

1. 启用详细日志：
   ```python
   import logging
   logging.basicConfig(level=logging.DEBUG)
   ```

2. 使用小数据集测试：
   ```python
   samples = dataset.sample_balanced(n_samples=10)
   ```

3. 检查 prompt 构建：
   ```python
   built = prompt_manager.build_prompt(template, code, lang)
   print("构建的 prompt:", built)
   ```

## 贡献

欢迎提交 Issue 和 Pull Request 来改进此实现。

## 许可证

与主项目相同的许可证。