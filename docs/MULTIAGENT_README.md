# Multi-Agent Collaborative Prompt Evolution

## 概述

这是一个基于Multi-agent框架和协同进化的代码漏洞检测Prompt调优系统,核心创新点包括:

### 🎯 核心特性

1. **双模型协作架构**
   - **Detection Agent (GPT-4)**: 执行漏洞检测,验证Prompt效果
   - **Meta Agent (Claude 4.5)**: 分析性能指标,指导Prompt优化

2. **Batch机制 + 统计信息反馈**
   - 每个Batch收集详细统计信息(准确率、F1、各类漏洞错判率)
   - Meta Agent接收历史统计信息,避免盲目搜索和局部最优

3. **层级化Prompt结构**
   - 大类路由: 先判断漏洞大类(Memory, Injection, Logic, etc.)
   - 小类检测: 针对具体CWE类型的细粒度检测

4. **协同进化算法**
   - 结合传统进化算法(crossover, mutation)
   - Meta-agent引导的智能优化
   - Elitism策略保留优秀个体

## 🏗️ 架构设计

```
┌─────────────────────────────────────────────────────────────┐
│                   Multi-Agent Framework                      │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐         ┌────────────────┐               │
│  │  Detection   │         │   Meta Agent   │               │
│  │    Agent     │◄───────►│  (Claude 4.5)  │               │
│  │   (GPT-4)    │         │                │               │
│  └──────────────┘         └────────────────┘               │
│         │                          │                        │
│         │                          │                        │
│         └──────────┬───────────────┘                        │
│                    │                                        │
│            ┌───────▼────────┐                               │
│            │  Coordinator   │                               │
│            │  - Batch eval  │                               │
│            │  - Statistics  │                               │
│            └───────┬────────┘                               │
│                    │                                        │
│         ┌──────────▼───────────┐                            │
│         │ Coevolution Algorithm│                            │
│         │  - Meta improvement  │                            │
│         │  - Crossover/Mutate  │                            │
│         │  - Elitism           │                            │
│         └──────────────────────┘                            │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## 📁 项目结构

```
src/evoprompt/
├── multiagent/              # Multi-agent框架
│   ├── agents.py           # Detection Agent + Meta Agent
│   └── coordinator.py      # 协调器
├── prompts/                # Prompt管理
│   └── hierarchical.py     # 层级化Prompt结构
├── optimization/           # Meta优化
│   └── meta_optimizer.py   # Meta-agent优化逻辑
├── evaluators/             # 统计收集
│   └── statistics.py       # 详细统计信息
├── algorithms/             # 进化算法
│   └── coevolution.py      # 协同进化算法
└── llm/                    # LLM客户端
    └── client.py           # 双模型支持

scripts/
└── demo_multiagent_coevolution.py  # 完整演示
```

## 🚀 快速开始

### 1. 环境配置

在`.env`文件中配置API密钥:

```bash
# Detection Model (GPT-4 or compatible)
API_BASE_URL=https://api.openai.com/v1
API_KEY=your-gpt4-api-key
MODEL_NAME=gpt-4

# Meta Model (Claude 4.5)
META_API_BASE_URL=https://api.anthropic.com/v1
META_API_KEY=your-claude-api-key
META_MODEL_NAME=claude-sonnet-4-5-20250929-thinking

# Backup API (optional)
BACKUP_API_BASE_URL=https://backup-api.example.com/v1
```

### 2. 准备数据

运行采样脚本生成1%均衡数据:

```bash
uv run python scripts/ablations/demo_primevul_1percent.py
```

### 3. 运行Multi-agent协同进化

```bash
uv run python scripts/ablations/demo_multiagent_coevolution.py
```

## 🔬 核心组件说明

### Detection Agent

负责使用Prompt检测漏洞:

```python
from evoprompt.multiagent.agents import create_detection_agent

# 创建Detection Agent (GPT-4)
detection_agent = create_detection_agent(
    model_name="gpt-4",
    temperature=0.1
)

# 执行检测
predictions = detection_agent.detect(
    prompt=your_prompt,
    code_samples=code_list
)
```

### Meta Agent

负责分析性能并优化Prompt:

```python
from evoprompt.multiagent.agents import create_meta_agent

# 创建Meta Agent (Claude 4.5)
meta_agent = create_meta_agent(
    model_name="claude-sonnet-4-5-20250929-thinking",
    temperature=0.7
)

# 优化Prompt
improved_prompt = meta_agent.improve_prompt(
    current_prompt=current_prompt,
    current_stats=detection_statistics,
    historical_stats=history,
    improvement_suggestions=suggestions
)
```

### Multi-Agent Coordinator

协调两个Agent的协作:

```python
from evoprompt.multiagent.coordinator import MultiAgentCoordinator, CoordinatorConfig

# 配置协调器
config = CoordinatorConfig(
    strategy=CoordinationStrategy.SEQUENTIAL,
    batch_size=16,
    enable_batch_feedback=True,
    statistics_window=3
)

coordinator = MultiAgentCoordinator(
    detection_agent=detection_agent,
    meta_agent=meta_agent,
    config=config
)

# 协同优化
improved_prompt, stats = coordinator.collaborative_improve(
    prompt=current_prompt,
    dataset=eval_dataset,
    generation=gen_number
)
```

### Coevolutionary Algorithm

协同进化算法集成所有组件:

```python
from evoprompt.algorithms.coevolution import CoevolutionaryAlgorithm

algorithm = CoevolutionaryAlgorithm(
    config={
        "population_size": 6,
        "max_generations": 4,
        "meta_improvement_rate": 0.5,  # 50%个体由Meta-agent改进
        "top_k": 3,
        "enable_elitism": True,
    },
    coordinator=coordinator,
    dataset=dataset
)

# 运行进化
results = algorithm.evolve(initial_prompts=initial_prompts)
```

## 📊 统计信息收集

系统收集详细的统计信息用于Meta-agent优化:

```python
from evoprompt.evaluators.statistics import DetectionStatistics

stats = DetectionStatistics()

# 添加预测结果
stats.add_prediction(
    predicted="vulnerable",
    actual="benign",
    category="CWE-120"  # 可选: CWE类型
)

# 计算指标
stats.compute_metrics()

# 获取总结
summary = stats.get_summary()
# {
#   "accuracy": 0.85,
#   "precision": 0.82,
#   "recall": 0.88,
#   "f1_score": 0.85,
#   "category_stats": {
#     "CWE-120": {"accuracy": 0.80, "error_rate": 0.20, ...}
#   },
#   "confusion_matrix": {...}
# }
```

## 🧬 进化流程

每代进化包含三个阶段:

### Phase 1: Meta-guided Improvement
```
Meta Agent接收:
- 当前Prompt性能(accuracy, F1, 各类错判率)
- 历史统计趋势
- 自动化分析建议

输出: 改进的Prompt(基于统计反馈)
```

### Phase 2: Evolutionary Operators
```
传统进化算法:
- Crossover: Meta Agent组合两个父代Prompt
- Mutation: Meta Agent进行有指导的变异
```

### Phase 3: Selection
```
选择策略:
- Elitism: 保留Top K最优个体
- 多样性维护: 随机选择填充种群
```

## 🎓 与传统方法对比

| 特性 | 传统进化算法 | Multi-Agent协同进化 |
|------|------------|-------------------|
| 优化方向 | 盲目搜索 | Meta-agent引导 |
| 反馈机制 | 仅适应度分数 | 详细统计 + 历史趋势 |
| 局部最优 | 易陷入 | 统计信息避免 |
| 小类检测 | 数据不足效果差 | 层级化结构优化 |
| 可解释性 | 低 | 高(Meta-agent分析) |

## 📈 实验输出

运行实验后,会生成以下文件:

```
outputs/multiagent_coevolution/multiagent_coevo_YYYYMMDD_HHMMSS/
├── experiment_config.json       # 实验配置
├── initial_prompts.txt          # 初始Prompt集合
├── evolution_results.json       # 进化结果
├── final_population.txt         # 最终种群Top Prompts
└── statistics.json              # 详细统计信息
```

### 结果示例

```json
{
  "best_fitness": 0.8542,
  "fitness_history": [0.7123, 0.7589, 0.8102, 0.8542],
  "generation_stats": [...],
  "coordinator_statistics": {
    "total_generations": 4,
    "total_batches": 24,
    "historical_trend": [...],
    "improvement_suggestions": [
      "Category 'CWE-120' has low accuracy. Focus on improving...",
      "High false positive rate. Make the prompt more specific..."
    ]
  }
}
```

## 🔧 高级配置

### 自定义Detection Agent

```python
from evoprompt.llm.client import create_llm_client
from evoprompt.multiagent.agents import DetectionAgent, AgentConfig, AgentRole

# 使用自定义模型
custom_client = create_llm_client(llm_type="your-model")
custom_config = AgentConfig(
    role=AgentRole.DETECTION,
    model_name="your-model",
    temperature=0.05,  # 更确定性
    batch_size=32
)

detection_agent = DetectionAgent(custom_config, custom_client)
```

### 层级化Prompt

```python
from evoprompt.prompts.hierarchical import PromptHierarchy, CWECategory

hierarchy = PromptHierarchy()
hierarchy.initialize_with_defaults()

# 设置大类路由Prompt
hierarchy.set_router_prompt("Classify this code into vulnerability categories...")

# 设置小类检测Prompt
hierarchy.set_category_prompt(
    CWECategory.MEMORY,
    "Analyze for memory vulnerabilities: buffer overflow, use-after-free..."
)
```

## 🎯 论文实验建议

### Baseline对比

1. **Rule-based Evolution**: 传统进化算法(无Meta-agent)
2. **Single-model Evolution**: 仅用GPT-4自我优化
3. **Multi-agent Coevolution**: 本框架(GPT-4检测 + Claude 4.5 Meta优化)

### 消融实验

- **无Batch反馈**: `enable_batch_feedback=False`
- **无统计信息**: 不传递`historical_stats`给Meta-agent
- **无Elitism**: `enable_elitism=False`
- **降低Meta改进率**: `meta_improvement_rate=0.1`

### 评估指标

- Accuracy, Precision, Recall, F1 Score
- 各CWE类型的错判率
- 小类漏洞检测精度(重点)
- 收敛速度(达到目标性能所需代数)

## 🐛 调试技巧

### 启用详细日志

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### 检查统计信息

```python
# 查看每代统计
summary = coordinator.get_statistics_summary()
print(json.dumps(summary, indent=2))

# 导出详细统计
coordinator.export_statistics("debug_stats.json")
```

### 追踪Prompt变化

所有Prompt变化都记录在Individual的metadata中:

```python
for ind in population.individuals:
    print(f"Fitness: {ind.fitness}")
    print(f"Operation: {ind.metadata.get('operation')}")
    print(f"Stats: {ind.metadata.get('stats').get_summary()}")
```

## 📚 参考文献

- APE: Large Language Models are Human-Level Prompt Engineers
- EvoPrompt: Automatic Prompt Optimization
- Multi-agent Collaboration (论文热点)

## 🤝 贡献

欢迎提交Issue和Pull Request!

## 📄 License

MIT License
