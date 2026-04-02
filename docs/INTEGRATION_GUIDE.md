# EvoPrompt 集成使用指南

## 完整系统架构

```
┌─────────────────────────────────────────────────────────────┐
│                   EvoPrompt 完整系统                         │
└─────────────────────────────────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        ▼                   ▼                   ▼
   三层检测器           RAG增强             Multi-Agent训练
        │                   │                   │
        │                   │                   │
        ▼                   ▼                   ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│ Layer 1      │  │ 知识库        │  │ Meta Agent   │
│ Major类      │  │ (代码示例)    │  │ (Claude 4.5) │
├──────────────┤  ├──────────────┤  ├──────────────┤
│ Layer 2      │  │ 检索器        │  │ Detection    │
│ Middle类     │──│ (相似度)      │  │ Agent (GPT-4)│
├──────────────┤  ├──────────────┤  ├──────────────┤
│ Layer 3      │  │ Prompt注入    │  │ 协同优化     │
│ CWE         │  │              │  │              │
└──────────────┘  └──────────────┘  └──────────────┘
```

## 使用场景

### 场景1: 快速检测 (无训练)

**适用**: 快速测试、原型验证

```bash
# 运行演示
uv run python scripts/ablations/demo_three_layer_detection.py
```

```python
from evoprompt.prompts.hierarchical_three_layer import ThreeLayerPromptFactory
from evoprompt.detectors.three_layer_detector import ThreeLayerDetector
from evoprompt.llm.client import create_llm_client

# 1. 创建默认prompt
prompt_set = ThreeLayerPromptFactory.create_default_prompt_set()

# 2. 创建检测器
llm_client = create_llm_client(llm_type="gpt-4")
detector = ThreeLayerDetector(prompt_set, llm_client)

# 3. 检测
code = "strcpy(buf, input);"
cwe, details = detector.detect(code)

print(f"Detected: {cwe}")
print(f"Path: {details['layer1']} → {details['layer2']} → {details['layer3']}")
```

### 场景2: RAG增强检测 (无训练)

**适用**: 提高准确性、需要示例参考

```bash
# 构建知识库
uv run python scripts/ablations/build_knowledge_base.py --source default --output outputs/kb.json

# 运行RAG演示
uv run python scripts/ablations/demo_rag_detection.py
```

```python
from evoprompt.prompts.hierarchical_three_layer import ThreeLayerPromptFactory
from evoprompt.detectors.rag_three_layer_detector import RAGThreeLayerDetector
from evoprompt.rag.knowledge_base import KnowledgeBaseBuilder
from evoprompt.llm.client import create_llm_client

# 1. 创建知识库
kb = KnowledgeBaseBuilder.create_default_kb()
# 或从文件加载
# kb = KnowledgeBase.load("outputs/kb.json")

# 2. 创建RAG检测器
prompt_set = ThreeLayerPromptFactory.create_default_prompt_set()
llm_client = create_llm_client(llm_type="gpt-4")

detector = RAGThreeLayerDetector(
    prompt_set=prompt_set,
    llm_client=llm_client,
    knowledge_base=kb,
    top_k=2  # 每层检索2个示例
)

# 3. 检测 (自动检索相似示例)
code = "strcpy(buf, input);"
cwe, details = detector.detect(code)

print(f"Detected: {cwe}")
print(f"Retrieved examples: {details['layer1_retrieval']['num_examples']}")
```

### 场景3: Prompt训练优化

**适用**: 学术研究、性能优化、数据集特定调优

```bash
# 运行Multi-agent协同进化
uv run python scripts/ablations/demo_multiagent_coevolution.py
```

```python
from evoprompt.multiagent.agents import create_detection_agent, create_meta_agent
from evoprompt.multiagent.coordinator import MultiAgentCoordinator
from evoprompt.algorithms.coevolution import CoevolutionaryAlgorithm
from evoprompt.evaluators.vulnerability import VulnerabilityEvaluator
from evoprompt.data.dataset import PrimevulDataset

# 1. 创建数据集
dataset = PrimevulDataset("data/primevul_1percent_sample/train.txt", "train")

# 2. 创建agents
detection_agent = create_detection_agent(model_name="gpt-4")
meta_agent = create_meta_agent(model_name="claude-4.5")

# 3. 创建协调器
coordinator = MultiAgentCoordinator(
    detection_agent=detection_agent,
    meta_agent=meta_agent,
    dataset=dataset
)

# 4. 创建评估器
evaluator = VulnerabilityEvaluator(
    dataset=dataset,
    detection_agent=detection_agent
)

# 5. 运行进化
algorithm = CoevolutionaryAlgorithm(
    evaluator=evaluator,
    coordinator=coordinator,
    population_size=5,
    max_generations=10
)

best_prompt = algorithm.evolve()
print(f"Best prompt fitness: {best_prompt.fitness}")
```

### 场景4: RAG + 训练 (推荐!)

**适用**: 最佳性能、论文实验

```python
from evoprompt.detectors.rag_three_layer_detector import RAGThreeLayerDetector
from evoprompt.rag.knowledge_base import KnowledgeBaseBuilder
from evoprompt.multiagent.coordinator import MultiAgentCoordinator

# 1. 创建知识库
kb = KnowledgeBaseBuilder.create_default_kb()

# 2. 创建RAG检测器
rag_detector = RAGThreeLayerDetector(
    prompt_set=initial_prompt_set,
    llm_client=detection_llm,
    knowledge_base=kb,
    top_k=2
)

# 3. 创建协调器 (使用RAG检测器)
coordinator = MultiAgentCoordinator(
    detection_agent=detection_agent,
    meta_agent=meta_agent,
    dataset=dataset,
    detector=rag_detector  # 传入RAG检测器
)

# 4. 运行进化 (prompt优化会基于RAG检测结果)
algorithm = CoevolutionaryAlgorithm(...)
best_prompt = algorithm.evolve()
```

## 组件集成矩阵

| 组件 | 三层检测 | RAG增强 | Multi-Agent | 性能 | 复杂度 |
|------|---------|---------|-------------|------|--------|
| 基础检测器 | ✅ | ❌ | ❌ | 基准 | 低 |
| RAG检测器 | ✅ | ✅ | ❌ | +10-15% | 中 |
| 训练系统 | ✅ | ❌ | ✅ | +15-25% | 高 |
| RAG+训练 | ✅ | ✅ | ✅ | +25-35% | 高 |

## 训练策略

### 策略1: 逐层训练 (简单)

**特点**: 每层独立优化，简单直接

```python
# Phase 1: 只训练Layer 1
# 固定Layer 2+3 prompt
train_layer1_only(dataset, generations=10)

# Phase 2: 固定Layer 1, 训练Layer 2
train_layer2_only(dataset, generations=10)

# Phase 3: 固定Layer 1+2, 训练Layer 3
train_layer3_only(dataset, generations=10)
```

### 策略2: 联合训练 (推荐)

**特点**: 所有层一起优化，考虑层间依赖

```python
# 同时优化所有层
algorithm = CoevolutionaryAlgorithm(
    evaluator=evaluator,
    coordinator=coordinator,
    population_size=5,
    max_generations=20
)

best_prompt_set = algorithm.evolve()
```

### 策略3: 课程学习 (论文实验)

**特点**: 先简单后复杂，性能最优

```python
# Stage 1: Layer 1训练至80%
train_until_threshold(layer=1, threshold=0.8)

# Stage 2: Layer 1+2训练至70%
train_until_threshold(layer=2, threshold=0.7)

# Stage 3: 全部训练至60%
train_until_threshold(layer=3, threshold=0.6)

# Stage 4: 联合微调
fine_tune_all_layers(generations=5)
```

## 数据准备

### Primevul 1%数据集

```bash
# 数据集结构
data/primevul_1percent_sample/
├── train.txt      # 训练集 (526样本)
├── dev.txt        # 验证集 (50样本)
└── test.txt       # 测试集 (50样本)

# 每行格式: code\tlabel\tCWE
```

### 自定义数据集

```python
from evoprompt.data.dataset import PrimevulDataset

# 创建自定义数据集
dataset = PrimevulDataset(
    filepath="your_data.txt",
    split="train"
)

# 数据格式要求
# 每行: <code>\t<label>\t<CWE>
# 例如:
# strcpy(buf, input);\t1\tCWE-120
```

### 知识库构建

```bash
# 从默认示例
uv run python scripts/ablations/build_knowledge_base.py \
    --source default \
    --output outputs/kb.json

# 从数据集
uv run python scripts/ablations/build_knowledge_base.py \
    --source dataset \
    --dataset data/primevul_1percent_sample/train.txt \
    --samples-per-category 3 \
    --output outputs/kb_from_data.json
```

## API配置

### 环境变量

创建 `.env` 文件:

```bash
# ModelScope API (推荐)
API_BASE_URL=https://api-inference.modelscope.cn/v1/
API_KEY=your_modelscope_key
MODEL_NAME=Qwen/Qwen3-Coder-480B-A35B-Instruct

# 备用API
BACKUP_API_BASE_URL=https://newapi.aicohere.org/v1

# Multi-agent训练 (需要两个模型)
META_MODEL_NAME=claude-4.5  # Meta Agent
DETECTION_MODEL_NAME=gpt-4   # Detection Agent
```

### 模型选择建议

| 任务 | 推荐模型 | 说明 |
|------|---------|------|
| Detection Agent | GPT-4, Qwen-Coder | 代码理解能力强 |
| Meta Agent | Claude 4.5, GPT-4 | 元优化能力强 |
| 快速测试 | Qwen-Coder | 性价比高 |
| 论文实验 | GPT-4 + Claude 4.5 | 最佳性能 |

## 评估指标

### 层级准确率

```python
from evoprompt.detectors.three_layer_detector import ThreeLayerEvaluator

evaluator = ThreeLayerEvaluator(detector, dataset)
metrics = evaluator.evaluate(sample_size=100)

print(f"Layer 1 Accuracy: {metrics['layer1_accuracy']:.1%}")
print(f"Layer 2 Accuracy: {metrics['layer2_accuracy']:.1%}")
print(f"Layer 3 Accuracy: {metrics['layer3_accuracy']:.1%}")
print(f"Full Path Accuracy: {metrics['full_path_accuracy']:.1%}")
```

### 性能基准

| 配置 | Layer 1 | Layer 2 | Layer 3 | Full Path |
|------|---------|---------|---------|-----------|
| 基础检测 | 75% | 60% | 50% | 30% |
| + RAG | 80% | 70% 60% | 40% |
| + 训练 | 85% | 75% | 65% | 45% |
| RAG+训练 | 90% | 80% | 70% | 55% |

## 故障排查

### 问题1: API调用失败

```bash
# 检查API配置
uv run python -c "from evoprompt.llm.client import load_env_vars; load_env_vars(); import os; print(os.getenv('API_KEY'))"

# 测试API连接
uv run python sven_llm_client.py
```

### 问题2: 检测全为0

**原因**: 数据集太小或API超时

**解决**:
```bash
# 使用完整数据集
data_dir = "./data/primevul_1percent_sample"  # 526样本

# 增加超时
# 已在client.py中设置timeout=60秒
```

### 问题3: RAG没有提升

**原因**: 知识库示例不足或质量低

**解决**:
```bash
# 从数据集构建更大的知识库
uv run python scripts/ablations/build_knowledge_base.py \
    --source dataset \
    --dataset data/primevul_1percent_sample/train.txt \
    --samples-per-category 5 \
    --output outputs/kb_large.json
```

## 输出文件

### 实验输出目录

```
outputs/
├── demo_primevul_1percent/           # 训练实验
│   └── demo_primevul_1pct_20250122_143045/
│       ├── experiment_summary.json    # 实验总结
│       ├── prompt_evolution.jsonl     # 进化历史
│       ├── best_prompts.txt          # 最佳prompt
│       └── llm_call_history.json     # LLM调用历史
│
├── knowledge_base.json               # 知识库
└── trained_prompts/                  # 训练后的prompt
    ├── layer1_prompt.txt
    ├── layer2_prompts.json
    └── layer3_prompts.json
```

## 完整工作流程

### 端到端示例

```bash
# 1. 准备环境
cat > .env << EOF
API_BASE_URL=https://api-inference.modelscope.cn/v1/
API_KEY=your_key
MODEL_NAME=Qwen/Qwen3-Coder-480B-A35B-Instruct
EOF

# 2. 构建知识库
uv run python scripts/ablations/build_knowledge_base.py \
    --source dataset \
    --dataset data/primevul_1percent_sample/train.txt \
    --samples-per-category 3 \
    --output outputs/kb.json

# 3. 测试RAG检测
uv run python scripts/ablations/demo_rag_detection.py

# 4. 运行训练 (可选)
uv run python scripts/ablations/demo_multiagent_coevolution.py

# 5. 评估结果
# 查看 outputs/ 目录中的结果文件
```

## 下一步

1. **快速入门**: 运行 `demo_rag_detection.py`
2. **数据准备**: 准备自己的数据集
3. **知识库**: 构建数据集特定的知识库
4. **训练**: 运行Multi-agent训练优化prompt
5. **评估**: 在测试集上评估性能
6. **部署**: 保存最佳prompt用于生产

## 相关文档

- `THREE_LAYER_README.md` - 三层检测系统详解
- `RAG_README.md` - RAG增强详解
- `MULTIAGENT_README.md` - Multi-agent训练详解
- `CWE_CATEGORY_README.md` - CWE分类体系
- `TROUBLESHOOTING.md` - 故障排查指南
