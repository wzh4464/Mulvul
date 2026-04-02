# RAG-Enhanced Vulnerability Detection

## 概述

RAG (Retrieval-Augmented Generation) 增强三层检测系统，通过在每一层检索相似代码示例来提高分类准确性。

```
代码输入
    ↓
检索相似示例 (top-k)
    ↓
将示例注入prompt
    ↓
Layer 1: Major Category (带示例增强)
    ↓
检索该大类下的相似示例
    ↓
Layer 2: Middle Category (带示例增强)
    ↓
检索该中类下的相似示例
    ↓
Layer 3: CWE (带示例增强)
```

## 核心组件

### 1. 知识库 (Knowledge Base)

存储每个类别的代码示例:

```python
from evoprompt.rag.knowledge_base import KnowledgeBaseBuilder

# 创建默认知识库 (包含预置示例)
kb = KnowledgeBaseBuilder.create_default_kb()

# 查看统计
stats = kb.statistics()
print(f"Total examples: {stats['total_examples']}")
print(f"Major categories: {stats['major_categories']}")
print(f"Middle categories: {stats['middle_categories']}")

# 保存知识库
kb.save("knowledge_base.json")

# 加载知识库
from evoprompt.rag.knowledge_base import KnowledgeBase
kb = KnowledgeBase.load("knowledge_base.json")
```

### 2. 检索器 (Retriever)

检索最相似的代码示例:

```python
from evoprompt.rag.retriever import create_retriever

# 创建词汇相似度检索器 (快速)
retriever = create_retriever(kb, retriever_type="lexical")

# 创建嵌入检索器 (更准确,未来实现)
retriever = create_retriever(kb, retriever_type="embedding")

# 检索示例
result = retriever.retrieve_for_major_category(code, top_k=2)
print(f"Retrieved {len(result.examples)} examples")
print(f"Similarity scores: {result.similarity_scores}")
print(f"Formatted text:\n{result.formatted_text}")
```

### 3. RAG检测器 (RAG Detector)

集成检索和检测:

```python
from evoprompt.detectors.rag_three_layer_detector import RAGThreeLayerDetector
from evoprompt.prompts.hierarchical_three_layer import ThreeLayerPromptFactory
from evoprompt.llm.client import create_llm_client

# 创建prompt集
prompt_set = ThreeLayerPromptFactory.create_default_prompt_set()

# 创建LLM客户端
llm_client = create_llm_client(llm_type="gpt-4")

# 创建RAG检测器
detector = RAGThreeLayerDetector(
    prompt_set=prompt_set,
    llm_client=llm_client,
    knowledge_base=kb,
    use_scale_enhancement=False,
    retriever_type="lexical",  # 或 "embedding"
    top_k=2  # 每层检索2个示例
)

# 检测
cwe, details = detector.detect(code)

# 查看检索信息
print(f"Layer 1 retrieved: {details['layer1_retrieval']['num_examples']} examples")
print(f"Layer 2 retrieved: {details['layer2_retrieval']['num_examples']} examples")
print(f"Layer 3 retrieved: {details['layer3_retrieval']['num_examples']} examples")
```

## 快速开始

### 1. 运行演示

```bash
uv run python scripts/ablations/demo_rag_detection.py
```

演示内容:
- 创建知识库
- RAG检测测试
- 对比有/无RAG的效果
- 展示RAG优势

### 2. 单次检测示例

```python
from evoprompt.rag.knowledge_base import KnowledgeBaseBuilder
from evoprompt.detectors.rag_three_layer_detector import RAGThreeLayerDetector
from evoprompt.prompts.hierarchical_three_layer import ThreeLayerPromptFactory
from evoprompt.llm.client import create_llm_client

# 1. 创建知识库
kb = KnowledgeBaseBuilder.create_default_kb()

# 2. 创建检测器
prompt_set = ThreeLayerPromptFactory.create_default_prompt_set()
llm_client = create_llm_client(llm_type="gpt-4")

detector = RAGThreeLayerDetector(
    prompt_set=prompt_set,
    llm_client=llm_client,
    knowledge_base=kb,
    top_k=2
)

# 3. 检测代码
code = """
void copy(char* input) {
    char buf[100];
    strcpy(buf, input);  // Vulnerable!
}
"""

cwe, details = detector.detect(code)

print(f"Detected CWE: {cwe}")
print(f"Classification path: {details['layer1']} → {details['layer2']} → {details['layer3']}")
```

### 3. 从数据集构建知识库

```python
from evoprompt.data.dataset import PrimevulDataset
from evoprompt.rag.knowledge_base import create_knowledge_base_from_dataset

# 加载数据集
dataset = PrimevulDataset("data/primevul_1percent_sample/train.txt", "train")

# 从数据集采样构建知识库
kb = create_knowledge_base_from_dataset(
    dataset,
    output_path="knowledge_base_from_data.json",
    samples_per_category=2  # 每个类别采样2个
)

print(f"Knowledge base created with {kb.statistics()['total_examples']} examples")
```

## 知识库结构

### CodeExample

单个代码示例:

```python
@dataclass
class CodeExample:
    code: str              # 代码片段
    category: str          # 类别 (Major/Middle/CWE)
    description: str       # 漏洞描述
    cwe: Optional[str]     # CWE ID
    severity: str          # 严重程度
    metadata: Dict         # 其他元数据
```

### KnowledgeBase

三层组织:

```python
class KnowledgeBase:
    major_examples: Dict[str, List[CodeExample]]    # 大类示例
    middle_examples: Dict[str, List[CodeExample]]   # 中类示例
    cwe_examples: Dict[str, List[CodeExample]]      # CWE示例
```

示例分布:

```
Memory (大类)
├─ Buffer Overflow (中类)
│  ├─ CWE-120 示例
│  ├─ CWE-121 示例
│  └─ CWE-787 示例
├─ Use After Free (中类)
│  └─ CWE-416 示例
└─ NULL Pointer (中类)
   └─ CWE-476 示例
```

## 检索策略

### Lexical Retriever (词汇相似度)

**原理**: Jaccard相似度基于token集合

**优点**:
- 快速 (无需API调用)
- 适用于代码模式匹配
- 可解释性强

**缺点**:
- 语义理解有限
- 对变量名敏感

**适用场景**: 快速原型、大规模检测

```python
retriever = create_retriever(kb, retriever_type="lexical")
```

### Embedding Retriever (嵌入相似度)

**原理**: 使用代码嵌入模型 (CodeBERT, OpenAI embeddings)

**优点**:
- 语义理解更强
- 对变量名不敏感
- 更好的泛化能力

**缺点**:
- 需要额外API调用或模型
- 速度较慢
- 需要嵌入缓存

**适用场景**: 高精度检测、论文实验

```python
# 未来实现
retriever = create_retriever(
    kb,
    retriever_type="embedding",
    embedding_model="openai"  # 或 "codebert"
)
```

## RAG工作流程

### Layer 1: 大类检测

```python
# 1. 检索全局相似示例
retrieval = retriever.retrieve_for_major_category(code, top_k=2)

# 2. 构建增强prompt
enhanced_prompt = f"""
{retrieval.formatted_text}

{base_layer1_prompt}

Code: {code}
"""

# 3. LLM分类
major_category = llm.generate(enhanced_prompt)
```

### Layer 2: 中类检测

```python
# 1. 检索该大类下的相似示例
retrieval = retriever.retrieve_for_middle_category(
    code,
    major_category,
    top_k=2
)

# 2. 构建增强prompt
enhanced_prompt = f"""
{retrieval.formatted_text}

{base_layer2_prompt}

Code: {code}
"""

# 3. LLM分类
middle_category = llm.generate(enhanced_prompt)
```

### Layer 3: CWE检测

```python
# 1. 检索该中类下的相似示例
retrieval = retriever.retrieve_for_cwe(
    code,
    middle_category,
    top_k=2
)

# 2. 构建增强prompt
enhanced_prompt = f"""
{retrieval.formatted_text}

{base_layer3_prompt}

Code: {code}
"""

# 3. LLM分类
cwe = llm.generate(enhanced_prompt)
```

## 参数调优

### top_k (检索数量)

```python
# 少量示例 (快速)
detector = RAGThreeLayerDetector(..., top_k=1)

# 中等示例 (平衡)
detector = RAGThreeLayerDetector(..., top_k=2)  # 推荐

# 多量示例 (详细)
detector = RAGThreeLayerDetector(..., top_k=3)
```

**建议**:
- top_k=1: 快速检测
- top_k=2: 平衡性能和准确性
- top_k=3+: 复杂场景或评估

### retriever_type (检索方式)

```python
# 词汇相似度 (快速)
detector = RAGThreeLayerDetector(..., retriever_type="lexical")

# 嵌入相似度 (准确,未来)
detector = RAGThreeLayerDetector(..., retriever_type="embedding")
```

## 性能影响

### API调用次数

**无RAG**: 3次 (Layer 1 + Layer 2 + Layer 3)

**有RAG**: 3次 (检索在本地,不增加API调用)

### 延迟分析

| 组件 | 时间 |
|------|------|
| 检索 (lexical) | <0.01s |
| LLM调用 | ~1-2s |
| 总延迟 | ~3-6s (3层) |

RAG检索几乎不增加延迟!

### 准确性提升

预期提升 (基于类似研究):
- Layer 1: +5-10%
- Layer 2: +10-15%
- Layer 3: +15-20%
- Full path: +10-15%

## 高级功能

### 自定义知识库

```python
from evoprompt.rag.knowledge_base import KnowledgeBase, CodeExample
from evoprompt.prompts.hierarchical_three_layer import MajorCategory

kb = KnowledgeBase()

# 添加自定义示例
example = CodeExample(
    code="your vulnerable code",
    category="Memory",
    description="Custom example",
    cwe="CWE-120",
    severity="high"
)

kb.add_major_example(MajorCategory.MEMORY, example)

# 保存
kb.save("custom_kb.json")
```

### 动态更新知识库

```python
# 加载现有知识库
kb = KnowledgeBase.load("knowledge_base.json")

# 添加新示例
new_example = CodeExample(...)
kb.add_cwe_example("CWE-120", new_example)

# 保存更新
kb.save("knowledge_base.json")
```

### 检索结果分析

```python
cwe, details = detector.detect(code)

# 分析每层的检索
for layer in [1, 2, 3]:
    retrieval = details[f'layer{layer}_retrieval']

    print(f"Layer {layer}:")
    print(f"  Examples: {retrieval['num_examples']}")
    print(f"  Scores: {retrieval['similarity_scores']}")

    # Layer 3还有CWE信息
    if layer == 3 and 'example_cwes' in retrieval:
        print(f"  CWEs: {retrieval['example_cwes']}")
```

## 与训练集成

### 在进化算法中使用RAG

```python
from evoprompt.algorithms.coevolution import CoevolutionaryAlgorithm
from evoprompt.multiagent.coordinator import MultiAgentCoordinator

# 创建RAG检测器
rag_detector = RAGThreeLayerDetector(...)

# 创建协调器 (使用RAG检测器)
coordinator = MultiAgentCoordinator(
    detection_agent=detection_agent,
    meta_agent=meta_agent,
    detector=rag_detector  # 传入RAG检测器
)

# 运行进化
algorithm = CoevolutionaryAlgorithm(
    evaluator=evaluator,
    coordinator=coordinator
)
```

### Layer-by-Layer训练

```python
# Phase 1: 训练Layer 1 (使用RAG)
# 固定Layer 2+3 prompt, 只优化Layer 1

# Phase 2: 训练Layer 2 (使用RAG)
# 固定Layer 1+3 prompt, 只优化Layer 2

# Phase 3: 训练Layer 3 (使用RAG)
# 固定Layer 1+2 prompt, 只优化Layer 3
```

## 故障排查

### 问题1: 检索不到示例

**原因**: 知识库太小或代码相似度低

**解决**:
```python
# 检查知识库
stats = kb.statistics()
print(f"Total examples: {stats['total_examples']}")

# 增加示例
kb_builder = KnowledgeBaseBuilder()
kb = kb_builder.create_default_kb()

# 或从数据集构建
kb = create_knowledge_base_from_dataset(dataset)
```

### 问题2: 相似度分数都很低

**原因**: 词汇相似度对变量名敏感

**解决**:
```python
# 使用更多示例
detector = RAGThreeLayerDetector(..., top_k=3)

# 或等待嵌入检索实现
# detector = RAGThreeLayerDetector(..., retriever_type="embedding")
```

### 问题3: RAG没有提升效果

**原因**: 示例质量不高或不够多样

**解决**:
```python
# 1. 从数据集构建知识库 (更真实的示例)
kb = create_knowledge_base_from_dataset(dataset, samples_per_category=5)

# 2. 手动添加高质量示例
high_quality_example = CodeExample(...)
kb.add_cwe_example("CWE-120", high_quality_example)

# 3. 增加每层检索数量
detector = RAGThreeLayerDetector(..., top_k=3)
```

## 文件结构

```
src/evoprompt/rag/
├── __init__.py                 # RAG模块导出
├── knowledge_base.py           # 知识库定义
└── retriever.py                # 检索器实现

src/evoprompt/detectors/
└── rag_three_layer_detector.py # RAG检测器

scripts/
└── demo_rag_detection.py       # RAG演示
```

## 下一步

1. ✅ RAG检索器实现
2. ✅ RAG三层检测器
3. ✅ 演示脚本
4. ⏳ 嵌入检索器 (OpenAI/CodeBERT)
5. ⏳ 检索缓存优化
6. ⏳ 与训练pipeline集成

## 相关文档

- `THREE_LAYER_README.md` - 三层检测系统
- `MULTIAGENT_README.md` - Multi-agent框架
- `CWE_CATEGORY_README.md` - CWE分类体系

## 参考文献

RAG相关论文:
- Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks (Lewis et al., 2020)
- In-Context Retrieval-Augmented Language Models (Ram et al., 2023)

代码检索相关:
- CodeBERT: A Pre-Trained Model for Programming and Natural Languages
- GraphCodeBERT: Pre-training Code Representations with Data Flow
