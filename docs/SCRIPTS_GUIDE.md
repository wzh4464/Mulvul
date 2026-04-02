# 脚本使用指南

## 脚本分类

### 🧪 测试脚本 (推荐优先运行)

#### `test_quick.py` - 快速测试 ⭐ 推荐首选

**用途**: 验证系统所有核心功能是否正常

**运行**:
```bash
uv run python scripts/ablations/test_quick.py
```

**测试内容**:
1. 基础三层检测
2. RAG增强检测
3. Scale增强

**预计时间**: 2-3分钟

---

### 🎯 主训练脚本

#### `train_three_layer.py` - 完整训练系统 ⭐ 主脚本

**用途**: 端到端的训练和评估系统

**功能**:
- ✅ 三层检测
- ✅ RAG增强 (可选)
- ✅ Scale增强 (可选)
- ✅ Multi-agent训练 (可选)
- ✅ 自动构建知识库

**使用示例**:

```bash
# 1. 仅评估 (基线)
uv run python scripts/ablations/train_three_layer.py --eval-samples 50

# 2. 评估 + RAG
uv run python scripts/ablations/train_three_layer.py --use-rag --eval-samples 50

# 3. 评估 + RAG + Scale
uv run python scripts/ablations/train_three_layer.py --use-rag --use-scale --eval-samples 50

# 4. 完整训练 (RAG + 训练)
uv run python scripts/ablations/train_three_layer.py \
    --train \
    --use-rag \
    --kb-from-dataset \
    --population-size 5 \
    --max-generations 20 \
    --eval-samples 100
```

**详细参数**: 见 `QUICKSTART.md`

---

### 📚 演示脚本

#### `demo_three_layer_detection.py` - 三层检测演示

**用途**: 演示三层检测结构和工作流程

**运行**:
```bash
uv run python scripts/ablations/demo_three_layer_detection.py
```

**功能**:
- 展示三层结构
- 单个样本检测
- 数据集评估 (可选)
- 训练策略说明

---

#### `demo_rag_detection.py` - RAG检测演示

**用途**: 演示RAG增强如何工作

**运行**:
```bash
uv run python scripts/ablations/demo_rag_detection.py
```

**功能**:
- 构建知识库
- RAG检测测试
- 对比有/无RAG效果
- RAG优势说明

---

#### `demo_multiagent_coevolution.py` - Multi-agent训练演示

**用途**: 演示Multi-agent协同进化

**运行**:
```bash
uv run python scripts/ablations/demo_multiagent_coevolution.py
```

**功能**:
- Detection Agent + Meta Agent
- 协同优化
- 统计反馈
- 进化过程展示

---

#### `demo_cwe_category_classification.py` - CWE分类演示

**用途**: 测试不同的大类分类prompt

**运行**:
```bash
uv run python scripts/ablations/demo_cwe_category_classification.py
```

**功能**:
- 测试4种分类prompt
- 每类准确率分析
- 最佳prompt选择

---

### 🔧 工具脚本

#### `build_knowledge_base.py` - 构建知识库

**用途**: 构建RAG知识库

**运行**:
```bash
# 从默认示例
uv run python scripts/ablations/build_knowledge_base.py \
    --source default \
    --output outputs/kb.json

# 从数据集
uv run python scripts/ablations/build_knowledge_base.py \
    --source dataset \
    --dataset data/primevul_1percent_sample/train.txt \
    --samples-per-category 5 \
    --output outputs/kb_from_data.json
```

---

### 📊 旧版脚本 (仍可用)

#### `run_primevul_1percent.py` - 旧版训练脚本

**说明**: 较早的训练脚本，功能较基础

**推荐**: 使用 `train_three_layer.py` 代替

---

#### `run_cwe_evolution.py` - CWE进化脚本

**说明**: 专注于CWE分类的进化

---

#### `demo_primevul_1percent.py` - 1%数据演示

**说明**: 早期演示脚本

---

## 推荐工作流程

### 新用户入门 (30分钟)

```bash
# 1. 快速测试 (5分钟)
uv run python scripts/ablations/test_quick.py

# 2. 三层检测演示 (10分钟)
uv run python scripts/ablations/demo_three_layer_detection.py

# 3. RAG演示 (15分钟)
uv run python scripts/ablations/demo_rag_detection.py
```

### 评估不同配置 (1小时)

```bash
# 基线
uv run python scripts/ablations/train_three_layer.py \
    --eval-samples 50 \
    --output-dir outputs/baseline

# + RAG
uv run python scripts/ablations/train_three_layer.py \
    --use-rag \
    --eval-samples 50 \
    --output-dir outputs/with_rag

# + Scale
uv run python scripts/ablations/train_three_layer.py \
    --use-scale \
    --eval-samples 50 \
    --output-dir outputs/with_scale

# RAG + Scale
uv run python scripts/ablations/train_three_layer.py \
    --use-rag \
    --use-scale \
    --eval-samples 50 \
    --output-dir outputs/rag_scale
```

### 完整训练实验 (数小时)

```bash
# 完整训练 (RAG + 训练)
uv run python scripts/ablations/train_three_layer.py \
    --train \
    --use-rag \
    --kb-from-dataset \
    --kb-samples-per-category 5 \
    --population-size 5 \
    --max-generations 20 \
    --batch-size 20 \
    --eval-samples 100 \
    --output-dir outputs/full_training
```

## 脚本对比

| 脚本 | 用途 | 时间 | 推荐 |
|------|------|------|------|
| `test_quick.py` | 快速测试 | 2-3分钟 | ⭐⭐⭐ |
| `train_three_layer.py` | 完整训练 | 可变 | ⭐⭐⭐ |
| `demo_three_layer_detection.py` | 三层演示 | 5-10分钟 | ⭐⭐ |
| `demo_rag_detection.py` | RAG演示 | 10-15分钟 | ⭐⭐ |
| `demo_multiagent_coevolution.py` | Multi-agent演示 | 30分钟+ | ⭐ |
| `demo_cwe_category_classification.py` | 分类测试 | 15-20分钟 | ⭐ |
| `build_knowledge_base.py` | 构建KB | 1-2分钟 | ⭐ |

## 快速命令参考

### 测试

```bash
# 快速测试所有功能
uv run python scripts/ablations/test_quick.py
```

### 评估

```bash
# 基础评估
uv run python scripts/ablations/train_three_layer.py --eval-samples 50

# RAG评估
uv run python scripts/ablations/train_three_layer.py --use-rag --eval-samples 50

# 完整评估
uv run python scripts/ablations/train_three_layer.py --use-rag --use-scale --eval-samples 50
```

### 训练

```bash
# 快速训练 (测试)
uv run python scripts/ablations/train_three_layer.py \
    --train --population-size 3 --max-generations 5 --eval-samples 30

# 完整训练
uv run python scripts/ablations/train_three_layer.py \
    --train --use-rag --kb-from-dataset \
    --population-size 5 --max-generations 20 --eval-samples 100
```

### 工具

```bash
# 构建知识库
uv run python scripts/ablations/build_knowledge_base.py --source default

# 从数据集构建
uv run python scripts/ablations/build_knowledge_base.py \
    --source dataset --dataset data/primevul_1percent_sample/train.txt
```

## 输出目录结构

```
outputs/
├── three_layer_eval_20250122_143000/     # 评估结果
│   ├── config.json
│   ├── metrics.json
│   ├── prompts.json
│   └── prompts.txt
│
├── three_layer_train_rag_20250122_150000/  # 训练结果
│   ├── config.json
│   ├── metrics.json
│   ├── prompts.json
│   └── prompts.txt
│
└── knowledge_base.json                    # 知识库
```

## 常见问题

### Q1: 应该先运行哪个脚本?

**A**: `test_quick.py` - 快速验证系统是否正常

### Q2: 如何快速评估性能?

**A**:
```bash
uv run python scripts/ablations/train_three_layer.py --use-rag --eval-samples 50
```

### Q3: 如何进行完整训练?

**A**:
```bash
uv run python scripts/ablations/train_three_layer.py \
    --train --use-rag --kb-from-dataset \
    --population-size 5 --max-generations 20
```

### Q4: 如何对比不同配置?

**A**: 使用 `--output-dir` 指定不同的输出目录:
```bash
# 基线
uv run python scripts/ablations/train_three_layer.py --output-dir outputs/baseline

# RAG
uv run python scripts/ablations/train_three_layer.py --use-rag --output-dir outputs/rag
```

### Q5: 演示脚本和训练脚本有什么区别?

**A**:
- 演示脚本: 展示功能，交互式，适合学习
- 训练脚本: 批量处理，自动化，适合实验

## 相关文档

- `QUICKSTART.md` - 快速开始指南
- `INTEGRATION_GUIDE.md` - 集成使用指南
- `THREE_LAYER_README.md` - 三层检测详解
- `RAG_README.md` - RAG增强详解
- `MULTIAGENT_README.md` - Multi-agent训练详解
