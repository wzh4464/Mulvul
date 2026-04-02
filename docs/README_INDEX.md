# EvoPrompt 文档索引

## 🚀 新用户入门 (推荐顺序)

### 第一步: 快速开始
📖 **[QUICKSTART.md](QUICKSTART.md)** - 5分钟上手指南

**内容**:
- 环境配置
- 快速测试
- 基本使用
- 参数说明

**推荐用时**: 10分钟

---

### 第二步: 脚本使用
📖 **[SCRIPTS_GUIDE.md](SCRIPTS_GUIDE.md)** - 所有脚本完整说明

**内容**:
- 脚本分类
- 使用示例
- 推荐工作流程
- 快速命令参考

**推荐用时**: 15分钟

---

### 第三步: 工作流程
📖 **[WORKFLOW.md](WORKFLOW.md)** - 完整系统流程图

**内容**:
- 系统架构流程
- 数据流
- API调用流程
- 时间估算
- 配置决策树

**推荐用时**: 20分钟

---

## 📚 核心技术文档

### 三层检测系统
📖 **[THREE_LAYER_README.md](THREE_LAYER_README.md)** - 三层层级检测

**内容**:
- 三层架构 (Major → Middle → CWE)
- 24+可训练prompt
- 训练策略
- 性能基准
- 评估指标

**适用**: 理解核心检测机制

---

### RAG增强
📖 **[RAG_README.md](RAG_README.md)** - 检索增强生成

**内容**:
- 知识库构建
- 相似度检索
- Prompt注入
- 性能提升 (+10-15%)
- 检索策略

**适用**: 提升检测准确性

---

### Multi-Agent训练
📖 **[MULTIAGENT_README.md](MULTIAGENT_README.md)** - 多智能体协同进化

**内容**:
- Detection Agent (GPT-4)
- Meta Agent (Claude 4.5)
- 协同优化
- 统计反馈
- 进化算法

**适用**: Prompt自动优化

---

### CWE分类体系
📖 **[CWE_CATEGORY_README.md](CWE_CATEGORY_README.md)** - CWE层级映射

**内容**:
- Major categories (6类)
- Middle categories (17类)
- CWE映射
- 类别分布

**适用**: 理解分类体系

---

### 评估指标指南
📖 **[METRICS_GUIDE.md](METRICS_GUIDE.md)** - Macro/Weighted/Micro F1详解

**内容**:
- 为什么使用Macro-F1
- 三种F1计算方式对比
- 类别不平衡问题
- 实际案例分析
- 论文报告建议

**适用**: 理解评估指标，撰写论文

---

## 🔧 高级文档

### 完整集成
📖 **[INTEGRATION_GUIDE.md](INTEGRATION_GUIDE.md)** - 系统集成指南

**内容**:
- 所有组件集成
- 完整使用场景
- 训练策略对比
- 数据准备
- API配置
- 性能基准

**适用**: 完整系统使用

---

### 故障排查
📖 **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)** - 问题解决

**内容**:
- 常见错误
- 调试方法
- 性能优化
- API问题

**适用**: 遇到问题时查阅

---

### 项目说明
📖 **[CLAUDE.md](CLAUDE.md)** - Claude开发笔记

**内容**:
- 项目概述
- 环境管理
- 核心功能
- 常用命令

**适用**: 开发者参考

---

## 📊 按使用场景查找

### 场景1: 我是新用户，想快速了解系统

**推荐阅读顺序**:
1. [QUICKSTART.md](QUICKSTART.md) - 快速开始
2. [SCRIPTS_GUIDE.md](SCRIPTS_GUIDE.md) - 脚本使用
3. 运行 `uv run python scripts/ablations/test_quick.py`

**预计时间**: 30分钟

---

### 场景2: 我想评估系统性能

**推荐阅读**:
1. [QUICKSTART.md](QUICKSTART.md) - 基本用法
2. [THREE_LAYER_README.md](THREE_LAYER_README.md) - 性能基准

**运行命令**:
```bash
# 基线
uv run python scripts/ablations/train_three_layer.py --eval-samples 50

# + RAG
uv run python scripts/ablations/train_three_layer.py --use-rag --eval-samples 50
```

**预计时间**: 1小时

---

### 场景3: 我想提升检测准确性

**推荐阅读**:
1. [RAG_README.md](RAG_README.md) - RAG增强
2. [THREE_LAYER_README.md](THREE_LAYER_README.md) - 三层检测

**运行命令**:
```bash
# RAG增强评估
uv run python scripts/ablations/train_three_layer.py \
    --use-rag \
    --kb-from-dataset \
    --kb-samples-per-category 5 \
    --eval-samples 100
```

**预期提升**: +10-15%

---

### 场景4: 我想训练优化prompt

**推荐阅读**:
1. [MULTIAGENT_README.md](MULTIAGENT_README.md) - Multi-agent训练
2. [INTEGRATION_GUIDE.md](INTEGRATION_GUIDE.md) - 训练策略

**运行命令**:
```bash
# 快速训练测试
uv run python scripts/ablations/train_three_layer.py \
    --train \
    --population-size 3 \
    --max-generations 5 \
    --eval-samples 30

# 完整训练
uv run python scripts/ablations/train_three_layer.py \
    --train \
    --use-rag \
    --kb-from-dataset \
    --population-size 5 \
    --max-generations 20 \
    --eval-samples 100
```

**预期提升**: +15-25%

---

### 场景5: 我想进行论文实验

**推荐阅读**:
1. [INTEGRATION_GUIDE.md](INTEGRATION_GUIDE.md) - 完整集成
2. [THREE_LAYER_README.md](THREE_LAYER_README.md) - 评估指标
3. [RAG_README.md](RAG_README.md) - RAG方法
4. [MULTIAGENT_README.md](MULTIAGENT_README.md) - 训练方法

**实验设计**:
```bash
# 对比实验组

# 1. 基线
uv run python scripts/ablations/train_three_layer.py \
    --eval-samples 100 \
    --output-dir outputs/exp1_baseline

# 2. + RAG
uv run python scripts/ablations/train_three_layer.py \
    --use-rag \
    --eval-samples 100 \
    --output-dir outputs/exp2_rag

# 3. + 训练
uv run python scripts/ablations/train_three_layer.py \
    --train \
    --max-generations 20 \
    --eval-samples 100 \
    --output-dir outputs/exp3_train

# 4. RAG + 训练 (最佳)
uv run python scripts/ablations/train_three_layer.py \
    --train \
    --use-rag \
    --kb-from-dataset \
    --max-generations 20 \
    --eval-samples 100 \
    --output-dir outputs/exp4_rag_train
```

**预计时间**: 数小时到一天

---

### 场景6: 遇到问题需要调试

**推荐阅读**:
1. [TROUBLESHOOTING.md](TROUBLESHOOTING.md) - 故障排查
2. [WORKFLOW.md](WORKFLOW.md) - 工作流程

**调试步骤**:
1. 运行快速测试确认问题
2. 查看错误日志
3. 参考故障排查文档
4. 减小规模复现问题

---

## 📖 文档速查表

| 文档 | 用途 | 阅读时间 | 优先级 |
|------|------|----------|--------|
| [QUICKSTART.md](QUICKSTART.md) | 快速上手 | 10分钟 | ⭐⭐⭐ |
| [SCRIPTS_GUIDE.md](SCRIPTS_GUIDE.md) | 脚本使用 | 15分钟 | ⭐⭐⭐ |
| [WORKFLOW.md](WORKFLOW.md) | 系统流程 | 20分钟 | ⭐⭐ |
| [THREE_LAYER_README.md](THREE_LAYER_README.md) | 三层检测 | 30分钟 | ⭐⭐⭐ |
| [RAG_README.md](RAG_README.md) | RAG增强 | 25分钟 | ⭐⭐ |
| [MULTIAGENT_README.md](MULTIAGENT_README.md) | Multi-agent | 30分钟 | ⭐⭐ |
| [INTEGRATION_GUIDE.md](INTEGRATION_GUIDE.md) | 完整集成 | 40分钟 | ⭐⭐ |
| [CWE_CATEGORY_README.md](CWE_CATEGORY_README.md) | CWE体系 | 15分钟 | ⭐ |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | 故障排查 | 按需 | ⭐ |
| [CLAUDE.md](CLAUDE.md) | 开发笔记 | 10分钟 | ⭐ |

## 🎯 推荐学习路径

### 路径1: 快速使用 (1小时)

```
QUICKSTART.md (10分钟)
    ↓
运行 test_quick.py (5分钟)
    ↓
SCRIPTS_GUIDE.md (15分钟)
    ↓
运行评估实验 (30分钟)
```

### 路径2: 深入理解 (2-3小时)

```
QUICKSTART.md (10分钟)
    ↓
THREE_LAYER_README.md (30分钟)
    ↓
RAG_README.md (25分钟)
    ↓
MULTIAGENT_README.md (30分钟)
    ↓
WORKFLOW.md (20分钟)
    ↓
运行完整实验 (1小时)
```

### 路径3: 论文研究 (1天)

```
所有核心文档阅读 (2-3小时)
    ↓
设计实验方案 (1小时)
    ↓
运行对比实验 (4-6小时)
    ↓
结果分析 (2小时)
    ↓
撰写论文 (按需)
```

## 🔗 快速链接

### 最常用文档
- [快速开始](QUICKSTART.md)
- [脚本指南](SCRIPTS_GUIDE.md)
- [三层检测](THREE_LAYER_README.md)

### 技术深入
- [RAG增强](RAG_README.md)
- [Multi-agent训练](MULTIAGENT_README.md)
- [完整集成](INTEGRATION_GUIDE.md)

### 参考文档
- [工作流程](WORKFLOW.md)
- [CWE分类](CWE_CATEGORY_README.md)
- [故障排查](TROUBLESHOOTING.md)

## 💡 提示

1. **新用户**: 从 `QUICKSTART.md` 开始
2. **想快速测试**: 运行 `test_quick.py`
3. **想评估性能**: 查看 `SCRIPTS_GUIDE.md`
4. **遇到问题**: 查阅 `TROUBLESHOOTING.md`
5. **论文实验**: 参考 `INTEGRATION_GUIDE.md`

## 📞 获取帮助

1. 查阅相关文档
2. 运行 `test_quick.py` 验证环境
3. 检查 `TROUBLESHOOTING.md`
4. 查看示例脚本输出

---

**最后更新**: 2025-01-22

**文档版本**: v2.0 (RAG + Multi-agent)
