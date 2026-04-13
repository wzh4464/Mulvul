# Constrained Mutation 与 Elitism 机制详解

本文档详细介绍 Mulvul 协同进化训练器中的两个核心演化保护机制：**Constrained Mutation（约束变异）** 和 **Elitism（精英保护）**。

## 目录

- [背景与动机](#背景与动机)
- [Constrained Mutation（约束变异）](#constrained-mutation约束变异)
  - [问题描述](#问题描述)
  - [解决方案](#解决方案)
  - [实现细节](#实现细节)
  - [使用示例](#使用示例)
- [Elitism（精英保护）](#elitism精英保护)
  - [问题描述](#问题描述-1)
  - [解决方案](#解决方案-1)
  - [实现细节](#实现细节-1)
  - [使用示例](#使用示例-1)
- [配置参数](#配置参数)
- [效果分析](#效果分析)

---

## 背景与动机

在 Mulvul 的协同进化框架中，每个分类节点（Major/Middle/CWE）维护一个 prompt 种群。每一代进化包含四个阶段：

1. **Tournament**：局部评估 + 锦标赛选择
2. **Cascade Evaluation**：组装最优 prompt 进行端到端检测
3. **Fitness Propagation**：将级联准确率反馈给各节点
4. **Evolution**：变异、交叉、迁移

在 v0.2.0 baseline 实验中发现了关键问题：

| 指标 | 数值 |
|------|------|
| 被 meta-LLM 重写的节点 | 3 / 64 |
| 重写后 prompt 平均 F1 | 0.306 |
| 原始 seed prompt 平均 F1 | 0.437 |

**结论**：无约束的 meta-LLM 变异策略**弊大于利**——它更多是在破坏而非改进 prompt。

---

## Constrained Mutation（约束变异）

### 问题描述

早期的变异策略允许 meta-LLM 完全重写整个 prompt，导致：

1. **格式破坏**：删除了 `{code}`、`{evidence}` 等必需的占位符
2. **结构丢失**：JSON 输出格式说明被意外删除
3. **候选项移除**：meta-LLM 可能删除或重命名分类候选项
4. **过度改写**：简单的添加任务变成了全面重构

### 解决方案

将 prompt 分为两个区域：

```
┌─────────────────────────────────────┐
│   MUTABLE HEADER (可变区域)          │
│   - 角色描述                         │
│   - 候选项列表                       │
│   - 决策规则                         │
│   - 推理提示                         │
├─────────────────────────────────────┤  ← Split Point (## Evidence)
│   PROTECTED FOOTER (保护区域)        │
│   - {evidence} 占位符                │
│   - {code} 占位符                    │
│   - JSON 输出格式说明                │
│   - ranking_v2 结构要求              │
└─────────────────────────────────────┘
```

变异和交叉操作**只修改可变区域**，保护区域保持不变。

### 实现细节

#### 1. Prompt 分割

文件：`src/mulvul/agents/coevolutionary_trainer.py`

```python
_SPLIT_RE = re.compile(r"(?i)(^|\n)(##\s*evidence\b|\{evidence\})")

def _split_prompt(self, prompt: str) -> Tuple[str, str]:
    """Split prompt into (mutable_header, protected_footer).
    
    The split point is a heading or placeholder containing 'evidence'.
    Uses case-insensitive regex so the split survives template changes
    (e.g., ``## Evidence:``, ``## evidence``, ``{evidence}``).
    """
    match = _SPLIT_RE.search(prompt)
    if match and match.start() > 0:
        idx = match.start()
        return prompt[:idx], prompt[idx:]
    # Fallback: can't find split point, protect everything
    return "", prompt
```

**关键设计**：
- 使用大小写不敏感的正则匹配
- 支持多种分割标记：`## Evidence:`、`## evidence`、`{evidence}`
- 找不到分割点时，**保护整个 prompt**，不进行任何变异

#### 2. 约束变异请求

```python
def _mutate_prompt(self, prompt: str, errors: List[Dict], node_key: str) -> str:
    if getattr(self, "_constrained_mutation", True):
        # 只提取可变区域
        mutable, protected = self._split_prompt(prompt)
        if not mutable:
            return prompt  # 无法分割，跳过变异
        
        mutation_request = (
            f"Improve this vulnerability detection instruction for node '{node_key}'.\n\n"
            f"--- CURRENT INSTRUCTION ---\n{mutable.strip()}\n"
            f"--- END INSTRUCTION ---\n\n"
            f"Cascade errors attributed to this node:\n{error_summary}\n\n"
            "You may:\n"
            "- Add decision boundaries between candidates\n"
            "- Add brief descriptions after candidate names\n"
            "- Refine the role description or task framing\n"
            "- Add reasoning hints based on error patterns\n\n"
            "You must NOT:\n"
            "- Remove any candidate from the list\n"
            "- Add {code}, {evidence}, or JSON format — those are handled separately\n\n"
            "Return ONLY the improved instruction text, nothing else."
        )
        
        result = self.meta_llm.generate(mutation_request)
        return self._reassemble(result, protected)  # 重新组装
```

**约束规则**：
- ✅ 可以添加候选项之间的决策边界
- ✅ 可以添加候选项的简短描述
- ✅ 可以改进角色描述和任务框架
- ❌ 不能移除候选项
- ❌ 不能添加 `{code}`、`{evidence}` 或 JSON 格式

#### 3. 约束交叉

```python
def _crossover_prompts(self, prompt_a: str, prompt_b: str, node_key: str) -> str:
    if getattr(self, "_constrained_mutation", True):
        mutable_a, protected_a = self._split_prompt(prompt_a)
        mutable_b, _ = self._split_prompt(prompt_b)
        
        # 只合并可变区域，保留 prompt_a 的保护区域
        crossover_request = (
            f"Merge the strengths of these two instructions for node '{node_key}'.\n\n"
            f"--- INSTRUCTION A ---\n{mutable_a.strip()}\n"
            f"--- INSTRUCTION B ---\n{mutable_b.strip()}\n"
            f"--- END ---\n\n"
            "Create a single improved instruction combining the best elements.\n"
            "Do NOT include {code}, {evidence}, or JSON output format.\n"
            "Return ONLY the merged instruction text."
        )
        
        result = self.meta_llm.generate(crossover_request)
        return self._reassemble(result, protected_a)
```

#### 4. 重新组装

```python
@staticmethod
def _reassemble(mutable: str, protected: str) -> str:
    """Join mutable header and protected footer with normalized spacing."""
    return mutable.rstrip() + "\n\n" + protected.lstrip()
```

### 使用示例

```python
trainer.train_all_levels(
    n_rounds=5,
    constrained_mutation=True,   # 启用约束变异（默认值）
)

# 禁用约束变异（允许完全重写）
trainer.train_all_levels(
    n_rounds=5,
    constrained_mutation=False,  # 无约束变异
)
```

---

## Elitism（精英保护）

### 问题描述

即使使用约束变异，表现优秀的 prompt 仍可能被变异操作退化：

- 已达到 F1=0.8 的节点可能因变异降至 F1=0.6
- 进化探索可能破坏已经收敛的好解
- 计算资源浪费在改进已经足够好的 prompt 上

### 解决方案

引入精英保护阈值：**当节点的最佳 prompt 达到指定 F1 阈值时，跳过该节点的所有变异和交叉操作**。

```
Node F1 >= threshold  →  SKIP mutation/crossover
Node F1 <  threshold  →  APPLY mutation/crossover
```

### 实现细节

文件：`src/mulvul/agents/coevolutionary_trainer.py`

```python
def _phase4_evolve(
    self,
    errors: List[Dict[str, Any]],
    gen: int,
    migration_rate: float,
    elitism_threshold: float = 0.5,  # 默认阈值
) -> None:
    """Mutate, crossover, and optionally migrate prompts.
    
    Nodes whose best individual exceeds *elitism_threshold* are
    protected from mutation and crossover to avoid degrading
    already-effective prompts.
    """
    
    for key, pop in self.populations.items():
        if pop.size < 2:
            continue
        
        best_f1 = pop.best().node_fitness
        
        # 精英保护检查
        if best_f1 >= elitism_threshold:
            self.log.emit("elitism_skip", {
                "node": key,
                "generation": gen,
                "best_f1": round(best_f1, 4),
                "threshold": elitism_threshold,
            })
            continue  # 跳过变异和交叉
        
        # 正常进化操作
        worst = pop.worst()
        mutated_prompt = self._mutate_prompt(worst.prompt, node_errors, key)
        worst.prompt = mutated_prompt
        # ... crossover 等操作
```

**关键行为**：

1. 检查节点最佳个体的 `node_fitness`（F1 分数）
2. 如果 >= 阈值，记录 `elitism_skip` 事件并跳过
3. 该节点的种群保持不变，等待下一轮评估
4. 迁移操作不受精英保护影响

### 使用示例

```python
# 默认配置：F1 >= 0.5 的节点受保护
trainer.train_all_levels(
    n_rounds=5,
    elitism_threshold=0.5,
)

# 更严格的保护：只保护 F1 >= 0.7 的节点
trainer.train_all_levels(
    n_rounds=5,
    elitism_threshold=0.7,
)

# 禁用精英保护（设为不可达值）
trainer.train_all_levels(
    n_rounds=5,
    elitism_threshold=1.1,  # 没有节点能达到 1.1
)
```

---

## 配置参数

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `constrained_mutation` | `bool` | `True` | 启用约束变异，只修改 prompt 的可变区域 |
| `elitism_threshold` | `float` | `0.5` | 精英保护阈值，F1 >= 此值的节点跳过变异 |

### 推荐配置

| 场景 | `constrained_mutation` | `elitism_threshold` |
|------|------------------------|---------------------|
| 生产训练 | `True` | `0.5` |
| 探索性实验 | `True` | `0.7` |
| 消融实验（无约束） | `False` | `1.1` |
| 激进探索 | `True` | `1.1` |

---

## 效果分析

### Constrained Mutation 效果

来自 baseline-results-v0.2.0 的有效进化案例：

| 节点 | 进化前 F1 | 进化后 F1 | 提升 |
|------|----------|----------|------|
| CWE-189 | 0.162 | 0.490 | +0.328 |
| middle_Path Traversal | - | - | +0.200 |
| middle_Buffer Errors | - | - | +0.160 |

**有效变异的共同特征**：
- 添加 CWE 语义描述：`CWE-189: Numeric Errors — general numeric calculation problems`
- 添加显式决策边界：`Choose CWE-190 only for clear integer overflow/wraparound`
- 使用格式强调：粗体、项目符号

### Elitism 效果

假设 `elitism_threshold=0.5`：

| 节点 | 最佳 F1 | 状态 |
|------|--------|------|
| cwe_CWE-617 | 0.829 | ✅ 受保护 |
| major_Crypto | 0.815 | ✅ 受保护 |
| middle_Buffer Errors | 0.806 | ✅ 受保护 |
| cwe_CWE-330 | 0.136 | ⚙️ 正常进化 |
| cwe_CWE-327 | 0.136 | ⚙️ 正常进化 |

**效果**：
- 防止 Top 10 节点被意外退化
- 让进化资源集中在需要改进的 Bottom 节点
- 减少无意义的计算开销

---

## 日志与监控

进化过程中会记录以下相关事件：

```jsonl
{"event": "elitism_skip", "data": {"node": "cwe_CWE-617", "generation": 2, "best_f1": 0.829, "threshold": 0.5}}
{"event": "elitism_skip", "data": {"node": "major_Crypto", "generation": 2, "best_f1": 0.815, "threshold": 0.5}}
```

可通过 `evolution.jsonl` 日志监控精英保护触发频率和受保护节点列表。

---

## 相关代码位置

| 功能 | 文件 | 行号 |
|------|------|------|
| 主入口 `train_all_levels` | `src/mulvul/agents/coevolutionary_trainer.py` | 173-294 |
| 精英保护检查 | `src/mulvul/agents/coevolutionary_trainer.py` | 840-851 |
| Prompt 分割 | `src/mulvul/agents/coevolutionary_trainer.py` | 892-905 |
| 约束变异 | `src/mulvul/agents/coevolutionary_trainer.py` | 911-980 |
| 约束交叉 | `src/mulvul/agents/coevolutionary_trainer.py` | 982-1032 |
| 跨阶段迁移 | `src/mulvul/agents/coevolutionary_trainer.py` | 1034-1080 |

---

## 未来改进方向

1. **Evolution Memory**：记录历史变异效果，让 meta-LLM 参考成功/失败经验
2. **Adaptive Elitism**：动态调整阈值，根据种群多样性自适应
3. **Semantic Constraints**：在变异请求中嵌入候选项语义信息，提高变异质量
