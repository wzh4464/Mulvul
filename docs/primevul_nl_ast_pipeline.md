# PrimeVul Natural Language AST Pipeline

## 概述

本文档提供使用真正的 parserTool（非 adapter）生成 PrimeVul Natural Language AST 数据的完整 pipeline。

## 验证状态

✅ **已验证**: parserTool 集成成功
- parserTool 路径已修复为使用相对路径
- scripts/ablations/preprocess_primevul_comment4vul.py 已更新支持自动发现 parserTool
- 小样本测试通过（10 条，成功率 100%）
- NL AST 转换验证：注释成功嵌入到控制流语句中

### 示例验证

**原始代码**:
```c
return; // Shader didn't validate, don't move forward with compiling translated source
```

**Natural Language AST**:
```c
return (Shader didn't validate, don't move forward with compiling translated source) ;
```

## Pipeline 步骤

### 1. 生成 Natural Language AST 数据

无需设置 PYTHONPATH，脚本已自动配置路径。

#### 开发集（Dev Set）

```bash
uv run python scripts/ablations/preprocess_primevul_comment4vul.py \
  --primevul-path data/primevul/primevul/dev.jsonl \
  --output outputs/primevul_nl_ast/dev_nl_ast.jsonl
```

#### 训练集（Train Set）

```bash
uv run python scripts/ablations/preprocess_primevul_comment4vul.py \
  --primevul-path data/primevul/primevul/primevul_train.jsonl \
  --output outputs/primevul_nl_ast/train_nl_ast.jsonl
```

#### 测试集（Test Set）

```bash
uv run python scripts/ablations/preprocess_primevul_comment4vul.py \
  --primevul-path data/primevul/primevul/primevul_test.jsonl \
  --output outputs/primevul_nl_ast/test_nl_ast.jsonl
```

### 2. 组织数据目录

创建专用的 NL AST 数据目录：

```bash
mkdir -p data/primevul_nl_ast

# 链接或复制生成的文件
ln -s ../../outputs/primevul_nl_ast/dev_nl_ast.jsonl data/primevul_nl_ast/dev.jsonl
ln -s ../../outputs/primevul_nl_ast/train_nl_ast.jsonl data/primevul_nl_ast/primevul_train.jsonl
ln -s ../../outputs/primevul_nl_ast/test_nl_ast.jsonl data/primevul_nl_ast/primevul_test.jsonl
```

### 3. 在 EvoPrompt 中使用 NL AST

#### 方式 A: 直接指定 NL AST 数据路径

在你的配置文件或代码中：

```python
from evoprompt.data.dataset import PrimevulDataset

# 使用 NL AST 数据
dataset = PrimevulDataset(
    primevul_dir="./outputs/primevul_nl_ast",
    split="dev",  # 或 "train", "test"
)

# 访问 NL AST
for sample in dataset.samples:
    nl_ast = sample.metadata.get("nl_ast", "")  # Natural Language AST
    original = sample.input  # 原始代码
```

#### 方式 B: 使用采样器和 NL AST

对于训练集的均衡采样：

```python
from evoprompt.data.dataset import PrimevulDataset
from evoprompt.data.sampler import BalancedCWESampler

# 加载完整训练集（NL AST 版本）
full_dataset = PrimevulDataset(
    primevul_dir="./outputs/primevul_nl_ast",
    split="train",
)

# 均衡采样 1%
sampler = BalancedCWESampler(
    dataset=full_dataset,
    sample_percentage=0.01,
    min_samples_per_cwe=10,
    random_seed=42,
)

sampled_dataset = sampler.sample()
print(f"采样后样本数: {len(sampled_dataset)}")

# 使用采样数据
for sample in sampled_dataset.samples:
    nl_ast = sample.metadata["nl_ast"]  # 带注释嵌入的代码
```

#### 方式 C: 在 Prompt 中使用 NL AST

VulnerabilityDetectionEvaluator 已支持 `{nl_ast}` 占位符：

```python
initial_prompt = """
Analyze the following code for security vulnerabilities.

Code:
{input}

Natural Language AST (with embedded comments):
{nl_ast}

Does this code contain a vulnerability? Answer: Yes or No
"""

# Evaluator 会自动替换 {nl_ast} 为 sample.metadata["nl_ast"]
```

### 4. 验证 NL AST 质量

检查样本处理质量：

```bash
# 检查第一个样本
head -n 1 outputs/primevul_nl_ast/dev_nl_ast.jsonl | \
  uv run python -m json.tool | \
  grep -A 5 "natural_language_ast"

# 统计有注释的样本数量
uv run python << 'EOF'
import json

total = 0
with_comments = 0
nl_differs = 0

with open('outputs/primevul_nl_ast/dev_nl_ast.jsonl') as f:
    for line in f:
        d = json.loads(line)
        total += 1
        if '//' in d['func'] or '/*' in d['func']:
            with_comments += 1
        if d['func'] != d['natural_language_ast']:
            nl_differs += 1

print(f"总样本数: {total}")
print(f"包含注释: {with_comments} ({100*with_comments/total:.1f}%)")
print(f"NL AST 有变化: {nl_differs} ({100*nl_differs/total:.1f}%)")
EOF
```

## 输出格式

生成的 JSONL 文件每行包含以下字段：

```json
{
  "idx": 89023,
  "target": 0,
  "func": "原始函数代码",
  "choices": "处理后的代码（去除注释）",
  "clean_code": "清理后的代码",
  "natural_language_ast": "Natural Language AST (注释嵌入版本)",
  "cwe": ["CWE-119"],
  "project": "Chrome"
}
```

**关键字段说明**:
- `func`: PrimeVul 原始代码
- `natural_language_ast`: 使用 Comment4Vul 技术处理后的代码，注释被嵌入到控制流结构中
- `clean_code`: 移除所有注释的代码

## 性能预期

基于 10 样本测试：
- **处理速度**: ~23 samples/sec
- **成功率**: 100%
- **注释处理**: 行尾注释 → 嵌入到语句中

## 技术细节

### parserTool 集成

1. **路径配置**: scripts/ablations/preprocess_primevul_comment4vul.py:76-89
   - 自动添加 `comment4vul/parserTool` 和 `comment4vul/SymbolicRule` 到 sys.path
   - 优先使用真正的 parserTool，失败时回退到 adapter

2. **parserTool 修复**: comment4vul/parserTool/parserTool/parse.py:23-33
   - 使用相对路径而非硬编码绝对路径
   - 基于 `__file__` 动态定位 my-languages.so 和 tree-sitter-*

3. **支持的语言**: C, Java, Python (通过 tree-sitter)

### NL AST 处理逻辑

1. **注释移动**: 将行尾注释移到单独的行
2. **AST 解析**: 使用 tree-sitter 解析代码结构
3. **注释嵌入**: 将注释内容嵌入到相邻的控制流语句中
   - `if (x > 0) // check x` → `if ((check x)) {...}`
   - `return; // error` → `return (error);`

## 故障排查

### ImportError: parserTool not found

确保目录结构正确：
```
comment4vul/
├── parserTool/
│   └── parserTool/
│       ├── __init__.py
│       ├── parse.py
│       └── my-languages.so
└── SymbolicRule/
    └── process.py
```

### FileNotFoundError: tree-sitter-c/src/parser.c

说明 parse.py 仍使用旧的硬编码路径，需要使用修复后的版本（见上文 parse.py:23-33）。

### 处理速度慢

- 正常速度：10-30 samples/sec
- 如果明显更慢，可能是 tree-sitter 编译问题
- 检查 my-languages.so 是否存在且可访问

## 下一步

1. ✅ **已完成**: parserTool 集成和验证
2. ✅ **已完成**: 小样本测试通过
3. **待执行**: 运行全量数据集处理（train/dev/test）
4. **待执行**: 在 EvoPrompt 进化实验中使用 NL AST

## 文件位置参考

- **预处理脚本**: `scripts/ablations/preprocess_primevul_comment4vul.py`
- **parserTool**: `comment4vul/parserTool/parserTool/`
- **测试脚本**: `test_parser_integration.py` (可选)
- **输出目录**: `outputs/primevul_nl_ast/`
- **数据目录**: `data/primevul_nl_ast/` (链接)
