# PrimeVul + comment4vul 集成指南

## 概述

本文档说明如何使用 comment4vul 的 Natural Language AST (NL AST) 技术处理 PrimeVul 漏洞检测数据集。

## 背景

**comment4vul** 是一个基于符号注释树(Symbolic Comment Tree, SCT)的漏洞检测框架。其核心创新是:

1. **Comment Generation**: 使用 LLM 为代码生成自然语言注释
2. **Symbolic Comment Tree**: 将注释插入 AST 结构中
3. **Natural Language AST**: 移除注释语法,保留自然语言内容,形成增强的代码表示

**PrimeVul** 是一个大规模 C/C++ 漏洞函数数据集,包含 24,000+ 真实漏洞样本。

## 数据格式

### PrimeVul 原始格式

```json
{
    "idx": 210536,
    "target": 1,
    "func": "static int vt_disallocate(...) {...}",
    "project": "linux",
    "cwe": ["CWE-416"],
    "cve": "CVE-2020-36557",
    ...
}
```

### comment4vul 输入格式

```json
{
    "idx": 210536,
    "target": 1,
    "func": "static int vt_disallocate(...) {...}",
    "choices": "// 注释内容\nstatic int vt_disallocate(...) {...}"
}
```

### comment4vul 输出格式 (含 NL AST)

```json
{
    "idx": 210536,
    "target": 1,
    "func": "原始函数代码",
    "choices": "带注释的代码",
    "clean_code": "Natural Language AST 表示",
    "natural_language_ast": "Natural Language AST 表示"
}
```

## 处理流程

### 1. Comment4vul NL AST 生成原理

comment4vul 通过以下步骤生成 NL AST:

```python
# 步骤 1: 移动内联注释到独立行
code = move_comments_to_new_line(code_with_comments)

# 步骤 2: 使用 Tree-sitter 解析 AST
ast = tree_sitter_ast(code, Lang.C)

# 步骤 3: 遍历 AST,将注释插入控制流语句
updated_code = print_ast_node(code, ast.root_node)
# 例如: if (condition) { ... }
# 前面有注释 "// check validity"
# 转换为: if (check validity) { ... }

# 步骤 4: 移除注释语法
clean_code = remove_comments(updated_code)
```

**支持的语句类型**:
- `if_statement`, `for_statement`, `while_statement`
- `switch_statement`, `case`
- `return_statement`, `break_statement`, `continue_statement`, `goto_statement`
- `else`

### 2. 依赖项

#### Tree-sitter

comment4vul 使用 Tree-sitter 进行 AST 解析。需要:

1. **Tree-sitter Python 绑定**:
   ```bash
   pip install tree-sitter
   ```

2. **parserTool 模块**:
   comment4vul 使用自定义的 `parserTool` 模块封装 Tree-sitter。

   根据 comment4vul README,需要下载预编译版本:
   - 下载链接: https://drive.google.com/file/d/1JMQbWIgN6GRGRAXW7UdYzD7OVScBK-Fq/view

3. **安装步骤**:
   ```bash
   # 下载 Tree-sitter 包后解压到项目目录
   # 确保 parserTool 模块在 Python 路径中
   export PYTHONPATH="${PYTHONPATH}:/path/to/parserTool"
   ```

## 使用预处理脚本

### 基本用法

```bash
# 处理 10 个样本进行测试
uv run python scripts/ablations/preprocess_primevul_comment4vul.py \
    --primevul-path data/primevul_1percent_sample/train_sample.jsonl \
    --output outputs/primevul_nl_ast/train_nl_ast.jsonl \
    --limit 10
```

### 完整数据集处理

```bash
# 处理训练集
uv run python scripts/ablations/preprocess_primevul_comment4vul.py \
    --primevul-path data/primevul/primevul/primevul_train.jsonl \
    --output outputs/primevul_nl_ast/train_nl_ast.jsonl

# 处理验证集
uv run python scripts/ablations/preprocess_primevul_comment4vul.py \
    --primevul-path data/primevul/primevul/primevul_valid.jsonl \
    --output outputs/primevul_nl_ast/valid_nl_ast.jsonl

# 处理测试集
uv run python scripts/ablations/preprocess_primevul_comment4vul.py \
    --primevul-path data/primevul/primevul/primevul_test.jsonl \
    --output outputs/primevul_nl_ast/test_nl_ast.jsonl
```

### 断点续跑

```bash
# 从索引 100 继续处理
uv run python scripts/ablations/preprocess_primevul_comment4vul.py \
    --primevul-path data/primevul_1percent_sample/train_sample.jsonl \
    --output outputs/primevul_nl_ast/train_nl_ast.jsonl \
    --start-idx 100
```

### 命令行参数

- `--primevul-path`: 输入 PrimeVul JSONL 文件路径 (必需)
- `--output`: 输出 JSONL 文件路径 (必需)
- `--limit`: 限制处理样本数量 (用于测试)
- `--start-idx`: 起始索引 (用于断点续跑)
- `--use-llm-comments`: 使用 LLM 生成注释 (暂未实现)
- `--comment4vul-root`: comment4vul 子模块根目录路径

## 输出说明

### 输出字段

生成的 JSONL 文件包含以下字段:

- `idx`: 样本索引 (继承自 PrimeVul)
- `target`: 标签 (0=正常, 1=漏洞)
- `func`: 原始函数代码
- `choices`: 用于 comment4vul 处理的代码版本
- `clean_code`: Natural Language AST 表示
- `natural_language_ast`: `clean_code` 的别名,便于理解
- `cwe`: CWE 类型列表 (如果原始数据包含)
- `project`: 项目名称 (如果原始数据包含)

### NL AST 示例

**原始代码** (`func`):
```c
static int vt_disallocate(unsigned int vc_num)
{
    if (vt_busy(vc_num))
        ret = -EBUSY;
    else if (vc_num)
        vc = vc_deallocate(vc_num);

    return ret;
}
```

**带注释版本** (`choices`):
```c
// Check if virtual console is busy
static int vt_disallocate(unsigned int vc_num)
{
    // Check busy status
    if (vt_busy(vc_num))
        ret = -EBUSY;
    // Validate vc_num is non-zero
    else if (vc_num)
        vc = vc_deallocate(vc_num);

    return ret;
}
```

**Natural Language AST** (`clean_code`):
```c
static int vt_disallocate(unsigned int vc_num)
{
    if (Check busy status)
        ret = -EBUSY;
    else if (Validate vc_num is non-zero)
        vc = vc_deallocate(vc_num);

    return ret;
}
```

## 下一步工作

### 短期 (已实现)
- ✅ 梳理 comment4vul NL AST 生成流程
- ✅ 确认 PrimeVul 数据格式映射
- ✅ 实现预处理脚本框架

### 中期 (待实现)
- ⏳ 配置 parserTool 依赖
- ⏳ 在小样本上测试脚本
- ⏳ 集成 LLM 注释生成

### 长期
- 在 EvoPrompt 框架中使用 NL AST 表示
- 评估 NL AST 对漏洞检测性能的提升
- 优化注释生成 prompt

## 问题排查

### parserTool 导入失败

**症状**:
```
ImportError: No module named 'parserTool'
```

**解决方案**:
1. 确认已下载 Tree-sitter 和 parserTool
2. 将 parserTool 添加到 Python 路径:
   ```bash
   export PYTHONPATH="${PYTHONPATH}:/path/to/parserTool"
   ```
3. 或将 parserTool 复制到项目目录

### Tree-sitter 解析失败

**症状**:
```
Tree-sitter parsing error
```

**解决方案**:
1. 检查代码语法是否正确
2. 确认 Tree-sitter C/C++ 语法文件已安装
3. 对于特殊语法,可能需要预处理代码

## 参考资料

- comment4vul 论文: SCALE - Symbolic Comment Trees for Vulnerability Detection
- comment4vul GitHub: (检查 comment4vul 子模块 README)
- PrimeVul 数据集: 项目内 `data/primevul/`
- Tree-sitter 文档: https://tree-sitter.github.io/tree-sitter/
