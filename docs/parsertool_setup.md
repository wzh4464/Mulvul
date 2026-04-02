# parserTool 配置指南

## 概述

parserTool 是 comment4vul 项目使用的 Tree-sitter AST 解析工具封装。本文档提供详细的配置步骤。

## 选项 1: 使用 comment4vul 提供的 parserTool (推荐)

### 步骤 1: 下载 Tree-sitter 预编译包

根据 comment4vul README,下载官方提供的 Tree-sitter 包:

```bash
# 下载链接(需要手动访问)
# https://drive.google.com/file/d/1JMQbWIgN6GRGRAXW7UdYzD7OVScBK-Fq/view
```

下载后解压到项目目录:
```bash
# 假设下载到 ~/Downloads/parserTool.zip
cd /Volumes/Mac_Ext/link_cache/codes/EvoPrompt
unzip ~/Downloads/parserTool.zip -d comment4vul/
```

### 步骤 2: 配置 Python 路径

将 parserTool 添加到 Python 路径:

```bash
# 方法 1: 环境变量 (临时)
export PYTHONPATH="${PYTHONPATH}:$(pwd)/comment4vul/parserTool"

# 方法 2: 符号链接 (永久)
ln -s $(pwd)/comment4vul/parserTool $(pwd)/parserTool

# 方法 3: 在脚本中添加 (推荐)
# 已在 scripts/ablations/preprocess_primevul_comment4vul.py 中实现
```

### 步骤 3: 验证安装

```bash
# 测试导入
uv run python -c "import sys; sys.path.insert(0, 'comment4vul'); import parserTool.parse as ps; print('✓ parserTool loaded successfully')"
```

## 选项 2: 使用 tree-sitter Python 包 (替代方案)

如果无法获取 comment4vul 的 parserTool,可以使用标准 tree-sitter 包:

### 步骤 1: 安装 tree-sitter

```bash
# 添加到 pyproject.toml
uv add tree-sitter tree-sitter-c tree-sitter-cpp

# 或直接安装
pip install tree-sitter tree-sitter-c tree-sitter-cpp
```

### 步骤 2: 创建 parserTool 适配器

我们提供了一个兼容层 `src/evoprompt/utils/parsertool_adapter.py`,可以使用标准 tree-sitter 包实现相同功能。

```python
# 使用适配器
from evoprompt.utils.parsertool_adapter import parse_c_code, Lang

code = "int main() { return 0; }"
ast = parse_c_code(code, Lang.C)
```

### 步骤 3: 构建语言库 (首次使用)

```python
# 运行一次即可
uv run python -c "from evoprompt.utils.parsertool_adapter import build_languages; build_languages()"
```

## 选项 3: 手动配置 Tree-sitter

### 步骤 1: 克隆语法仓库

```bash
mkdir -p vendor/tree-sitter
cd vendor/tree-sitter

# 克隆 C 和 C++ 语法
git clone https://github.com/tree-sitter/tree-sitter-c
git clone https://github.com/tree-sitter/tree-sitter-cpp
```

### 步骤 2: 构建 .so 文件

```bash
cd tree-sitter-c
gcc -shared -fPIC -o c.so src/parser.c -I src/
cd ../tree-sitter-cpp
g++ -shared -fPIC -o cpp.so src/parser.c src/scanner.cc -I src/
```

### 步骤 3: 使用自定义路径

```python
from tree_sitter import Language, Parser

Language.build_library(
    'build/languages.so',
    ['vendor/tree-sitter/tree-sitter-c', 'vendor/tree-sitter/tree-sitter-cpp']
)
```

## 测试配置

运行测试脚本验证配置:

```bash
# 测试 parserTool (选项 1)
uv run python scripts/test_parsertool_config.py --mode parsertool

# 测试 tree-sitter 适配器 (选项 2)
uv run python scripts/test_parsertool_config.py --mode adapter

# 测试预处理脚本
uv run python scripts/ablations/test_preprocess_basic.py
```

## 故障排查

### 问题 1: `ImportError: No module named 'parserTool'`

**解决方案**:
- 检查 parserTool 路径是否正确
- 确认 PYTHONPATH 包含 parserTool 目录
- 使用绝对路径而非相对路径

### 问题 2: `OSError: cannot load library`

**解决方案**:
- 确认 .so 文件权限正确: `chmod +x *.so`
- 检查系统架构匹配(x86_64 vs arm64)
- 重新编译 .so 文件

### 问题 3: Tree-sitter 解析失败

**解决方案**:
- 检查代码语法是否正确(可能包含预处理宏)
- 尝试移除宏定义: `#define`, `#ifdef` 等
- 使用 `gcc -E` 预处理代码

## 推荐配置

对于本项目,推荐使用 **选项 2 (tree-sitter Python 包 + 适配器)**:

优点:
- ✅ 不需要手动下载外部文件
- ✅ 通过 pip/uv 管理依赖
- ✅ 跨平台兼容性好
- ✅ 我们已提供适配器代码

步骤:
```bash
# 1. 安装依赖
uv add tree-sitter

# 2. 构建语言库 (一次性)
uv run python -c "from evoprompt.utils.parsertool_adapter import build_languages; build_languages()"

# 3. 测试
uv run python scripts/test_parsertool_config.py --mode adapter

# 4. 运行预处理
uv run python scripts/ablations/preprocess_primevul_comment4vul.py \
    --primevul-path data/primevul_1percent_sample/train_sample.jsonl \
    --output outputs/primevul_nl_ast/train_nl_ast.jsonl \
    --limit 10 \
    --use-adapter  # 使用适配器而非 parserTool
```

## 下一步

配置完成后,可以开始生成 NL AST:

```bash
# 生成完整数据集的 NL AST
bash scripts/generate_nl_ast_dataset.sh
```

详见: `docs/primevul_comment4vul_integration.md`
