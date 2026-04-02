# EvoPrompt Project - Claude Development Notes

## 项目概述

EvoPrompt是一个专注于漏洞检测的prompt进化优化框架，使用进化算法自动优化安全代码分析的prompt性能。项目已完成现代化重构，专注于SVEN和Primevul数据集支持。

## 环境管理

**重要**: 所有Python命令都使用`uv run`来执行，项目已配置好uv环境管理。

```bash
# 所有Python脚本都通过uv运行
uv run python script_name.py

# 示例
uv run python demo_primevul_1percent.py
uv run python sven_llm_client.py
```

## 项目结构

```
EvoPrompt/
├── src/evoprompt/           # 现代化包结构
│   ├── core/               # 核心模块
│   │   ├── evolution.py    # 进化算法引擎
│   │   └── prompt_tracker.py # Prompt追踪系统
│   ├── algorithms/         # 算法实现
│   │   ├── genetic.py      # 遗传算法
│   │   └── differential.py # 差分进化算法
│   ├── llm/               # LLM客户端
│   │   └── client.py      # SVEN兼容的LLM客户端
│   ├── data/              # 数据处理
│   │   ├── dataset.py     # 数据集处理
│   │   └── sampler.py     # 均衡采样器
│   └── evaluators/        # 评估器
│       └── vulnerability.py # 漏洞检测评估
├── data/                  # 数据文件
├── outputs/               # 实验输出
├── sven_llm_client.py    # SVEN风格LLM客户端
├── demo_primevul_1percent.py # 1%数据演示
└── pyproject.toml        # 现代化配置
```

## API配置

项目现在使用ModelScope API，通过`.env`文件管理配置：

```bash
# .env文件内容 - ModelScope配置
API_BASE_URL=https://api-inference.modelscope.cn/v1/
API_KEY=your-api-key-here
BACKUP_API_BASE_URL=https://newapi.aicohere.org/v1
MODEL_NAME=Qwen/Qwen3-Coder-480B-A35B-Instruct
```

### ModelScope集成优势
- ✅ OpenAI兼容API格式
- ✅ 支持Qwen大模型系列
- ✅ 更稳定的服务质量
- ✅ 代码生成专用模型

## SVEN LLM客户端集成

项目已实现与SVEN submodule一致的LLM API调用：

### API配置一致性
- ✅ 相同的环境变量名：`API_BASE_URL`, `API_KEY`, `BACKUP_API_BASE_URL`, `MODEL_NAME`
- ✅ 相同的默认值：主API使用`https://newapi.pockgo.com/v1`，备用API使用`https://newapi.aicohere.org/v1`
- ✅ 相同的模型配置：默认使用`kimi-k2-code`模型
- ✅ 相同的.env文件加载逻辑

### 调用接口一致性
```python
# SVEN风格的客户端初始化
client = sven_llm_init()

# SVEN风格的查询接口  
result = sven_llm_query(prompt, client, task=True, temperature=0.1)

# 批量查询支持
results = sven_llm_query([prompt1, prompt2], client, task=True)
```

### 功能特性对齐
- ✅ 主API失败自动切换到备用API
- ✅ 支持任务导向的响应截断（task=True时只取第一段）
- ✅ 批量处理和进度显示
- ✅ 错误处理和重试机制
- ✅ 速率限制和延时控制

## 核心功能

### 1. 漏洞检测专用
- ✅ SVEN数据集：9种CWE类型支持
- ✅ Primevul数据集：24,000+漏洞样本
- ✅ 均衡采样：智能处理不平衡数据集
- ✅ 代码安全分析：专门的提示词优化

### 2. 现代化架构
- ✅ src/包结构：现代Python包管理
- ✅ pyproject.toml：标准化配置
- ✅ uv包管理：高效依赖管理
- ✅ 类型提示：完整的类型支持

### 3. SVEN兼容性
- ✅ API调用一致性：与SVEN submodule完全兼容
- ✅ 环境变量加载：自动.env文件处理
- ✅ 主/备用API：自动故障切换
- ✅ 批量处理：高效的并发查询

## 常用命令

### 测试ModelScope集成
```bash
# 运行ModelScope集成演示
uv run python test_modelscope_demo.py

# 运行完整测试（需要绑定阿里云账户）
uv run python test_modelscope.py
```

### 运行1%数据演示
```bash
uv run python demo_primevul_1percent.py
```

### 测试采样功能
```bash
uv run python test_primevul_1percent.py
```

### 运行完整进化实验
```bash
# 现在使用SVEN风格的API配置，从.env文件自动加载
uv run python run_primevul_1percent.py
```

### 环境变量配置验证
脚本会自动检查SVEN风格的API配置：
```
✅ SVEN风格API配置检查通过:
   API_BASE_URL: https://newapi.pockgo.com/v1
   MODEL_NAME: kimi-k2-code
   API_KEY: sk-dqKjXVx...
```

## 开发和测试

### Lint和类型检查
```bash
# 需要确认项目具体使用的工具
uv run ruff check src/
uv run mypy src/
```

### 运行测试
```bash
uv run pytest tests/
```

## 文件生成位置

实验结果默认保存在`outputs/`目录：
```
outputs/demo_primevul_1percent/demo_primevul_1pct_20250729_HHMMSS/
├── experiment_summary.json      # 实验总结
├── prompt_evolution.jsonl       # 完整进化记录
├── best_prompts.txt            # 最佳prompt历史
├── top_prompts.txt             # 适应度排行榜
└── llm_call_history.json       # LLM调用历史
```

## 关键特性

1. **现代化架构**: 使用pyproject.toml和src/包结构
2. **SVEN兼容**: 与submodule sven保持一致的API调用方式
3. **完整追踪**: 详细记录每次prompt更新过程
4. **均衡采样**: 智能处理数据不平衡问题
5. **多格式支持**: JSONL、Tab、JSON多种输出格式

## 扩展性

- 支持多种数据集(Primevul、SVEN、自定义)
- 支持多种进化算法(DE、GA、可扩展)
- 支持多种评估指标(准确率、F1分数、自定义)

## 注意事项

1. **必须使用`uv run`**: 所有Python命令都通过uv执行
2. **API密钥安全**: 确保.env文件不被提交到版本控制
3. **环境配置**: 项目已配置好uv环境，直接使用即可
4. **兼容性**: 保持与原EvoPrompt接口的向后兼容

在开发阶段，尽量少写 try/except，让异常直接抛出来，你能从 traceback 里快速定位。
只有在你需要做 容错处理 或 对用户友好提示 的地方，再加上 try/except。
