# EvoPrompt 架构级优化计划（面向更好 Prompt 模板）

## 目标
1. 以“更好的 prompt 模板”为主线，完成结构化、可进化、可复现的模板体系。
2. 统一检测与训练主流程，减少分叉实现与隐性不一致。
3. 保证每一步均有明确测试门槛，通过后才进入下一步。

## 约束与原则
1. 任何重构不得破坏现有功能入口（保留兼容层）。
2. 所有 prompt 模板必须显式保留 `{input}` 等占位符与输出约束。
3. 模板必须可序列化、可版本化、可回放。
4. 训练/评测必须可重复，禁止依赖非确定性行为作为单点证据。
5. 任何改动都要以“提示词质量提升”为主要收益衡量。

## 优先级与步骤（含测试门槛）

### 1. 基线与提示词质量护栏（P0）
**目的**：建立模板质量与评测基线，防止后续重构造成提示词退化。  
**主要工作**：
1. 新增 Prompt Contract 校验器，强制要求：
1. 必须包含 `{input}` 或明确指定的输入占位符。
1. 输出格式约束完整且可解析。
1. 可训练段与固定段边界清晰。
2. 建立小规模、确定性的评测基准（如固定 50 条样本）。
3. 在结果目录保存基线指标快照与模板版本。

**测试门槛**：  
`uv run pytest tests/test_response_parsing.py tests/test_prompt_truncation.py tests/test_evaluator.py`

**注意点**：
1. 不引入网络依赖或真实 API 调用作为测试的一部分。
2. 基线评测必须可重复，且与数据切片绑定。

---

### 2. 统一 Prompt Template 架构（P0）
**目的**：让“提示词模板”成为第一类对象，支持演化与复用。  
**主要工作**：
1. 引入 `PromptTemplate` 与 `PromptSet`，包含：
1. 固定结构段。
1. 可训练段。
1. 输出约束段。
2. 将 `StructuredPromptBuilder` 与层级 prompts 迁移到统一模板。
3. 加入模板序列化、版本号与元数据。

**测试门槛**：  
`uv run pytest tests/test_algorithms.py tests/test_prompt_truncation.py`

**注意点**：
1. 保持现有 prompt 文本含义不变，优先结构化而非内容替换。
2. 模板版本变更需要明确变更原因与兼容策略。

---

### 3. 统一检测流水线（P1）
**目的**：消除 `ThreeLayerDetector`、`RAGThreeLayerDetector`、`ParallelHierarchicalDetector` 的重复实现。  
**主要工作**：
1. 建立 `DetectionPipeline`：
1. Enhancement → Retrieval → Prompt Build → LLM → Parse → Path Selection。
2. 让 RAG 作为可插拔 PromptAugmentor，而非独立 detector。
3. 让并行能力作为执行策略（同步/并发），而非独立逻辑。

**测试门槛**：  
`uv run pytest tests/test_parallel_detector.py tests/test_batch_processing.py`

**注意点**：
1. 不改变现有三层分类逻辑与类别映射。
2. 仅在执行层解耦并发，不改动语义层。

---

### 4. 统一 LLM Runtime（P1）
**目的**：统一同步/异步调用、并发、重试与缓存，并保证测试稳定。  
**主要工作**：
1. 构建 `LLMRuntime` 服务，统一：
1. 同步/异步调用。
1. 限速、重试、超时策略。
1. 可选响应缓存（提升重复实验可复现性）。
2. 引入 deterministic stub client，测试无需真实请求。

**测试门槛**：  
`uv run pytest tests/test_concurrent_batch.py tests/test_concurrent_default.py tests/test_concurrent_fix.py`

**注意点**：
1. 缓存必须包含 prompt + 参数 hash。
2. 禁止测试依赖真实网络和 API key。

---

### 5. 多层训练演化（P1）
**目的**：从仅优化 Layer1 扩展到三层协同优化。  
**主要工作**：
1. Coevolution 支持多层 prompt 集合优化。
2. 引入分层 fitness 与错误统计反馈。
3. 与模板系统深度集成：只修改可训练段。

**测试门槛**：  
`uv run pytest tests/test_multiagent_components.py tests/test_batch_optimization.py`

**注意点**：
1. 训练策略不应改变输出格式要求。
2. 多层 fitness 的聚合公式必须可解释、可记录。

---

### 6. 实验与产物管理统一（P2）
**目的**：统一输出结构，方便对比 prompt 演化效果。  
**主要工作**：
1. 建立 `Run/Experiment` 管理器：
1. 配置统一存档。
1. Checkpoint 统一存档。
1. Prompt/metrics 统一存档。
2. 让 scripts 与 workflows 使用同一管理器。

**测试门槛**：  
`uv run pytest tests/test_batch_script_run.py tests/test_static_analysis.py`

**注意点**：
1. 历史输出结构保持兼容。
2. 新输出不覆盖旧结果，默认新目录。

---

### 7. 文档与迁移（P2）
**目的**：保证新结构可被理解与复用。  
**主要工作**：
1. 更新 `docs/` 中的流程说明与使用指南。
2. 增加“迁移指南”和“模板版本说明”。
3. 保留兼容入口但明确弃用计划。

**测试门槛**：  
`uv run pytest -m "not slow"`

**注意点**：
1. 文档示例与实际命令保持一致。
2. 明确新旧入口的适用范围。

## 风险与缓解
1. **Prompt 结构变化导致性能下降**  
缓解：建立基线快照与回归测试，所有改动必须对比基线。
2. **统一检测流程引入回归**  
缓解：将 RAG/Parallel 的逻辑保留为策略层，先功能等价再逐步优化。
3. **训练阶段不稳定**  
缓解：引入 stub LLM 与固定切片，保证训练逻辑可回放。

## 验收标准
1. Prompt 模板统一且可版本化。
2. 检测流程单一化，RAG/Parallel 只作为策略差异存在。
3. 三层 prompt 可同时优化并被统计反馈驱动。
4. 所有步骤测试通过，且基线指标不下降或有明确提升。

