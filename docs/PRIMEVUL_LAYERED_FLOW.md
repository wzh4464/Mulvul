# PrimeVul 分层并发运行链路

## 总览
该流程将 PrimeVul 漏洞检测的 Prompt 进化拆成两层：第一层利用高并发粗调生成高质量候选 Prompt，第二层在这些候选的基础上做精细复盘，从而缩短总耗时并提升结果稳定性。VS Code 的 `launch.json` 已预置两套调试入口，分别对应两个阶段。

## 分层流程

- **Layer 1 · 并发粗调**  
  入口：`PrimeVul Layer 1 · 并发粗调` 调试配置，或命令 `uv run python scripts/ablations/run_primevul_concurrent_optimized.py`。  
  关键动作：自动检查 `.env` 中的 API 配置，必要时重建 `data/primevul_1percent_sample/`，然后以 `max_concurrency=16`、样本级反馈等参数执行差分进化。  
  产物：`outputs/primevul_concurrent_feedback/<experiment_id>/top_prompts.txt`（后续层的初始 Prompt 库），以及完整的进化日志和样本记录。

- **Layer 2 · 精调复盘**  
  入口：`PrimeVul Layer 2 · 精调复盘` 调试配置，或命令 `uv run python scripts/ablations/run_primevul_layer2.py --top-prompts <path>`。  
  关键动作：脚本读取 Layer 1 的 `top_prompts.txt`，确保 1% 采样数据可用，构建一个并发度较低（默认 8）、禁用 CWE 大类约束的精调配置并执行 `VulnerabilityDetectionWorkflow`。  
  产物：`outputs/primevul_layer2/<experiment_id>/` 下的 `final_results.json`、`prompt_evolution.jsonl` 等，用于评估精调效果。

## 调试与排错节点

- 日志：Layer 1 输出到 `primevul_concurrent_evolution.log`，Layer 2 直接打印到终端，同时存档于实验目录。调试时可 `tail -f` 观测并发批次是否阻塞。  
- 参数调整：在 `scripts/ablations/run_primevul_concurrent_optimized.py` 或运行 Layer 2 时传入 `--max-concurrency`、`--population-size` 等参数，即可测试不同并发和进化设置。  
- 数据校验：Layer 2 脚本会自动再生 1% 样本；若路径错误，可通过 `--sample-dir` 与 `--primevul-dir` 重定向。  
- 配置覆盖：Layer 2 支持 `--config configs/override.json` 合并额外参数，但会强制保留 `initial_prompts_file` 等关键键，防止意外覆盖。

## 关键输入输出

- **输入**：`.env` 提供 API 认证；`data/primevul/primevul/` 为原始数据；Layer 2 需要 Layer 1 生成的 `top_prompts.txt`。  
- **中间产物**：`outputs/primevul_concurrent_feedback/` 与 `outputs/primevul_layer2/` 分别存储两层的实验目录。  
- **诊断文件**：`prompt_evolution.jsonl` 记录每次评估的样本结果，`sample_feedback.jsonl` 保存 Layer 1 的样本级反馈，可用于复现问题或对比改进；`experiment_config.json`、`final_results.json` 便于汇报与归档。
