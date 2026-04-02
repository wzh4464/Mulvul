EvoPrompt Pipeline & Capabilities Overview

1. Core Capabilities
- Evolutionary prompt optimization for vulnerability detection tasks
- Support for multiple datasets: PrimeVul, SVEN-style vul_detection, generic benchmark JSON
- Evolution algorithms: Differential Evolution (DE), Genetic Algorithm (GA)
- LLM integration: SVEN-compatible HTTP client, OpenAI-compatible client, async/batch calls
- Static analysis integration via Bandit for Python (optional)
- Rich tracking: prompt_evolution logs, best_prompts, experiment_summary, per-sample / per-batch logs
- Checkpoint, retry, and recovery for long-running experiments

2. Data & Preprocessing Pipeline
- PrimeVul raw JSONL under `data/primevul/primevul/`
  - `PrimevulDataset` (src/evoprompt/data/dataset.py) loads JSONL or tab-separated files
  - Infers language (`lang`) from filename/heuristics, attaches CWE/CVE metadata
  - Optionally attaches NL AST / cleaned code from comment4vul outputs (via `nl_ast` metadata)
- Balanced sampling utilities (src/evoprompt/data/sampler.py)
  - `BalancedSampler.sample_primevul_balanced` for target / CWE major / layer1-balanced subsamples
  - `sample_primevul_1percent` helper: 1% balanced sample, train/dev split, saves JSONL + TSV
  - Sampling stats written to `sampling_stats.json` alongside generated train/dev files
- CWE taxonomy helpers (src/evoprompt/data/cwe_categories.py, cwe_layer1.py, cwe_research_concepts.py)
  - Map concrete CWE IDs to
    - Old major categories (for binary/major classification)
    - Layer-1 root categories used by `main.py` pipeline
    - Research concepts (10-class) for CWE concept experiments
- comment4vul integration (docs/IMPLEMENTATION_SUMMARY.md, scripts/ablations/preprocess_primevul_comment4vul.py)
  - Preprocess PrimeVul to add NL AST and comment-enhanced code (`natural_language_ast`, `choices`)
  - Outputs enriched JSONL that feeds back into `PrimevulDataset` via `nl_ast` metadata

3. LLM Client & Concurrency Pipeline
- SVEN-style HTTP client (src/evoprompt/llm/client.py)
  - `SVENLLMClient`: chat-completions over configurable API_BASE_URL / MODEL_NAME / API_KEY
  - Automatic .env loading (`load_env_vars`), primary + backup endpoints, retry with backoff
  - `generate` for single prompt, `batch_generate` for batched prompts with optional concurrency
  - `paraphrase` helper for prompt variation
- OpenAI-compatible client
  - `OpenAICompatibleClient`: uses `openai` Python SDK over arbitrary base_url/model
  - Same generate / batch_generate interface, with simple batching and (optional) concurrency
- Async helper (src/evoprompt/llm/async_client.py)
  - Utilities to run multiple LLM calls concurrently when needed
- High-level factory
  - `create_llm_client(llm_type=...)` used by workflows (supports "sven", "openai", etc.)

4. Core Evolution Pipeline (Library Layer)
- Datasets & Metrics
  - `Dataset` / `PrimevulDataset` / `BenchmarkDataset` / `TextClassificationDataset` in src/evoprompt/data/dataset.py
  - Metrics in src/evoprompt/metrics/base.py: Accuracy, F1, Precision, Recall, ROUGE, BLEU
- Evaluator (src/evoprompt/core/evaluator.py)
  - Formats prompts with `{input}` (and optionally `{nl_ast}` + static-analysis hints)
  - Optional static analysis enhancement:
    - `BanditAnalyzer` (src/evoprompt/analysis/bandit_analyzer.py) via `AnalysisCache`
    - Injects summary of static-analysis results into prompts when enabled
  - Evaluates prompts over dataset, logs filled prompt instances to file if configured
- Evolution algorithms (src/evoprompt/algorithms)
  - Base types in base.py: `Individual`, `Population`, `EvolutionAlgorithm`
  - `DifferentialEvolution` (differential.py)
    - Initializes population from initial prompts
    - Uses the LLM itself to perform DE-style mutation/crossover on prompt text
    - Tracks fitness history and returns best prompt + final population
  - `GeneticAlgorithm` (genetic.py)
    - Tournament selection, crossover, mutation over prompt strings
- Evolution engine (src/evoprompt/core/evolution.py)
  - `EvolutionEngine`: thin wrapper that wires `EvolutionAlgorithm`, `Evaluator`, `LLMClient`
  - Legacy APE/GA/DE wrappers for older SVEN-style code
- Prompt tracking (src/evoprompt/core/prompt_tracker.py)
  - `PromptTracker` records `PromptSnapshot` events to `prompt_evolution.jsonl`
  - Maintains best-per-generation and global best; writes `best_prompts.txt` & `experiment_summary.json`

5. Vulnerability Detection Workflows
- Generic vulnerability detection workflow (src/evoprompt/workflows/vulnerability_detection.py)
  - `VulnerabilityDetectionWorkflow` orchestrates end-to-end runs for PrimeVul/SVEN/benchmark data
  - Data preparation (`prepare_data`):
    - For dataset="primevul": converts JSONL to tab-separated dev/test via `prepare_primevul_data`
    - For others: uses existing dev/test files
  - Component creation (`create_components`):
    - LLM client via `create_llm_client`
    - Metric: `AccuracyMetric`
    - `VulnerabilityEvaluator` evaluator with prompt tracking and optional CWE-major mode
      - Binary vs CWE-major label mapping via `extract_vulnerability_label` / `extract_cwe_major`
      - Records all filled prompts into `filled_prompts.jsonl`
  - Evolution (`run_evolution`):
    - Builds `EvolutionEngine` with DE or GA
    - Runs evolution, logs via `PromptTracker`
    - Evaluates best prompt on test set and saves `test_results.json`
  - Convenience entry: `run_vulnerability_detection_workflow` helper

6. CWE Research Concepts Workflow
- CWE 10-class research concept pipeline (src/evoprompt/workflows/cwe_research_concepts.py)
  - `CWEConceptEvaluator`: maps CWE lists to concept IDs / names and parses model responses
  - `CWEConceptWorkflow`: mirrors VulnerabilityDetectionWorkflow but for 10-class labels
    - Saves filled prompts and evolution artifacts under `outputs/cwe_research_concepts/`
  - CLI entry: `scripts/ablations/run_cwe_evolution.py` (dataset-agnostic, dev/test file based)

7. PrimeVul-Specific Pipelines
- 1% PrimeVul evolution (scripts/ablations/run_primevul_1percent.py)
  - Checks SVEN-style API config from `.env`
  - Uses `sample_primevul_1percent` to build a balanced 1% subset (train/dev)
  - Instantiates `VulnerabilityDetectionWorkflow` with DE, custom initial prompts
  - Manually controls DE loop to log detailed steps and intermediate `generation_X_results.json`
  - Saves experiment config, initial_prompts, final results, and analysis summary
- High-concurrency + sample-wise feedback (scripts/ablations/run_primevul_concurrent_optimized.py)
  - Same 1% sampling but optimized for
    - `max_concurrency` (default 16)
    - Sample-level feedback and per-sample logging (`sample_feedback.jsonl`, `sample_statistics.json`)
  - Uses DE with customized evolution loop, including:
    - Shuffled training data
    - Feedback-driven prompt updates per misclassified sample
    - Detailed per-category and per-CWE analysis, confusion matrix, and statistics export
- Layered PrimeVul pipeline (PRIMEVUL_LAYERED_FLOW.md)
  - Layer 1: concurrent coarse-tuning via `run_primevul_concurrent_optimized.py`, outputs `top_prompts.txt`
  - Layer 2: refinement via `scripts/ablations/run_primevul_layer2.py` + `VulnerabilityDetectionWorkflow`
    - Takes Layer 1 top prompts as initial population
    - Runs lower-concurrency evolution without CWE-major constraint for fine-grained behavior
- Demo pipeline with mock LLM (scripts/ablations/demo_primevul_1percent.py)
  - Creates large synthetic PrimeVul-like dataset
  - Uses `MockLLMClient` (no real API) to exercise the full loop
  - Demonstrates tracking artifacts in `outputs/demo_primevul_1percent/`
- Main entry for Layer-1 CWE-major classification (main.py + README_MAIN.md)
  - Batch-based, checkpointed evolution over PrimeVul 1% sample
  - Uses `BatchAnalyzer` + `PromptEvolver` to evolve only the analysis guidance section of a structured prompt
  - Integrates
    - `CheckpointManager` / `BatchCheckpointer` / `ExperimentRecovery`
    - Robust retry logic via `RetryManager`
  - Outputs full classification reports, confusion matrix, batch_analyses.jsonl, final prompt, and checkpoints under `result/`

8. Benchmark & SVEN Pipelines
- Benchmark JSON tuning (scripts/ablations/run_benchmark_tuning.py)
  - Takes a benchmark JSON file (with vulnerability annotations)
  - Splits into dev/test, writes split JSON files
  - Runs `VulnerabilityDetectionWorkflow` with configurable DE/GA and LLM type
- SVEN-style usage
  - `data/vul_detection/` stores SVEN-processed datasets
  - `CONCURRENT_USAGE.md` documents how to run EvoPrompt with high-concurrency SVEN clients
  - Tests like `tests/test_batch_processing.py` illustrate direct use of `sven_llm_init` and `sven_llm_query`

9. Static Analysis & NL AST Integration
- Static analysis (src/evoprompt/analysis/)
  - `BanditAnalyzer` wraps Bandit CLI, maps test IDs to CWE IDs
  - `AnalysisCache` deduplicates analyses across runs
  - `AnalysisResult` / `Vulnerability` provide structured outputs and summaries
  - Evaluator can append static-analysis summaries into prompts when enabled
- comment4vul NL AST (docs/NL_AST_*.md, scripts/ablations/preprocess_primevul_comment4vul.py)
  - Uses comment4vul symbolic rules and Tree-sitter via `parsertool_adapter`
  - Produces NL AST strings stored in sample metadata as `nl_ast`
  - Evaluator can:
    - Inject `{nl_ast}` placeholder content directly
    - Or append a "Natural Language AST" section automatically when configured

10. Checkpoint, Retry, and Recovery Pipeline
- Checkpoint utilities (src/evoprompt/utils/checkpoint.py)
  - `CheckpointManager`: generation/batch-level state saving + dual JSON + pickle-backed full state
  - `BatchCheckpointer`: per-batch results with predictions, ground truths, batch analysis, prompt
  - `ExperimentRecovery`: detection and restoration of interrupted experiments, with recovery logs
  - `RetryManager` and `with_retry` decorator: generic retry with exponential backoff
- Checkpoint usage pattern (CHECKPOINT_GUIDE.md)
  - main.py Layer-1 pipeline is the reference implementation of these utilities

11. CLI & Utilities
- CLI entrypoint (src/evoprompt/cli.py)
  - Placeholder for future unified CLI (currently minimal)
- Utility helpers (src/evoprompt/utils)
  - `response_parsing.py`: shared label parsing (`extract_vulnerability_label`, `extract_cwe_major`)
  - `text.py`: `safe_format` and truncation helpers for prompts
  - `parsertool_adapter.py`: bridge to external comment4vul/parserTool stack

12. How to Choose a Pipeline
- For end-to-end PrimeVul CWE-major evolution with checkpoints and batch feedback:
  - Use `uv run python main.py` (see README_MAIN.md, CHECKPOINT_GUIDE.md, SAMPLE_FEEDBACK_GUIDE.md)
- For fast 1% PrimeVul experiments on real APIs:
  - Use `uv run python scripts/ablations/run_primevul_1percent.py`
- For high-concurrency + sample-wise feedback experiments:
  - Use `uv run python scripts/ablations/run_primevul_concurrent_optimized.py`
- For layered PrimeVul flows (coarse + fine tuning):
  - Follow PRIMEVUL_LAYERED_FLOW.md and combine `run_primevul_concurrent_optimized.py` with `run_primevul_layer2.py`
- For demo / offline experiments without real LLM:
  - Use `uv run python scripts/ablations/demo_primevul_1percent.py`
- For generic benchmark datasets with JSON annotations:
  - Use `uv run python scripts/ablations/run_benchmark_tuning.py data/benchmark.json`
- For CWE research-concepts experiments (10-class):
  - Use `uv run python scripts/ablations/run_cwe_evolution.py --dev_file ... --test_file ...`

