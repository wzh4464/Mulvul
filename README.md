# Mulvul: Two-Line Prompt Evolution for Vulnerability Detection

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Mulvul is organized around two first-class workflows:

1. Evolve the best prompt for each router/detector stage.
2. Freeze that prompt bundle and evaluate end-to-end vulnerability detection.

Other ideas such as RAG, parallel scoring, top-k routing, and alternative
detectors should be treated as ablations layered on top of this baseline.

Minimal repository docs live in:

- `docs/README.md`
- `docs/MAINLINE_ARCHITECTURE.md`
- `docs/ABLATIONS.md`

## 🎯 Focus Areas

- **Vulnerability Detection**: Primary focus on code security analysis
- **SVEN Dataset**: Support for CWE-based vulnerability classification
- **Primevul Dataset**: Large-scale vulnerability detection dataset support

## ✨ Mainline Workflows

- **Prompt Evolution**: Train stage-specific prompts for router and detector nodes.
- **Frozen Evaluation**: Load the best prompt artifact and test vulnerability detection.
- **Ablation Layering**: Add optional features back with explicit ablation flags.

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd Mulvul

# Install with uv (recommended)
uv sync
```

### Configuration

Create a `.env` file with your API configuration:

```env
API_BASE_URL=https://newapi.pockgo.com/v1
API_KEY=your-api-key-here
BACKUP_API_BASE_URL=https://newapi.aicohere.org/v1
MODEL_NAME=kimi-k2-code
```

### Basic Usage

```bash
# 1. Evolve best prompts for each stage
uv run python scripts/run_mainline_evolution.py \
  --train-file data/primevul/primevul/primevul_train.jsonl \
  --output-dir outputs/mainline/evolution

# 2. Evaluate the frozen prompt bundle
uv run python scripts/run_mainline_evaluation.py \
  --eval-file data/primevul/primevul/primevul_valid.jsonl \
  --prompts-path outputs/mainline/evolution/prompt_artifact.json \
  --output-dir outputs/mainline/evaluation

# Optional ablations
uv run python scripts/run_mainline_evaluation.py \
  --eval-file data/primevul/primevul/primevul_valid.jsonl \
  --prompts-path outputs/mainline/evolution/prompt_artifact.json \
  --ablation rag \
  --ablation parallel
```

## 📊 Supported Datasets

### SVEN Dataset
- **CWE Types**: 9 common vulnerability types
- **Format**: JSONL with function context
- **Location**: `data/vul_detection/sven/`

### Primevul Dataset  
- **Scale**: 24,000+ vulnerability samples
- **Format**: JSONL with code analysis
- **Location**: `data/primevul/primevul/`

## 🧬 Evolutionary Algorithms

### Differential Evolution (DE)
- Continuous optimization approach
- Good for fine-tuning prompts
- Configurable mutation and crossover rates

### Genetic Algorithm (GA)
- Population-based optimization
- Diverse prompt generation
- Tournament selection and crossover

## 📁 Project Structure

```
Mulvul/
├── src/mulvul/mainline/   # First-class workflows and prompt artifacts
├── src/mulvul/agents/     # Reused router/detector building blocks
├── src/mulvul/rag/        # Retrieval components, only via ablations
├── scripts/ablations/        # Legacy experiments, demos, and utilities
├── scripts/run_mainline_evolution.py
├── scripts/run_mainline_evaluation.py
└── tests/test_mainline_*.py
```

## 🔧 API Usage

### SVEN-Compatible Client

```python
from mulvul import sven_llm_init, sven_llm_query

# Initialize client
client = sven_llm_init()

# Single query
result = sven_llm_query("Analyze this code for vulnerabilities", client, task=True)

# Batch queries
results = sven_llm_query(["query1", "query2"], client, task=True)
```

### Vulnerability Detection Workflow

```python
from mulvul import VulnerabilityDetectionWorkflow

# Configure experiment
config = {
    "algorithm": "de",
    "population_size": 10,
    "max_generations": 5,
    "llm_type": "sven"
}

# Run evolution
workflow = VulnerabilityDetectionWorkflow(config)
results = workflow.run()
```

## 📈 Performance Tracking

Mulvul provides comprehensive tracking of the evolution process:

- **Real-time Logging**: All prompt updates recorded in `prompt_evolution.jsonl`
- **Best Prompts**: History of best-performing prompts
- **Fitness Tracking**: Complete fitness evolution over generations
- **LLM Call History**: All API calls logged for analysis

## 🧪 Example Results

### Primevul 1% Demo Results
- **Total Samples**: 100 (balanced: 50 benign + 50 vulnerable)
- **Evolution Generations**: 4
- **LLM Calls**: 924
- **Output Files**: 5 detailed tracking files

## 🔄 Development Commands

```bash
# Mainline workflows
uv run python scripts/run_mainline_evolution.py
uv run python scripts/run_mainline_evaluation.py

# Legacy experiments and ablations
uv run python scripts/ablations/<name>.py

# Run tests
uv run pytest tests/

# Check code quality
uv run ruff check src/
uv run mypy src/
```

## 🧪 Response Parsing Harness

Use `scripts/ablations/verify_response_parsing.py` to run a handful of real LLM calls and
confirm that the parser recovers the intended labels:

```bash
uv run python scripts/ablations/verify_response_parsing.py \
  --llm-type openai \
  --model-name gpt-4o-mini \
  --sample-file data/primevul_1percent_sample/dev_sample.jsonl \
  --max-samples 3 \
  --temperature 0.0 \
  --verbose
```

- To run with full PrimeVul samples and output archiving:

```bash
uv run python scripts/ablations/verify_response_parsing.py \
  --model-name gpt-4o \
  --sample-file data/primevul_1percent_sample/dev_sample.jsonl \
  --max-samples 10 \
  --temperature 0.0 \
  --verbose \
  --use-cwe-major \
  --output-json result.json
```

- Runs against a real LLM by default; ensure `API_KEY`, `API_BASE_URL`, `MODEL_NAME` are set in `.env`.
- Use `--use-cwe-major` mode to verify major-category classification parsing.
- For offline debugging, pass `--mock-response "benign"` to reuse a single response (no real API validation).
- Use `--output-json` to save per-sample prompts, raw responses, and parsed results for further analysis.

> By default, `pytest` will not run `tests/test_response_parsing.py`.
> To include it in the test run, set `RUN_RESPONSE_PARSING_TESTS=1` before the command.

## 📋 Requirements

- Python 3.11+
- uv package manager
- API access (configured in .env)

## 🤝 Contributing

1. Focus on vulnerability detection improvements
2. Maintain SVEN compatibility
3. Follow modern Python practices
4. Add comprehensive tests

## 📄 License

MIT License - see LICENSE file for details

## 🔗 Related Projects

- **SVEN**: Vulnerability detection submodule
- **Primevul**: Large-scale vulnerability dataset

---

**Note**: Mulvul now uses `src/mulvul` as the canonical package namespace throughout the repository. Mainline workflows live at the top level, while older experiments stay under `scripts/ablations/`.
