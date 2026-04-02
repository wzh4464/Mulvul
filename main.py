#!/usr/bin/env python3
"""
EvoPrompt Main Entry - PrimeVul Layer-1 并发漏洞分类

功能:
1. 从 init/ 文件夹读取初始化 prompts
2. 对 PrimeVul 数据集进行 CWE 大类分层漏洞检测
3. 每 16 条 code 为一个 batch 进行批量处理
4. Batch 级别的分析和反馈机制指导 prompt 进化
5. 输出最终 prompt 和各类别的 precision/recall/f1-score 到 result/ 文件夹
"""

import logging
import sys
import json
import time
import random
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Tuple, Optional
import textwrap
from string import Template

# 添加 src 路径
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from evoprompt.data.sampler import sample_primevul_1percent
from evoprompt.data.dataset import PrimevulDataset
from evoprompt.data.cwe_categories import (
    CWE_MAJOR_CATEGORIES,
    canonicalize_category,
    map_cwe_to_major,
    CATEGORY_DESCRIPTIONS_BLOCK,
)
from evoprompt.strategies import create_strategy
from evoprompt.llm.client import create_default_client, create_meta_prompt_client
from evoprompt.algorithms.base import Individual, Population
from evoprompt.utils.checkpoint import (
    CheckpointManager,
    RetryManager,
    BatchCheckpointer,
    ExperimentRecovery,
)
from evoprompt.utils.text import safe_format
from sklearn.metrics import classification_report, confusion_matrix
import numpy as np

# Module-level constant for the default fitness metric.
# Used by both the CLI argument parser and all config.get() fallbacks
# so that changing the default in one place keeps everything in sync.
DEFAULT_FITNESS_METRIC = "macro_f1"
VALID_FITNESS_METRICS = {"accuracy", "macro_f1"}

logger = logging.getLogger(__name__)


def get_fitness(config: Dict[str, Any], eval_result: Dict[str, Any]) -> Tuple[str, float]:
    """Return (metric_name, fitness_value) from *eval_result* based on *config*.

    Centralises the fitness-metric lookup that was previously duplicated in the
    initial-evaluation loop and the per-generation evolution loop.

    Raises ``ValueError`` if the configured metric is not in
    :data:`VALID_FITNESS_METRICS`.  If the chosen metric is absent from
    *eval_result* (e.g. when resuming from an older checkpoint), falls back to
    ``"accuracy"`` with a warning instead of crashing.
    """
    fitness_metric = config.get("fitness_metric", DEFAULT_FITNESS_METRIC)
    if fitness_metric not in VALID_FITNESS_METRICS:
        raise ValueError(
            f"Unknown fitness_metric {fitness_metric!r}; "
            f"expected one of {sorted(VALID_FITNESS_METRICS)}"
        )
    if fitness_metric not in eval_result:
        # Gracefully handle older checkpoints that lack newer metrics.
        fallback = "accuracy"
        logger.warning(
            "Fitness metric %r not found in eval_result "
            "(available keys: %s); falling back to %r. "
            "This can happen when resuming from an older checkpoint.",
            fitness_metric,
            sorted(eval_result.keys()),
            fallback,
        )
        fitness_metric = fallback
    fitness = eval_result.get(fitness_metric, 0.0)
    if fitness_metric not in eval_result:
        logger.warning(
            "Fallback metric %r also missing from eval_result; using 0.0",
            fitness_metric,
        )
    return fitness_metric, fitness


def _safe_metric(result: Dict[str, Any], key: str, default: float = 0.0) -> float:
    """Return ``result[key]`` if present, else *default* with a debug log."""
    if key in result:
        return result[key]
    logger.debug("Metric %r missing from result dict; defaulting to %.1f", key, default)
    return default


class BatchAnalyzer:
    """Batch 级别的分析器，对比预测结果和 ground truth 并生成反馈"""

    def __init__(self, batch_size: int = 16):
        self.batch_size = batch_size
        self.analysis_history = []

    def analyze_batch(
        self,
        predictions: List[str],
        ground_truths: List[str],
        batch_idx: int
    ) -> Dict[str, Any]:
        """
        分析一个 batch 的预测结果

        Returns:
            analysis: 包含准确率、错误模式、改进建议的字典
        """
        correct = sum(p == g for p, g in zip(predictions, ground_truths))
        accuracy = correct / len(predictions) if predictions else 0.0

        # 统计错误类型
        error_patterns = {}
        for pred, truth in zip(predictions, ground_truths):
            if pred != truth:
                error_key = f"{truth} -> {pred}"
                error_patterns[error_key] = error_patterns.get(error_key, 0) + 1

        # 生成改进建议
        improvement_suggestions = self._generate_improvement_suggestions(
            error_patterns, ground_truths, predictions
        )

        analysis = {
            "batch_idx": batch_idx,
            "batch_size": len(predictions),
            "correct": correct,
            "accuracy": accuracy,
            "error_patterns": error_patterns,
            "improvement_suggestions": improvement_suggestions,
            "timestamp": datetime.now().isoformat(),
        }

        self.analysis_history.append(analysis)
        return analysis

    def _generate_improvement_suggestions(
        self,
        error_patterns: Dict[str, int],
        ground_truths: List[str],
        predictions: List[str]
    ) -> List[str]:
        """根据错误模式生成改进建议"""
        suggestions = []

        if not error_patterns:
            suggestions.append("This batch achieved perfect accuracy. Maintain current approach.")
            return suggestions

        # 分析最常见的错误
        sorted_errors = sorted(error_patterns.items(), key=lambda x: x[1], reverse=True)

        for error_pattern, count in sorted_errors[:3]:  # 只取前3个最常见错误
            true_cat, pred_cat = error_pattern.split(" -> ")

            suggestion = (
                f"Improve detection of '{true_cat}' (misclassified as '{pred_cat}' {count} times). "
                f"Focus on distinguishing {true_cat} characteristics from {pred_cat}."
            )
            suggestions.append(suggestion)

        # 统计每个类别的表现
        category_stats = {}
        for truth in set(ground_truths):
            category_stats[truth] = {
                "total": ground_truths.count(truth),
                "correct": sum(1 for p, g in zip(predictions, ground_truths) if g == truth and p == g)
            }

        # 找出表现最差的类别
        worst_category = None
        worst_accuracy = 1.0
        for cat, stats in category_stats.items():
            if stats["total"] > 0:
                acc = stats["correct"] / stats["total"]
                if acc < worst_accuracy:
                    worst_accuracy = acc
                    worst_category = cat

        if worst_category and worst_accuracy < 0.5:
            suggestions.append(
                f"Category '{worst_category}' has low accuracy ({worst_accuracy:.2%}). "
                f"Emphasize patterns specific to this vulnerability type."
            )

        return suggestions


class StructuredPromptBuilder:
    """Helper to build prompts with fixed structure and mutable guidance."""

    ANALYSIS_START = "### ANALYSIS GUIDANCE START"
    ANALYSIS_END = "### ANALYSIS GUIDANCE END"

    def __init__(
        self,
        categories: List[str],
        default_guidance: str,
        subcategory_reference: Optional[str] = None,
        category_descriptions: Optional[str] = None,
    ):
        self.categories = categories
        self.default_guidance = default_guidance.strip()
        self.subcategory_reference = (
            textwrap.dedent(subcategory_reference).strip()
            if subcategory_reference
            else ""
        )
        self.category_descriptions = (
            textwrap.dedent(category_descriptions).strip()
            if category_descriptions
            else ""
        )
        self.template = Template(
            textwrap.dedent(
                """You are a security-focused code analysis assistant.

Classify the provided code into exactly one of the following level-0 CWE root categories:
$categories_block$category_descriptions_block$subcategory_reference_block
$analysis_start
$analysis_guidance
$analysis_end

Decision Rules (do not modify):
- Examine control flow, data flow, and API usage for concrete vulnerability patterns.
- Confirm that untrusted input crossing trust boundaries is either sanitized or defended.
- Validate memory and pointer operations for bounds, lifetime, and null safety.
- Prefer `Benign` when there is no actionable, exploitable vulnerability evidence.

Output Requirements (do not modify):
- Respond with a single category name from the list above.
- Do not provide explanations or additional text.

Code to analyze:
$code_placeholder

CWE Major Category:
"""
            ).strip()
        )

    @property
    def template_preview(self) -> str:
        """Return a preview of the structured template for evolution instructions."""
        return self.template.substitute(
            categories_block=self._format_categories(),
            category_descriptions_block=self._format_category_descriptions_block(),
            subcategory_reference_block=self._preview_subcategory_reference_block(),
            analysis_start=self.ANALYSIS_START,
            analysis_end=self.ANALYSIS_END,
            analysis_guidance="<<analysis guidance text>>",
            code_placeholder="{input}",
        )

    def _format_categories(self) -> str:
        return "\n".join(f"- {cat}" for cat in self.categories)

    def _format_category_descriptions_block(self) -> str:
        if not self.category_descriptions:
            return "\n"
        return (
            "\nCategory Descriptions (fixed reference):\n"
            f"{self.category_descriptions}\n"
        )

    def _format_subcategory_reference_block(self) -> str:
        if not self.subcategory_reference:
            return "\n"
        return (
            "\nReference Subcategories (for context):\n"
            f"{self.subcategory_reference}\n"
        )

    def _preview_subcategory_reference_block(self) -> str:
        if not self.subcategory_reference:
            return "\n"
        return "\nReference Subcategories (for context):\n<<subcategory reference>>\n"

    def render(self, guidance: str) -> str:
        """Render the full prompt using the provided guidance."""
        cleaned_guidance = self._sanitize_guidance_text(guidance)
        return self.template.substitute(
            categories_block=self._format_categories(),
            category_descriptions_block=self._format_category_descriptions_block(),
            subcategory_reference_block=self._format_subcategory_reference_block(),
            analysis_start=self.ANALYSIS_START,
            analysis_end=self.ANALYSIS_END,
            analysis_guidance=cleaned_guidance,
            code_placeholder="{input}",
        )

    def _sanitize_guidance_text(self, guidance: Optional[str]) -> str:
        if not guidance:
            return self.default_guidance
        cleaned = textwrap.dedent(guidance).replace(self.ANALYSIS_START, "").replace(self.ANALYSIS_END, "")
        cleaned = cleaned.replace("{input}", "").strip()
        return cleaned if cleaned else self.default_guidance

    def extract_guidance(self, prompt: str) -> Optional[str]:
        """Extract the mutable guidance section from an existing prompt."""
        if not prompt:
            return None

        start_idx = prompt.find(self.ANALYSIS_START)
        end_idx = prompt.find(self.ANALYSIS_END)

        if start_idx == -1 or end_idx == -1 or end_idx <= start_idx:
            return None

        start_idx += len(self.ANALYSIS_START)
        guidance = prompt[start_idx:end_idx].strip()
        return guidance if guidance else None

    def ensure_structure(self, prompt: str, fallback_guidance: Optional[str] = None) -> Tuple[str, str]:
        """
        Ensure the prompt adheres to the structured template.

        Returns:
            (structured_prompt, guidance_text)
        """
        guidance = self.extract_guidance(prompt)
        if guidance is None:
            fallback = fallback_guidance.strip() if fallback_guidance and fallback_guidance.strip() else self.default_guidance
            guidance = fallback
        sanitized_guidance = self._sanitize_guidance_text(guidance)
        structured_prompt = self.render(sanitized_guidance)
        return structured_prompt, sanitized_guidance


class PromptEvolver:
    """基于 Batch 分析反馈的 Prompt 进化器"""

    DEFAULT_GUIDANCE = textwrap.dedent(
        """
        - Start by identifying whether external input influences security-critical operations.
        - Inspect array, buffer, and pointer handling for missing bounds and lifetime safeguards.
        - Check memory allocation/freeing patterns for leaks, double frees, or use-after-free issues.
        - Look for concurrency primitives that could cause race conditions or inconsistent state.
        - When no concrete vulnerability conditions exist, return 'Benign'.
        """
    ).strip()

    def __init__(self, llm_client, config: Dict[str, Any]):
        self.llm_client = llm_client
        self.config = config
        self.evolution_history = []
        self.builder = StructuredPromptBuilder(
            CWE_MAJOR_CATEGORIES,
            self.DEFAULT_GUIDANCE,
            category_descriptions=CATEGORY_DESCRIPTIONS_BLOCK,
        )

    def evolve_with_feedback(
        self,
        current_prompt: str,
        batch_analysis: Dict[str, Any],
        generation: int
    ) -> str:
        """根据 batch 分析反馈进化 prompt，仅调整可变指导部分"""

        structured_prompt, current_guidance = self.builder.ensure_structure(current_prompt)
        if self.builder.extract_guidance(current_prompt) is None:
            print("    ℹ️ 原 prompt 已包装为固定结构，以保护 {input} 占位符和输出格式")
        current_prompt = structured_prompt

        # 如果准确率已经很高，不需要改进
        if batch_analysis["accuracy"] >= 0.95:
            return current_prompt

        improvement_text = "\n".join(
            f"- {sug}" for sug in batch_analysis["improvement_suggestions"]
        )

        error_text = "\n".join(
            f"- {pattern}: {count} occurrences"
            for pattern, count in batch_analysis["error_patterns"].items()
        )

        guidance_for_prompt = self._trim_for_prompt(current_guidance)
        improvement_for_prompt = self._trim_for_prompt(improvement_text)
        errors_for_prompt = self._trim_for_prompt(error_text if error_text else "None - all predictions were correct")

        evolution_instruction = textwrap.dedent(
            f"""
            You are improving only the ANALYSIS GUIDANCE section of a structured vulnerability classification prompt.

            The prompt uses this fixed template (do not alter anything outside the guidance markers):
            {self.builder.template_preview}

            Current ANALYSIS GUIDANCE:
            {guidance_for_prompt}

            Batch Analysis Results:
            - Accuracy: {batch_analysis['accuracy']:.2%}
            - Batch size: {batch_analysis['batch_size']}
            - Correct predictions: {batch_analysis['correct']}

            Common Error Patterns:
            {errors_for_prompt}

            Improvement Suggestions:
            {improvement_for_prompt if improvement_text else '- Maintain current guidance with minor refinements.'}

            Requirements:
            - Return a JSON object with a single key "analysis_guidance" whose value is the improved multi-line guidance text.
            - Preserve the intent of the fixed template, keep category coverage balanced, and emphasize distinctions for observed errors.
            - Keep bullet style or numbered lists if they help clarity.
            """
        ).strip()

        try:
            raw_response = self.llm_client.generate(
                evolution_instruction,
                temperature=0.7,
                max_tokens=600
            ).strip()

            new_guidance = self._parse_guidance_response(raw_response)
            if not new_guidance:
                print("    ⚠️ 进化响应无法解析，保持原 prompt")
                return current_prompt

            new_prompt = self.builder.render(new_guidance)

            self.evolution_history.append({
                "generation": generation,
                "batch_idx": batch_analysis["batch_idx"],
                "old_accuracy": batch_analysis["accuracy"],
                "new_guidance": new_guidance,
                "timestamp": datetime.now().isoformat(),
            })
            return new_prompt

        except Exception as e:
            print(f"    ❌ Prompt 进化失败: {e}")
            return current_prompt

    def _parse_guidance_response(self, response: str) -> Optional[str]:
        """Parse the LLM response for the updated guidance text."""
        if not response:
            return None

        cleaned = response.strip()

        if cleaned.startswith("```") and cleaned.endswith("```"):
            cleaned = cleaned.strip("`").strip()
            if cleaned.startswith("json"):
                cleaned = cleaned[4:].strip()

        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError:
            # Treat plain text as guidance fallback
            return cleaned.strip()

        if isinstance(data, dict):
            guidance = data.get("analysis_guidance")
            if isinstance(guidance, str):
                return guidance.strip()
            if isinstance(guidance, list):
                joined = "\n".join(str(item) for item in guidance)
                return joined.strip()
        if isinstance(data, list) and data:
            first = data[0]
            if isinstance(first, dict):
                return self._parse_guidance_response(json.dumps(first))
            joined = "\n".join(str(item) for item in data)
            return joined.strip()
        return None

    def _trim_for_prompt(self, text: str, limit: int = 1200) -> str:
        if not text:
            return ""
        stripped = text.strip()
        if len(stripped) <= limit:
            return stripped
        return stripped[:limit].rstrip() + "\n... (truncated)"


DEFAULT_MAX_CATEGORY_DROP = 0.15

# sklearn classification_report aggregate keys that are not real categories
_REPORT_AGGREGATE_KEYS = frozenset({
    "accuracy", "macro avg", "weighted avg", "micro avg", "samples avg",
})


class PrimeVulLayer1Pipeline:
    """PrimeVul Layer-1 并发漏洞分类流水线"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.batch_size = config.get("batch_size", 16)
        self.init_dir = Path("init")
        self.result_dir = Path("result")

        # 创建必要的目录
        self.init_dir.mkdir(exist_ok=True)
        self.result_dir.mkdir(exist_ok=True)

        # 创建实验子目录
        self.exp_id = config.get("experiment_id") or f"layer1_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.exp_dir = self.result_dir / self.exp_id
        self.exp_dir.mkdir(exist_ok=True, parents=True)

        # 初始化组件
        self.llm_client = create_default_client(
            model_name=config.get("analysis_model_name"),
            api_base=config.get("analysis_api_base"),
            api_key=config.get("analysis_api_key"),
        )
        self.meta_llm_client = create_meta_prompt_client(
            model_name=config.get("meta_model_name"),
            api_base=config.get("meta_api_base"),
            api_key=config.get("meta_api_key"),
        )
        self.batch_analyzer = BatchAnalyzer(batch_size=self.batch_size)
        self.prompt_evolver = PromptEvolver(self.meta_llm_client, config)

        # 初始化 Checkpoint 管理器
        self.checkpoint_manager = CheckpointManager(self.exp_dir, auto_save=True)
        self.batch_checkpointer = BatchCheckpointer(self.exp_dir / "checkpoints", self.batch_size)
        self.retry_manager = RetryManager(
            max_retries=config.get("max_retries", 3),
            base_delay=config.get("retry_delay", 1.0),
            exponential_backoff=True
        )
        self.recovery = ExperimentRecovery(self.exp_dir)
        self.strategy = create_strategy(
            config.get("mode", "flat"), self.llm_client, config
        )

        if config.get("enable_rag"):
            from evoprompt.strategies.rag_wrapper import RAGStrategyWrapper
            from evoprompt.rag.knowledge_base import KnowledgeBase, KnowledgeBaseBuilder
            from evoprompt.rag.retriever import CodeSimilarityRetriever
            from pathlib import Path as _Path

            kb_path = _Path(config.get("sample_dir", ".")) / "knowledge_base.json"
            if kb_path.exists():
                print(f"  [RAG] Loading knowledge base from {kb_path}")
                kb = KnowledgeBase.load(str(kb_path))
            else:
                print(f"  [RAG] Knowledge base not found at {kb_path}, using built-in defaults")
                kb = KnowledgeBaseBuilder.create_default_kb()

            retriever = CodeSimilarityRetriever(kb, contrastive=True)
            self.strategy = RAGStrategyWrapper(self.strategy, retriever, config)
            print(f"  [RAG] Strategy wrapped with RAG retrieval (vuln_top_k=2, clean_top_k=1)")

        if config.get("enable_meta"):
            from evoprompt.strategies.meta_wrapper import MetaEvolutionWrapper
            self.prompt_evolver = MetaEvolutionWrapper(self.prompt_evolver, self.meta_llm_client, config)
            print(f"  [Meta] Prompt evolver wrapped with error accumulation + meta-learning")

        print(f"✅ 初始化 PrimeVul Layer-1 Pipeline")
        print(f"   实验 ID: {self.exp_id}")
        print(f"   Batch 大小: {self.batch_size}")
        print(f"   结果目录: {self.exp_dir}")
        print(f"   Checkpoint: 启用 (最大重试: {config.get('max_retries', 3)})")

    def load_initial_prompts(self) -> List[str]:
        """从 init/ 文件夹加载初始 prompts"""
        prompts_file = self.init_dir / "layer1_prompts.txt"

        if not prompts_file.exists():
            print(f"⚠️ 未找到初始 prompts 文件: {prompts_file}")
            print(f"   使用默认 prompts 并保存到 {prompts_file}")
            default_prompts = self._create_default_prompts()

            # 保存默认 prompts
            with open(prompts_file, "w", encoding="utf-8") as f:
                f.write("# PrimeVul Layer-1 初始化 Prompts\n")
                f.write("# 每个 prompt 之间用空行分隔\n")
                f.write("# Prompt 中必须包含 {input} 占位符\n\n")
                for i, prompt in enumerate(default_prompts, 1):
                    f.write(f"# Prompt {i}\n")
                    f.write(prompt)
                    f.write("\n\n" + "="*80 + "\n\n")

            return default_prompts

        # 读取 prompts
        with open(prompts_file, "r", encoding="utf-8") as f:
            content = f.read()

        # 按分隔符分割
        prompts = []
        sections = content.split("=" * 80)

        for section in sections:
            section = section.strip()
            if not section:
                continue

            # 移除注释行（以 # 开头的行）
            lines = []
            for line in section.split("\n"):
                stripped = line.strip()
                # 跳过注释行，但保留非注释内容
                if not stripped.startswith("#"):
                    lines.append(line)

            prompt = "\n".join(lines).strip()

            if not prompt:
                continue

            structured_prompt, _ = self.prompt_evolver.builder.ensure_structure(
                prompt, fallback_guidance=prompt
            )
            prompts.append(structured_prompt)
            print(f"   ✓ 加载 Prompt {len(prompts)}: {structured_prompt[:60]}...")
            if structured_prompt != prompt:
                print("     ↳ 已转换为结构化模板，固定 {input} 占位符和输出规范")

        print(f"✅ 从 {prompts_file} 加载了 {len(prompts)} 个初始 prompts")
        return prompts if prompts else self._create_default_prompts()

    def _create_default_prompts(self) -> List[str]:
        """创建默认的初始 prompts

        重要: 所有 prompt 都必须显式列出完整的类别列表
        """
        builder = self.prompt_evolver.builder

        guidance_variations = [
            builder.default_guidance,
            textwrap.dedent(
                """
                - Review buffer allocations, index arithmetic, and memcpy/memset usage for overflow or underflow patterns.
                - Distinguish pointer misuse by checking for null validation, dangling references, and invalid dereferences.
                - Confirm lifetime management: match allocations to frees and inspect error paths for leaks or double frees.
                - Prefer 'Benign' when operations stay within documented bounds and defensive guards are present.
                """
            ).strip(),
            textwrap.dedent(
                """
                - Trace all user-controlled inputs; ensure sanitization before reaching system, SQL, or command execution calls.
                - Map CWE hints (e.g., CWE-79, CWE-89) to major categories while verifying the exploit is feasible.
                - Contrast injection findings with buffer or integer issues to avoid mislabeling multi-symptom defects.
                - Choose 'Benign' when inputs are validated, escaped, or unused in sensitive contexts.
                """
            ).strip(),
            textwrap.dedent(
                """
                - Focus on concurrency primitives (locks, atomics, threads); identify missing synchronization around shared state.
                - Examine memory sharing, producer/consumer logic, and ordering guarantees for race windows.
                - When concurrency looks safe, fall back to scanning for memory, buffer, or injection issues before 'Benign'.
                - Document evidence-driven reasoning within the guidance to disambiguate close categories.
                """
            ).strip(),
            textwrap.dedent(
                """
                - Audit memory allocation and cleanup paths: ensure every malloc/new has a corresponding free/delete.
                - Detect use-after-free by following pointers after deallocation or across error labels.
                - Treat lack of deallocation on all exit paths as Memory Management issues unless the lifetime is intentional.
                - If memory handling is correct, check pointer, integer, and buffer safety before defaulting to 'Benign'.
                """
            ).strip(),
            textwrap.dedent(
                """
                - Evaluate arithmetic and casting for overflow/underflow when values influence lengths, indexes, or allocations.
                - Watch for signed/unsigned conversions, bit shifts, and loop counters that can wrap unexpectedly.
                - Differentiate between Buffer Errors (actual out-of-bounds access) and Integer Errors (unsafe numeric range handling).
                - Confirm no exploitable arithmetic flaw exists before selecting 'Benign'.
                """
            ).strip(),
            textwrap.dedent(
                """
                - Inspect file and path construction for traversal sequences or unsafe concatenation of untrusted input.
                - Review cryptographic usage for deprecated algorithms, missing randomness, or hard-coded secrets.
                - Check logging and error handling for unintended information disclosure.
                - Mark as 'Benign' only if path, crypto, and disclosure surfaces are hardened and validated.
                """
            ).strip(),
            textwrap.dedent(
                """
                - Combine control-flow and data-flow evidence to justify selecting a specific CWE major category.
                - Prioritize categories that align with the root cause, not just surface symptoms.
                - Highlight differentiators between closely related categories (e.g., Buffer Errors vs. Pointer Dereference).
                - Default to 'Benign' when safeguards mitigate potential issues or evidence is speculative.
                """
            ).strip(),
            textwrap.dedent(
                """
                - Use a two-pass review: first scan for any vulnerability triggers, then confirm mitigation coverage.
                - Record decisive cues (API usage, missing checks, lifetime anomalies) that map to each CWE major category.
                - Reinforce conservative judgment—require demonstrable exploit paths before assigning a vulnerable label.
                - End guidance with a reminder to return just the category token.
                """
            ).strip(),
            textwrap.dedent(
                """
                - Validate that selected categories remain mutually exclusive: choose the most specific applicable label.
                - Escalate ambiguous findings to 'Other' only when no primary category captures the vulnerability traits.
                - Encourage deeper inspection of secondary evidence when error patterns repeat across batches.
                - Reinforce the requirement to output exactly one category name and nothing else.
                """
            ).strip(),
        ]

        return [builder.render(guidance) for guidance in guidance_variations]

    def batch_predict(
        self,
        prompt: str,
        samples: List[Any],
        batch_idx: int
    ) -> Tuple[List[str], List[str]]:
        """批量预测一个 batch 的样本，委托给 strategy"""
        ground_truths = [self.strategy.get_ground_truth(s) for s in samples]

        try:
            def _predict_with_retry():
                return self.strategy.predict_batch(prompt, samples, batch_idx)
            predictions = self.retry_manager.retry_with_backoff(_predict_with_retry)
        except Exception as e:
            print(f"      ❌ 批量预测失败 (已达最大重试次数): {e}")
            predictions = ["Other"] * len(samples)

        return predictions, ground_truths

    def evaluate_prompt_on_dataset(
        self,
        prompt: str,
        dataset,
        generation: int,
        prompt_id: str,
        enable_evolution: bool = False,
        start_batch_idx: int = 0
    ) -> Dict[str, Any]:
        """在完整数据集上评估 prompt，使用 batch 处理和 checkpoint"""
        samples = dataset.get_samples()
        total_samples = len(samples)

        all_predictions = []
        all_ground_truths = []
        batch_analyses = []

        current_prompt, _ = self.prompt_evolver.builder.ensure_structure(
            prompt, fallback_guidance=prompt
        )
        num_batches = (total_samples + self.batch_size - 1) // self.batch_size

        print(f"    📊 评估 prompt (共 {num_batches} 个 batches, {total_samples} 个样本)")

        # 检查是否有未完成的 batch
        if start_batch_idx > 0:
            print(f"    🔄 从 Batch {start_batch_idx + 1} 继续...")

        for batch_idx in range(start_batch_idx, num_batches):
            start_idx = batch_idx * self.batch_size
            end_idx = min(start_idx + self.batch_size, total_samples)
            batch_samples = samples[start_idx:end_idx]

            print(f"      Batch {batch_idx + 1}/{num_batches} (样本 {start_idx+1}-{end_idx})")

            # 检查是否已有 checkpoint
            cached_batch = self.batch_checkpointer.load_batch_result(generation, batch_idx)
            cached_prompt = cached_batch.get("prompt") if cached_batch else None
            if cached_batch and cached_prompt == current_prompt:
                print(f"        📦 从 checkpoint 加载结果")
                predictions = cached_batch["predictions"]
                ground_truths = cached_batch["ground_truths"]
                batch_analysis = cached_batch["analysis"]
                cached_prompt = cached_batch.get("prompt", current_prompt)
                current_prompt, _ = self.prompt_evolver.builder.ensure_structure(
                    cached_prompt, fallback_guidance=cached_prompt
                )
            else:
                # 批量预测
                predictions, ground_truths = self.batch_predict(
                    current_prompt, batch_samples, batch_idx
                )

                # 分析 batch 结果
                batch_analysis = self.batch_analyzer.analyze_batch(
                    predictions, ground_truths, batch_idx
                )

                # 保存 batch checkpoint
                self.batch_checkpointer.save_batch_result(
                    generation, batch_idx, predictions, ground_truths,
                    batch_analysis, current_prompt
                )

            print(f"        ✓ 准确率: {batch_analysis['accuracy']:.2%} ({batch_analysis['correct']}/{batch_analysis['batch_size']})")

            if batch_analysis["error_patterns"]:
                print(f"        ⚠️ 错误模式: {len(batch_analysis['error_patterns'])} 种")

            batch_analyses.append(batch_analysis)
            all_predictions.extend(predictions)
            all_ground_truths.extend(ground_truths)

            # 根据 batch 分析进化 prompt (仅在训练模式下)
            if enable_evolution and batch_analysis["accuracy"] < 0.95:
                print(f"        🧬 尝试进化 prompt...")

                def evolve_with_retry():
                    return self.prompt_evolver.evolve_with_feedback(
                        current_prompt, batch_analysis, generation
                    )

                try:
                    new_prompt = self.retry_manager.retry_with_backoff(evolve_with_retry)
                    if new_prompt != current_prompt:
                        print(f"        ✅ Prompt 已进化")
                        current_prompt = new_prompt
                except Exception as e:
                    print(f"        ⚠️ Prompt 进化失败: {e}")
                    # 继续使用当前 prompt

        # 计算整体指标
        overall_accuracy = sum(p == g for p, g in zip(all_predictions, all_ground_truths)) / len(all_predictions)

        # 生成分类报告
        report = classification_report(
            all_ground_truths,
            all_predictions,
            labels=CWE_MAJOR_CATEGORIES,
            output_dict=True,
            zero_division=0
        )

        # 混淆矩阵
        cm = confusion_matrix(
            all_ground_truths,
            all_predictions,
            labels=CWE_MAJOR_CATEGORIES
        )

        # Extract macro / weighted F1 for fitness selection
        macro_f1 = report.get("macro avg", {}).get("f1-score", 0.0)
        weighted_f1 = report.get("weighted avg", {}).get("f1-score", 0.0)

        return {
            "prompt_id": prompt_id,
            "generation": generation,
            "final_prompt": current_prompt,
            "accuracy": overall_accuracy,
            "macro_f1": macro_f1,
            "weighted_f1": weighted_f1,
            "total_samples": total_samples,
            "num_batches": num_batches,
            "batch_analyses": batch_analyses,
            "classification_report": report,
            "confusion_matrix": cm.tolist(),
            "predictions": all_predictions,
            "ground_truths": all_ground_truths,
        }

    def _check_category_regression(
        self,
        old_report: Dict[str, Any],
        new_report: Dict[str, Any],
        max_drop: float,
    ) -> Tuple[bool, List[Tuple[str, float, float, float]]]:
        """Check if any category F1 dropped more than max_drop.

        Iterates over CWE_MAJOR_CATEGORIES plus any additional category
        keys found in either report (excluding sklearn aggregates like
        ``accuracy``, ``macro avg``, ``weighted avg``).  Categories
        missing from one report are treated as having f1-score of 0.0.

        Returns (passed: bool, regressions: list of (category, old_f1, new_f1, drop))
        """
        regressions = []
        # Start with known CWE categories, then add any extra report keys
        # that look like per-class entries (dict with "f1-score").
        all_categories = set(CWE_MAJOR_CATEGORIES)
        for k in set(old_report) | set(new_report):
            if k in _REPORT_AGGREGATE_KEYS or k in all_categories:
                continue
            entry = old_report.get(k) or new_report.get(k)
            if isinstance(entry, dict) and "f1-score" in entry:
                all_categories.add(k)

        for cat in sorted(all_categories):
            old_entry = old_report.get(cat)
            new_entry = new_report.get(cat)
            if old_entry is None and new_entry is None:
                continue
            old_f1 = old_entry.get("f1-score", 0.0) if old_entry is not None else 0.0
            # Treat a category that disappeared from the new report as f1=0.0
            # so that dropping a previously-evaluated category counts as regression
            new_f1 = new_entry.get("f1-score", 0.0) if new_entry is not None else 0.0
            drop = old_f1 - new_f1
            if old_f1 > 0 and drop > max_drop:
                regressions.append((cat, old_f1, new_f1, drop))
        return len(regressions) == 0, regressions

    def run_evolution(self) -> Dict[str, Any]:
        """运行完整的进化流程 (支持断点恢复)"""
        print("\n" + "="*80)
        print("🚀 开始 PrimeVul Layer-1 并发漏洞分类")
        print("="*80 + "\n")

        # 0. 检查是否可以恢复实验
        start_generation = 0
        population = None
        best_results = []

        # 检查是否启用自动恢复
        auto_recover = self.config.get("auto_recover", False)

        if self.recovery.can_recover():
            print("🔄 检测到未完成的实验...")

            # 根据配置决定是否自动恢复
            should_recover = auto_recover

            if not auto_recover:
                try:
                    user_input = input("是否从 checkpoint 恢复? (y/n): ").strip().lower()
                    should_recover = (user_input == 'y')
                except (EOFError, KeyboardInterrupt):
                    print("\n⚠️ 无法读取用户输入，跳过恢复")
                    should_recover = False

            if should_recover:
                recovered_state = self.recovery.recover_experiment()
                if recovered_state and recovered_state.get("full_state"):
                    print("✅ 从完整状态恢复")
                    start_generation = recovered_state["generation"]
                    population = recovered_state["population"]
                    best_results = recovered_state["best_results"]
                    print(f"   将从第 {start_generation + 1} 代继续\n")
                else:
                    print("⚠️ 只能恢复部分信息，将重新开始实验\n")
            else:
                print("⚠️ 跳过恢复，重新开始实验\n")

        # 1. 准备数据
        print("📁 准备数据集...")
        primevul_dir = Path(self.config.get("primevul_dir", "./data/primevul/primevul"))
        sample_dir = Path(self.config.get("sample_dir", "./data/primevul_1percent_sample"))
        balance_mode = self.config.get("balance_mode", "layer1")
        force_resample = bool(self.config.get("force_resample", False))

        stats_file = sample_dir / "sampling_stats.json"
        regenerate_samples = force_resample or not sample_dir.exists()

        if not regenerate_samples and stats_file.exists():
            try:
                with open(stats_file, "r", encoding="utf-8") as f:
                    stats_payload = json.load(f)
                existing_mode = (
                    stats_payload.get("sampling_config", {}).get("balance_mode", "target")
                )
                if existing_mode != balance_mode:
                    print(
                        f"   ⚠️ 当前采样使用 {existing_mode}，与配置的 {balance_mode} 不一致，重新采样"
                    )
                    regenerate_samples = True
            except Exception as exc:
                print(f"   ⚠️ 读取采样统计失败: {exc}，重新采样")
                regenerate_samples = True
        elif not regenerate_samples:
            print("   ⚠️ 未找到采样统计信息，将重新采样")
            regenerate_samples = True

        if regenerate_samples:
            ratio_pct = float(self.config.get("sample_ratio", 0.10)) * 100
            print(f"   生成 {ratio_pct:.0f}% 采样数据到 {sample_dir} (balance_mode={balance_mode})")
            sample_primevul_1percent(
                str(primevul_dir),
                str(sample_dir),
                seed=42,
                balance_mode=balance_mode,
                sample_ratio=float(self.config.get("sample_ratio", 0.10)),
                dev_ratio=float(self.config.get("dev_ratio", 0.3)),
                remove_benign_train=bool(self.config.get("remove_benign_train", False)),
                min_dev_per_label=int(self.config.get("min_dev_per_label", 5)),
            )
        else:
            print(f"   使用已有采样数据 {sample_dir} (balance_mode={balance_mode})")

        # Prefer JSONL (has CWE metadata for ground truth mapping).
        # Fall back to tab format for backward compatibility.
        train_file = sample_dir / "train_sample.jsonl"
        dev_file = sample_dir / "dev_sample.jsonl"
        if not train_file.exists():
            train_file = sample_dir / "train.txt"
        if not dev_file.exists():
            dev_file = sample_dir / "dev.txt"

        train_dataset = PrimevulDataset(str(train_file), "train")
        dev_dataset = PrimevulDataset(str(dev_file), "dev")

        print(f"   ✅ 训练集: {len(train_dataset)} 样本")
        print(f"   ✅ 开发集: {len(dev_dataset)} 样本")

        # 2. 加载初始 prompts (如果没有恢复种群)
        if population is None:
            print("\n📝 加载初始 prompts...")
            initial_prompts = self.load_initial_prompts()

            # 3. 初始评估
            print(f"\n📊 初始评估 ({len(initial_prompts)} 个 prompts)...")
            population = []

            for i, prompt in enumerate(initial_prompts):
                print(f"\n  Prompt {i+1}/{len(initial_prompts)}")
                result = self.evaluate_prompt_on_dataset(
                    prompt, dev_dataset, generation=0,
                    prompt_id=f"initial_{i}", enable_evolution=False
                )
                individual = Individual(prompt)
                fitness_metric, individual.fitness = get_fitness(self.config, result)
                population.append((individual, result))
                print(f"    ✓ 适应度: {individual.fitness:.4f} ({fitness_metric})")

            # 保存初始 checkpoint
            self.checkpoint_manager.save_checkpoint(
                generation=0,
                batch_idx=0,
                population=population,
                best_results=best_results,
                metadata={"stage": "initial_evaluation"}
            )

        # 4. 进化过程
        max_generations = self.config.get("max_generations", 5)
        print(f"\n🧬 开始进化 (共 {max_generations} 代)...")

        for generation in range(start_generation + 1, max_generations + 1):
            print(f"\n{'='*80}")
            print(f"📈 第 {generation} 代进化")
            print(f"{'='*80}\n")

            try:
                # 选择最佳个体
                population.sort(key=lambda x: x[0].fitness, reverse=True)
                best_individual, best_result = population[0]
                best_results.append(best_result)

                print(f"  当前最佳适应度: {best_individual.fitness:.4f}")

                # 在训练集上进化最佳 prompt
                print(f"\n  在训练集上进化最佳 prompt...")
                evolved_result = self.evaluate_prompt_on_dataset(
                    best_individual.prompt,
                    train_dataset,
                    generation=generation,
                    prompt_id=f"gen{generation}_best",
                    enable_evolution=True
                )

                # 创建进化后的个体并在开发集上评估
                evolved_prompt = evolved_result["final_prompt"]
                if evolved_prompt != best_individual.prompt:
                    print(f"\n  在开发集上评估进化后的 prompt...")
                    eval_result = self.evaluate_prompt_on_dataset(
                        evolved_prompt,
                        dev_dataset,
                        generation=generation,
                        prompt_id=f"gen{generation}_evolved",
                        enable_evolution=False
                    )

                    evolved_individual = Individual(evolved_prompt)
                    fitness_metric, evolved_individual.fitness = get_fitness(self.config, eval_result)

                    print(f"    进化前适应度: {best_individual.fitness:.4f} ({fitness_metric})")
                    print(f"    进化后适应度: {evolved_individual.fitness:.4f} ({fitness_metric})")

                    if evolved_individual.fitness > best_individual.fitness:
                        # Check for category regression before accepting
                        max_drop = self.config.get("max_category_drop", DEFAULT_MAX_CATEGORY_DROP)
                        old_cr = best_result.get("classification_report")
                        new_cr = eval_result.get("classification_report")
                        if not isinstance(old_cr, dict) or not isinstance(new_cr, dict):
                            print("    [warn] classification_report missing or not a dict, rejecting candidate")
                            passed, regressions = False, []
                        else:
                            passed, regressions = self._check_category_regression(
                                old_cr, new_cr, max_drop,
                            )
                        if not passed:
                            print(f"    ⚠️ 拒绝进化: 类别退化超过阈值 (max_drop={max_drop:.2f})")
                            for cat, old_f1, new_f1, drop in regressions:
                                print(f"      {cat}: {old_f1:.3f} → {new_f1:.3f} (↓{drop:.3f})")
                        else:
                            print(f"    ✅ 接受进化后的 prompt!")
                            population[0] = (evolved_individual, eval_result)
                    else:
                        print(f"    ❌ 保留原 prompt")

                # 保存代级 checkpoint
                self.checkpoint_manager.save_checkpoint(
                    generation=generation,
                    batch_idx=0,
                    population=population,
                    best_results=best_results,
                    metadata={"stage": f"generation_{generation}_complete"}
                )
                print(f"\n  💾 Checkpoint 已保存 (第 {generation} 代)")

                # 清理旧的 checkpoint
                if generation % 3 == 0:
                    self.checkpoint_manager.cleanup_old_checkpoints(keep_last_n=10)

            except KeyboardInterrupt:
                print(f"\n⚠️ 用户中断实验")
                print(f"💾 保存当前进度到 checkpoint...")
                self.checkpoint_manager.save_checkpoint(
                    generation=generation,
                    batch_idx=0,
                    population=population,
                    best_results=best_results,
                    metadata={"stage": "interrupted", "reason": "keyboard_interrupt"}
                )
                print(f"✅ Checkpoint 已保存，可以稍后恢复")
                raise

            except Exception as e:
                print(f"\n❌ 第 {generation} 代发生错误: {e}")
                print(f"💾 保存当前进度到 checkpoint...")
                self.checkpoint_manager.save_checkpoint(
                    generation=generation,
                    batch_idx=0,
                    population=population,
                    best_results=best_results,
                    metadata={"stage": "error", "error": str(e)}
                )
                print(f"✅ Checkpoint 已保存，可以稍后恢复")
                raise

        # 5. 最终结果
        population.sort(key=lambda x: x[0].fitness, reverse=True)
        best_individual, best_result = population[0]

        print(f"\n{'='*80}")
        print(f"🎉 进化完成!")
        print(f"{'='*80}\n")
        print(f"  最终适应度: {best_individual.fitness:.4f}")

        # 打印重试统计
        retry_stats = self.retry_manager.get_stats()
        print(f"\n📊 API 调用统计:")
        print(f"   成功: {retry_stats['success_count']}")
        print(f"   失败: {retry_stats['failure_count']}")
        if retry_stats['failure_count'] > 0:
            print(f"   重试成功率: {retry_stats['success_count'] / (retry_stats['success_count'] + retry_stats['failure_count']):.2%}")

        # 6. 保存结果
        self.save_results(best_individual, best_result, best_results)

        return {
            "best_prompt": best_individual.prompt,
            "best_fitness": best_individual.fitness,
            "best_result": best_result,
            "evolution_history": best_results,
        }

    def save_results(
        self,
        best_individual: Individual,
        best_result: Dict[str, Any],
        evolution_history: List[Dict[str, Any]]
    ):
        """保存结果到 result/ 文件夹"""
        print(f"\n💾 保存结果到 {self.exp_dir}...")

        # 1. 保存最终 prompt
        prompt_file = self.exp_dir / "final_prompt.txt"
        with open(prompt_file, "w", encoding="utf-8") as f:
            f.write(f"# 最终优化的 Prompt (适应度: {best_individual.fitness:.4f})\n")
            f.write(f"# 实验 ID: {self.exp_id}\n")
            f.write(f"# 生成时间: {datetime.now().isoformat()}\n\n")
            f.write(best_individual.prompt)
        print(f"  ✓ {prompt_file}")

        # 2. 保存分类报告 (precision, recall, f1-score)
        report = best_result["classification_report"]
        metrics_file = self.exp_dir / "classification_metrics.json"
        with open(metrics_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"  ✓ {metrics_file}")

        # 3. 保存分类报告的易读版本
        readable_report_file = self.exp_dir / "classification_report.txt"
        fitness_metric = self.config.get("fitness_metric", DEFAULT_FITNESS_METRIC)
        with open(readable_report_file, "w", encoding="utf-8") as f:
            f.write(f"PrimeVul Layer-1 分类报告\n")
            f.write(f"{'='*80}\n")
            f.write(f"实验 ID: {self.exp_id}\n")
            f.write(f"适应度指标: {fitness_metric}\n")
            f.write(f"最终适应度: {best_individual.fitness:.4f}\n")
            f.write(f"准确率: {_safe_metric(best_result, 'accuracy'):.4f}\n")
            f.write(f"Macro F1: {_safe_metric(best_result, 'macro_f1'):.4f}\n")
            f.write(f"Weighted F1: {_safe_metric(best_result, 'weighted_f1'):.4f}\n")
            f.write(f"总样本数: {best_result['total_samples']}\n")
            f.write(f"Batch 大小: {self.batch_size}\n")
            f.write(f"Batch 总数: {best_result['num_batches']}\n\n")

            f.write(f"各类别性能指标:\n")
            f.write(f"{'-'*80}\n")
            f.write(f"{'Category':<25} {'Precision':>10} {'Recall':>10} {'F1-Score':>10} {'Support':>10}\n")
            f.write(f"{'-'*80}\n")

            for category in CWE_MAJOR_CATEGORIES:
                if category in report:
                    metrics = report[category]
                    f.write(f"{category:<25} {metrics['precision']:>10.4f} {metrics['recall']:>10.4f} "
                           f"{metrics['f1-score']:>10.4f} {metrics['support']:>10}\n")

            f.write(f"{'-'*80}\n")
            f.write(f"{'Overall (macro avg)':<25} {report['macro avg']['precision']:>10.4f} "
                   f"{report['macro avg']['recall']:>10.4f} {report['macro avg']['f1-score']:>10.4f} "
                   f"{report['macro avg']['support']:>10}\n")
            f.write(f"{'Overall (weighted avg)':<25} {report['weighted avg']['precision']:>10.4f} "
                   f"{report['weighted avg']['recall']:>10.4f} {report['weighted avg']['f1-score']:>10.4f} "
                   f"{report['weighted avg']['support']:>10}\n")

        print(f"  ✓ {readable_report_file}")

        # 4. 保存混淆矩阵
        confusion_file = self.exp_dir / "confusion_matrix.json"
        with open(confusion_file, "w", encoding="utf-8") as f:
            json.dump({
                "labels": CWE_MAJOR_CATEGORIES,
                "matrix": best_result["confusion_matrix"]
            }, f, indent=2, ensure_ascii=False)
        print(f"  ✓ {confusion_file}")

        # 5. 保存 batch 分析历史
        batch_history_file = self.exp_dir / "batch_analyses.jsonl"
        with open(batch_history_file, "w", encoding="utf-8") as f:
            for analysis in best_result["batch_analyses"]:
                f.write(json.dumps(analysis, ensure_ascii=False) + "\n")
        print(f"  ✓ {batch_history_file}")

        # 6. 保存完整的实验配置和结果
        summary_file = self.exp_dir / "experiment_summary.json"
        summary = {
            "experiment_id": self.exp_id,
            "timestamp": datetime.now().isoformat(),
            "config": self.config,
            "fitness_metric": self.config.get("fitness_metric", DEFAULT_FITNESS_METRIC),
            "best_fitness": best_individual.fitness,
            "accuracy": _safe_metric(best_result, "accuracy"),
            "macro_f1": _safe_metric(best_result, "macro_f1"),
            "weighted_f1": _safe_metric(best_result, "weighted_f1"),
            "best_prompt": best_individual.prompt,
            "total_samples": best_result["total_samples"],
            "num_batches": best_result["num_batches"],
            "batch_size": self.batch_size,
            "classification_report": report,
        }
        with open(summary_file, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        print(f"  ✓ {summary_file}")

        # 7. 打印最终报告到控制台
        print(f"\n📊 最终分类性能:")
        print(f"{'-'*80}")
        print(f"{'Category':<25} {'Precision':>10} {'Recall':>10} {'F1-Score':>10} {'Support':>10}")
        print(f"{'-'*80}")

        for category in CWE_MAJOR_CATEGORIES:
            if category in report:
                metrics = report[category]
                print(f"{category:<25} {metrics['precision']:>10.4f} {metrics['recall']:>10.4f} "
                     f"{metrics['f1-score']:>10.4f} {metrics['support']:>10.0f}")

        print(f"{'-'*80}")
        print(f"{'Overall (macro avg)':<25} {report['macro avg']['precision']:>10.4f} "
              f"{report['macro avg']['recall']:>10.4f} {report['macro avg']['f1-score']:>10.4f}")


def main():
    """主入口函数"""
    from dotenv import load_dotenv
    load_dotenv()

    import argparse

    parser = argparse.ArgumentParser(description="EvoPrompt Main - PrimeVul Layer-1 并发漏洞分类")
    parser.add_argument("--mode", choices=["flat", "hierarchical", "mulvul", "baseline", "coevolution"],
                       default="flat", help="检测策略: flat=11类平铺, hierarchical=三层级联, mulvul=路由+检测+聚合, baseline=零样本, coevolution=多智能体协同")
    parser.add_argument("--batch-size", type=int, default=16, help="每个 batch 的样本数")
    parser.add_argument("--max-generations", type=int, default=5, help="最大进化代数")
    parser.add_argument("--primevul-dir", type=str, default="./data/primevul/primevul",
                       help="PrimeVul 数据集目录")
    parser.add_argument("--sample-dir", type=str, default="./data/primevul_1percent_sample",
                       help="采样数据目录")
    parser.add_argument("--experiment-id", type=str, default=None,
                       help="实验 ID (默认自动生成)")
    parser.add_argument("--max-retries", type=int, default=3,
                       help="API 调用最大重试次数")
    parser.add_argument("--retry-delay", type=float, default=1.0,
                       help="重试基础延迟时间（秒）")
    parser.add_argument("--no-checkpoint", action="store_true",
                       help="禁用 checkpoint 功能")
    parser.add_argument("--auto-recover", action="store_true",
                       help="自动从 checkpoint 恢复（不询问）")
    parser.add_argument(
        "--balance-mode",
        choices=["target", "major", "layer1"],
        default="layer1",
        help="采样均衡模式: target=二分类, major/layer1=CWE大类",
    )
    parser.add_argument("--fitness-metric", choices=sorted(VALID_FITNESS_METRICS), default=DEFAULT_FITNESS_METRIC,
                       help=f"进化适应度指标 (default: {DEFAULT_FITNESS_METRIC})")
    parser.add_argument("--sample-ratio", type=float, default=0.10,
                       help="采样比例 (默认 0.10 = 10%%)")
    parser.add_argument("--dev-ratio", type=float, default=0.3,
                       help="开发集比例 (默认 0.3)")
    parser.add_argument("--remove-benign-train", action="store_true",
                       help="从训练集中移除 Benign 样本")
    parser.add_argument("--min-dev-per-label", type=int, default=5,
                       help="每个类别在 dev 集中的最少样本数 (默认 5)")
    parser.add_argument(
        "--force-resample",
        action="store_true",
        help="无论采样目录是否存在都重新采样",
    )
    parser.add_argument(
        "--enable-rag",
        action="store_true",
        help="启用 RAG 检索增强",
    )
    parser.add_argument(
        "--enable-meta",
        action="store_true",
        help="启用错误累积+元学习调优",
    )
    parser.add_argument(
        "--max-category-drop",
        type=float,
        default=DEFAULT_MAX_CATEGORY_DROP,
        help=f"最大允许的单类别 F1 下降幅度 (default: {DEFAULT_MAX_CATEGORY_DROP})",
    )

    args = parser.parse_args()

    if not (0.0 <= args.max_category_drop <= 1.0):
        parser.error(
            f"--max-category-drop must be between 0.0 and 1.0, got {args.max_category_drop}"
        )

    # 创建配置
    config = {
        "batch_size": args.batch_size,
        "max_generations": args.max_generations,
        "primevul_dir": args.primevul_dir,
        "sample_dir": args.sample_dir,
        "experiment_id": args.experiment_id,
        "max_retries": args.max_retries,
        "retry_delay": args.retry_delay,
        "enable_checkpoint": not args.no_checkpoint,
        "auto_recover": args.auto_recover,
        "mode": args.mode,
        "balance_mode": args.balance_mode,
        "fitness_metric": args.fitness_metric,
        "sample_ratio": args.sample_ratio,
        "dev_ratio": args.dev_ratio,
        "remove_benign_train": args.remove_benign_train,
        "min_dev_per_label": args.min_dev_per_label,
        "force_resample": args.force_resample,
        "enable_rag": args.enable_rag,
        "enable_meta": args.enable_meta,
        "max_category_drop": args.max_category_drop,
    }

    # 创建并运行 pipeline
    pipeline = PrimeVulLayer1Pipeline(config)
    results = pipeline.run_evolution()

    print(f"\n✅ 实验完成!")
    print(f"📂 结果已保存到: {pipeline.exp_dir}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
