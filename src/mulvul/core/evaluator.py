"""Evaluator for prompt performance assessment."""

import json
import os
import logging
from typing import Dict, Any, List, Optional, Protocol
import numpy as np

from ..llm.client import LLMClient
from ..data.dataset import Dataset
from ..metrics.base import Metric

logger = logging.getLogger(__name__)


class EvaluationResult:
    """Container for evaluation results."""
    
    def __init__(self, score: float, details: Optional[Dict[str, Any]] = None):
        self.score = score
        self.details = details or {}
        
    def __repr__(self):
        return f"EvaluationResult(score={self.score}, details={self.details})"


class Evaluator:
    """Modern evaluator for prompt performance assessment."""

    def __init__(
        self,
        dataset: Dataset,
        metric: Metric,
        llm_client: LLMClient,
        template_config: Optional[Dict[str, Any]] = None
    ):
        self.dataset = dataset
        self.metric = metric
        self.llm_client = llm_client
        self.config = template_config or {}

        # 静态分析配置
        self.static_analysis_enabled = self.config.get("enable_static_analysis", False)
        self.analysis_cache = None
        self.analyzers = {}

        if self.static_analysis_enabled:
            self._initialize_static_analysis()

    def _initialize_static_analysis(self) -> None:
        """初始化静态分析器和缓存"""
        try:
            from ..analysis.cache import AnalysisCache
            from ..analysis.bandit_analyzer import BanditAnalyzer

            # 初始化缓存
            cache_dir = self.config.get("analysis_cache_dir", ".cache/analysis")
            self.analysis_cache = AnalysisCache(cache_dir)

            # 注册可用的分析器
            if BanditAnalyzer.is_available():
                analyzer = BanditAnalyzer()
                self.analyzers['python'] = analyzer
                self.analyzers['py'] = analyzer
                logger.info("Bandit analyzer initialized")
            else:
                logger.warning("Bandit is not available, Python analysis will be skipped")

        except ImportError as e:
            logger.warning(f"Static analysis module not available: {e}")
            self.static_analysis_enabled = False

    def evaluate(self, prompt: str, sample_size: Optional[int] = None, filled_prompts_file: Optional[str] = None) -> EvaluationResult:
        """Evaluate a prompt on the dataset. Optionally log all filled prompt instances."""
        samples = self.dataset.get_samples(sample_size)
        predictions = []
        targets = []
        filled_examples = []

        # 收集静态分析统计
        analysis_stats = {
            "total_analyzed": 0,
            "total_vulnerabilities": 0,
            "high_severity_count": 0,
            "medium_severity_count": 0,
            "low_severity_count": 0,
        }

        for idx, sample in enumerate(samples):
            # Format prompt with sample (may include static analysis)
            formatted_prompt = self._format_prompt(prompt, sample)

            # 收集填充实例
            instance = {
                "template": prompt,
                "filled": formatted_prompt,
                "sample_id": getattr(sample, 'id', idx),
                "generation": getattr(self, 'generation', None),
                "target": getattr(sample, 'target', None)
            }
            filled_examples.append(instance)

            # Get prediction from LLM
            response = self.llm_client.generate(formatted_prompt)
            predictions.append(response)
            targets.append(sample.target)

            # 汇总静态分析结果
            metadata = getattr(sample, 'metadata', {})
            if '_analysis_result' in metadata:
                result = metadata['_analysis_result']
                analysis_stats["total_analyzed"] += 1
                analysis_stats["total_vulnerabilities"] += len(result.vulnerabilities)

                for vuln in result.vulnerabilities:
                    if vuln.severity == "high":
                        analysis_stats["high_severity_count"] += 1
                    elif vuln.severity == "medium":
                        analysis_stats["medium_severity_count"] += 1
                    elif vuln.severity == "low":
                        analysis_stats["low_severity_count"] += 1

        # 写入聚合的填充实例（如指定文件）
        if filled_prompts_file is not None and filled_examples:
            try:
                with open(filled_prompts_file, 'a', encoding='utf-8') as f:
                    for item in filled_examples:
                        f.write(json.dumps(item, ensure_ascii=False) + '\n')
            except Exception as e:
                print(f"⚠️ 填充prompt样例保存失败: {e}")

        # Calculate metric
        score = self.metric.compute(predictions, targets)

        # 构建详细信息
        details = {
            "num_samples": len(samples),
            "predictions": predictions[:5],  # Store first 5 for debugging
            "targets": targets[:5]
        }

        # 添加静态分析统计
        if self.static_analysis_enabled and analysis_stats["total_analyzed"] > 0:
            details["analysis_stats"] = analysis_stats
            details["analysis_summary"] = (
                f"{analysis_stats['total_vulnerabilities']} issues found "
                f"({analysis_stats['high_severity_count']} high, "
                f"{analysis_stats['medium_severity_count']} medium, "
                f"{analysis_stats['low_severity_count']} low) "
                f"in {analysis_stats['total_analyzed']} samples"
            )

        return EvaluationResult(score=score, details=details)
        
    def _format_prompt(self, prompt: str, sample) -> str:
        """Format the prompt with sample data and optional enhancements.

        Args:
            prompt: Template prompt with {input} and/or {nl_ast} placeholders
            sample: Sample object with input_text and metadata

        Returns:
            str: Formatted prompt, optionally enhanced with NL AST and/or static analysis results
        """
        # 基础格式化
        formatted = prompt
        if hasattr(sample, 'input_text'):
            formatted = formatted.replace("{input}", sample.input_text)

        # NL AST 增强
        if "{nl_ast}" in formatted and hasattr(sample, 'metadata'):
            nl_ast = sample.metadata.get("nl_ast")
            if nl_ast:
                # Replace {nl_ast} placeholder with actual NL AST
                formatted = formatted.replace("{nl_ast}", nl_ast)
            else:
                # If nl_ast not available but placeholder exists, remove it or use original code
                formatted = formatted.replace("{nl_ast}", sample.input_text)
                if sample.metadata.get("idx"):
                    logger.debug(f"NL AST not available for sample {sample.metadata['idx']}, using original code")

        # 自动注入 NL AST (可选,如果配置启用且 prompt 中没有明确使用)
        if (self.config.get("auto_inject_nl_ast", False) and
            "{nl_ast}" not in prompt and
            hasattr(sample, 'metadata')):
            nl_ast = sample.metadata.get("nl_ast")
            if nl_ast and nl_ast != sample.input_text:
                # Only inject if NL AST is different from original code
                formatted = f"{formatted}\n\n### Natural Language AST\n{nl_ast}"

        # 静态分析增强
        if self.static_analysis_enabled and hasattr(sample, 'metadata'):
            lang = sample.metadata.get("lang")
            analyzer = self.analyzers.get(lang)

            if analyzer:
                try:
                    # 使用缓存的分析
                    result = analyzer.analyze_with_cache(
                        sample.input_text,
                        lang,
                        self.analysis_cache
                    )

                    if not result.is_empty():
                        summary = result.get_summary()
                        formatted = f"{formatted}\n\n### Static Analysis Hints\n{summary}"

                        # 保存到 sample metadata 供后续使用
                        sample.metadata['_analysis_result'] = result

                except Exception as e:
                    logger.warning(f"Static analysis failed for sample: {e}")

        return formatted


# Legacy evaluator class for backward compatibility
class LegacyEvaluator:
    """Legacy evaluator wrapper for backward compatibility."""
    
    def __init__(self, args):
        """Initialize legacy evaluator with old interface."""
        # Import legacy evaluator
        import sys
        sys.path.append("../../")
        from evaluator import Evaluator as OldEvaluator
        
        self._evaluator = OldEvaluator(args)
        
    def __getattr__(self, name):
        """Delegate to legacy evaluator."""
        return getattr(self._evaluator, name)