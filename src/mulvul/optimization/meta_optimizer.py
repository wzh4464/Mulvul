"""Meta-level prompt optimizer using high-level LLM (Claude 4.5).

This module implements a meta-optimization approach where:
1. A detection model (e.g., GPT-4) performs vulnerability detection
2. A meta model (e.g., Claude 4.5) analyzes performance and suggests prompt improvements
3. The meta model receives batch statistics and historical trends to guide evolution
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
import json

from ..llm.client import LLMClient
from ..evaluators.statistics import DetectionStatistics, BatchStatistics


@dataclass
class OptimizationContext:
    """Context information for meta-optimization.

    This contains all the information the meta-optimizer needs to
    suggest improvements to prompts.

    Attributes:
        current_prompt: The current prompt being optimized
        current_stats: Current performance statistics
        historical_stats: Statistics from previous generations
        batch_stats: Recent batch statistics
        improvement_suggestions: Automated suggestions from statistics
        generation: Current generation number
        metadata: Additional context metadata
    """

    current_prompt: str
    current_stats: DetectionStatistics
    historical_stats: List[DetectionStatistics] = field(default_factory=list)
    batch_stats: List[BatchStatistics] = field(default_factory=list)
    improvement_suggestions: List[str] = field(default_factory=list)
    generation: int = 0
    metadata: Dict = field(default_factory=dict)


class MetaOptimizer:
    """Meta-level optimizer that uses a high-capability LLM to improve prompts.

    The meta-optimizer analyzes:
    - Current prompt performance (accuracy, F1, per-category errors)
    - Historical trends (is it improving or degrading?)
    - Specific error patterns (which categories have high error rates?)
    - Misclassification patterns (false positives vs false negatives)

    Based on this analysis, it generates improved prompts.
    """

    def __init__(self, meta_llm_client: LLMClient, temperature: float = 0.7):
        """Initialize meta-optimizer.

        Args:
            meta_llm_client: High-capability LLM client (e.g., Claude 4.5)
            temperature: Temperature for meta-model generation
        """
        self.meta_llm_client = meta_llm_client
        self.temperature = temperature

    def optimize_prompt(
        self,
        context: OptimizationContext,
        optimization_type: str = "improve"
    ) -> str:
        """Optimize a prompt using meta-level analysis.

        Args:
            context: Optimization context with current performance and history
            optimization_type: Type of optimization ("improve", "crossover", "mutate")

        Returns:
            Optimized prompt string
        """
        if optimization_type == "crossover":
            return self._optimize_crossover(context)
        elif optimization_type == "mutate":
            return self._optimize_mutation(context)
        else:
            return self._optimize_improvement(context)

    def _optimize_improvement(self, context: OptimizationContext) -> str:
        """Generate improved prompt based on performance analysis."""
        meta_prompt = self._create_improvement_meta_prompt(context)

        try:
            response = self.meta_llm_client.generate(
                meta_prompt,
                temperature=self.temperature
            )
            return self._extract_prompt_from_response(response)
        except Exception as e:
            print(f"Meta-optimization failed: {e}")
            return context.current_prompt  # Fallback to current prompt

    def _optimize_crossover(self, context: OptimizationContext) -> str:
        """Generate crossover prompt combining multiple prompts."""
        # Assumes context.metadata contains parent prompts
        parent1 = context.metadata.get("parent1", context.current_prompt)
        parent2 = context.metadata.get("parent2", context.current_prompt)

        meta_prompt = f"""You are an expert prompt engineer for code vulnerability detection.

You have two prompts that perform vulnerability detection. Analyze their strengths and create a new prompt that combines their best elements.

**Prompt 1:**
{parent1}

**Prompt 2:**
{parent2}

**Performance Context:**
- Current accuracy: {context.current_stats.accuracy:.2%}
- F1 score: {context.current_stats.f1_score:.2%}
- Generation: {context.generation}

**Task:**
Create a NEW prompt that:
1. Combines the most effective elements from both parent prompts
2. Addresses any weaknesses shown in the performance metrics
3. Maintains clarity and specificity for vulnerability detection
4. Uses {{input}} placeholder for code to be analyzed
5. Expects binary output: 'vulnerable' or 'benign'

Output ONLY the new prompt, nothing else:"""

        try:
            response = self.meta_llm_client.generate(
                meta_prompt,
                temperature=self.temperature
            )
            return self._extract_prompt_from_response(response)
        except Exception as e:
            print(f"Meta-crossover failed: {e}")
            return parent1  # Fallback

    def _optimize_mutation(self, context: OptimizationContext) -> str:
        """Generate mutated prompt with guided changes."""
        meta_prompt = self._create_mutation_meta_prompt(context)

        try:
            response = self.meta_llm_client.generate(
                meta_prompt,
                temperature=self.temperature
            )
            return self._extract_prompt_from_response(response)
        except Exception as e:
            print(f"Meta-mutation failed: {e}")
            return context.current_prompt  # Fallback

    def _create_improvement_meta_prompt(self, context: OptimizationContext) -> str:
        """Create meta-prompt for improvement-based optimization."""
        # Prepare statistics summary
        stats_summary = context.current_stats.get_summary()

        # Format performance metrics
        perf_text = f"""Current Performance:
- Accuracy: {stats_summary['accuracy']:.2%}
- Precision: {stats_summary['precision']:.2%}
- Recall: {stats_summary['recall']:.2%}
- F1 Score: {stats_summary['f1_score']:.2%}
- True Positives: {stats_summary['true_positives']}
- False Positives: {stats_summary['false_positives']}
- False Negatives: {stats_summary['false_negatives']}"""

        # Add category-specific stats if available
        if 'category_stats' in stats_summary:
            perf_text += "\n\nPer-Category Performance:"
            for cat, cat_stats in stats_summary['category_stats'].items():
                perf_text += f"\n- {cat}: Accuracy {cat_stats['accuracy']:.2%}, Error Rate {cat_stats['error_rate']:.2%}"
                perf_text += f" (FP: {cat_stats['fp']}, FN: {cat_stats['fn']})"

        # Add improvement suggestions
        suggestions_text = ""
        if context.improvement_suggestions:
            suggestions_text = "\n\nAutomated Analysis Suggestions:\n"
            suggestions_text += "\n".join(f"- {s}" for s in context.improvement_suggestions)

        # Add historical context if available
        historical_text = ""
        if context.historical_stats:
            prev_stats = context.historical_stats[-1].get_summary()
            acc_change = stats_summary['accuracy'] - prev_stats['accuracy']
            historical_text = f"\n\nHistorical Context:\n- Previous accuracy: {prev_stats['accuracy']:.2%}\n- Accuracy change: {acc_change:+.2%}"

        meta_prompt = f"""You are an expert prompt engineer specializing in code vulnerability detection systems.

Your task is to improve a prompt used for detecting security vulnerabilities in code. The prompt is evaluated on real vulnerability datasets with diverse CWE types.

**Current Prompt:**
{context.current_prompt}

{perf_text}
{suggestions_text}
{historical_text}

**Your Task:**
Based on the performance metrics and error patterns, create an IMPROVED version of this prompt that:

1. **Addresses Specific Weaknesses:**
   - If precision is low (many false positives), make the prompt more conservative and specific
   - If recall is low (many false negatives), make the prompt more sensitive to potential vulnerabilities
   - If certain categories have high error rates, add specific guidance for those vulnerability types

2. **Maintains Strengths:**
   - Keep elements that contribute to good performance
   - Preserve the core structure if it's working well

3. **Technical Requirements:**
   - Must use {{input}} placeholder for code to be analyzed
   - Must instruct the model to respond with 'vulnerable' or 'benign'
   - Should be clear, specific, and actionable

4. **Strategic Improvements:**
   - Add examples of vulnerability patterns if needed
   - Include specific CWE types to watch for
   - Provide clear decision criteria

Output ONLY the improved prompt, nothing else. Do not include explanations or meta-commentary:"""

        return meta_prompt

    def _create_mutation_meta_prompt(self, context: OptimizationContext) -> str:
        """Create meta-prompt for mutation-based optimization."""
        stats_summary = context.current_stats.get_summary()

        meta_prompt = f"""You are an expert prompt engineer for code vulnerability detection.

Generate a MUTATED version of this prompt with small but meaningful changes:

**Original Prompt:**
{context.current_prompt}

**Current Performance:**
- Accuracy: {stats_summary['accuracy']:.2%}
- F1 Score: {stats_summary['f1_score']:.2%}

**Mutation Guidelines:**
1. Make 1-3 targeted changes (not wholesale rewrite)
2. Focus on:
   - Rewording instructions for clarity
   - Adding or removing specific vulnerability types
   - Adjusting the level of detail
   - Changing the structure slightly
3. Preserve the {{input}} placeholder
4. Keep the 'vulnerable'/'benign' output format

Output ONLY the mutated prompt:"""

        return meta_prompt

    def _extract_prompt_from_response(self, response: str) -> str:
        """Extract the actual prompt from meta-model response.

        The meta-model might include explanations or formatting.
        This method extracts just the prompt content.
        """
        # Clean up response
        response = response.strip()

        # Remove common meta-commentary patterns
        lines = response.split('\n')
        prompt_lines = []
        in_prompt = False

        for line in lines:
            # Skip meta-commentary
            if line.startswith('**') or line.startswith('##'):
                continue
            if line.lower().startswith('explanation:') or line.lower().startswith('note:'):
                break

            # Try to detect the start of actual prompt
            if '{input}' in line or 'analyze' in line.lower() or 'code' in line.lower():
                in_prompt = True

            if in_prompt or (line and not line.startswith('#')):
                prompt_lines.append(line)

        if prompt_lines:
            extracted = '\n'.join(prompt_lines).strip()
            # Ensure it has the placeholder
            if '{input}' in extracted:
                return extracted

        # Fallback: return entire response if extraction failed
        return response

    def batch_optimize_prompts(
        self,
        prompts: List[str],
        contexts: List[OptimizationContext]
    ) -> List[str]:
        """Optimize multiple prompts in batch.

        Args:
            prompts: List of prompts to optimize
            contexts: Corresponding optimization contexts

        Returns:
            List of optimized prompts
        """
        optimized = []
        for prompt, context in zip(prompts, contexts):
            optimized_prompt = self.optimize_prompt(context)
            optimized.append(optimized_prompt)
        return optimized

    def analyze_population(
        self,
        prompts: List[str],
        stats_list: List[DetectionStatistics]
    ) -> Dict:
        """Analyze a population of prompts and provide insights.

        Args:
            prompts: List of prompts in the population
            stats_list: Corresponding statistics for each prompt

        Returns:
            Dictionary with analysis insights
        """
        analysis = {
            "population_size": len(prompts),
            "avg_accuracy": sum(s.accuracy for s in stats_list) / len(stats_list) if stats_list else 0,
            "avg_f1": sum(s.f1_score for s in stats_list) / len(stats_list) if stats_list else 0,
            "best_accuracy": max((s.accuracy for s in stats_list), default=0),
            "worst_accuracy": min((s.accuracy for s in stats_list), default=0),
        }

        # Compute variance
        if stats_list:
            mean_acc = analysis["avg_accuracy"]
            variance = sum((s.accuracy - mean_acc) ** 2 for s in stats_list) / len(stats_list)
            analysis["accuracy_variance"] = variance
            analysis["accuracy_std"] = variance ** 0.5

        return analysis
