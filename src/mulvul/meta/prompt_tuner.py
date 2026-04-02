"""Meta-learning prompt tuner for hierarchical detection.

Uses LLM to analyze error patterns and improve detection prompts
through guided refinement.
"""

import asyncio
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple

from ..llm.async_client import AsyncLLMClient
from ..detectors.parallel_hierarchical_detector import HierarchicalPromptSet
from .error_accumulator import ErrorAccumulator, ErrorPattern

# Lazy import to avoid circular dependency
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ..core.prompt_change_logger import PromptChangeLogger


logger = logging.getLogger(__name__)


# Meta-learning prompt template
META_PROMPT_TEMPLATE = """You are an expert in software security and prompt engineering.

Your task is to improve a vulnerability detection prompt that has been making classification errors.

## Current Prompt
```
{current_prompt}
```

## Error Analysis
The prompt is confusing the following categories:

{confusion_patterns}

## Example Errors
{error_examples}

## Task
Rewrite the prompt to better distinguish between the confused categories.

Guidelines:
1. Preserve the overall structure and output format requirements
2. Add specific patterns or indicators that differentiate the confused categories
3. Include negative examples or anti-patterns to avoid false positives/negatives
4. Keep the prompt concise but precise
5. Maintain the {{CODE}} placeholder for code injection
6. Keep any {{{{TRAINABLE_START}}}} and {{{{TRAINABLE_END}}}} markers

Output ONLY the improved prompt, nothing else.
"""


@dataclass
class TuningResult:
    """Result of a prompt tuning operation.
    
    Attributes:
        layer: Detection layer that was tuned
        category: Category whose prompt was tuned
        original_prompt: Original prompt before tuning
        tuned_prompt: New prompt after tuning
        patterns_addressed: Error patterns that were addressed
        success: Whether tuning was successful
        error_message: Error message if tuning failed
        timestamp: When tuning occurred
    """
    layer: int
    category: str
    original_prompt: str
    tuned_prompt: str
    patterns_addressed: List[Tuple[str, str]] = field(default_factory=list)
    success: bool = True
    error_message: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "layer": self.layer,
            "category": self.category,
            "original_prompt": self.original_prompt,
            "tuned_prompt": self.tuned_prompt,
            "success": self.success,
            "error_message": self.error_message,
            "patterns_addressed": [
                {"predicted": p, "actual": a} for p, a in self.patterns_addressed
            ],
            "prompt_length_change": len(self.tuned_prompt) - len(self.original_prompt),
            "timestamp": self.timestamp.isoformat(),
        }


class MetaLearningPromptTuner:
    """Tunes prompts using meta-learning from error patterns.
    
    Analyzes accumulated errors to identify prompts that need improvement,
    then uses an LLM to generate improved prompts.
    """
    
    def __init__(
        self,
        llm_client: AsyncLLMClient,
        min_pattern_count: int = 3,
        max_prompts_per_tuning: int = 5,
        temperature: float = 0.7,
        prompt_change_logger: Optional["PromptChangeLogger"] = None,
    ):
        """Initialize the tuner.

        Args:
            llm_client: LLM client for generating improved prompts
            min_pattern_count: Minimum errors for a pattern to trigger tuning
            max_prompts_per_tuning: Maximum prompts to tune in one session
            temperature: LLM temperature for creative generation
            prompt_change_logger: Always-on prompt change logger
        """
        self.llm_client = llm_client
        self.min_pattern_count = min_pattern_count
        self.max_prompts_per_tuning = max_prompts_per_tuning
        self.temperature = temperature
        self.prompt_change_logger = prompt_change_logger

        # Tuning history
        self._tuning_history: List[TuningResult] = []
    
    async def tune_prompts_async(
        self,
        prompt_set: HierarchicalPromptSet,
        error_accumulator: ErrorAccumulator,
    ) -> List[TuningResult]:
        """Tune prompts based on accumulated errors.
        
        Args:
            prompt_set: Current prompt set to improve
            error_accumulator: Error accumulator with patterns
            
        Returns:
            List of tuning results
        """
        # Identify prompts that need tuning
        prompts_to_tune = self._identify_prompts_to_tune(
            prompt_set, 
            error_accumulator
        )
        
        if not prompts_to_tune:
            logger.info("No prompts identified for tuning")
            return []
        
        logger.info(f"Tuning {len(prompts_to_tune)} prompts")
        
        # Tune each prompt
        results = []
        for prompt_info in prompts_to_tune[:self.max_prompts_per_tuning]:
            result = await self._tune_single_prompt(
                prompt_set=prompt_set,
                layer=prompt_info["layer"],
                category=prompt_info["category"],
                parent=prompt_info.get("parent"),
                patterns=prompt_info["patterns"],
                error_accumulator=error_accumulator,
            )
            results.append(result)
            self._tuning_history.append(result)
        
        # Mark meta-learning as triggered
        error_accumulator.mark_meta_learning_triggered()
        
        # Log summary
        successful = sum(1 for r in results if r.success)
        logger.info(f"Tuning complete: {successful}/{len(results)} successful")
        
        return results
    
    def _identify_prompts_to_tune(
        self,
        prompt_set: HierarchicalPromptSet,
        error_accumulator: ErrorAccumulator,
    ) -> List[Dict[str, Any]]:
        """Identify which prompts need tuning based on error patterns.
        
        Args:
            prompt_set: Current prompt set
            error_accumulator: Error accumulator
            
        Returns:
            List of prompt info dicts with layer, category, patterns
        """
        prompts_to_tune = []
        
        # Analyze each layer
        for layer in [1, 2, 3]:
            patterns = error_accumulator.get_top_confusion_patterns(
                top_k=10,
                layer=layer,
                min_count=self.min_pattern_count,
            )
            
            if not patterns:
                continue
            
            # Group patterns by predicted category (the category making errors)
            by_category: Dict[str, List[ErrorPattern]] = {}
            for pattern in patterns:
                cat = pattern.predicted_category
                if cat not in by_category:
                    by_category[cat] = []
                by_category[cat].append(pattern)
            
            # Create tuning entries
            for category, cat_patterns in by_category.items():
                # Find the prompt
                prompt = None
                parent = None
                
                if layer == 1:
                    prompt = prompt_set.layer1_prompts.get(category)
                elif layer == 2:
                    # Find parent major category
                    for major, middles in prompt_set.layer2_prompts.items():
                        if category in middles:
                            prompt = middles[category]
                            parent = major
                            break
                elif layer == 3:
                    # Find parent middle category
                    for middle, cwes in prompt_set.layer3_prompts.items():
                        if category in cwes:
                            prompt = cwes[category]
                            parent = middle
                            break
                
                if prompt:
                    prompts_to_tune.append({
                        "layer": layer,
                        "category": category,
                        "parent": parent,
                        "patterns": cat_patterns,
                        "total_errors": sum(p.count for p in cat_patterns),
                    })
        
        # Sort by total errors (most problematic first)
        prompts_to_tune.sort(key=lambda x: x["total_errors"], reverse=True)
        
        return prompts_to_tune
    
    async def _tune_single_prompt(
        self,
        prompt_set: HierarchicalPromptSet,
        layer: int,
        category: str,
        parent: Optional[str],
        patterns: List[ErrorPattern],
        error_accumulator: ErrorAccumulator,
    ) -> TuningResult:
        """Tune a single prompt based on error patterns.
        
        Args:
            prompt_set: Current prompt set
            layer: Layer of the prompt
            category: Category of the prompt
            parent: Parent category (for layer 2/3)
            patterns: Error patterns to address
            error_accumulator: Error accumulator for examples
            
        Returns:
            Tuning result
        """
        # Get current prompt
        if layer == 1:
            current_prompt = prompt_set.layer1_prompts.get(category, "")
        elif layer == 2 and parent:
            current_prompt = prompt_set.layer2_prompts.get(parent, {}).get(category, "")
        elif layer == 3 and parent:
            current_prompt = prompt_set.layer3_prompts.get(parent, {}).get(category, "")
        else:
            return TuningResult(
                layer=layer,
                category=category,
                original_prompt="",
                tuned_prompt="",
                success=False,
                error_message="Could not find prompt",
            )
        
        # Format confusion patterns
        confusion_text = "\n".join([
            f"- Predicted '{p.predicted_category}' when actual was '{p.actual_category}' ({p.count} times, avg confidence: {p.avg_confidence:.2f})"
            for p in patterns
        ])
        
        # Get error examples
        example_errors = []
        for pattern in patterns[:3]:  # Top 3 patterns
            errors = error_accumulator.get_errors_for_category(
                category=pattern.predicted_category,
                layer=layer,
                limit=2,
            )
            for error in errors:
                example_errors.append(
                    f"Code: {error.code_snippet[:200]}...\n"
                    f"Predicted: {error.predicted_category}, Actual: {error.actual_category}"
                )
        
        examples_text = "\n\n".join(example_errors) if example_errors else "No specific examples available."
        
        # Generate meta-learning prompt
        meta_prompt = META_PROMPT_TEMPLATE.format(
            current_prompt=current_prompt,
            confusion_patterns=confusion_text,
            error_examples=examples_text,
        )
        
        try:
            # Generate improved prompt
            response = await self.llm_client.generate_async(
                meta_prompt,
                temperature=self.temperature,
            )
            
            tuned_prompt = self._extract_improved_prompt(response, current_prompt)
            
            if not tuned_prompt or tuned_prompt == current_prompt:
                return TuningResult(
                    layer=layer,
                    category=category,
                    original_prompt=current_prompt,
                    tuned_prompt=current_prompt,
                    patterns_addressed=[(p.predicted_category, p.actual_category) for p in patterns],
                    success=False,
                    error_message="No improvement generated",
                )
            
            # Update the prompt set
            prompt_set.update_prompt(
                layer=layer,
                category=category,
                new_prompt=tuned_prompt,
                parent=parent,
            )

            if self.prompt_change_logger:
                self.prompt_change_logger.log_change(
                    operation="meta_tune",
                    prompt_before=current_prompt,
                    prompt_after=tuned_prompt,
                    layer=layer,
                    category=category,
                    trigger_reason="error_pattern",
                    context={
                        "patterns_addressed": [
                            (p.predicted_category, p.actual_category) for p in patterns
                        ],
                        "parent_category": parent,
                    },
                )

            logger.info(f"Successfully tuned Layer {layer} prompt for '{category}'")
            
            return TuningResult(
                layer=layer,
                category=category,
                original_prompt=current_prompt,
                tuned_prompt=tuned_prompt,
                patterns_addressed=[(p.predicted_category, p.actual_category) for p in patterns],
                success=True,
            )
            
        except Exception as e:
            logger.error(f"Failed to tune prompt for {category}: {e}")
            return TuningResult(
                layer=layer,
                category=category,
                original_prompt=current_prompt,
                tuned_prompt=current_prompt,
                patterns_addressed=[(p.predicted_category, p.actual_category) for p in patterns],
                success=False,
                error_message=str(e),
            )
    
    def _extract_improved_prompt(
        self, 
        response: str, 
        original: str
    ) -> str:
        """Extract improved prompt from LLM response.
        
        Args:
            response: Raw LLM response
            original: Original prompt for fallback
            
        Returns:
            Extracted improved prompt
        """
        if not response or response == "error":
            return original
        
        # Try to extract from code blocks
        code_block_pattern = r"```(?:text|prompt)?\n?(.*?)```"
        matches = re.findall(code_block_pattern, response, re.DOTALL)
        
        if matches:
            return matches[0].strip()
        
        # If no code block, use the entire response (cleaned)
        cleaned = response.strip()
        
        # Validate it looks like a prompt (has code placeholder)
        if "{CODE}" in cleaned or "{{CODE}}" in cleaned:
            return cleaned
        
        # Return original if response doesn't look valid
        logger.warning("Generated response doesn't contain code placeholder, keeping original")
        return original
    
    def get_tuning_history(
        self, 
        layer: Optional[int] = None,
        successful_only: bool = False,
    ) -> List[TuningResult]:
        """Get tuning history.
        
        Args:
            layer: Filter by layer
            successful_only: Only return successful tunings
            
        Returns:
            List of tuning results
        """
        results = self._tuning_history
        
        if layer is not None:
            results = [r for r in results if r.layer == layer]
        
        if successful_only:
            results = [r for r in results if r.success]
        
        return results
    
    def get_summary(self) -> Dict[str, Any]:
        """Get tuning summary statistics.
        
        Returns:
            Summary dictionary
        """
        total = len(self._tuning_history)
        successful = sum(1 for r in self._tuning_history if r.success)
        
        by_layer = {1: 0, 2: 0, 3: 0}
        for r in self._tuning_history:
            if r.success:
                by_layer[r.layer] += 1
        
        return {
            "total_tuning_attempts": total,
            "successful_tunings": successful,
            "success_rate": f"{successful / total:.1%}" if total > 0 else "N/A",
            "tunings_by_layer": by_layer,
            "last_tuning": (
                self._tuning_history[-1].timestamp.isoformat() 
                if self._tuning_history else None
            ),
        }
