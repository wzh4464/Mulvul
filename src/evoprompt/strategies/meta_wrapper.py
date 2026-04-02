"""Meta-learning wrapper for the evolution loop.

Adds error accumulation and meta-learning prompt tuning on top of
the standard PromptEvolver.  After each batch evaluation the wrapper
records misclassification patterns.  When the error rate exceeds a
configurable threshold it asks an LLM to rewrite the prompt so that
the most frequent confusion pairs are addressed.
"""

import logging
import textwrap
from typing import Any, Dict

from evoprompt.meta.error_accumulator import (
    ClassificationError,
    ErrorAccumulator,
)

logger = logging.getLogger(__name__)

# Template used when meta-learning triggers a prompt rewrite.
_META_REWRITE_TEMPLATE = textwrap.dedent("""\
    You are an expert in software security and prompt engineering.

    The current vulnerability-classification prompt has been producing
    the following systematic errors:

    {confusion_summary}

    Current prompt (abbreviated):
    ```
    {current_prompt_abbrev}
    ```

    Rewrite the prompt so that it better distinguishes between the
    confused categories listed above.  Preserve the overall structure,
    the {{input}} placeholder, and any ANALYSIS GUIDANCE markers.

    Output ONLY the improved prompt, nothing else.
""")


class MetaEvolutionWrapper:
    """Wraps PromptEvolver with error accumulation and meta-tuning.

    After each batch evaluation, accumulates error patterns.
    When the error rate exceeds the threshold, triggers a meta-learning
    prompt rewrite that targets specific confusion pairs (e.g.,
    "Memory -> Buffer" confusion).

    The public interface mirrors ``PromptEvolver.evolve_with_feedback``
    so the wrapper is a drop-in replacement.
    """

    def __init__(self, prompt_evolver, llm_client, config: Dict[str, Any]):
        self.inner = prompt_evolver
        self.llm_client = llm_client
        self.config = config

        # Forward builder attribute so callers that access
        # prompt_evolver.builder keep working.
        self.builder = getattr(prompt_evolver, "builder", None)

        self.error_accumulator = ErrorAccumulator(
            threshold_count=config.get("meta_threshold_count", 50),
            threshold_rate=config.get("meta_threshold_rate", 0.15),
            window_size=config.get("meta_window_size", 200),
        )

        self._meta_rewrite_count = 0

        logger.info(
            "MetaEvolutionWrapper initialised "
            "(threshold_count=%d, threshold_rate=%.2f)",
            self.error_accumulator.threshold_count,
            self.error_accumulator.threshold_rate,
        )

    # ------------------------------------------------------------------
    # Public API (same signature as PromptEvolver)
    # ------------------------------------------------------------------

    def evolve_with_feedback(
        self,
        current_prompt: str,
        batch_analysis: Dict[str, Any],
        generation: int,
    ) -> str:
        """Evolve the prompt, optionally applying meta-learning.

        1. Accumulate errors from *batch_analysis*.
        2. If meta-learning should trigger, rewrite the prompt using
           the LLM to target the top confusion patterns.
        3. Otherwise delegate to the inner ``PromptEvolver``.
        """
        # -- Step 1: accumulate errors from this batch ----------------
        self._accumulate_from_batch(batch_analysis)

        # -- Step 2: decide whether to meta-rewrite -------------------
        if self.error_accumulator.should_trigger_meta_learning():
            logger.info(
                "Meta-learning triggered at generation %d "
                "(errors=%d, rate=%.2%%)",
                generation,
                self.error_accumulator.total_errors,
                self.error_accumulator.recent_error_rate,
            )
            rewritten = self._meta_rewrite(current_prompt, generation)
            if rewritten is not None:
                return rewritten
            # If the rewrite failed, fall through to normal evolution.

        # -- Step 3: delegate to inner evolver ------------------------
        return self.inner.evolve_with_feedback(
            current_prompt, batch_analysis, generation
        )

    # ------------------------------------------------------------------
    # Proxy for any other attribute (e.g. evolution_history)
    # ------------------------------------------------------------------

    def __getattr__(self, name: str):
        """Proxy attribute access to the inner evolver."""
        return getattr(self.inner, name)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _accumulate_from_batch(self, batch_analysis: Dict[str, Any]) -> None:
        """Feed batch results into the ErrorAccumulator."""
        error_patterns = batch_analysis.get("error_patterns", {})
        correct_count = batch_analysis.get("correct", 0)

        # Record correct predictions.
        for _ in range(correct_count):
            self.error_accumulator.add_correct_prediction()

        # Record misclassifications.
        for pattern_key, count in error_patterns.items():
            # pattern_key has the form "ActualCategory -> PredictedCategory"
            parts = pattern_key.split(" -> ", 1)
            if len(parts) != 2:
                continue
            actual, predicted = parts[0].strip(), parts[1].strip()

            for _ in range(count):
                error = ClassificationError.from_detection_result(
                    code="",  # no snippet available at this level
                    predicted=predicted,
                    actual=actual,
                    layer=1,
                )
                self.error_accumulator.add_error(error)

    def _meta_rewrite(self, current_prompt: str, generation: int) -> str | None:
        """Ask the LLM to rewrite the prompt based on confusion patterns.

        Returns the new prompt on success, or ``None`` on failure.
        """
        top_patterns = self.error_accumulator.get_top_confusion_patterns(
            top_k=5, layer=1, min_count=2,
        )
        if not top_patterns:
            return None

        confusion_lines = []
        for p in top_patterns:
            confusion_lines.append(
                f"- Predicted '{p.predicted_category}' when actual was "
                f"'{p.actual_category}' ({p.count} times, "
                f"avg confidence {p.avg_confidence:.2f})"
            )
        confusion_summary = "\n".join(confusion_lines)

        # Abbreviate the prompt to avoid blowing up the context.
        abbrev = current_prompt[:2000]
        if len(current_prompt) > 2000:
            abbrev += "\n... (truncated)"

        meta_prompt = _META_REWRITE_TEMPLATE.format(
            confusion_summary=confusion_summary,
            current_prompt_abbrev=abbrev,
        )

        try:
            response = self.llm_client.generate(
                meta_prompt, temperature=0.7, max_tokens=1200,
            ).strip()

            if not response or response == "error":
                logger.warning("Meta-rewrite returned empty/error response")
                return None

            # Basic validation: the rewritten prompt should still contain
            # the {input} placeholder.
            if "{input}" not in response and "{CODE}" not in response:
                logger.warning(
                    "Meta-rewrite response missing {input}/{CODE} placeholder; "
                    "discarding"
                )
                return None

            self.error_accumulator.mark_meta_learning_triggered()
            self._meta_rewrite_count += 1

            logger.info(
                "Meta-rewrite #%d applied (generation %d)",
                self._meta_rewrite_count,
                generation,
            )
            return response

        except Exception as e:
            logger.error("Meta-rewrite failed: %s", e)
            return None
