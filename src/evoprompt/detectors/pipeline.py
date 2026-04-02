"""Unified detection pipeline with composable steps.

Provides a pipeline-based approach to vulnerability detection,
replacing multiple separate detector implementations with a
single configurable pipeline of steps.
"""
from __future__ import annotations

import asyncio
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from evoprompt.detectors.scoring import (
    ScoredPrediction,
    DetectionPath,
    SelectionStrategy,
    MaxConfidenceSelection,
)
from evoprompt.detectors.parallel_hierarchical_detector import (
    NoOpEnhancer,
)
from evoprompt.prompts.prompt_set import PromptSet


@dataclass
class DetectionContext:
    """Context that flows through the detection pipeline.

    Accumulates data as each step processes it.

    Attributes:
        code: Original source code to analyze.
        enhanced_code: Code after enhancement step.
        prompts: Category -> filled prompt text.
        raw_responses: Category -> raw LLM response.
        predictions: Scored predictions from parsing.
        paths: Detection paths built from predictions.
        metadata: Arbitrary metadata from steps.
    """

    code: str
    enhanced_code: str = ""
    prompts: Dict[str, str] = field(
        default_factory=dict
    )
    raw_responses: Dict[str, str] = field(
        default_factory=dict
    )
    predictions: List[ScoredPrediction] = field(
        default_factory=list
    )
    paths: List[DetectionPath] = field(
        default_factory=list
    )
    metadata: Dict[str, Any] = field(
        default_factory=dict
    )


class PipelineStep(ABC):
    """Abstract base class for pipeline steps."""

    @abstractmethod
    async def execute(
        self, context: DetectionContext
    ) -> DetectionContext:
        """Execute this step on the given context.

        Args:
            context: The detection context to process.

        Returns:
            The updated detection context.
        """
        ...


class CodeEnhancementStep(PipelineStep):
    """Enhances code using a CodeEnhancer."""

    def __init__(self, enhancer):
        self._enhancer = enhancer

    async def execute(
        self, context: DetectionContext
    ) -> DetectionContext:
        """Enhance the code and store result."""
        context.enhanced_code = (
            await self._enhancer.enhance_async(
                context.code
            )
        )
        return context


class PromptBuildStep(PipelineStep):
    """Builds prompts for each category at a layer."""

    def __init__(
        self, prompt_set: PromptSet, layer: int = 1
    ):
        self._prompt_set = prompt_set
        self._layer = layer

    async def execute(
        self, context: DetectionContext
    ) -> DetectionContext:
        """Build prompts from templates for the layer."""
        code = context.enhanced_code or context.code
        templates = self._prompt_set._templates
        for (layer, category), template in templates.items():
            if layer == self._layer:
                rendered = template.render(input=code)
                context.prompts[category] = rendered
        return context


class LLMInferenceStep(PipelineStep):
    """Calls LLM for each prompt in the context."""

    def __init__(self, llm_client):
        self._client = llm_client

    async def execute(
        self, context: DetectionContext
    ) -> DetectionContext:
        """Run LLM inference for each prompt."""
        for category, prompt in context.prompts.items():
            response = await self._client.generate_async(
                prompt
            )
            context.raw_responses[category] = response
        return context


_CONFIDENCE_RE = re.compile(
    r"CONFIDENCE:\s*([0-9]*\.?[0-9]+)", re.IGNORECASE
)


class ResponseParseStep(PipelineStep):
    """Parses raw LLM responses into predictions."""

    async def execute(
        self, context: DetectionContext
    ) -> DetectionContext:
        """Parse confidence from raw responses."""
        for category, response in (
            context.raw_responses.items()
        ):
            confidence = 0.5
            match = _CONFIDENCE_RE.search(response)
            if match:
                confidence = float(match.group(1))
            pred = ScoredPrediction(
                category=category,
                confidence=confidence,
                layer=1,
                raw_response=response,
            )
            context.predictions.append(pred)
        # Build detection paths from predictions
        for pred in context.predictions:
            path = DetectionPath(
                layer1_category=pred.category,
                layer1_confidence=pred.confidence,
            )
            context.paths.append(path)
        return context


class PathSelectionStep(PipelineStep):
    """Selects best paths using a SelectionStrategy."""

    def __init__(self, strategy: SelectionStrategy):
        self._strategy = strategy

    async def execute(
        self, context: DetectionContext
    ) -> DetectionContext:
        """Apply selection strategy to paths."""
        if context.paths:
            context.paths = self._strategy.select(
                context.paths
            )
        return context


class SequentialStrategy:
    """Runs pipeline steps sequentially."""

    def __init__(self, steps: List[PipelineStep]):
        self._steps = steps

    async def execute(
        self, context: DetectionContext
    ) -> DetectionContext:
        """Execute all steps in order."""
        for step in self._steps:
            context = await step.execute(context)
        return context


class ParallelStrategy:
    """Strategy for running independent steps in parallel.

    Attributes:
        max_concurrent: Maximum number of concurrent steps.
    """

    def __init__(self, max_concurrent: int = 4):
        self.max_concurrent = max_concurrent

    async def execute(
        self,
        steps: List[PipelineStep],
        context: DetectionContext,
    ) -> DetectionContext:
        """Execute steps concurrently up to limit."""
        sem = asyncio.Semaphore(self.max_concurrent)

        async def run(step):
            async with sem:
                return await step.execute(context)

        await asyncio.gather(
            *(run(s) for s in steps)
        )
        return context


class DetectionPipeline:
    """Unified detection pipeline.

    Composes steps into a configurable pipeline for
    vulnerability detection.
    """

    def __init__(
        self,
        llm_client,
        prompt_set: PromptSet,
        enhancer=None,
        selection_strategy: Optional[
            SelectionStrategy
        ] = None,
        extra_steps: Optional[
            List[PipelineStep]
        ] = None,
        layer: int = 1,
    ):
        self._llm_client = llm_client
        self._prompt_set = prompt_set
        self._enhancer = enhancer or NoOpEnhancer()
        self._selection_strategy = (
            selection_strategy or MaxConfidenceSelection()
        )
        self._extra_steps = extra_steps or []
        self._layer = layer

    def _build_steps(self) -> List[PipelineStep]:
        """Build the ordered list of pipeline steps."""
        steps: List[PipelineStep] = [
            CodeEnhancementStep(self._enhancer),
            PromptBuildStep(
                self._prompt_set, self._layer
            ),
            LLMInferenceStep(self._llm_client),
            ResponseParseStep(),
            PathSelectionStep(self._selection_strategy),
        ]
        steps.extend(self._extra_steps)
        return steps

    async def detect_async(
        self, code: str
    ) -> DetectionContext:
        """Run the detection pipeline asynchronously.

        Args:
            code: Source code to analyze.

        Returns:
            DetectionContext with accumulated results.
        """
        ctx = DetectionContext(code=code)
        strategy = SequentialStrategy(
            self._build_steps()
        )
        return await strategy.execute(ctx)

    def detect(self, code: str) -> DetectionContext:
        """Run the detection pipeline synchronously.

        Args:
            code: Source code to analyze.

        Returns:
            DetectionContext with accumulated results.
        """
        return asyncio.run(self.detect_async(code))
