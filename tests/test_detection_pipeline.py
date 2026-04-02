"""Tests for unified detection pipeline."""
import asyncio
from evoprompt.detectors.pipeline import (
    DetectionContext,
    PipelineStep,
    CodeEnhancementStep,
    PromptBuildStep,
    ResponseParseStep,
    PathSelectionStep,
    LLMInferenceStep,
    DetectionPipeline,
    SequentialStrategy,
    ParallelStrategy,
)
from evoprompt.detectors.scoring import (
    ScoredPrediction,
    DetectionPath,
    MaxConfidenceSelection,
)
from evoprompt.llm.stub import DeterministicStubClient
from evoprompt.prompts.prompt_set import PromptSet
from evoprompt.prompts.template import (
    PromptTemplate,
    PromptSection,
    PromptMetadata,
)
from evoprompt.detectors.parallel_hierarchical_detector import (
    NoOpEnhancer,
)


class TestDetectionContext:
    def test_creation(self):
        ctx = DetectionContext(code="int x = 0;")
        assert ctx.code == "int x = 0;"
        assert ctx.enhanced_code == ""
        assert ctx.prompts == {}
        assert ctx.raw_responses == {}
        assert ctx.predictions == []
        assert ctx.paths == []
        assert ctx.metadata == {}

    def test_accumulates_data(self):
        ctx = DetectionContext(code="test code")
        ctx.enhanced_code = "// enhanced\ntest code"
        ctx.prompts["layer1"] = ["prompt1"]
        ctx.metadata["step"] = "done"
        assert ctx.enhanced_code == "// enhanced\ntest code"
        assert "layer1" in ctx.prompts
        assert ctx.metadata["step"] == "done"


class TestPipelineSteps:
    def test_code_enhancement_step(self):
        enhancer = NoOpEnhancer()
        step = CodeEnhancementStep(enhancer)
        ctx = DetectionContext(code="int x = 0;")
        result = asyncio.run(step.execute(ctx))
        assert result.enhanced_code == "int x = 0;"

    def test_prompt_build_step(self):
        ps = PromptSet()
        ps.set_template(
            1, "Memory",
            PromptTemplate(
                sections=[PromptSection(
                    content="Analyze for memory bugs:\n{input}"
                )],
                metadata=PromptMetadata(
                    layer=1, category="Memory"
                ),
            )
        )
        step = PromptBuildStep(prompt_set=ps, layer=1)
        ctx = DetectionContext(code="int buf[10];")
        ctx.enhanced_code = "int buf[10];"
        result = asyncio.run(step.execute(ctx))
        assert "Memory" in result.prompts
        assert "int buf[10];" in result.prompts["Memory"]

    def test_llm_inference_step(self):
        stub = DeterministicStubClient(
            default_response="CONFIDENCE: 0.85"
        )
        step = LLMInferenceStep(llm_client=stub)
        ctx = DetectionContext(code="test")
        ctx.prompts = {"Memory": "Analyze: test code"}
        result = asyncio.run(step.execute(ctx))
        assert "Memory" in result.raw_responses
        assert "CONFIDENCE: 0.85" in result.raw_responses[
            "Memory"
        ]

    def test_response_parse_step(self):
        step = ResponseParseStep()
        ctx = DetectionContext(code="test")
        ctx.raw_responses = {
            "Memory": "CONFIDENCE: 0.85",
            "Benign": "CONFIDENCE: 0.2",
        }
        result = asyncio.run(step.execute(ctx))
        assert len(result.predictions) == 2
        # Check predictions are ScoredPrediction instances
        assert all(
            isinstance(p, ScoredPrediction)
            for p in result.predictions
        )

    def test_path_selection_step(self):
        strategy = MaxConfidenceSelection()
        step = PathSelectionStep(strategy=strategy)
        ctx = DetectionContext(code="test")
        ctx.paths = [
            DetectionPath(
                layer1_category="Memory",
                layer1_confidence=0.9,
            ),
            DetectionPath(
                layer1_category="Benign",
                layer1_confidence=0.3,
            ),
        ]
        result = asyncio.run(step.execute(ctx))
        assert len(result.paths) >= 1
        assert result.paths[0].layer1_category == "Memory"


class TestExecutionStrategy:
    def test_sequential_strategy(self):
        steps = []
        strategy = SequentialStrategy(steps)
        ctx = DetectionContext(code="test")
        result = asyncio.run(strategy.execute(ctx))
        assert isinstance(result, DetectionContext)

    def test_parallel_strategy(self):
        strategy = ParallelStrategy(max_concurrent=4)
        # Just verify it can be constructed
        assert strategy.max_concurrent == 4


class TestDetectionPipeline:
    def test_full_pipeline_with_stub(self):
        stub = DeterministicStubClient(
            default_response="CONFIDENCE: 0.75"
        )
        ps = PromptSet()
        ps.set_template(
            1, "Memory",
            PromptTemplate(
                sections=[PromptSection(
                    content=(
                        "Analyze for memory bugs:\n{input}"
                    )
                )],
                metadata=PromptMetadata(
                    layer=1, category="Memory"
                ),
            )
        )
        ps.set_template(
            1, "Benign",
            PromptTemplate(
                sections=[PromptSection(
                    content="Check if safe:\n{input}"
                )],
                metadata=PromptMetadata(
                    layer=1, category="Benign"
                ),
            )
        )

        pipeline = DetectionPipeline(
            llm_client=stub,
            prompt_set=ps,
            enhancer=NoOpEnhancer(),
            selection_strategy=MaxConfidenceSelection(),
        )
        result = asyncio.run(
            pipeline.detect_async("int buf[10];")
        )
        assert isinstance(result, DetectionContext)
        assert len(result.predictions) > 0

    def test_pipeline_context_flows_through(self):
        stub = DeterministicStubClient(
            default_response="CONFIDENCE: 0.5"
        )
        ps = PromptSet()
        ps.set_template(
            1, "Memory",
            PromptTemplate(
                sections=[PromptSection(
                    content="Check: {input}"
                )],
            )
        )
        pipeline = DetectionPipeline(
            llm_client=stub,
            prompt_set=ps,
        )
        result = asyncio.run(
            pipeline.detect_async("int x;")
        )
        assert result.code == "int x;"
        assert result.enhanced_code != ""

    def test_pipeline_detect_sync(self):
        stub = DeterministicStubClient(
            default_response="CONFIDENCE: 0.6"
        )
        ps = PromptSet()
        ps.set_template(
            1, "Memory",
            PromptTemplate(
                sections=[PromptSection(
                    content="Analyze: {input}"
                )],
            )
        )
        pipeline = DetectionPipeline(
            llm_client=stub,
            prompt_set=ps,
        )
        result = pipeline.detect("int x;")
        assert isinstance(result, DetectionContext)

    def test_custom_step_injection(self):
        """Test that custom steps can be added."""

        class CustomStep(PipelineStep):
            async def execute(
                self, context: DetectionContext
            ) -> DetectionContext:
                context.metadata["custom"] = True
                return context

        stub = DeterministicStubClient(
            default_response="CONFIDENCE: 0.5"
        )
        ps = PromptSet()
        ps.set_template(
            1, "Memory",
            PromptTemplate(
                sections=[PromptSection(
                    content="Check: {input}"
                )],
            )
        )
        pipeline = DetectionPipeline(
            llm_client=stub,
            prompt_set=ps,
            extra_steps=[CustomStep()],
        )
        result = asyncio.run(
            pipeline.detect_async("int x;")
        )
        assert result.metadata.get("custom") is True
