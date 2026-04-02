"""Agent definitions for multi-agent vulnerability detection framework.

This module defines two main agent types:
1. DetectionAgent: Uses a lower-level LLM (e.g., GPT-4) to detect vulnerabilities
2. MetaAgent: Uses a higher-level LLM (e.g., Claude 4.5) to optimize prompts
"""

from enum import Enum
from dataclasses import dataclass
from typing import List, Dict, Optional

from ..llm.client import LLMClient
from ..evaluators.statistics import DetectionStatistics
from ..optimization.meta_optimizer import MetaOptimizer, OptimizationContext


class AgentRole(Enum):
    """Agent role in the multi-agent system."""
    DETECTION = "detection"  # Performs vulnerability detection
    META = "meta"  # Optimizes prompts based on performance


@dataclass
class AgentConfig:
    """Configuration for an agent.

    Attributes:
        role: Agent role (detection or meta)
        model_name: Name of the LLM model to use
        temperature: Temperature for generation
        max_tokens: Maximum tokens to generate
        batch_size: Batch size for processing
    """

    role: AgentRole
    model_name: str
    temperature: float = 0.1
    max_tokens: Optional[int] = None
    batch_size: int = 8


class Agent:
    """Base class for agents in the multi-agent system."""

    def __init__(self, config: AgentConfig, llm_client: LLMClient):
        """Initialize agent.

        Args:
            config: Agent configuration
            llm_client: LLM client for this agent
        """
        self.config = config
        self.llm_client = llm_client
        self.role = config.role

    def __repr__(self):
        return f"{self.__class__.__name__}(role={self.role.value}, model={self.config.model_name})"


class DetectionAgent(Agent):
    """Agent responsible for detecting vulnerabilities using prompts.

    This agent:
    - Takes a prompt and code samples
    - Performs vulnerability detection
    - Returns predictions and can collect statistics
    """

    def __init__(self, config: AgentConfig, llm_client: LLMClient):
        """Initialize detection agent.

        Args:
            config: Agent configuration with role=DETECTION
            llm_client: LLM client (e.g., GPT-4)
        """
        if config.role != AgentRole.DETECTION:
            raise ValueError("DetectionAgent must have role=DETECTION")
        super().__init__(config, llm_client)

    def detect(self, prompt: str, code_samples: List[str]) -> List[str]:
        """Perform vulnerability detection on code samples.

        Args:
            prompt: Detection prompt template (should contain {input} placeholder)
            code_samples: List of code samples to analyze

        Returns:
            List of predictions ('vulnerable' or 'benign')
        """
        # Format prompts for each sample
        formatted_prompts = [
            prompt.replace("{input}", code)
            for code in code_samples
        ]

        # Batch generate predictions
        predictions = self.llm_client.batch_generate(
            formatted_prompts,
            temperature=self.config.temperature,
            max_tokens=self.config.max_tokens,
            batch_size=self.config.batch_size,
        )

        # Normalize predictions
        normalized = []
        for pred in predictions:
            pred_lower = pred.lower().strip()
            if "vulnerable" in pred_lower:
                normalized.append("vulnerable")
            elif "benign" in pred_lower:
                normalized.append("benign")
            else:
                # Default to benign if unclear
                normalized.append("benign")

        return normalized

    def detect_single(self, prompt: str, code: str) -> str:
        """Detect vulnerability in a single code sample.

        Args:
            prompt: Detection prompt template
            code: Code sample to analyze

        Returns:
            Prediction ('vulnerable' or 'benign')
        """
        formatted_prompt = prompt.replace("{input}", code)
        response = self.llm_client.generate(
            formatted_prompt,
            temperature=self.config.temperature,
            max_tokens=self.config.max_tokens,
        )

        response_lower = response.lower().strip()
        if "vulnerable" in response_lower:
            return "vulnerable"
        else:
            return "benign"


class MetaAgent(Agent):
    """Agent responsible for meta-level prompt optimization.

    This agent:
    - Analyzes detection performance statistics
    - Receives batch performance and historical trends
    - Generates improved prompts using meta-optimization
    """

    def __init__(self, config: AgentConfig, llm_client: LLMClient):
        """Initialize meta agent.

        Args:
            config: Agent configuration with role=META
            llm_client: High-capability LLM client (e.g., Claude 4.5)
        """
        if config.role != AgentRole.META:
            raise ValueError("MetaAgent must have role=META")
        super().__init__(config, llm_client)

        # Create meta-optimizer
        self.optimizer = MetaOptimizer(
            meta_llm_client=llm_client,
            temperature=config.temperature
        )

    def improve_prompt(
        self,
        current_prompt: str,
        current_stats: DetectionStatistics,
        historical_stats: List[DetectionStatistics] = None,
        improvement_suggestions: List[str] = None,
        generation: int = 0,
    ) -> str:
        """Improve a prompt based on performance analysis.

        Args:
            current_prompt: Current prompt to improve
            current_stats: Current performance statistics
            historical_stats: Optional historical statistics
            improvement_suggestions: Optional automated suggestions
            generation: Current generation number

        Returns:
            Improved prompt
        """
        context = OptimizationContext(
            current_prompt=current_prompt,
            current_stats=current_stats,
            historical_stats=historical_stats or [],
            improvement_suggestions=improvement_suggestions or [],
            generation=generation,
        )

        improved_prompt = self.optimizer.optimize_prompt(context, optimization_type="improve")
        return improved_prompt

    def crossover_prompts(
        self,
        parent1: str,
        parent2: str,
        stats1: DetectionStatistics,
        stats2: DetectionStatistics,
        generation: int = 0,
    ) -> str:
        """Create a new prompt by combining two parent prompts.

        Args:
            parent1: First parent prompt
            parent2: Second parent prompt
            stats1: Statistics for parent1
            stats2: Statistics for parent2
            generation: Current generation number

        Returns:
            New combined prompt
        """
        # Use the better performing parent's stats as base
        if stats1.f1_score >= stats2.f1_score:
            base_stats = stats1
        else:
            base_stats = stats2

        context = OptimizationContext(
            current_prompt=parent1,  # Base prompt
            current_stats=base_stats,
            generation=generation,
            metadata={"parent1": parent1, "parent2": parent2}
        )

        offspring = self.optimizer.optimize_prompt(context, optimization_type="crossover")
        return offspring

    def mutate_prompt(
        self,
        prompt: str,
        stats: DetectionStatistics,
        generation: int = 0,
    ) -> str:
        """Mutate a prompt with guided changes.

        Args:
            prompt: Prompt to mutate
            stats: Current performance statistics
            generation: Current generation number

        Returns:
            Mutated prompt
        """
        context = OptimizationContext(
            current_prompt=prompt,
            current_stats=stats,
            generation=generation,
        )

        mutated = self.optimizer.optimize_prompt(context, optimization_type="mutate")
        return mutated

    def analyze_population(
        self,
        prompts: List[str],
        stats_list: List[DetectionStatistics]
    ) -> Dict:
        """Analyze population-level performance.

        Args:
            prompts: List of prompts in population
            stats_list: Corresponding statistics

        Returns:
            Analysis dictionary with insights
        """
        return self.optimizer.analyze_population(prompts, stats_list)


def create_detection_agent(
    model_name: str = "gpt-4",
    temperature: float = 0.1,
    llm_client: Optional[LLMClient] = None
) -> DetectionAgent:
    """Factory function to create a detection agent.

    Args:
        model_name: Name of the detection model
        temperature: Temperature for detection
        llm_client: Optional pre-configured LLM client

    Returns:
        DetectionAgent instance
    """
    from ..llm.client import create_llm_client

    config = AgentConfig(
        role=AgentRole.DETECTION,
        model_name=model_name,
        temperature=temperature,
    )

    if llm_client is None:
        llm_client = create_llm_client(llm_type=model_name)

    return DetectionAgent(config, llm_client)


def create_meta_agent(
    model_name: str = "claude-sonnet-4-5-20250929-thinking",
    temperature: float = 0.7,
    llm_client: Optional[LLMClient] = None
) -> MetaAgent:
    """Factory function to create a meta agent.

    Args:
        model_name: Name of the meta model (default: Claude 4.5)
        temperature: Temperature for meta-optimization
        llm_client: Optional pre-configured LLM client

    Returns:
        MetaAgent instance
    """
    from ..llm.client import create_meta_prompt_client

    config = AgentConfig(
        role=AgentRole.META,
        model_name=model_name,
        temperature=temperature,
    )

    if llm_client is None:
        llm_client = create_meta_prompt_client(model_name=model_name)

    return MetaAgent(config, llm_client)
