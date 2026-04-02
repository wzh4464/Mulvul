"""Multi-agent coordinator for collaborative prompt evolution.

The coordinator manages the interaction between:
- DetectionAgent: Performs vulnerability detection
- MetaAgent: Optimizes prompts based on performance feedback
"""

from enum import Enum
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass

from .agents import DetectionAgent, MetaAgent
from ..evaluators.statistics import DetectionStatistics, BatchStatistics, StatisticsCollector
from ..data.dataset import Dataset


class CoordinationStrategy(Enum):
    """Strategy for coordinating agents."""
    SEQUENTIAL = "sequential"  # Meta-agent optimizes after each detection batch
    PARALLEL = "parallel"  # Multiple detection agents work in parallel
    HIERARCHICAL = "hierarchical"  # Hierarchical routing + category-specific detection


@dataclass
class CoordinatorConfig:
    """Configuration for multi-agent coordinator.

    Attributes:
        strategy: Coordination strategy
        batch_size: Size of evaluation batches
        enable_batch_feedback: Whether to provide batch-level feedback to meta-agent
        statistics_window: Number of recent batches to include in feedback
    """

    strategy: CoordinationStrategy = CoordinationStrategy.SEQUENTIAL
    batch_size: int = 32
    enable_batch_feedback: bool = True
    statistics_window: int = 5  # Track last 5 batches


class MultiAgentCoordinator:
    """Coordinates detection and meta-optimization agents.

    The coordinator implements a collaborative evolution loop:
    1. DetectionAgent evaluates prompts on a batch of data
    2. Statistics are collected and analyzed
    3. MetaAgent receives performance feedback and suggests improvements
    4. Process repeats with improved prompts
    """

    def __init__(
        self,
        detection_agent: DetectionAgent,
        meta_agent: MetaAgent,
        config: Optional[CoordinatorConfig] = None
    ):
        """Initialize coordinator.

        Args:
            detection_agent: Agent for vulnerability detection
            meta_agent: Agent for meta-level optimization
            config: Coordinator configuration
        """
        self.detection_agent = detection_agent
        self.meta_agent = meta_agent
        self.config = config or CoordinatorConfig()

        # Statistics tracking
        self.statistics_collector = StatisticsCollector()
        self.batch_history: List[BatchStatistics] = []

    def evaluate_prompt(
        self,
        prompt: str,
        dataset: Dataset,
        sample_size: Optional[int] = None
    ) -> DetectionStatistics:
        """Evaluate a prompt on a dataset.

        Args:
            prompt: Prompt to evaluate
            dataset: Dataset to evaluate on
            sample_size: Optional number of samples to use

        Returns:
            Detection statistics
        """
        samples = dataset.get_samples(sample_size)
        stats = DetectionStatistics()

        # Extract code and labels
        code_samples = [s.input_text for s in samples]
        labels = [s.target for s in samples]

        # Get predictions from detection agent
        predictions = self.detection_agent.detect(prompt, code_samples)

        # Collect statistics
        for pred, actual, sample in zip(predictions, labels, samples):
            # Convert label to string
            actual_str = "vulnerable" if str(actual) == "1" else "benign"

            # Get category/CWE if available
            category = None
            if hasattr(sample, 'metadata') and 'cwe' in sample.metadata:
                cwes = sample.metadata['cwe']
                category = cwes[0] if cwes else None

            stats.add_prediction(
                predicted=pred,
                actual=actual_str,
                category=category,
                sample_id=getattr(sample, 'id', None)
            )

        stats.compute_metrics()
        return stats

    def evaluate_with_batches(
        self,
        prompt: str,
        dataset: Dataset,
        sample_size: Optional[int] = None
    ) -> Tuple[DetectionStatistics, List[BatchStatistics]]:
        """Evaluate a prompt using batch processing.

        This enables batch-level feedback to the meta-agent.

        Args:
            prompt: Prompt to evaluate
            dataset: Dataset to evaluate on
            sample_size: Optional number of samples to use

        Returns:
            Tuple of (overall statistics, list of batch statistics)
        """
        samples = dataset.get_samples(sample_size)
        overall_stats = DetectionStatistics()
        batch_stats_list = []

        # Process in batches
        for batch_id, i in enumerate(range(0, len(samples), self.config.batch_size)):
            batch_samples = samples[i:i + self.config.batch_size]

            # Evaluate batch
            batch_stats_obj = DetectionStatistics()
            code_samples = [s.input_text for s in batch_samples]
            labels = [s.target for s in batch_samples]

            predictions = self.detection_agent.detect(prompt, code_samples)

            for pred, actual, sample in zip(predictions, labels, batch_samples):
                actual_str = "vulnerable" if str(actual) == "1" else "benign"
                category = None
                if hasattr(sample, 'metadata') and 'cwe' in sample.metadata:
                    cwes = sample.metadata['cwe']
                    category = cwes[0] if cwes else None

                # Update both overall and batch stats
                batch_stats_obj.add_prediction(pred, actual_str, category)
                overall_stats.add_prediction(pred, actual_str, category)

            batch_stats_obj.compute_metrics()

            # Create batch statistics record
            batch_stat = BatchStatistics(
                batch_id=batch_id,
                batch_size=len(batch_samples),
                statistics=batch_stats_obj,
                metadata={"start_idx": i, "end_idx": i + len(batch_samples)}
            )
            batch_stats_list.append(batch_stat)

        overall_stats.compute_metrics()
        return overall_stats, batch_stats_list

    def collaborative_improve(
        self,
        prompt: str,
        dataset: Dataset,
        generation: int = 0,
        historical_stats: Optional[List[DetectionStatistics]] = None
    ) -> Tuple[str, DetectionStatistics]:
        """Collaboratively improve a prompt using detection + meta agents.

        Workflow:
        1. DetectionAgent evaluates current prompt
        2. Statistics are collected (overall + batches)
        3. MetaAgent analyzes performance and suggests improvements
        4. Return improved prompt

        Args:
            prompt: Current prompt to improve
            dataset: Dataset for evaluation
            generation: Current generation number
            historical_stats: Optional historical statistics

        Returns:
            Tuple of (improved prompt, evaluation statistics)
        """
        # Evaluate current prompt
        if self.config.enable_batch_feedback:
            stats, batch_stats = self.evaluate_with_batches(prompt, dataset)
            # Track batch statistics
            self.batch_history.extend(batch_stats)
            # Keep only recent batches
            if len(self.batch_history) > self.config.statistics_window * 10:
                self.batch_history = self.batch_history[-self.config.statistics_window * 10:]
        else:
            stats = self.evaluate_prompt(prompt, dataset)
            batch_stats = []

        # Get improvement suggestions from statistics
        self.statistics_collector.add_generation_stats(generation, stats)
        suggestions = self.statistics_collector.get_improvement_suggestions()

        # Meta-agent improves prompt
        improved_prompt = self.meta_agent.improve_prompt(
            current_prompt=prompt,
            current_stats=stats,
            historical_stats=historical_stats or [],
            improvement_suggestions=suggestions,
            generation=generation
        )

        return improved_prompt, stats

    def collaborative_crossover(
        self,
        parent1: str,
        parent2: str,
        dataset: Dataset,
        generation: int = 0
    ) -> Tuple[str, DetectionStatistics]:
        """Perform collaborative crossover of two parent prompts.

        Args:
            parent1: First parent prompt
            parent2: Second parent prompt
            dataset: Dataset for evaluation
            generation: Current generation number

        Returns:
            Tuple of (offspring prompt, evaluation statistics)
        """
        # Evaluate both parents
        stats1 = self.evaluate_prompt(parent1, dataset)
        stats2 = self.evaluate_prompt(parent2, dataset)

        # Meta-agent creates offspring
        offspring = self.meta_agent.crossover_prompts(
            parent1, parent2, stats1, stats2, generation
        )

        # Evaluate offspring
        offspring_stats = self.evaluate_prompt(offspring, dataset)

        return offspring, offspring_stats

    def collaborative_mutate(
        self,
        prompt: str,
        dataset: Dataset,
        generation: int = 0
    ) -> Tuple[str, DetectionStatistics]:
        """Perform collaborative mutation of a prompt.

        Args:
            prompt: Prompt to mutate
            dataset: Dataset for evaluation
            generation: Current generation number

        Returns:
            Tuple of (mutated prompt, evaluation statistics)
        """
        # Evaluate current prompt
        stats = self.evaluate_prompt(prompt, dataset)

        # Meta-agent mutates prompt
        mutated = self.meta_agent.mutate_prompt(prompt, stats, generation)

        # Evaluate mutated prompt
        mutated_stats = self.evaluate_prompt(mutated, dataset)

        return mutated, mutated_stats

    def get_statistics_summary(self) -> Dict:
        """Get summary of collected statistics.

        Returns:
            Dictionary with statistics summary
        """
        return {
            "total_generations": len(self.statistics_collector.generation_stats),
            "total_batches": len(self.batch_history),
            "historical_trend": self.statistics_collector.get_historical_trend(),
            "category_error_patterns": self.statistics_collector.get_category_error_patterns(),
            "improvement_suggestions": self.statistics_collector.get_improvement_suggestions(),
        }

    def export_statistics(self, filepath: str):
        """Export all statistics to file.

        Args:
            filepath: Path to export JSON file
        """
        self.statistics_collector.export_to_json(filepath)
