"""Co-evolutionary algorithm with multi-agent collaboration.

This algorithm implements collaborative evolution where:
1. Detection agents evaluate prompts
2. Meta agents optimize prompts based on statistical feedback
3. Evolution is guided by batch statistics and historical trends
"""

import random
from typing import List, Dict, Any, Optional
import numpy as np

from .base import EvolutionAlgorithm, Individual, Population
from ..multiagent.coordinator import MultiAgentCoordinator
from ..data.dataset import Dataset
from ..evaluators.statistics import DetectionStatistics


class CoevolutionaryAlgorithm(EvolutionAlgorithm):
    """Coevolutionary algorithm with multi-agent collaboration.

    Instead of blind search, this algorithm:
    - Uses a detection agent (e.g., GPT-4) to evaluate prompts
    - Uses a meta agent (e.g., Claude 4.5) to guide evolution
    - Collects batch-level statistics for targeted improvements
    - Tracks historical performance to avoid local optima
    """

    def __init__(
        self,
        config: Dict[str, Any],
        coordinator: MultiAgentCoordinator,
        dataset: Dataset
    ):
        """Initialize coevolutionary algorithm.

        Args:
            config: Algorithm configuration
            coordinator: Multi-agent coordinator
            dataset: Evaluation dataset
        """
        super().__init__(config)
        self.coordinator = coordinator
        self.dataset = dataset

        # Coevolution-specific parameters
        self.top_k = config.get("top_k", 5)  # Keep top K prompts each generation
        self.enable_elitism = config.get("enable_elitism", True)
        self.meta_improvement_rate = config.get("meta_improvement_rate", 0.3)  # Fraction improved by meta-agent

    def initialize_population(self, initial_prompts: List[str]) -> Population:
        """Initialize population and evaluate with detection agent."""
        individuals = []

        for prompt in initial_prompts[:self.population_size]:
            # Evaluate using coordinator
            stats = self.coordinator.evaluate_prompt(prompt, self.dataset)

            individual = Individual(prompt, fitness=stats.f1_score)
            individual.metadata['stats'] = stats
            individuals.append(individual)

        # Fill remaining slots if needed
        while len(individuals) < self.population_size:
            # Use meta-agent to create variations
            base_prompt = random.choice(initial_prompts)
            stats = DetectionStatistics()  # Dummy stats for initialization
            stats.accuracy = 0.5
            stats.f1_score = 0.5

            mutated = self.coordinator.meta_agent.mutate_prompt(
                base_prompt, stats, generation=0
            )
            mutated_stats = self.coordinator.evaluate_prompt(mutated, self.dataset)

            individual = Individual(mutated, fitness=mutated_stats.f1_score)
            individual.metadata['stats'] = mutated_stats
            individuals.append(individual)

        return Population(individuals[:self.population_size])

    def select_parents(self, population: Population) -> List[Individual]:
        """Select parents using tournament selection."""
        # Tournament selection
        tournament_size = min(3, len(population))
        tournament = random.sample(population.individuals, tournament_size)
        winner = max(tournament, key=lambda x: x.fitness or 0)

        # Select second parent
        remaining = [ind for ind in population.individuals if ind != winner]
        if remaining:
            tournament2 = random.sample(remaining, min(tournament_size, len(remaining)))
            winner2 = max(tournament2, key=lambda x: x.fitness or 0)
            return [winner, winner2]
        else:
            return [winner, winner]

    def crossover(
        self,
        parents: List[Individual],
        llm_client=None  # Not used, we use coordinator
    ) -> List[Individual]:
        """Perform crossover using meta-agent."""
        if len(parents) < 2:
            return []

        parent1, parent2 = parents[0], parents[1]

        # Use coordinator for collaborative crossover
        offspring_prompt, offspring_stats = self.coordinator.collaborative_crossover(
            parent1.prompt,
            parent2.prompt,
            self.dataset,
            generation=getattr(parent1, 'generation', 0)
        )

        offspring = Individual(offspring_prompt, fitness=offspring_stats.f1_score)
        offspring.metadata['stats'] = offspring_stats
        offspring.metadata['operation'] = 'crossover'
        offspring.metadata['parents'] = [parent1.prompt[:50], parent2.prompt[:50]]

        return [offspring]

    def mutate(
        self,
        individual: Individual,
        llm_client=None,  # Not used, we use coordinator
        generation: int = 0
    ) -> Individual:
        """Perform mutation using meta-agent."""
        stats = individual.metadata.get('stats', DetectionStatistics())

        # Use coordinator for collaborative mutation
        mutated_prompt, mutated_stats = self.coordinator.collaborative_mutate(
            individual.prompt,
            self.dataset,
            generation=generation
        )

        mutated_individual = Individual(mutated_prompt, fitness=mutated_stats.f1_score)
        mutated_individual.metadata['stats'] = mutated_stats
        mutated_individual.metadata['operation'] = 'mutation'
        mutated_individual.metadata['parent'] = individual.prompt[:50]

        return mutated_individual

    def meta_improve_population(
        self,
        population: Population,
        generation: int,
        num_to_improve: Optional[int] = None
    ) -> List[Individual]:
        """Use meta-agent to improve population members.

        This is the key innovation: instead of random mutation,
        we use meta-agent with statistical feedback.

        Args:
            population: Current population
            generation: Current generation number
            num_to_improve: Number of individuals to improve (default: based on meta_improvement_rate)

        Returns:
            List of improved individuals
        """
        if num_to_improve is None:
            num_to_improve = max(1, int(len(population) * self.meta_improvement_rate))

        # Select individuals to improve (prefer those with lower fitness)
        sorted_pop = sorted(population.individuals, key=lambda x: x.fitness or 0)
        to_improve = sorted_pop[:num_to_improve]

        improved_individuals = []

        # Collect historical stats for context
        historical_stats = []
        for ind in population.individuals:
            if 'stats' in ind.metadata:
                historical_stats.append(ind.metadata['stats'])

        for individual in to_improve:
            stats = individual.metadata.get('stats', DetectionStatistics())

            # Use coordinator for collaborative improvement
            improved_prompt, improved_stats = self.coordinator.collaborative_improve(
                individual.prompt,
                self.dataset,
                generation=generation,
                historical_stats=historical_stats[-5:]  # Last 5 generations
            )

            improved_ind = Individual(improved_prompt, fitness=improved_stats.f1_score)
            improved_ind.metadata['stats'] = improved_stats
            improved_ind.metadata['operation'] = 'meta_improvement'
            improved_ind.metadata['original_fitness'] = individual.fitness
            improved_ind.generation = generation

            improved_individuals.append(improved_ind)

        return improved_individuals

    def evolve(self, evaluator=None, llm_client=None, **kwargs) -> Dict[str, Any]:
        """Main coevolution loop with multi-agent collaboration.

        Note: evaluator and llm_client are not used directly;
        we use the coordinator instead.
        """
        # Get initial prompts
        initial_prompts = kwargs.get("initial_prompts", [])
        if not initial_prompts:
            raise ValueError("Initial prompts must be provided")

        # Initialize population
        print("🔬 Initializing population with detection agent...")
        population = self.initialize_population(initial_prompts)
        population.sort_by_fitness()

        best_fitness_history = []
        generation_stats = []

        for generation in range(self.max_generations):
            print(f"\n🧬 Generation {generation + 1}/{self.max_generations}")

            # Track best fitness
            best_individual = population.best()
            best_fitness_history.append(best_individual.fitness)

            print(f"   Current best fitness: {best_individual.fitness:.4f}")

            # Phase 1: Meta-guided improvement
            print(f"   Phase 1: Meta-agent improving {int(len(population) * self.meta_improvement_rate)} prompts...")
            improved_individuals = self.meta_improve_population(population, generation)

            # Phase 2: Evolutionary operators (crossover + mutation)
            print("   Phase 2: Evolutionary crossover and mutation...")
            offspring = []

            # Crossover
            num_crossovers = max(1, self.population_size // 4)
            for _ in range(num_crossovers):
                parents = self.select_parents(population)
                offspring.extend(self.crossover(parents))

            # Mutation
            num_mutations = max(1, self.population_size // 4)
            for _ in range(num_mutations):
                individual = random.choice(population.individuals)
                mutated = self.mutate(individual, generation=generation)
                offspring.append(mutated)

            # Phase 3: Combine and select survivors
            all_individuals = (
                population.individuals +
                improved_individuals +
                offspring
            )

            # Create new population
            all_population = Population(all_individuals)
            all_population.sort_by_fitness()

            # Elitism: keep top K
            if self.enable_elitism:
                survivors = all_population.individuals[:self.top_k]
                # Fill remaining with diverse selection
                remaining = all_population.individuals[self.top_k:]
                random.shuffle(remaining)
                survivors.extend(remaining[:self.population_size - self.top_k])
            else:
                survivors = all_population.individuals[:self.population_size]

            population = Population(survivors)

            # Collect generation statistics
            gen_stats = {
                "generation": generation,
                "best_fitness": best_individual.fitness,
                "avg_fitness": sum(ind.fitness or 0 for ind in population.individuals) / len(population),
                "population_diversity": len(set(ind.prompt for ind in population.individuals)),
            }
            generation_stats.append(gen_stats)

            print(f"   Avg fitness: {gen_stats['avg_fitness']:.4f}")
            print(f"   Population diversity: {gen_stats['population_diversity']}/{len(population)}")

        # Final results
        final_best = population.best()

        # Get detailed statistics
        coordinator_stats = self.coordinator.get_statistics_summary()

        return {
            "best_prompt": final_best.prompt,
            "best_fitness": final_best.fitness,
            "fitness_history": best_fitness_history,
            "generation_stats": generation_stats,
            "final_population": [
                {
                    "prompt": ind.prompt,
                    "fitness": ind.fitness,
                    "metadata": ind.metadata
                }
                for ind in population.individuals
            ],
            "coordinator_statistics": coordinator_stats,
        }

    def _select_survivors(self, population: Population) -> Population:
        """Select survivors with elitism."""
        population.sort_by_fitness()
        survivors = population.individuals[:self.population_size]
        return Population(survivors)
