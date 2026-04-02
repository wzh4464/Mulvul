"""Base classes for evolutionary algorithms."""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Protocol, Optional
from ..core.evaluator import Evaluator
from ..llm.client import LLMClient
import numpy as np


class Individual:
    """Represents an individual in the population (a prompt)."""
    
    def __init__(self, prompt: str, fitness: Optional[float] = None):
        self.prompt = prompt
        self.fitness = fitness
        self.generation = 0
        self.metadata = {}
        
    def __repr__(self):
        # Truncate to 43 chars + '...' when length exceeds 46 to match tests
        truncated = (self.prompt[:43] + '...') if len(self.prompt) > 46 else self.prompt
        return f"Individual(prompt='{truncated}', fitness={self.fitness})"


class Population:
    """Manages a population of individuals."""
    
    def __init__(self, individuals: List[Individual]):
        self.individuals = individuals
        
    def __len__(self):
        return len(self.individuals)
        
    def __iter__(self):
        return iter(self.individuals)
        
    def best(self) -> Individual:
        """Get the best individual by fitness."""
        return max(self.individuals, key=lambda x: x.fitness or 0)
        
    def worst(self) -> Individual:
        """Get the worst individual by fitness."""
        return min(self.individuals, key=lambda x: x.fitness or 0)
        
    def sort_by_fitness(self, reverse: bool = True):
        """Sort population by fitness."""
        self.individuals.sort(key=lambda x: x.fitness or 0, reverse=reverse)


class EvolutionAlgorithm(ABC):
    """Abstract base class for evolutionary algorithms."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.population_size = config.get("population_size", 20)
        self.max_generations = config.get("max_generations", 10)
        self.mutation_rate = config.get("mutation_rate", 0.1)
        
    @abstractmethod
    def initialize_population(self, initial_prompts: List[str]) -> Population:
        """Initialize the population with given prompts."""
        pass
        
    @abstractmethod
    def select_parents(self, population: Population) -> List[Individual]:
        """Select parents for reproduction."""
        pass
        
    @abstractmethod
    def crossover(self, parents: List[Individual], llm_client: LLMClient) -> List[Individual]:
        """Perform crossover operation."""
        pass
        
    @abstractmethod
    def mutate(self, individual: Individual, llm_client: LLMClient) -> Individual:
        """Perform mutation operation."""
        pass
        
    def evaluate_population(self, population: Population, evaluator: Evaluator) -> Population:
        """Evaluate fitness for all individuals in population."""
        for individual in population:
            if individual.fitness is None:
                result = evaluator.evaluate(individual.prompt)
                individual.fitness = result.score
        return population
        
    def evolve(self, evaluator: Evaluator, llm_client: LLMClient, **kwargs) -> Dict[str, Any]:
        """Main evolution loop."""
        # Get initial prompts
        initial_prompts = kwargs.get("initial_prompts", [])
        if not initial_prompts:
            raise ValueError("Initial prompts must be provided")
            
        # Initialize population
        population = self.initialize_population(initial_prompts)
        population = self.evaluate_population(population, evaluator)
        
        best_fitness_history = []
        
        for generation in range(self.max_generations):
            # Track best fitness
            best_individual = population.best()
            best_fitness_history.append(best_individual.fitness)
            
            # Select parents
            parents = self.select_parents(population)
            
            # Generate offspring
            offspring = []
            offspring.extend(self.crossover(parents, llm_client))
            
            # Mutate some individuals
            for individual in population:
                if np.random.random() < self.mutation_rate:
                    mutated = self.mutate(individual, llm_client)
                    offspring.append(mutated)
                    
            # Create new population
            all_individuals = population.individuals + offspring
            all_population = Population(all_individuals)
            all_population = self.evaluate_population(all_population, evaluator)
            
            # Select survivors
            population = self._select_survivors(all_population)
            
        # Return results
        final_best = population.best()
        return {
            "best_prompt": final_best.prompt,
            "best_fitness": final_best.fitness,
            "fitness_history": best_fitness_history,
            "final_population": [ind.prompt for ind in population.individuals]
        }
        
    def _select_survivors(self, population: Population) -> Population:
        """Select survivors for next generation (default: elitist selection)."""
        population.sort_by_fitness()
        survivors = population.individuals[:self.population_size]
        return Population(survivors)