"""Genetic Algorithm implementation for EvoPrompt."""

import random
import numpy as np
from typing import List, Dict, Any

from .base import EvolutionAlgorithm, Individual, Population
from ..llm.client import LLMClient


class GeneticAlgorithm(EvolutionAlgorithm):
    """Genetic Algorithm for prompt evolution."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.crossover_rate = config.get("crossover_rate", 0.8)
        self.selection_method = config.get("selection_method", "tournament")
        self.tournament_size = config.get("tournament_size", 3)
        
    def initialize_population(self, initial_prompts: List[str]) -> Population:
        """Initialize population with given prompts."""
        individuals = []
        
        # Use provided prompts
        for prompt in initial_prompts:
            individuals.append(Individual(prompt))
            
        # Fill remaining slots with variations if needed
        while len(individuals) < self.population_size:
            # Randomly select a base prompt to vary
            base_prompt = random.choice(initial_prompts)
            individuals.append(Individual(base_prompt))
            
        # Trim to exact population size
        individuals = individuals[:self.population_size]
        
        return Population(individuals)
        
    def select_parents(self, population: Population) -> List[Individual]:
        """Select parents for reproduction."""
        if self.selection_method == "tournament":
            return self._tournament_selection(population)
        elif self.selection_method == "roulette":
            return self._roulette_selection(population)
        else:
            return self._random_selection(population)
            
    def _tournament_selection(self, population: Population) -> List[Individual]:
        """Tournament selection."""
        parents = []
        
        for _ in range(2):  # Select 2 parents
            tournament = random.sample(population.individuals, 
                                     min(self.tournament_size, len(population)))
            winner = max(tournament, key=lambda x: x.fitness or 0)
            parents.append(winner)
            
        return parents
        
    def _roulette_selection(self, population: Population) -> List[Individual]:
        """Roulette wheel selection."""
        # Calculate fitness sum
        fitness_values = [ind.fitness or 0 for ind in population.individuals]
        min_fitness = min(fitness_values)
        
        # Shift fitness to be positive
        if min_fitness < 0:
            fitness_values = [f - min_fitness + 0.01 for f in fitness_values]
            
        total_fitness = sum(fitness_values)
        
        if total_fitness == 0:
            return random.sample(population.individuals, 2)
            
        parents = []
        for _ in range(2):
            pick = random.uniform(0, total_fitness)
            current = 0
            for i, individual in enumerate(population.individuals):
                current += fitness_values[i]
                if current >= pick:
                    parents.append(individual)
                    break
                    
        return parents if len(parents) == 2 else random.sample(population.individuals, 2)
        
    def _random_selection(self, population: Population) -> List[Individual]:
        """Random selection."""
        return random.sample(population.individuals, 2)
        
    def crossover(self, parents: List[Individual], llm_client: LLMClient) -> List[Individual]:
        """Perform crossover operation using LLM."""
        if len(parents) < 2 or random.random() > self.crossover_rate:
            return []
            
        parent1, parent2 = parents[0], parents[1]
        
        # Create crossover prompt for LLM
        crossover_prompt = f"""
Given these two prompts for the same task, create a new prompt that combines the best elements of both:

Prompt 1: {parent1.prompt}

Prompt 2: {parent2.prompt}

Create a new prompt that:
1. Combines effective elements from both prompts
2. Maintains clarity and coherence
3. Is suitable for the same task
4. Is different from both parent prompts
5. If either prompt uses {{input}} or {{nl_ast}} placeholders, preserve their effective usage
6. The {{nl_ast}} placeholder provides semantic code structure and can enhance understanding

New combined prompt:"""

        try:
            response = llm_client.generate(
                crossover_prompt,
                temperature=0.7
            )
            
            # Clean up response
            new_prompt = response.strip()
            if new_prompt and len(new_prompt) > 10:
                offspring = Individual(new_prompt)
                return [offspring]
                
        except Exception as e:
            print(f"Crossover failed: {e}")
            
        # Fallback: return a copy of one parent with slight modification
        return [Individual(parent1.prompt)]
        
    def mutate(self, individual: Individual, llm_client: LLMClient) -> Individual:
        """Perform mutation operation using LLM."""
        mutation_prompt = f"""
Improve the following prompt by making small modifications while keeping its core purpose:

Original prompt: {individual.prompt}

Create an improved version that:
1. Maintains the same task objective
2. Has slightly different wording or structure
3. Might be more clear, specific, or effective
4. Is still coherent and well-formed
5. Preserves any {{input}} or {{nl_ast}} placeholders if they exist
6. Consider that {{nl_ast}} provides semantic code structure that can enhance analysis

Improved prompt:"""

        try:
            response = llm_client.generate(
                mutation_prompt,
                temperature=0.8
            )
            
            # Clean up response
            new_prompt = response.strip()
            if new_prompt and len(new_prompt) > 10:
                return Individual(new_prompt)
                
        except Exception as e:
            print(f"Mutation failed: {e}")
            
        # Fallback: return original individual
        return Individual(individual.prompt)