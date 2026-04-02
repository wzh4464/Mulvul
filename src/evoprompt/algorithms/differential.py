"""Differential Evolution implementation for EvoPrompt."""

import random
import numpy as np
from typing import List, Dict, Any

from .base import EvolutionAlgorithm, Individual, Population
from ..llm.client import LLMClient


class DifferentialEvolution(EvolutionAlgorithm):
    """Differential Evolution algorithm for prompt evolution."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.mutation_factor = config.get("mutation_factor", 0.5)
        self.crossover_probability = config.get("crossover_probability", 0.7)
        
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
        """Select three random individuals for DE mutation."""
        return random.sample(population.individuals, min(3, len(population.individuals)))
        
    def crossover(self, parents: List[Individual], llm_client: LLMClient) -> List[Individual]:
        """Perform DE mutation and crossover to create a trial vector."""
        if len(parents) < 3:
            return []
            
        # In DE, we select three different individuals: x_r1, x_r2, x_r3
        x_r1, x_r2, x_r3 = parents[0], parents[1], parents[2]
        
        # Create DE mutation prompt
        de_prompt = f"""
You are helping with differential evolution for prompt optimization. Given three prompts, create a new "mutant" prompt by:
1. Taking the base prompt (Prompt 1)
2. Adding the "difference" between Prompt 2 and Prompt 3
3. The result should combine elements that make Prompt 2 better than Prompt 3
4. Preserve any {{input}} or {{nl_ast}} placeholders if they effectively contribute to performance
5. Note that {{nl_ast}} provides semantic code structure and may enhance analysis

Base Prompt (x_r1): {x_r1.prompt}

Better Prompt (x_r2): {x_r2.prompt}

Worse Prompt (x_r3): {x_r3.prompt}

Create a mutant prompt that takes the base and adds the improvements that make Prompt 2 better than Prompt 3:

Mutant prompt:"""

        try:
            response = llm_client.generate(
                de_prompt,
                temperature=0.6
            )
            
            # Clean up response
            mutant_prompt = response.strip()
            if mutant_prompt and len(mutant_prompt) > 10:
                return [Individual(mutant_prompt)]
                
        except Exception as e:
            print(f"DE mutation failed: {e}")
            
        # Fallback: return base individual with modification
        return [Individual(x_r1.prompt)]
        
    def mutate(self, individual: Individual, llm_client: LLMClient) -> Individual:
        """In DE, mutation is handled in crossover. This is for additional mutation."""
        mutation_prompt = f"""
Make a small improvement to this prompt while maintaining its core functionality:

Original: {individual.prompt}

Create a slightly improved version that:
1. Maintains core functionality
2. Preserves {{input}} and {{nl_ast}} placeholders if present
3. Leverages {{nl_ast}} semantic information effectively if used

Improved prompt:"""

        try:
            response = llm_client.generate(
                mutation_prompt,
                temperature=0.5
            )
            
            new_prompt = response.strip()
            if new_prompt and len(new_prompt) > 10:
                return Individual(new_prompt)
                
        except Exception as e:
            print(f"Additional mutation failed: {e}")
            
        return Individual(individual.prompt)
        
    def evolve(self, evaluator, llm_client: LLMClient, **kwargs) -> Dict[str, Any]:
        """Main DE evolution loop with DE-specific selection."""
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
            
            # Create new population using DE
            new_individuals = []
            
            for i, target_individual in enumerate(population.individuals):
                # Select three random individuals different from target
                candidates = [ind for j, ind in enumerate(population.individuals) if j != i]
                if len(candidates) >= 3:
                    parents = random.sample(candidates, 3)
                    
                    # Create trial vector (mutant)
                    trial_individuals = self.crossover(parents, llm_client)
                    if trial_individuals:
                        trial_individual = trial_individuals[0]
                        
                        # Crossover between target and trial
                        if random.random() < self.crossover_probability:
                            # Use trial
                            new_individuals.append(trial_individual)
                        else:
                            # Use target
                            new_individuals.append(Individual(target_individual.prompt))
                    else:
                        # Keep target if crossover failed
                        new_individuals.append(Individual(target_individual.prompt))
                else:
                    # Not enough individuals for DE, keep target
                    new_individuals.append(Individual(target_individual.prompt))
            
            # Evaluate new population
            new_population = Population(new_individuals)
            new_population = self.evaluate_population(new_population, evaluator)
            
            # Selection: for each position, keep better of target vs trial
            final_individuals = []
            for i in range(len(population.individuals)):
                target = population.individuals[i]
                trial = new_population.individuals[i]
                
                # Keep the better one
                if trial.fitness and target.fitness and trial.fitness > target.fitness:
                    final_individuals.append(trial)
                else:
                    final_individuals.append(target)
                    
            population = Population(final_individuals)
            
        # Return results
        final_best = population.best()
        return {
            "best_prompt": final_best.prompt,
            "best_fitness": final_best.fitness,
            "fitness_history": best_fitness_history,
            "final_population": [ind.prompt for ind in population.individuals]
        }