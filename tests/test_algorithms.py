"""Tests for evolutionary algorithms."""

import pytest
from unittest.mock import Mock, patch
import numpy as np

from evoprompt.algorithms.base import (
    Individual, Population, EvolutionAlgorithm
)


class TestIndividual:
    """Test cases for Individual class."""
    
    def test_individual_creation(self):
        """Test individual creation."""
        individual = Individual("Test prompt", 0.85)
        
        assert individual.prompt == "Test prompt"
        assert individual.fitness == 0.85
        assert individual.generation == 0
        assert individual.metadata == {}
        
    def test_individual_without_fitness(self):
        """Test individual creation without fitness."""
        individual = Individual("Test prompt")
        
        assert individual.prompt == "Test prompt"
        assert individual.fitness is None
        
    def test_individual_repr(self):
        """Test individual string representation."""
        individual = Individual("A very long test prompt that should be truncated", 0.9)
        repr_str = repr(individual)
        
        assert "Individual" in repr_str
        assert "A very long test prompt that should be trun..." in repr_str
        assert "0.9" in repr_str


class TestPopulation:
    """Test cases for Population class."""
    
    def test_population_creation(self):
        """Test population creation."""
        individuals = [
            Individual("Prompt 1", 0.8),
            Individual("Prompt 2", 0.9),
            Individual("Prompt 3", 0.7)
        ]
        population = Population(individuals)
        
        assert len(population) == 3
        assert list(population) == individuals
        
    def test_best_individual(self):
        """Test getting best individual."""
        individuals = [
            Individual("Prompt 1", 0.8),
            Individual("Prompt 2", 0.9),
            Individual("Prompt 3", 0.7)
        ]
        population = Population(individuals)
        
        best = population.best()
        assert best.prompt == "Prompt 2"
        assert best.fitness == 0.9
        
    def test_worst_individual(self):
        """Test getting worst individual."""
        individuals = [
            Individual("Prompt 1", 0.8),
            Individual("Prompt 2", 0.9),
            Individual("Prompt 3", 0.7)
        ]
        population = Population(individuals)
        
        worst = population.worst()
        assert worst.prompt == "Prompt 3" 
        assert worst.fitness == 0.7
        
    def test_sort_by_fitness(self):
        """Test sorting population by fitness."""
        individuals = [
            Individual("Prompt 1", 0.8),
            Individual("Prompt 2", 0.9),
            Individual("Prompt 3", 0.7)
        ]
        population = Population(individuals)
        population.sort_by_fitness()
        
        fitness_values = [ind.fitness for ind in population.individuals]
        assert fitness_values == [0.9, 0.8, 0.7]


class MockEvolutionAlgorithm(EvolutionAlgorithm):
    """Mock implementation of EvolutionAlgorithm for testing."""
    
    def initialize_population(self, initial_prompts):
        individuals = [Individual(prompt) for prompt in initial_prompts]
        return Population(individuals)
        
    def select_parents(self, population):
        return population.individuals[:2]
        
    def crossover(self, parents, llm_client):
        return [Individual("Crossover result")]
        
    def mutate(self, individual, llm_client):
        return Individual("Mutated: " + individual.prompt)


class TestEvolutionAlgorithm:
    """Test cases for EvolutionAlgorithm base class."""
    
    def test_algorithm_initialization(self):
        """Test algorithm initialization."""
        config = {
            "population_size": 10,
            "max_generations": 5,
            "mutation_rate": 0.2
        }
        algorithm = MockEvolutionAlgorithm(config)
        
        assert algorithm.population_size == 10
        assert algorithm.max_generations == 5
        assert algorithm.mutation_rate == 0.2
        
    def test_evaluate_population(self, mock_evaluator):
        """Test population evaluation."""
        config = {"population_size": 3}
        algorithm = MockEvolutionAlgorithm(config)
        
        individuals = [
            Individual("Prompt 1"),
            Individual("Prompt 2"),
            Individual("Prompt 3")
        ]
        population = Population(individuals)
        
        # Mock evaluator to return different scores
        def mock_evaluate(prompt):
            from evoprompt.core.evaluator import EvaluationResult
            scores = {"Prompt 1": 0.8, "Prompt 2": 0.9, "Prompt 3": 0.7}
            return EvaluationResult(scores.get(prompt, 0.5))
            
        mock_evaluator.evaluate = mock_evaluate
        
        evaluated_pop = algorithm.evaluate_population(population, mock_evaluator)
        
        assert evaluated_pop.individuals[0].fitness == 0.8
        assert evaluated_pop.individuals[1].fitness == 0.9
        assert evaluated_pop.individuals[2].fitness == 0.7
        
    def test_evolve_requires_initial_prompts(self, mock_evaluator, mock_llm_client):
        """Test that evolve requires initial prompts."""
        config = {"population_size": 3, "max_generations": 1}
        algorithm = MockEvolutionAlgorithm(config)
        
        with pytest.raises(ValueError, match="Initial prompts must be provided"):
            algorithm.evolve(mock_evaluator, mock_llm_client)