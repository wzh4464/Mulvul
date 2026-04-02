"""Multi-layer evolution for optimizing prompt sets.

Extends evolution to optimize all 3 layers of prompts
simultaneously using PromptSet as the unit of evolution.
"""
from __future__ import annotations

import copy
import random
from typing import (
    Any, Callable, Dict, List, Optional, Tuple,
)

from ..prompts.prompt_set import PromptSet


class MultiLayerIndividual:
    """An individual holding a full PromptSet."""

    def __init__(
        self,
        prompt_set: PromptSet,
        fitness: Optional[float] = None,
    ):
        self.prompt_set = prompt_set
        self.fitness = fitness
        self.generation: int = 0
        self.metadata: Dict[str, Any] = {}
        self.layer_fitness: Dict[int, float] = {}


class MultiLayerPopulation:
    """Population of MultiLayerIndividual."""

    def __init__(
        self,
        individuals: List[MultiLayerIndividual],
    ):
        self.individuals = individuals

    def __len__(self) -> int:
        return len(self.individuals)

    def __iter__(self):
        return iter(self.individuals)

    def best(self) -> MultiLayerIndividual:
        """Return individual with highest fitness."""
        return max(
            self.individuals,
            key=lambda x: x.fitness or 0,
        )

    def worst(self) -> MultiLayerIndividual:
        """Return individual with lowest fitness."""
        return min(
            self.individuals,
            key=lambda x: x.fitness or 0,
        )

    def sort_by_fitness(
        self, reverse: bool = True
    ) -> None:
        """Sort individuals by fitness (descending)."""
        self.individuals.sort(
            key=lambda x: x.fitness or 0,
            reverse=reverse,
        )


class MultiLayerFitness:
    """Computes fitness for multi-layer prompt sets."""

    def __init__(
        self,
        weights: Optional[Dict[int, float]] = None,
    ):
        self.weights = weights or {}

    def compute_per_layer(
        self,
        predictions: Dict[
            int, List[Tuple[str, str]]
        ],
    ) -> Dict[int, float]:
        """Compute accuracy per layer.

        Args:
            predictions: Dict mapping layer -> list of
                (predicted, actual) tuples

        Returns:
            Dict mapping layer -> accuracy
        """
        result: Dict[int, float] = {}
        for layer, preds in predictions.items():
            if not preds:
                result[layer] = 0.0
                continue
            correct = sum(
                1 for p, a in preds if p == a
            )
            result[layer] = correct / len(preds)
        return result

    def aggregate(
        self,
        per_layer: Dict[int, float],
        error_penalty: float = 0.0,
        error_count: int = 0,
    ) -> float:
        """Aggregate per-layer fitness into one score.

        Uses weighted average if weights provided,
        otherwise equal weights.
        """
        if not per_layer:
            return 0.0

        if self.weights:
            total_w = 0.0
            weighted_sum = 0.0
            for layer, score in per_layer.items():
                w = self.weights.get(layer, 1.0)
                weighted_sum += w * score
                total_w += w
            base = (
                weighted_sum / total_w
                if total_w > 0
                else 0.0
            )
        else:
            base = (
                sum(per_layer.values())
                / len(per_layer)
            )

        # Apply error penalty
        penalty = error_penalty * error_count
        return max(0.0, base - penalty)


class MultiLayerEvolution:
    """Evolution algorithm for multi-layer prompts."""

    def __init__(
        self,
        config: Dict[str, Any],
        llm_client: Any,
    ):
        self.config = config
        self.population_size = config.get(
            "population_size", 20
        )
        self.max_generations = config.get(
            "max_generations", 10
        )
        self.mutation_rate = config.get(
            "mutation_rate", 0.1
        )
        self.llm_client = llm_client

    def crossover_layer(
        self,
        parent1: MultiLayerIndividual,
        parent2: MultiLayerIndividual,
        layer: int,
        category: str,
    ) -> MultiLayerIndividual:
        """Crossover trainable sections at one layer.

        Deep copies parent1's prompt set, then uses
        the LLM to combine trainable sections from
        both parents.
        """
        new_ps_dict = copy.deepcopy(
            parent1.prompt_set.to_dict()
        )
        new_ps = PromptSet.from_dict(new_ps_dict)

        t1 = parent1.prompt_set.get_template(
            layer, category
        )
        t2 = parent2.prompt_set.get_template(
            layer, category
        )
        if t1 is None or t2 is None:
            return MultiLayerIndividual(
                prompt_set=new_ps
            )

        trainable1 = t1.get_trainable_sections()
        trainable2 = t2.get_trainable_sections()

        if not trainable1:
            return MultiLayerIndividual(
                prompt_set=new_ps
            )

        t1_content = trainable1[0].content
        t2_content = (
            trainable2[0].content
            if trainable2
            else t1_content
        )

        prompt = (
            "Combine these two analysis approaches"
            " into one:\n\n"
            f"Approach 1: {t1_content}\n\n"
            f"Approach 2: {t2_content}\n\n"
            "Output only the combined approach:"
        )
        new_content = self.llm_client.generate(
            prompt
        )

        current = new_ps.get_template(
            layer, category
        )
        if current is not None:
            updated = current.set_trainable_content(
                trainable1[0].name, new_content
            )
            new_ps.set_template(
                layer, category, updated
            )

        return MultiLayerIndividual(
            prompt_set=new_ps
        )

    def mutate_layer(
        self,
        individual: MultiLayerIndividual,
        layer: int,
        category: str,
        error_patterns: Optional[
            List[str]
        ] = None,
    ) -> MultiLayerIndividual:
        """Mutate trainable section at one layer.

        Deep copies the individual's prompt set,
        then uses the LLM to improve the trainable
        content.
        """
        new_ps_dict = copy.deepcopy(
            individual.prompt_set.to_dict()
        )
        new_ps = PromptSet.from_dict(new_ps_dict)

        template = new_ps.get_template(
            layer, category
        )
        if template is None:
            return MultiLayerIndividual(
                prompt_set=new_ps
            )

        trainable = template.get_trainable_sections()
        if not trainable:
            return MultiLayerIndividual(
                prompt_set=new_ps
            )

        current = trainable[0].content
        prompt = (
            "Improve this analysis guidance:\n\n"
            f"{current}\n\n"
            "Output only the improved guidance:"
        )
        new_content = self.llm_client.generate(
            prompt
        )

        updated = template.set_trainable_content(
            trainable[0].name, new_content
        )
        new_ps.set_template(
            layer, category, updated
        )

        return MultiLayerIndividual(
            prompt_set=new_ps
        )

    def _get_first_template_key(
        self, prompt_set: PromptSet
    ) -> Optional[Tuple[int, str]]:
        """Get the first (layer, category) key."""
        ps_dict = prompt_set.to_dict()
        templates = ps_dict.get("templates", {})
        if not templates:
            return None
        key = list(templates.keys())[0]
        layer_s, cat = key.split(":", 1)
        return int(layer_s), cat

    def evolve_multilayer(
        self,
        initial_prompt_sets: List[PromptSet],
        evaluate_fn: Callable[
            [PromptSet], float
        ],
    ) -> Dict[str, Any]:
        """Run multi-layer evolution loop.

        Args:
            initial_prompt_sets: Starting prompt sets
            evaluate_fn: Evaluates a PromptSet,
                returns float fitness

        Returns:
            Dict with best_prompt_set, best_fitness,
            fitness_history
        """
        population = MultiLayerPopulation([
            MultiLayerIndividual(
                prompt_set=copy.deepcopy(ps)
            )
            for ps in initial_prompt_sets
        ])

        for ind in population:
            ind.fitness = evaluate_fn(
                ind.prompt_set
            )

        fitness_history: List[Optional[float]] = []

        for gen in range(self.max_generations):
            best = population.best()
            fitness_history.append(best.fitness)

            offspring: List[
                MultiLayerIndividual
            ] = []

            # Crossover: select pairs
            population.sort_by_fitness()
            inds = population.individuals
            for i in range(0, len(inds) - 1, 2):
                key = self._get_first_template_key(
                    inds[i].prompt_set
                )
                if key is not None:
                    layer, cat = key
                    child = self.crossover_layer(
                        inds[i],
                        inds[i + 1],
                        layer,
                        cat,
                    )
                    child.generation = gen + 1
                    offspring.append(child)

            # Mutation
            for ind in list(population):
                if random.random() < self.mutation_rate:
                    key = self._get_first_template_key(
                        ind.prompt_set
                    )
                    if key is not None:
                        layer, cat = key
                        mutated = self.mutate_layer(
                            ind, layer, cat
                        )
                        mutated.generation = gen + 1
                        offspring.append(mutated)

            # Evaluate offspring
            for ind in offspring:
                ind.fitness = evaluate_fn(
                    ind.prompt_set
                )

            # Select survivors
            all_inds = (
                population.individuals + offspring
            )
            all_pop = MultiLayerPopulation(all_inds)
            all_pop.sort_by_fitness()
            population = MultiLayerPopulation(
                all_pop.individuals[
                    :self.population_size
                ]
            )

        final_best = population.best()
        return {
            "best_prompt_set": final_best.prompt_set,
            "best_fitness": final_best.fitness,
            "fitness_history": fitness_history,
        }
