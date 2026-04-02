"""Tests for multi-layer evolution."""
from evoprompt.algorithms.multilayer_evolution import (
    MultiLayerIndividual,
    MultiLayerPopulation,
    MultiLayerFitness,
    MultiLayerEvolution,
)
from evoprompt.prompts.prompt_set import PromptSet
from evoprompt.prompts.template import (
    PromptTemplate,
    PromptSection,
    PromptMetadata,
)
from evoprompt.llm.stub import DeterministicStubClient


def _make_prompt_set():
    """Create a simple PromptSet for testing."""
    ps = PromptSet()
    ps.set_template(
        1, "Memory",
        PromptTemplate(
            sections=[
                PromptSection(
                    content="Analyze for memory bugs:\n",
                ),
                PromptSection(
                    content="Check pointers carefully.",
                    is_trainable=True,
                    name="guidance",
                ),
                PromptSection(
                    content="\nCONFIDENCE: {input}",
                ),
            ],
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
    return ps


class TestMultiLayerIndividual:
    def test_holds_prompt_set(self):
        ps = _make_prompt_set()
        ind = MultiLayerIndividual(prompt_set=ps)
        assert ind.prompt_set is ps
        assert ind.prompt_set.count_templates() == 2

    def test_default_fitness_none(self):
        ps = _make_prompt_set()
        ind = MultiLayerIndividual(prompt_set=ps)
        assert ind.fitness is None

    def test_generation_default(self):
        ps = _make_prompt_set()
        ind = MultiLayerIndividual(prompt_set=ps)
        assert ind.generation == 0

    def test_metadata_default(self):
        ps = _make_prompt_set()
        ind = MultiLayerIndividual(prompt_set=ps)
        assert ind.metadata == {}

    def test_layer_fitness_default(self):
        ps = _make_prompt_set()
        ind = MultiLayerIndividual(prompt_set=ps)
        assert ind.layer_fitness == {}


class TestMultiLayerPopulation:
    def test_best_by_fitness(self):
        ps1 = _make_prompt_set()
        ps2 = _make_prompt_set()
        ind1 = MultiLayerIndividual(
            prompt_set=ps1, fitness=0.7
        )
        ind2 = MultiLayerIndividual(
            prompt_set=ps2, fitness=0.9
        )
        pop = MultiLayerPopulation([ind1, ind2])
        assert pop.best().fitness == 0.9

    def test_worst_by_fitness(self):
        ps1 = _make_prompt_set()
        ps2 = _make_prompt_set()
        ind1 = MultiLayerIndividual(
            prompt_set=ps1, fitness=0.7
        )
        ind2 = MultiLayerIndividual(
            prompt_set=ps2, fitness=0.9
        )
        pop = MultiLayerPopulation([ind1, ind2])
        assert pop.worst().fitness == 0.7

    def test_sort_by_fitness(self):
        individuals = []
        for f in [0.5, 0.9, 0.3, 0.7]:
            ps = _make_prompt_set()
            individuals.append(
                MultiLayerIndividual(
                    prompt_set=ps, fitness=f
                )
            )
        pop = MultiLayerPopulation(individuals)
        pop.sort_by_fitness()
        fitnesses = [
            ind.fitness for ind in pop.individuals
        ]
        assert fitnesses == [0.9, 0.7, 0.5, 0.3]

    def test_len(self):
        inds = [
            MultiLayerIndividual(
                prompt_set=_make_prompt_set()
            )
            for _ in range(5)
        ]
        pop = MultiLayerPopulation(inds)
        assert len(pop) == 5

    def test_iter(self):
        inds = [
            MultiLayerIndividual(
                prompt_set=_make_prompt_set()
            )
            for _ in range(3)
        ]
        pop = MultiLayerPopulation(inds)
        assert list(pop) == inds


class TestMultiLayerFitness:
    def test_per_layer_computation(self):
        fitness = MultiLayerFitness()
        predictions = {
            1: [("vulnerable", "vulnerable"), ("benign", "benign")],
            2: [("vulnerable", "benign")],
        }
        result = fitness.compute_per_layer(predictions)
        assert 1 in result
        assert 2 in result
        assert result[1] == 1.0  # 2/2 correct
        assert result[2] == 0.0  # 0/1 correct

    def test_aggregation_with_weights(self):
        fitness = MultiLayerFitness(
            weights={1: 0.5, 2: 0.3, 3: 0.2}
        )
        per_layer = {1: 0.8, 2: 0.6, 3: 0.4}
        aggregated = fitness.aggregate(per_layer)
        expected = 0.5 * 0.8 + 0.3 * 0.6 + 0.2 * 0.4
        assert abs(aggregated - expected) < 1e-6

    def test_aggregation_equal_weights(self):
        fitness = MultiLayerFitness()
        per_layer = {1: 0.8, 2: 0.6}
        aggregated = fitness.aggregate(per_layer)
        expected = (0.8 + 0.6) / 2.0
        assert abs(aggregated - expected) < 1e-6

    def test_error_feedback_adjusts(self):
        fitness = MultiLayerFitness()
        per_layer = {1: 0.8}
        error_patterns = [
            "Confused Memory with Input"
        ]
        aggregated = fitness.aggregate(
            per_layer, error_penalty=0.05,
            error_count=len(error_patterns),
        )
        # Penalty reduces score
        assert aggregated < 0.8


class TestMultiLayerEvolution:
    def test_crossover_preserves_fixed_sections(self):
        stub = DeterministicStubClient(
            default_response="Improved guidance text"
        )
        evo = MultiLayerEvolution(
            config={
                "population_size": 4,
                "max_generations": 1,
            },
            llm_client=stub,
        )
        ps1 = _make_prompt_set()
        ps2 = _make_prompt_set()
        parent1 = MultiLayerIndividual(
            prompt_set=ps1, fitness=0.7
        )
        parent2 = MultiLayerIndividual(
            prompt_set=ps2, fitness=0.8
        )
        child = evo.crossover_layer(
            parent1, parent2, layer=1, category="Memory"
        )
        # Fixed sections should still exist
        template = child.prompt_set.get_template(
            1, "Memory"
        )
        assert template is not None
        # The full text should still contain fixed parts
        full = template.full_text
        assert "Analyze for memory bugs:" in full

    def test_mutation_preserves_fixed_sections(self):
        stub = DeterministicStubClient(
            default_response="Mutated guidance text"
        )
        evo = MultiLayerEvolution(
            config={
                "population_size": 4,
                "max_generations": 1,
            },
            llm_client=stub,
        )
        ps = _make_prompt_set()
        ind = MultiLayerIndividual(
            prompt_set=ps, fitness=0.6
        )
        mutated = evo.mutate_layer(
            ind, layer=1, category="Memory"
        )
        template = mutated.prompt_set.get_template(
            1, "Memory"
        )
        full = template.full_text
        assert "Analyze for memory bugs:" in full

    def test_mutation_changes_trainable(self):
        stub = DeterministicStubClient(
            default_response="New trainable content"
        )
        evo = MultiLayerEvolution(
            config={
                "population_size": 4,
                "max_generations": 1,
            },
            llm_client=stub,
        )
        ps = _make_prompt_set()
        ind = MultiLayerIndividual(
            prompt_set=ps, fitness=0.6
        )
        original_trainable = ps.get_template(
            1, "Memory"
        ).get_trainable_sections()[0].content
        mutated = evo.mutate_layer(
            ind, layer=1, category="Memory"
        )
        new_trainable = mutated.prompt_set.get_template(
            1, "Memory"
        ).get_trainable_sections()[0].content
        assert new_trainable != original_trainable

    def test_evolution_loop_with_stub(self):
        stub = DeterministicStubClient(
            default_response="Evolved content"
        )
        evo = MultiLayerEvolution(
            config={
                "population_size": 4,
                "max_generations": 2,
                "mutation_rate": 0.5,
            },
            llm_client=stub,
        )
        # Create initial population
        initial_sets = [
            _make_prompt_set() for _ in range(4)
        ]
        result = evo.evolve_multilayer(
            initial_prompt_sets=initial_sets,
            evaluate_fn=lambda ps: 0.5 + 0.01 * hash(
                str(ps.to_dict())
            ) % 0.5,
        )
        assert "best_prompt_set" in result
        assert "best_fitness" in result
        assert "fitness_history" in result
