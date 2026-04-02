"""Workflow for CWE Research Concepts (10-class) classification using EvoPrompt."""
from typing import Any, Dict, List, Optional
import os
import json
import time
from pathlib import Path

from ..core.evolution import EvolutionEngine
from ..core.evaluator import Evaluator, EvaluationResult
from ..core.prompt_tracker import PromptTracker, EvolutionLogger
from ..data.dataset import create_dataset
from ..algorithms.differential import DifferentialEvolution
from ..algorithms.genetic import GeneticAlgorithm
from ..llm.client import create_llm_client
from ..metrics.base import AccuracyMetric
from ..data.cwe_research_concepts import (
    RESEARCH_CONCEPTS,
    concept_id_to_name,
    all_concepts_enumeration,
    map_cwe_list_to_concept_id,
    parse_concept_from_response,
)


class CWEConceptEvaluator(Evaluator):
    """Evaluator for 10-class CWE Research Concepts, with filled prompt记录功能."""
    def __init__(
        self,
        dataset,
        metric,
        llm_client,
        prompt_tracker: Optional[PromptTracker] = None,
        sample_size: int = 100,
        filled_prompts_file: Optional[str] = None # 新增
    ):
        super().__init__(dataset, metric, llm_client)
        self.prompt_tracker = prompt_tracker
        self.sample_size = sample_size
        self.evaluation_count = 0
        self.filled_prompts_file = filled_prompts_file

    def evaluate(self, prompt: str, generation: int = 0) -> EvaluationResult:
        self.evaluation_count += 1
        samples = self.dataset.get_samples(self.sample_size)
        predictions: List[str] = []
        targets: List[str] = []
        enum_text = all_concepts_enumeration()
        filled_examples = []
        for idx, sample in enumerate(samples):
            formatted_prompt = (
                f"{prompt}\n\nClassify the following code into one of the CWE Research Concepts (0-10).\n"
                f"Respond ONLY with the category number (0-10).\n\n{enum_text}\n\nCode to analyze:\n{{input}}\n".replace("{input}", sample.input_text)
            )
            instance = {
                "template": prompt,
                "filled": formatted_prompt,
                "sample_id": getattr(sample, 'id', idx),
                "generation": generation,
                "target": getattr(sample, 'target', None)
            }
            filled_examples.append(instance)
            try:
                response = self.llm_client.generate(formatted_prompt, max_tokens=8, temperature=0.1)
                cid = parse_concept_from_response(response)
                if cid is None:
                    cid = 0
                pred_name = concept_id_to_name(cid)
            except Exception:
                pred_name = concept_id_to_name(0)
            predictions.append(pred_name)
            # Target mapping
            if str(sample.target) == "0":
                targets.append(concept_id_to_name(0))
            else:
                cid_t = map_cwe_list_to_concept_id(sample.metadata.get("cwe", []))
                targets.append(concept_id_to_name(cid_t))
        # 写入filled prompt实例
        if self.filled_prompts_file and filled_examples:
            try:
                with open(self.filled_prompts_file, 'a', encoding='utf-8') as f:
                    for item in filled_examples:
                        f.write(json.dumps(item, ensure_ascii=False) + '\n')
            except Exception as e:
                print(f"⚠️ 填充prompt样例保存失败: {e}")
        score = self.metric.compute(predictions, targets)
        if self.prompt_tracker:
            self.prompt_tracker.log_prompt(
                prompt=prompt,
                fitness=score,
                generation=generation,
                individual_id=f"eval_{self.evaluation_count}",
                operation="evaluation",
                metadata={
                    "sample_size": len(samples),
                    "predictions_sample": predictions[:5],
                    "targets_sample": targets[:5],
                },
            )
        return EvaluationResult(
            score=score,
            details={
                "num_samples": len(samples),
                "predictions": predictions[:10],
                "targets": targets[:10],
                "accuracy": score,
            },
        )


class CWEConceptWorkflow:
    """Complete workflow for CWE Research Concepts prompt optimization."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.setup_directories()
        self.setup_logging()
        self.setup_prompt_tracker()

    def setup_directories(self):
        self.output_dir = Path(self.config.get("output_dir", "./outputs/cwe_research_concepts"))
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.experiment_id = self.config.get("experiment_id") or f"cwe_rc_{int(time.time())}"
        self.exp_dir = self.output_dir / self.experiment_id
        self.exp_dir.mkdir(exist_ok=True)

    def setup_logging(self):
        self.logger = EvolutionLogger(output_dir=str(self.output_dir), experiment_id=self.experiment_id)

    def setup_prompt_tracker(self):
        self.prompt_tracker = PromptTracker(output_dir=str(self.output_dir), experiment_id=self.experiment_id)
        self.prompt_tracker.set_config(self.config)

    def prepare_data(self) -> tuple:
        dataset_name = self.config["dataset"]
        dev_file = self.config.get("dev_file")
        test_file = self.config.get("test_file", dev_file)
        dev_dataset = create_dataset(dataset_name, dev_file, "dev")
        test_dataset = create_dataset(dataset_name, test_file, "test")
        self.logger.info(f"Loaded datasets: dev={len(dev_dataset)}, test={len(test_dataset)}")
        return dev_dataset, test_dataset

    def create_components(self, dev_dataset):
        llm_client = create_llm_client(llm_type=self.config.get("llm_type", "sven"))
        metric = AccuracyMetric()
        filled_prompts_file = str(self.exp_dir / "filled_prompts.jsonl")
        evaluator = CWEConceptEvaluator(
            dataset=dev_dataset,
            metric=metric,
            llm_client=llm_client,
            prompt_tracker=self.prompt_tracker,
            sample_size=self.config.get("sample_size", 100),
            filled_prompts_file=filled_prompts_file
        )
        algorithm_type = self.config.get("algorithm", "de").lower()
        algorithm_config = {
            "population_size": self.config.get("population_size", 20),
            "max_generations": self.config.get("max_generations", 10),
            "mutation_rate": self.config.get("mutation_rate", 0.1),
        }
        if algorithm_type == "de":
            algorithm = DifferentialEvolution(algorithm_config)
        elif algorithm_type == "ga":
            algorithm_config["crossover_rate"] = self.config.get("crossover_rate", 0.8)
            algorithm = GeneticAlgorithm(algorithm_config)
        else:
            raise ValueError(f"Unknown algorithm: {algorithm_type}")
        return llm_client, evaluator, algorithm

    def get_initial_prompts(self) -> List[str]:
        defaults = [
            "Analyze the following code and classify it into one CWE Research Concept (0-10). Respond only with the number.\n\nCode:{input}\n",
            "You are a security analyst. Look at the code and output only the matching Research Concept ID (0-10).\n\n{input}\n",
            "Review this function and output the best Research Concept (0-10). Only the number.\n\n{input}\n",
        ]
        custom_prompts_file = self.config.get("initial_prompts_file")
        if custom_prompts_file and os.path.exists(custom_prompts_file):
            try:
                with open(custom_prompts_file, "r", encoding="utf-8") as f:
                    lines = [l.strip() for l in f if l.strip()]
                if lines:
                    return lines
            except Exception:
                pass
        return defaults

    def run_evolution(self) -> Dict[str, Any]:
        self.logger.info("Starting CWE Research Concepts evolution...")
        # 保存 meta prompt
        if self.config.get("meta_prompt"):
            meta_path = self.exp_dir / "meta_prompt.txt"
            try:
                with open(meta_path, 'w', encoding='utf-8') as f:
                    f.write(str(self.config["meta_prompt"]).strip() + '\n')
            except Exception as e:
                self.logger.warning(f"Failed to save meta prompt: {e}")
        dev_dataset, test_dataset = self.prepare_data()
        llm_client, evaluator, algorithm = self.create_components(dev_dataset)
        initial_prompts = self.get_initial_prompts()
        for i, p in enumerate(initial_prompts):
            self.prompt_tracker.log_prompt(prompt=p, generation=0, individual_id=f"init_{i}", operation="initialization")
        engine = EvolutionEngine(algorithm=algorithm, evaluator=evaluator, llm_client=llm_client, config=self.config)
        results = engine.evolve(initial_prompts=initial_prompts)
        self.save_results(results, test_dataset, llm_client)
        return results

    def save_results(self, results: Dict[str, Any], test_dataset, llm_client):
        # 再次确保 meta prompt 单独保存
        if self.config.get("meta_prompt"):
            meta_path = self.exp_dir / "meta_prompt.txt"
            try:
                with open(meta_path, 'w', encoding='utf-8') as f:
                    f.write(str(self.config["meta_prompt"]).strip() + '\n')
            except Exception as e:
                self.logger.warning(f"Failed to save meta prompt: {e}")
        self.prompt_tracker.save_summary(results)
        top_prompts_file = self.exp_dir / "top_prompts.txt"
        self.prompt_tracker.export_prompts_by_fitness(str(top_prompts_file), top_k=10)
        if results.get("best_prompt"):
            self.evaluate_on_test_set(results["best_prompt"], test_dataset, llm_client)
        results_file = self.exp_dir / "final_results.json"
        with open(results_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

    def evaluate_on_test_set(self, best_prompt: str, test_dataset, llm_client):
        evaluator = CWEConceptEvaluator(
            dataset=test_dataset,
            metric=AccuracyMetric(),
            llm_client=llm_client,
            prompt_tracker=None,
            sample_size=self.config.get("test_sample_size", 200),
        )
        result = evaluator.evaluate(best_prompt)
        test_file = self.exp_dir / "test_results.json"
        with open(test_file, "w", encoding="utf-8") as f:
            json.dump({"prompt": best_prompt, "test_accuracy": result.score, "test_details": result.details}, f, indent=2, ensure_ascii=False)


def run_cwe_rc_workflow(**kwargs) -> Dict[str, Any]:
    default = {
        "dataset": "primevul",
        "algorithm": "de",
        "population_size": 20,
        "max_generations": 10,
        "mutation_rate": 0.1,
        "llm_type": "gpt-3.5-turbo",
        "sample_size": 100,
        "test_sample_size": 200,
        "output_dir": "./outputs/cwe_research_concepts",
    }
    default.update(kwargs)
    wf = CWEConceptWorkflow(default)
    return wf.run_evolution()