"""华为安全检测数据集的完整工作流程."""

import json
import logging
import random
import time
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

try:
    from .dataset import HuaweiDataset
    from .prompt_manager import HuaweiPromptManager
    from ..evoprompt.core.evolution import EvolutionEngine
    from ..evoprompt.core.evaluator import Evaluator
    from ..evoprompt.core.prompt_tracker import PromptTracker, EvolutionLogger
    from ..evoprompt.algorithms.differential import DifferentialEvolution
    from ..evoprompt.algorithms.genetic import GeneticAlgorithm
    from ..evoprompt.llm.client import create_llm_client
    from ..evoprompt.metrics.base import AccuracyMetric
    from ..evoprompt.utils.text import safe_format
except ImportError:
    # 处理直接运行时的导入问题
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from huawei.dataset import HuaweiDataset
    from huawei.prompt_manager import HuaweiPromptManager
    from evoprompt.core.evolution import EvolutionEngine
    from evoprompt.core.evaluator import Evaluator
    from evoprompt.core.prompt_tracker import PromptTracker, EvolutionLogger
    from evoprompt.algorithms.differential import DifferentialEvolution
    from evoprompt.algorithms.genetic import GeneticAlgorithm
    from evoprompt.llm.client import create_llm_client
    from evoprompt.metrics.base import AccuracyMetric
    from evoprompt.utils.text import safe_format

logger = logging.getLogger(__name__)


class HuaweiSecurityEvaluator(Evaluator):
    """华为安全检测专用评估器."""

    def __init__(self, dataset: HuaweiDataset, llm_client, config: Dict[str, Any]):
        super().__init__(dataset, llm_client)
        self.config = config
        self.dataset = dataset

    def evaluate_prompt(self, prompt: str, samples: Optional[List] = None) -> Dict[str, float]:
        """评估 prompt 在华为数据集上的性能.

        Args:
            prompt: 要评估的 prompt
            samples: 评估样本，如果为 None 则使用全部样本

        Returns:
            评估结果字典
        """
        if samples is None:
            samples = self.dataset.get_samples(
                self.config.get("evaluation_config", {}).get("max_eval_samples", 50)
            )

        predictions = []
        ground_truths = []

        for sample in samples:
            try:
                # 构建评估 prompt
                evaluation_prompt = safe_format(
                    prompt,
                    category_list="\\n".join(f"- {cat}" for cat in self.dataset.get_categories()),
                    code=sample.code,
                    lang=sample.metadata.get("lang", "cpp"),
                )

                # 获取 LLM 响应
                response = self.llm_client.generate(evaluation_prompt)

                # 解析响应
                parsed_response = self._parse_response(response)
                predictions.append(parsed_response)

                # 解析真实标签
                ground_truth = self._parse_ground_truth(sample)
                ground_truths.append(ground_truth)

            except Exception as e:
                logger.warning(f"评估样本时出错: {e}")
                # 使用默认值
                predictions.append({"vulnerabilities": []})
                ground_truths.append({"vulnerabilities": sample.ground_truth})

        # 计算指标
        metrics = self._calculate_metrics(predictions, ground_truths)
        return metrics

    def _parse_response(self, response: str) -> Dict[str, List]:
        """解析 LLM 响应."""
        try:
            # 尝试直接解析 JSON
            if response.strip().startswith('{'):
                return json.loads(response.strip())

            # 尝试从响应中提取 JSON
            start_idx = response.find('{')
            end_idx = response.rfind('}') + 1

            if start_idx != -1 and end_idx > start_idx:
                json_str = response[start_idx:end_idx]
                return json.loads(json_str)

            # 如果无法解析，返回空结果
            logger.warning(f"无法解析响应: {response[:100]}...")
            return {"vulnerabilities": []}

        except json.JSONDecodeError:
            logger.warning(f"JSON 解析失败: {response[:100]}...")
            return {"vulnerabilities": []}

    def _parse_ground_truth(self, sample) -> Dict[str, List]:
        """解析真实标签."""
        return {"vulnerabilities": sample.ground_truth}

    def _calculate_metrics(self, predictions: List[Dict], ground_truths: List[Dict]) -> Dict[str, float]:
        """计算评估指标."""
        if not predictions or not ground_truths:
            return {"accuracy": 0.0, "precision": 0.0, "recall": 0.0, "f1_score": 0.0}

        # 计算二分类指标（有漏洞 vs 无漏洞）
        tp = fp = tn = fn = 0

        for pred, gt in zip(predictions, ground_truths):
            pred_has_vuln = len(pred.get("vulnerabilities", [])) > 0
            gt_has_vuln = len(gt.get("vulnerabilities", [])) > 0

            if pred_has_vuln and gt_has_vuln:
                tp += 1
            elif pred_has_vuln and not gt_has_vuln:
                fp += 1
            elif not pred_has_vuln and not gt_has_vuln:
                tn += 1
            else:  # not pred_has_vuln and gt_has_vuln
                fn += 1

        # 计算指标
        accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1_score = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        return {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1_score": f1_score,
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn
        }


class HuaweiWorkflow:
    """华为安全检测数据集的完整工作流程."""

    def __init__(self, config_path: str, data_path: str):
        """初始化工作流程.

        Args:
            config_path: 配置文件路径
            data_path: 数据文件路径
        """
        self.config_path = config_path
        self.data_path = data_path

        # 加载配置
        with open(config_path, 'r', encoding='utf-8') as f:
            self.config = json.load(f)

        # 初始化组件
        self.dataset = HuaweiDataset(data_path, config_path)
        self.prompt_manager = HuaweiPromptManager(config_path)
        self.llm_client = None
        self.evaluator = None

        # 设置输出目录
        self.setup_directories()
        self.setup_logging()

    def setup_directories(self):
        """设置输出目录."""
        output_config = self.config.get("output_config", {})
        base_dir = output_config.get("base_dir", "./outputs/huawei")
        self.output_dir = Path(base_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # 创建实验ID
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.experiment_id = f"huawei_security_{timestamp}"
        self.exp_dir = self.output_dir / self.experiment_id
        self.exp_dir.mkdir(exist_ok=True)

    def setup_logging(self):
        """设置日志."""
        self.logger = EvolutionLogger(
            output_dir=str(self.output_dir),
            experiment_id=self.experiment_id
        )

    def initialize_llm_client(self):
        """初始化 LLM 客户端."""
        llm_config = self.config.get("llm_config", {})
        self.llm_client = create_llm_client(llm_config)

    def load_and_prepare_data(self, sample_size: Optional[int] = None) -> None:
        """加载并准备数据.

        Args:
            sample_size: 采样大小，如果为 None 则使用全部数据
        """
        logger.info("加载华为安全数据集...")

        # 加载数据
        samples = self.dataset.load_data(self.data_path)
        logger.info(f"成功加载 {len(samples)} 个样本")

        # 打印数据集统计
        stats = self.dataset.get_statistics()
        logger.info(f"数据集统计: {json.dumps(stats, ensure_ascii=False, indent=2)}")

        # 如果指定了采样大小，进行均衡采样
        if sample_size and sample_size < len(samples):
            samples = self.dataset.sample_balanced(sample_size)
            logger.info(f"均衡采样到 {len(samples)} 个样本")

        # 保存统计信息
        stats_file = self.exp_dir / "dataset_statistics.json"
        with open(stats_file, 'w', encoding='utf-8') as f:
            json.dump(stats, f, ensure_ascii=False, indent=2)

    def run_evolution(self) -> Dict[str, Any]:
        """运行 prompt 进化过程.

        Returns:
            进化结果
        """
        logger.info("开始 prompt 进化过程...")

        # 初始化 LLM 客户端
        if self.llm_client is None:
            self.initialize_llm_client()

        # 初始化评估器
        self.evaluator = HuaweiSecurityEvaluator(
            self.dataset, self.llm_client, self.config
        )

        # 初始化 prompt 种群
        evolution_config = self.config.get("evolution_config", {})
        population_size = evolution_config.get("population_size", 8)
        initial_prompts = self.prompt_manager.initialize_prompts(population_size)

        # 设置进化算法
        algorithm_type = evolution_config.get("algorithm", "differential")
        if algorithm_type == "differential":
            algorithm = DifferentialEvolution(
                population_size=population_size,
                mutation_rate=evolution_config.get("mutation_rate", 0.3),
                crossover_rate=evolution_config.get("crossover_rate", 0.7)
            )
        else:  # genetic
            algorithm = GeneticAlgorithm(
                population_size=population_size,
                mutation_rate=evolution_config.get("mutation_rate", 0.3),
                crossover_rate=evolution_config.get("crossover_rate", 0.7)
            )

        # 设置 prompt 追踪器
        prompt_tracker = PromptTracker(
            output_dir=str(self.exp_dir),
            experiment_id=self.experiment_id
        )

        # 运行进化
        max_generations = evolution_config.get("max_generations", 10)
        best_fitness = 0
        patience_counter = 0
        patience = evolution_config.get("early_stopping", {}).get("patience", 3)

        for generation in range(max_generations):
            logger.info(f"开始第 {generation + 1} 代进化...")

            # 评估当前种群
            fitness_scores = []
            for i, prompt in enumerate(initial_prompts):
                try:
                    # 使用少量样本进行快速评估
                    eval_samples = self.dataset.get_samples(20)  # 使用20个样本快速评估
                    metrics = self.evaluator.evaluate_prompt(prompt, eval_samples)
                    fitness = metrics.get("f1_score", 0.0)
                    fitness_scores.append(fitness)

                    # 记录 prompt 快照
                    prompt_tracker.log_prompt(
                        prompt=prompt,
                        fitness=fitness,
                        generation=generation,
                        individual_id=f"ind_{i}",
                        operation="evaluation",
                        metadata=metrics
                    )

                    logger.info(f"个体 {i} 适应度: {fitness:.4f}")

                except Exception as e:
                    logger.error(f"评估个体 {i} 时出错: {e}")
                    fitness_scores.append(0.0)

            # 检查是否有改进
            current_best = max(fitness_scores)
            if current_best > best_fitness:
                improvement = current_best - best_fitness
                best_fitness = current_best
                patience_counter = 0
                logger.info(f"发现更好的解: {current_best:.4f} (提升 {improvement:.4f})")
            else:
                patience_counter += 1
                logger.info(f"本代无改进，耐心计数: {patience_counter}/{patience}")

            # 早停检查
            if patience_counter >= patience:
                logger.info("触发早停条件，结束进化")
                break

            # 生成下一代（如果不是最后一代）
            if generation < max_generations - 1:
                # 选择、交叉、变异
                next_generation = []

                # 保留最佳个体
                best_idx = fitness_scores.index(max(fitness_scores))
                next_generation.append(initial_prompts[best_idx])

                # 生成其余个体
                while len(next_generation) < population_size:
                    # 选择父代
                    parent1_idx = self._tournament_selection(fitness_scores)
                    parent2_idx = self._tournament_selection(fitness_scores)

                    parent1 = initial_prompts[parent1_idx]
                    parent2 = initial_prompts[parent2_idx]

                    # 交叉
                    if random.random() < evolution_config.get("crossover_rate", 0.7):
                        child1, child2 = self.prompt_manager.crossover_prompts(parent1, parent2)
                    else:
                        child1, child2 = parent1, parent2

                    # 变异
                    child1 = self.prompt_manager.mutate_prompt(
                        child1, evolution_config.get("mutation_rate", 0.3)
                    )
                    child2 = self.prompt_manager.mutate_prompt(
                        child2, evolution_config.get("mutation_rate", 0.3)
                    )

                    next_generation.extend([child1, child2])

                initial_prompts = next_generation[:population_size]

        # 最终评估
        logger.info("进行最终评估...")
        final_results = {}
        for i, prompt in enumerate(initial_prompts):
            metrics = self.evaluator.evaluate_prompt(prompt)
            final_results[f"prompt_{i}"] = {
                "prompt": prompt,
                "metrics": metrics
            }

        # 找到最佳 prompt
        best_prompt_id = max(final_results.keys(),
                           key=lambda k: final_results[k]["metrics"].get("f1_score", 0))
        best_result = final_results[best_prompt_id]

        # 保存结果
        self._save_results(final_results, best_result)

        return best_result

    def _tournament_selection(self, fitness_scores: List[float], tournament_size: int = 3) -> int:
        """锦标赛选择."""
        import random
        tournament_indices = random.sample(range(len(fitness_scores)), tournament_size)
        best_idx = max(tournament_indices, key=lambda i: fitness_scores[i])
        return best_idx

    def _save_results(self, all_results: Dict, best_result: Dict) -> None:
        """保存结果."""
        # 保存所有结果
        results_file = self.exp_dir / "evolution_results.json"
        with open(results_file, 'w', encoding='utf-8') as f:
            json.dump({
                "experiment_id": self.experiment_id,
                "config": self.config,
                "all_results": all_results,
                "best_result": best_result,
                "timestamp": datetime.now().isoformat()
            }, f, ensure_ascii=False, indent=2)

        # 保存最佳 prompt
        best_prompt_file = self.exp_dir / "best_prompt.txt"
        with open(best_prompt_file, 'w', encoding='utf-8') as f:
            f.write(best_result["prompt"])

        logger.info(f"结果已保存到: {self.exp_dir}")

    def get_experiment_summary(self) -> Dict[str, Any]:
        """获取实验总结."""
        return {
            "experiment_id": self.experiment_id,
            "dataset_name": self.dataset.name,
            "total_samples": len(self.dataset),
            "categories": self.dataset.get_categories(),
            "config": self.config,
            "output_dir": str(self.exp_dir)
        }
