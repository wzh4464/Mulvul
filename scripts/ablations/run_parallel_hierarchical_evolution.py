#!/usr/bin/env python3
"""
并行分层漏洞检测进化实验

功能:
- Seed prompts 作为初始种群，输出 CONFIDENCE score
- Task-aware evolution prompts 指导进化
- 进度条显示
- 实时保存结果
- Checkpoint resume 支持
"""

import sys
import json
import re
import argparse
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field, asdict
from tqdm import tqdm

# 添加项目路径
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from evoprompt.llm.client import create_default_client
from evoprompt.algorithms.genetic import GeneticAlgorithm
from evoprompt.algorithms.base import Individual
from evoprompt.prompts import (
    load_seeds_for_ga,
    get_task_context,
    LAYER1_SEED_PROMPTS,
)
from evoprompt.data.dataset import PrimevulDataset
from evoprompt.data.sampler import sample_primevul_1percent
from evoprompt.utils.text import safe_format


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class SampleResult:
    """单个样本的评估结果"""
    sample_id: str
    code_hash: str
    ground_truth: int  # 0=benign, 1=vulnerable
    predicted_score: float  # 0.0-1.0
    prompt_idx: int
    category: str
    response_raw: str = ""


@dataclass
class PromptEvaluation:
    """单个 prompt 的评估结果"""
    prompt_idx: int
    prompt_text: str
    category: str
    samples_evaluated: int = 0
    total_samples: int = 0
    true_positives: int = 0
    true_negatives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    sample_results: List[SampleResult] = field(default_factory=list)

    @property
    def accuracy(self) -> float:
        total = self.true_positives + self.true_negatives + self.false_positives + self.false_negatives
        if total == 0:
            return 0.0
        return (self.true_positives + self.true_negatives) / total

    @property
    def precision(self) -> float:
        if self.true_positives + self.false_positives == 0:
            return 0.0
        return self.true_positives / (self.true_positives + self.false_positives)

    @property
    def recall(self) -> float:
        if self.true_positives + self.false_negatives == 0:
            return 0.0
        return self.true_positives / (self.true_positives + self.false_negatives)

    @property
    def f1(self) -> float:
        if self.precision + self.recall == 0:
            return 0.0
        return 2 * self.precision * self.recall / (self.precision + self.recall)


@dataclass
class GenerationResult:
    """单代进化结果"""
    generation: int
    category: str
    prompt_evaluations: List[PromptEvaluation] = field(default_factory=list)
    best_prompt_idx: int = 0
    best_accuracy: float = 0.0
    best_f1: float = 0.0
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


@dataclass
class ExperimentCheckpoint:
    """实验 checkpoint"""
    config: Dict[str, Any]
    category: str
    current_generation: int
    current_prompt_idx: int
    current_sample_idx: int
    generation_results: List[GenerationResult] = field(default_factory=list)
    prompts: List[str] = field(default_factory=list)
    timestamp: str = ""
    completed: bool = False

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

    def save(self, path: Path):
        """保存 checkpoint"""
        data = asdict(self)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    @classmethod
    def load(cls, path: Path) -> "ExperimentCheckpoint":
        """加载 checkpoint"""
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        # 重建嵌套对象
        gen_results = []
        for gr in data.get("generation_results", []):
            prompt_evals = []
            for pe in gr.get("prompt_evaluations", []):
                sample_results = [SampleResult(**sr) for sr in pe.get("sample_results", [])]
                pe_obj = PromptEvaluation(
                    prompt_idx=pe["prompt_idx"],
                    prompt_text=pe["prompt_text"],
                    category=pe["category"],
                    samples_evaluated=pe.get("samples_evaluated", 0),
                    total_samples=pe.get("total_samples", 0),
                    true_positives=pe.get("true_positives", 0),
                    true_negatives=pe.get("true_negatives", 0),
                    false_positives=pe.get("false_positives", 0),
                    false_negatives=pe.get("false_negatives", 0),
                    sample_results=sample_results,
                )
                prompt_evals.append(pe_obj)
            gr_obj = GenerationResult(
                generation=gr["generation"],
                category=gr["category"],
                prompt_evaluations=prompt_evals,
                best_prompt_idx=gr.get("best_prompt_idx", 0),
                best_accuracy=gr.get("best_accuracy", 0.0),
                best_f1=gr.get("best_f1", 0.0),
                timestamp=gr.get("timestamp", ""),
            )
            gen_results.append(gr_obj)

        return cls(
            config=data["config"],
            category=data["category"],
            current_generation=data["current_generation"],
            current_prompt_idx=data["current_prompt_idx"],
            current_sample_idx=data["current_sample_idx"],
            generation_results=gen_results,
            prompts=data.get("prompts", []),
            timestamp=data.get("timestamp", ""),
            completed=data.get("completed", False),
        )


# =============================================================================
# Score Parsing
# =============================================================================

def parse_confidence_score(response: str) -> float:
    """从 LLM 响应中解析 CONFIDENCE score

    支持格式:
    - CONFIDENCE: 0.8
    - CONFIDENCE: 0.85
    - confidence: 0.7
    - Score: 0.9
    - 0.75 (纯数字)
    """
    response = response.strip()

    # 尝试匹配 CONFIDENCE: <score> 格式
    patterns = [
        r'CONFIDENCE:\s*([\d.]+)',
        r'confidence:\s*([\d.]+)',
        r'Score:\s*([\d.]+)',
        r'score:\s*([\d.]+)',
        r'^([\d.]+)$',  # 纯数字
        r'(0\.\d+|1\.0|1|0)',  # 任何 0-1 数字
    ]

    for pattern in patterns:
        match = re.search(pattern, response, re.IGNORECASE)
        if match:
            try:
                score = float(match.group(1))
                return max(0.0, min(1.0, score))  # 限制在 0-1 范围
            except ValueError:
                continue

    # 如果包含 vulnerable/unsafe 等关键词，返回高分
    vulnerable_keywords = ['vulnerable', 'unsafe', 'insecure', 'dangerous', 'risk', 'flaw']
    safe_keywords = ['safe', 'secure', 'benign', 'clean', 'no vulnerability']

    response_lower = response.lower()
    for kw in vulnerable_keywords:
        if kw in response_lower:
            return 0.8
    for kw in safe_keywords:
        if kw in response_lower:
            return 0.2

    # 默认返回 0.5 (不确定)
    return 0.5


# =============================================================================
# Pipeline
# =============================================================================

class ParallelHierarchicalEvolutionPipeline:
    """并行分层漏洞检测进化实验"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.output_dir = Path(config.get("output_dir", "outputs/parallel_evolution"))
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Checkpoint 目录
        self.checkpoint_dir = self.output_dir / "checkpoints"
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)

        # 结果目录
        self.results_dir = self.output_dir / "results"
        self.results_dir.mkdir(parents=True, exist_ok=True)

        # Score 阈值 (用于二分类)
        self.score_threshold = config.get("score_threshold", 0.5)

        # 初始化 LLM 客户端
        print("初始化 LLM 客户端...")
        self.llm_client = self._create_llm_client()

        # 进化配置
        self.ga_config = {
            "population_size": config.get("population_size", 5),
            "max_generations": config.get("max_generations", 3),
            "mutation_rate": config.get("mutation_rate", 0.3),
            "crossover_rate": config.get("crossover_rate", 0.8),
        }

        print(f"✅ Pipeline 初始化完成")
        print(f"   输出目录: {self.output_dir}")
        print(f"   种群大小: {self.ga_config['population_size']}")
        print(f"   进化代数: {self.ga_config['max_generations']}")
        print(f"   Score 阈值: {self.score_threshold}")

    def _create_llm_client(self):
        """创建 LLM 客户端"""
        return create_default_client()

    def load_dataset(self) -> tuple:
        """加载数据集"""
        print("\n📁 加载数据集...")

        primevul_dir = Path(self.config.get("primevul_dir", "./data/primevul/primevul"))
        sample_dir = Path(self.config.get("sample_dir", "./data/primevul_1percent_sample"))

        if not sample_dir.exists():
            print(f"   生成 1% 采样数据到 {sample_dir}")
            sample_primevul_1percent(str(primevul_dir), str(sample_dir), seed=42)

        train_file = sample_dir / "train.txt"
        dev_file = sample_dir / "dev.txt"

        train_dataset = PrimevulDataset(str(train_file), "train")
        dev_dataset = PrimevulDataset(str(dev_file), "dev")

        print(f"   ✅ 训练集: {len(train_dataset)} 样本")
        print(f"   ✅ 开发集: {len(dev_dataset)} 样本")

        return train_dataset, dev_dataset

    def get_checkpoint_path(self, category: str) -> Path:
        """获取 checkpoint 文件路径"""
        return self.checkpoint_dir / f"checkpoint_{category}.json"

    def get_results_path(self, category: str) -> Path:
        """获取结果文件路径"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return self.results_dir / f"results_{category}_{timestamp}.json"

    def save_checkpoint(self, checkpoint: ExperimentCheckpoint):
        """保存 checkpoint"""
        path = self.get_checkpoint_path(checkpoint.category)
        checkpoint.save(path)
        print(f"\n💾 Checkpoint 已保存: {path}")

    def load_checkpoint(self, category: str) -> Optional[ExperimentCheckpoint]:
        """加载 checkpoint"""
        path = self.get_checkpoint_path(category)
        if path.exists():
            return ExperimentCheckpoint.load(path)
        return None

    def save_generation_result(self, gen_result: GenerationResult):
        """实时保存单代结果"""
        path = self.results_dir / f"gen_{gen_result.category}_{gen_result.generation}.json"

        # 转换为可序列化格式
        data = {
            "generation": gen_result.generation,
            "category": gen_result.category,
            "best_prompt_idx": gen_result.best_prompt_idx,
            "best_accuracy": gen_result.best_accuracy,
            "best_f1": gen_result.best_f1,
            "timestamp": gen_result.timestamp,
            "prompt_evaluations": [
                {
                    "prompt_idx": pe.prompt_idx,
                    "accuracy": pe.accuracy,
                    "precision": pe.precision,
                    "recall": pe.recall,
                    "f1": pe.f1,
                    "samples_evaluated": pe.samples_evaluated,
                    "true_positives": pe.true_positives,
                    "true_negatives": pe.true_negatives,
                    "false_positives": pe.false_positives,
                    "false_negatives": pe.false_negatives,
                }
                for pe in gen_result.prompt_evaluations
            ]
        }

        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def evaluate_prompt_with_progress(
        self,
        prompt: str,
        prompt_idx: int,
        category: str,
        dataset,
        max_samples: int = None,
        start_sample_idx: int = 0,
        existing_eval: Optional[PromptEvaluation] = None,
    ) -> PromptEvaluation:
        """评估单个 prompt，带进度条和实时保存"""
        samples = dataset.get_samples()
        if max_samples:
            samples = samples[:max_samples]

        # 使用现有评估或创建新的
        if existing_eval:
            eval_result = existing_eval
        else:
            eval_result = PromptEvaluation(
                prompt_idx=prompt_idx,
                prompt_text=prompt[:200] + "..." if len(prompt) > 200 else prompt,
                category=category,
                total_samples=len(samples),
            )

        # 从 start_sample_idx 继续
        samples_to_process = samples[start_sample_idx:]

        pbar = tqdm(
            enumerate(samples_to_process, start=start_sample_idx),
            total=len(samples),
            initial=start_sample_idx,
            desc=f"  Prompt {prompt_idx+1}",
            leave=False,
        )

        for sample_idx, sample in pbar:
            code = sample.input_text
            query = safe_format(prompt, input=code, CODE=code)

            # Ground truth: 0=benign, 1=vulnerable
            gt_binary = int(sample.target)

            # 预测
            try:
                response = self.llm_client.generate(query, temperature=0.1, max_tokens=100)
                score = parse_confidence_score(response)
            except Exception as e:
                print(f"\n      ⚠️ 样本 {sample_idx} 预测失败: {e}")
                score = 0.5
                response = f"ERROR: {e}"

            # 根据阈值转换为二分类
            predicted_binary = 1 if score >= self.score_threshold else 0

            # 记录结果
            sample_result = SampleResult(
                sample_id=str(sample_idx),
                code_hash=str(hash(code))[:16],
                ground_truth=gt_binary,
                predicted_score=score,
                prompt_idx=prompt_idx,
                category=category,
                response_raw=response[:200] if response else "",
            )
            eval_result.sample_results.append(sample_result)

            # 更新统计
            if predicted_binary == 1 and gt_binary == 1:
                eval_result.true_positives += 1
            elif predicted_binary == 0 and gt_binary == 0:
                eval_result.true_negatives += 1
            elif predicted_binary == 1 and gt_binary == 0:
                eval_result.false_positives += 1
            else:
                eval_result.false_negatives += 1

            eval_result.samples_evaluated += 1

            # 更新进度条
            pbar.set_postfix({
                "acc": f"{eval_result.accuracy:.1%}",
                "f1": f"{eval_result.f1:.2f}",
            })

        return eval_result

    def run_category_evolution(
        self,
        category: str,
        train_dataset,
        dev_dataset,
        resume_checkpoint: Optional[ExperimentCheckpoint] = None,
    ) -> Dict[str, Any]:
        """对单个类别运行进化"""
        print(f"\n{'='*60}")
        print(f"🧬 进化类别: {category}")
        print(f"{'='*60}")

        # 获取 task context
        task_context = get_task_context(category)
        if task_context:
            print(f"   任务描述: {task_context.description[:60]}...")
            print(f"   关键指标: {len(task_context.indicators)} 个")

        # 创建或恢复 checkpoint
        if resume_checkpoint and not resume_checkpoint.completed:
            checkpoint = resume_checkpoint
            prompts = checkpoint.prompts
            start_gen = checkpoint.current_generation
            start_prompt_idx = checkpoint.current_prompt_idx
            start_sample_idx = checkpoint.current_sample_idx
            generation_results = checkpoint.generation_results
            print(f"   📂 从 checkpoint 恢复: 第 {start_gen} 代, Prompt {start_prompt_idx}, 样本 {start_sample_idx}")
        else:
            # 创建 GA 并获取种子 prompts
            ga = GeneticAlgorithm.with_seed_prompts(
                self.ga_config,
                layer=1,
                category=category
            )
            prompts = ga._seed_prompts
            start_gen = 0
            start_prompt_idx = 0
            start_sample_idx = 0
            generation_results = []

            checkpoint = ExperimentCheckpoint(
                config=self.config,
                category=category,
                current_generation=0,
                current_prompt_idx=0,
                current_sample_idx=0,
                prompts=prompts,
            )

        print(f"   种子 prompts: {len(prompts)} 个")

        eval_samples = self.config.get("eval_samples", 50)

        # 进化循环
        for gen in range(start_gen, self.ga_config["max_generations"] + 1):
            print(f"\n📈 第 {gen} 代 (共 {self.ga_config['max_generations']} 代)")

            gen_result = GenerationResult(generation=gen, category=category)

            # 确定起始 prompt 索引
            prompt_start = start_prompt_idx if gen == start_gen else 0

            for prompt_idx in range(prompt_start, len(prompts)):
                prompt = prompts[prompt_idx]

                # 确定起始样本索引
                sample_start = start_sample_idx if (gen == start_gen and prompt_idx == start_prompt_idx) else 0

                # 查找已有评估
                existing_eval = None
                if sample_start > 0:
                    # 从 checkpoint 恢复现有评估
                    for gr in generation_results:
                        if gr.generation == gen:
                            for pe in gr.prompt_evaluations:
                                if pe.prompt_idx == prompt_idx:
                                    existing_eval = pe
                                    break

                # 评估 prompt
                eval_result = self.evaluate_prompt_with_progress(
                    prompt=prompt,
                    prompt_idx=prompt_idx,
                    category=category,
                    dataset=dev_dataset,
                    max_samples=eval_samples,
                    start_sample_idx=sample_start,
                    existing_eval=existing_eval,
                )

                gen_result.prompt_evaluations.append(eval_result)
                print(f"      Prompt {prompt_idx+1}: acc={eval_result.accuracy:.1%}, f1={eval_result.f1:.2f}, "
                      f"TP={eval_result.true_positives}, TN={eval_result.true_negatives}, "
                      f"FP={eval_result.false_positives}, FN={eval_result.false_negatives}")

                # 更新 checkpoint
                checkpoint.current_generation = gen
                checkpoint.current_prompt_idx = prompt_idx + 1
                checkpoint.current_sample_idx = 0
                self.save_checkpoint(checkpoint)

            # 找最佳 prompt
            if gen_result.prompt_evaluations:
                best_eval = max(gen_result.prompt_evaluations, key=lambda x: x.f1)
                gen_result.best_prompt_idx = best_eval.prompt_idx
                gen_result.best_accuracy = best_eval.accuracy
                gen_result.best_f1 = best_eval.f1

            generation_results.append(gen_result)
            checkpoint.generation_results = generation_results

            # 实时保存本代结果
            self.save_generation_result(gen_result)

            print(f"\n   ✅ 第 {gen} 代完成: 最佳 F1={gen_result.best_f1:.2f}, Acc={gen_result.best_accuracy:.1%}")

            # 重置起始索引
            start_prompt_idx = 0
            start_sample_idx = 0

        # 标记完成
        checkpoint.completed = True
        self.save_checkpoint(checkpoint)

        # 返回结果
        best_gen = max(generation_results, key=lambda x: x.best_f1)
        best_prompt = prompts[best_gen.best_prompt_idx]

        return {
            "category": category,
            "best_prompt": best_prompt,
            "best_f1": best_gen.best_f1,
            "best_accuracy": best_gen.best_accuracy,
            "fitness_history": [gr.best_f1 for gr in generation_results],
            "generation_results": generation_results,
        }

    def run(self, resume: bool = True) -> Dict[str, Any]:
        """运行完整实验"""
        print("\n" + "="*80)
        print("🚀 并行分层漏洞检测进化实验")
        print("="*80)

        # 加载数据
        train_dataset, dev_dataset = self.load_dataset()

        # 选择要进化的类别
        categories = self.config.get("categories", ["Memory"])
        print(f"\n目标类别: {categories}")

        # 对每个类别进行进化
        results = {}
        for category in categories:
            if category not in LAYER1_SEED_PROMPTS:
                print(f"⚠️ 跳过类别 {category}: 无 seed prompts")
                continue

            # 检查是否有可恢复的 checkpoint
            checkpoint = None
            if resume:
                checkpoint = self.load_checkpoint(category)
                if checkpoint and checkpoint.completed:
                    print(f"\n⏭️ 类别 {category} 已完成，跳过")
                    continue

            result = self.run_category_evolution(
                category, train_dataset, dev_dataset, checkpoint
            )
            results[category] = result

        # 保存最终结果
        self.save_final_results(results)

        return results

    def save_final_results(self, results: Dict[str, Any]):
        """保存最终结果"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # 保存汇总
        summary_file = self.output_dir / f"evolution_summary_{timestamp}.json"

        summary = {
            "timestamp": timestamp,
            "config": self.config,
            "results": {
                cat: {
                    "best_f1": r["best_f1"],
                    "best_accuracy": r["best_accuracy"],
                    "fitness_history": r["fitness_history"],
                }
                for cat, r in results.items()
            }
        }

        with open(summary_file, "w", encoding='utf-8') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)

        print(f"\n💾 最终结果已保存到: {summary_file}")

        # 打印最终结果
        print("\n" + "="*80)
        print("📊 最终结果")
        print("="*80)

        for cat, result in results.items():
            print(f"\n{cat}:")
            print(f"  最佳 F1: {result['best_f1']:.2f}")
            print(f"  最佳 Accuracy: {result['best_accuracy']:.1%}")
            print(f"  F1 历史: {' → '.join(f'{f:.2f}' for f in result['fitness_history'])}")


def main():
    parser = argparse.ArgumentParser(description="并行分层漏洞检测进化实验")
    parser.add_argument("--population-size", type=int, default=5, help="种群大小")
    parser.add_argument("--max-generations", type=int, default=3, help="最大进化代数")
    parser.add_argument("--eval-samples", type=int, default=50, help="每次评估样本数")
    parser.add_argument("--score-threshold", type=float, default=0.5, help="Score 二分类阈值")
    parser.add_argument("--categories", nargs="+", default=["Memory"],
                        help="要进化的类别")
    parser.add_argument("--output-dir", type=str, default="outputs/parallel_evolution",
                        help="输出目录")
    parser.add_argument("--primevul-dir", type=str, default="./data/primevul/primevul")
    parser.add_argument("--sample-dir", type=str, default="./data/primevul_1percent_sample")
    parser.add_argument("--no-resume", action="store_true", help="不从 checkpoint 恢复")

    args = parser.parse_args()

    config = {
        "population_size": args.population_size,
        "max_generations": args.max_generations,
        "eval_samples": args.eval_samples,
        "score_threshold": args.score_threshold,
        "categories": args.categories,
        "output_dir": args.output_dir,
        "primevul_dir": args.primevul_dir,
        "sample_dir": args.sample_dir,
    }

    pipeline = ParallelHierarchicalEvolutionPipeline(config)
    results = pipeline.run(resume=not args.no_resume)

    print("\n✅ 实验完成!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
