#!/usr/bin/env python3
"""
优化版本：使用并发加速的Primevul 1% Prompt进化实验
支持训练集打乱和每个样本结果反馈更新prompt
"""

import os
import sys
import json
import time
import random
from pathlib import Path
from datetime import datetime
from typing import List

# 添加src路径
sys.path.insert(0, "src")

from mulvul.data.sampler import sample_primevul_1percent
from mulvul.core.prompt_tracker import PromptTracker
from mulvul.algorithms.base import Population
from mulvul.data.dataset import PrimevulDataset
from mulvul.data.cwe_categories import (
    CWE_MAJOR_CATEGORIES,
    map_cwe_to_major,
    canonicalize_category,
)
from mulvul.utils.text import safe_format


def setup_logging():
    """设置日志"""
    import logging

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler("primevul_concurrent_evolution.log", encoding="utf-8"),
        ],
    )

    return logging.getLogger(__name__)


def check_api_configuration():
    """检查API配置（ChatAnywhere）"""
    # 加载.env文件中的环境变量
    from src.mulvul.llm.client import load_env_vars

    load_env_vars()

    api_key = os.getenv("API_KEY")
    if not api_key:
        print("❌ 请设置 API_KEY 环境变量")
        print("   在.env文件中设置: API_KEY='your-api-key-here'")
        return None

    # 检查ChatAnywhere配置
    api_base = os.getenv("API_BASE_URL", "https://api.chatanywhere.tech/v1")
    model_name = os.getenv("MODEL_NAME", "gpt-3.5-turbo")

    print("✅ ChatAnywhere API配置检查通过:")
    print(f"   API_BASE_URL: {api_base}")
    print(f"   MODEL_NAME: {model_name}")
    print(f"   API_KEY: {api_key[:10]}...")

    return api_key


def create_optimized_config():
    """创建优化的实验配置，充分利用并发优势"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    config = {
        # 实验标识
        "experiment_id": f"primevul_concurrent_1pct_{timestamp}",
        "experiment_name": "Primevul 1% Concurrent Optimized Evolution with Sample-wise Feedback",
        "timestamp": timestamp,
        # 数据配置
        "dataset": "primevul",
        "sample_ratio": 0.01,
        "balanced_sampling": True,
        "shuffle_training_data": True,  # 启用训练集打乱
        # 算法配置 - 优化参数以利用并发
        "algorithm": "de",
        "population_size": 8,  # 调整种群大小适应样本级反馈
        "max_generations": 5,  # 调整代数
        "mutation_rate": 0.15,
        "crossover_probability": 0.8,
        # 样本级反馈配置
        "sample_wise_feedback": True,  # 启用样本级反馈
        "feedback_batch_size": 10,  # 每批反馈的样本数
        "feedback_update_threshold": 0.1,  # 反馈更新阈值
        "record_all_samples": True,  # 记录所有样本结果
        # 并发优化配置
        "max_concurrency": 16,  # 基于测试的最佳并发度
        "force_async": True,  # 强制使用异步处理
        "batch_evaluation": True,  # 批量评估优化
        # LLM批处理配置
        "llm_batch_size": 8,  # LLM API调用的批处理大小
        "enable_batch_processing": True,  # 启用批处理优化
        "enable_concurrent": True,  # 启用批次内并发处理
        # LLM配置
        "llm_type": "gpt-3.5-turbo",
        "temperature": 0.7,
        # 评估配置
        "sample_size": None,
        "test_sample_size": None,
        # 输出配置
        "output_dir": "./outputs/primevul_concurrent_feedback",
        "save_population": True,
        "detailed_logging": True,
        # 高性能追踪配置
        "track_every_evaluation": True,
        "save_intermediate_results": True,
        "export_top_k": 15,
        "save_sample_results": True,  # 保存样本级结果
        # 启用CWE大类模式
        "use_cwe_major": True,
    }

    return config


def create_diverse_initial_prompts():
    """创建多样化的初始prompt集合，支持CWE大类分类"""
    # 获取CWE大类列表用于提示
    categories_text = ", ".join([f"'{cat}'" for cat in CWE_MAJOR_CATEGORIES])

    initial_prompts = [
        # CWE大类导向分析
        f"Analyze this code for security vulnerabilities and classify it into one of these CWE major categories: {categories_text}. If no vulnerability is found, respond with 'Benign'.\n\nCode to analyze:\n{{input}}\n\nCWE Major Category:",
        f"You are a security expert. Examine this code and identify the primary CWE major category from: {categories_text}. For secure code, use 'Benign'.\n\nCode: {{input}}\n\nCWE Classification:",
        # 具体分析导向类
        "Perform detailed security analysis and classify into CWE major categories:\n- Buffer Errors: buffer overflows, bounds checking issues\n- Injection: SQL, command, XSS injection attacks\n- Memory Management: use-after-free, double-free, memory leaks\n- Pointer Dereference: null pointer, invalid pointer usage\n- Integer Errors: overflow, underflow, wraparound\n- Concurrency Issues: race conditions, synchronization problems\n- Path Traversal: directory traversal attacks\n- Cryptography Issues: weak crypto, broken algorithms\n- Information Exposure: data leaks, privacy issues\n- Other: other security issues\n- Benign: no vulnerabilities\n\nCode: {input}\n\nCategory:",
        f"Identify the primary vulnerability type. Choose from: {categories_text}. Focus on the most significant security issue present.\n\n{{input}}\n\nPrimary vulnerability category:",
        # 专家角色类
        f"As a cybersecurity expert, classify this code's primary security issue using CWE major categories: {categories_text}. Use 'Benign' for secure code.\n\nCode under review:\n{{input}}\n\nExpert classification:",
        "Security code review: Examine for buffer errors, injection flaws, memory issues, pointer problems, integer errors, concurrency bugs, path traversal, crypto weaknesses, or information exposure. Classify accordingly or mark as 'Benign'.\n\nCode: {input}\n\nSecurity classification:",
        # 结构化分析类
        "Systematic vulnerability analysis:\n1. Check for buffer/bounds issues → Buffer Errors\n2. Look for injection vectors → Injection\n3. Analyze memory management → Memory Management\n4. Check pointer usage → Pointer Dereference\n5. Review integer operations → Integer Errors\n6. Examine concurrency → Concurrency Issues\n7. Check path handling → Path Traversal\n8. Review cryptography → Cryptography Issues\n9. Look for data leaks → Information Exposure\n10. Other security issues → Other\n11. No issues → Benign\n\nCode: {input}\n\nResult:",
        # CWE模式识别类
        "Identify CWE patterns and map to major categories. Examples:\n- CWE-120,119,787: Buffer Errors\n- CWE-78,79,89: Injection\n- CWE-416,415,401: Memory Management\n- CWE-476: Pointer Dereference\n- CWE-190,191: Integer Errors\n- CWE-362: Concurrency Issues\n- CWE-22: Path Traversal\n- CWE-327,326: Cryptography Issues\n- CWE-200: Information Exposure\n\nClassify: {input}\n\nCWE Major Category:",
        # 攻击场景类
        f"From an attacker's perspective, what's the primary exploitable weakness? Categorize as: {categories_text}.\n\n{{input}}\n\nExploitable weakness category:",
        # 简洁高效类
        f"Security category classification. Options: {categories_text}.\n\nCode: {{input}}\n\nCategory:",
        "Vulnerability type identification. Choose the most appropriate: Buffer Errors, Injection, Memory Management, Pointer Dereference, Integer Errors, Concurrency Issues, Path Traversal, Cryptography Issues, Information Exposure, Other, or Benign.\n\n{input}\n\nType:",
        # 防御角度类
        f"Defense-focused analysis: What type of security control would prevent exploitation? Map to vulnerability categories: {categories_text}.\n\nCode to protect:\n{{input}}\n\nVulnerability category:",
    ]

    return initial_prompts


class SampleWiseTracker:
    """样本级结果追踪器"""

    def __init__(self, exp_dir: Path):
        self.exp_dir = exp_dir
        self.sample_results = []
        self.sample_feedback_log = exp_dir / "sample_feedback.jsonl"
        self.sample_stats = exp_dir / "sample_statistics.json"

    def log_sample_result(
        self,
        prompt_id: str,
        sample_idx: int,
        sample_data: dict,
        prediction: str,
        ground_truth: int,
        correct: bool,
        generation: int,
        feedback_applied: bool = False,
    ):
        """记录单个样本的结果"""
        cwe_codes = sample_data.get("cwe", [])
        result = {
            "timestamp": datetime.now().isoformat(),
            "prompt_id": prompt_id,
            "generation": generation,
            "sample_idx": sample_idx,
            "sample_func": sample_data.get("func", "")[:100],  # 截取前100字符
            "sample_target": ground_truth,
            "prediction": prediction,
            "correct": correct,
            "feedback_applied": feedback_applied,
            "cwe_codes": cwe_codes,  # 明确输出CWE代码
            "cve_id": sample_data.get("cve", "None"),
            "metadata": {
                "project": sample_data.get("project", ""),
                "cwe": cwe_codes,
                "cve": sample_data.get("cve", "None"),
                "cve_desc": sample_data.get("cve_desc", "None"),
                "func_hash": sample_data.get("func_hash", ""),
                "file_name": sample_data.get("file_name", ""),
                "ground_truth_category": sample_data.get(
                    "ground_truth_category", "Unknown"
                ),
                "predicted_category": sample_data.get("predicted_category", "Unknown"),
            },
        }

        self.sample_results.append(result)

        # 实时写入日志
        with open(self.sample_feedback_log, "a", encoding="utf-8") as f:
            f.write(json.dumps(result, ensure_ascii=False) + "\n")

    def get_recent_performance(self, prompt_id: str, last_n: int = 10):
        """获取最近N个样本的性能"""
        recent_results = [
            r for r in self.sample_results if r["prompt_id"] == prompt_id
        ][-last_n:]

        if not recent_results:
            return {"accuracy": 0.0, "count": 0}

        correct_count = sum(1 for r in recent_results if r["correct"])
        return {
            "accuracy": correct_count / len(recent_results),
            "count": len(recent_results),
            "correct": correct_count,
            "total": len(recent_results),
        }

    def save_statistics(self):
        """保存统计信息（支持CWE大类多分类）"""
        if not self.sample_results:
            return

        # 按prompt统计
        prompt_stats = {}
        cwe_analysis = {}
        category_analysis = {}  # 新增：CWE大类分析
        confusion_matrix = {}  # 新增：混淆矩阵

        for result in self.sample_results:
            prompt_id = result["prompt_id"]
            if prompt_id not in prompt_stats:
                prompt_stats[prompt_id] = {
                    "total_samples": 0,
                    "correct_samples": 0,
                    "accuracy": 0.0,
                    "generations": set(),
                    "feedback_applied_count": 0,
                }

            stats = prompt_stats[prompt_id]
            stats["total_samples"] += 1
            if result["correct"]:
                stats["correct_samples"] += 1
            stats["generations"].add(result["generation"])
            if result["feedback_applied"]:
                stats["feedback_applied_count"] += 1

            # CWE大类分析（新增）
            # 从样本结果的metadata中获取类别信息
            metadata = result.get("metadata", {})
            ground_truth_cat = metadata.get("ground_truth_category", "Unknown")
            predicted_cat = metadata.get("predicted_category", "Unknown")

            # 更新混淆矩阵
            if ground_truth_cat not in confusion_matrix:
                confusion_matrix[ground_truth_cat] = {}
            if predicted_cat not in confusion_matrix[ground_truth_cat]:
                confusion_matrix[ground_truth_cat][predicted_cat] = 0
            confusion_matrix[ground_truth_cat][predicted_cat] += 1

            # 按CWE大类统计
            if ground_truth_cat not in category_analysis:
                category_analysis[ground_truth_cat] = {
                    "total_samples": 0,
                    "correct_predictions": 0,
                    "accuracy": 0.0,
                    "predicted_as": {},  # 被预测为各个类别的次数
                }

            cat_stats = category_analysis[ground_truth_cat]
            cat_stats["total_samples"] += 1
            if result["correct"]:
                cat_stats["correct_predictions"] += 1

            # 记录预测分布
            if predicted_cat not in cat_stats["predicted_as"]:
                cat_stats["predicted_as"][predicted_cat] = 0
            cat_stats["predicted_as"][predicted_cat] += 1

            # 原有CWE统计分析（保留兼容）
            cwe_codes = result.get("cwe_codes", [])
            for cwe in cwe_codes:
                if cwe not in cwe_analysis:
                    cwe_analysis[cwe] = {
                        "total_samples": 0,
                        "correct_predictions": 0,
                        "false_positives": 0,
                        "false_negatives": 0,
                        "accuracy": 0.0,
                    }

                cwe_stats = cwe_analysis[cwe]
                cwe_stats["total_samples"] += 1

                if result["correct"]:
                    cwe_stats["correct_predictions"] += 1
                else:
                    # 分析错误类型
                    if result["sample_target"] == 1:  # 实际是漏洞，但预测错了
                        cwe_stats["false_negatives"] += 1
                    else:  # 实际不是漏洞，但预测是漏洞
                        cwe_stats["false_positives"] += 1

        # 计算最终统计
        for prompt_id in prompt_stats:
            stats = prompt_stats[prompt_id]
            stats["accuracy"] = (
                stats["correct_samples"] / stats["total_samples"]
                if stats["total_samples"] > 0
                else 0
            )
            stats["generations"] = list(stats["generations"])

        # 计算CWE大类准确率
        for cat in category_analysis:
            cat_stats = category_analysis[cat]
            cat_stats["accuracy"] = (
                cat_stats["correct_predictions"] / cat_stats["total_samples"]
                if cat_stats["total_samples"] > 0
                else 0
            )

        # 计算原有CWE准确率
        for cwe in cwe_analysis:
            cwe_stats = cwe_analysis[cwe]
            cwe_stats["accuracy"] = (
                cwe_stats["correct_predictions"] / cwe_stats["total_samples"]
                if cwe_stats["total_samples"] > 0
                else 0
            )
            cwe_stats["precision"] = (
                cwe_stats["correct_predictions"]
                / (cwe_stats["correct_predictions"] + cwe_stats["false_positives"])
                if (cwe_stats["correct_predictions"] + cwe_stats["false_positives"]) > 0
                else 0
            )
            cwe_stats["recall"] = (
                cwe_stats["correct_predictions"]
                / (cwe_stats["correct_predictions"] + cwe_stats["false_negatives"])
                if (cwe_stats["correct_predictions"] + cwe_stats["false_negatives"]) > 0
                else 0
            )

        # 保存到文件
        final_stats = {
            "total_samples_evaluated": len(self.sample_results),
            "total_prompts": len(prompt_stats),
            "overall_accuracy": sum(1 for r in self.sample_results if r["correct"])
            / len(self.sample_results),
            "prompt_statistics": prompt_stats,
            "generation_summary": self._get_generation_summary(),
            "cwe_major_category_analysis": category_analysis,  # 新增：CWE大类分析
            "confusion_matrix": confusion_matrix,  # 新增：混淆矩阵
            "category_summary": {  # 新增：类别总结
                "total_categories": len(category_analysis),
                "best_performing_categories": sorted(
                    category_analysis.items(),
                    key=lambda x: x[1]["accuracy"],
                    reverse=True,
                )[:5],
                "worst_performing_categories": sorted(
                    category_analysis.items(), key=lambda x: x[1]["accuracy"]
                )[:5],
                "most_common_categories": sorted(
                    category_analysis.items(),
                    key=lambda x: x[1]["total_samples"],
                    reverse=True,
                )[:5],
            },
            "cwe_analysis": cwe_analysis,  # 保留原有统计
            "cwe_summary": {
                "total_cwe_types": len(cwe_analysis),
                "most_common_cwes": sorted(
                    cwe_analysis.items(),
                    key=lambda x: x[1]["total_samples"],
                    reverse=True,
                )[:10],
                "best_performing_cwes": sorted(
                    cwe_analysis.items(), key=lambda x: x[1]["accuracy"], reverse=True
                )[:10],
                "worst_performing_cwes": sorted(
                    cwe_analysis.items(), key=lambda x: x[1]["accuracy"]
                )[:10],
            },
        }

        with open(self.sample_stats, "w", encoding="utf-8") as f:
            json.dump(final_stats, f, indent=2, ensure_ascii=False)

    def _get_generation_summary(self):
        """获取代际总结"""
        gen_stats = {}
        for result in self.sample_results:
            gen = result["generation"]
            if gen not in gen_stats:
                gen_stats[gen] = {"total": 0, "correct": 0}
            gen_stats[gen]["total"] += 1
            if result["correct"]:
                gen_stats[gen]["correct"] += 1

        for gen in gen_stats:
            gen_stats[gen]["accuracy"] = (
                gen_stats[gen]["correct"] / gen_stats[gen]["total"]
            )

        return gen_stats


def run_concurrent_evolution_with_feedback(config: dict, sample_data_dir: str):
    """运行支持样本级反馈的高并发进化实验"""
    print(f"⚡ 开始样本级反馈的高并发Prompt进化实验: {config['experiment_id']}")
    print(f"🔥 使用 {config['max_concurrency']} 个并发连接")
    print(f"📊 样本级反馈: 每批 {config['feedback_batch_size']} 个样本")
    if config.get("use_cwe_major"):
        print("🔎 已启用 CWE 大类模式：固定要求模型只输出大类（或Benign）作为评估依据")

    # 创建实验目录
    exp_dir = Path(config["output_dir"]) / config["experiment_id"]
    exp_dir.mkdir(parents=True, exist_ok=True)

    # 创建样本追踪器
    sample_tracker = SampleWiseTracker(exp_dir)

    # 创建prompt追踪器
    prompt_tracker = PromptTracker(str(config["output_dir"]), config["experiment_id"])
    prompt_tracker.set_config(config)

    # 设置数据路径
    dev_file = Path(sample_data_dir) / "dev.txt"
    train_file = Path(sample_data_dir) / "train.txt"

    print("📁 数据配置:")
    print(f"   开发集: {dev_file}")
    print(f"   训练集: {train_file}")

    # 加载和打乱训练数据
    print("🔄 加载并打乱训练数据...")
    train_dataset = PrimevulDataset(str(train_file), "train")
    train_samples = train_dataset.get_samples()  # 使用正确的方法获取样本

    if config.get("shuffle_training_data", True):
        random.seed(42)  # 确保可重现
        random.shuffle(train_samples)
        print(f"   ✅ 训练数据已打乱: {len(train_samples)} 个样本")

    # 加载开发集
    dev_dataset = PrimevulDataset(str(dev_file), "dev")
    print(f"   开发集: {len(dev_dataset)} 个样本")

    # 保存配置
    config_file = exp_dir / "experiment_config.json"
    with open(config_file, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)

    # 创建LLM客户端 - 支持并发批处理
    from mulvul.llm.client import create_default_client

    llm_client = create_default_client()
    if hasattr(llm_client, "max_concurrency"):
        llm_client.max_concurrency = config["max_concurrency"]
    print(
        f"🤖 使用LLM客户端，支持并发批处理 (concurrent={config['enable_concurrent']})"
    )

    # 创建初始prompts
    initial_prompts = create_diverse_initial_prompts()

    # 保存初始prompts
    initial_prompts_file = exp_dir / "initial_prompts.txt"
    with open(initial_prompts_file, "w", encoding="utf-8") as f:
        f.write("Initial Prompts for Sample-wise Feedback Evolution\n")
        f.write("=" * 50 + "\n\n")
        for i, prompt in enumerate(initial_prompts, 1):
            f.write(f"Prompt {i}:\n{'-' * 20}\n{prompt}\n\n")

    print("💾 实验配置:")
    print(f"   初始prompts: {len(initial_prompts)}")
    print(f"   种群大小: {config['population_size']}")
    print(f"   最大代数: {config['max_generations']}")
    print(f"   反馈批大小: {config['feedback_batch_size']}")
    print(f"   CWE大类模式: {config.get('use_cwe_major', False)}")

    # 创建进化算法（配置存储但算法在后续使用中直接调用）

    # 记录初始prompts
    for i, prompt in enumerate(initial_prompts):
        prompt_tracker.log_prompt(
            prompt=prompt,
            generation=0,
            individual_id=f"initial_{i}",
            operation="initialization",
            metadata={"sample_wise_feedback": True, "prompt_index": i},
        )

    print("\n🚀 启动样本级反馈进化...")
    start_time = time.time()

    try:
        # 初始化种群
        from mulvul.algorithms.base import Individual

        population_individuals = [Individual(prompt) for prompt in initial_prompts]
        population = Population(population_individuals)

        # 在开发集上评估初始种群
        print("📊 评估初始种群...")
        for i, individual in enumerate(population.individuals):
            individual.fitness = evaluate_on_dataset(
                individual.prompt,
                dev_dataset,
                llm_client,
                f"initial_{i}",
                sample_tracker,
                generation=0,
                config=config,
            )

        print(
            f"   初始适应度: {[f'{ind.fitness:.3f}' for ind in population.individuals]}"
        )

        # 记录初始评估
        prompt_tracker.log_population(
            population.individuals, generation=0, operation="initial_evaluation"
        )

        best_fitness_history = []

        # 样本级反馈进化循环
        for generation in range(1, config["max_generations"] + 1):
            print(f"\n⚡ 第 {generation} 代样本级反馈进化...")
            gen_start_time = time.time()

            current_best = population.best()
            best_fitness_history.append(current_best.fitness)
            print(f"   当前最佳适应度: {current_best.fitness:.4f}")

            # 样本级训练和反馈
            new_individuals = []
            batch_count = 0

            for i, target_individual in enumerate(population.individuals):
                print(f"   处理个体 {i+1}/{len(population.individuals)}")

                # DE进化操作
                candidates = [
                    ind for j, ind in enumerate(population.individuals) if j != i
                ]
                if len(candidates) >= 3:
                    # 选择三个不同的个体
                    parents = random.sample(candidates, 3)

                    # 创建变异个体
                    mutant_prompt = create_mutant_prompt(
                        target_individual.prompt,
                        [p.prompt for p in parents],
                        llm_client,
                        config,
                    )

                    if mutant_prompt and mutant_prompt != target_individual.prompt:
                        # 在训练样本上进行样本级反馈
                        improved_prompt = sample_wise_feedback_training(
                            mutant_prompt,
                            train_samples,
                            llm_client,
                            sample_tracker,
                            config,
                            generation,
                            f"gen{generation}_individual_{i}",
                            batch_count,
                        )

                        # 在开发集上评估改进后的prompt
                        trial_individual = Individual(improved_prompt)
                        trial_individual.fitness = evaluate_on_dataset(
                            improved_prompt,
                            dev_dataset,
                            llm_client,
                            f"gen{generation}_trial_{i}",
                            sample_tracker,
                            generation,
                            config,
                        )

                        # 记录试验个体
                        prompt_tracker.log_prompt(
                            prompt=improved_prompt,
                            fitness=trial_individual.fitness,
                            generation=generation,
                            individual_id=f"gen{generation}_trial_{i}",
                            operation="sample_feedback_evolution",
                            metadata={
                                "target_fitness": target_individual.fitness,
                                "improvement": trial_individual.fitness
                                - target_individual.fitness,
                                "feedback_applied": True,
                            },
                        )

                        # 选择更好的个体
                        if trial_individual.fitness > target_individual.fitness:
                            new_individuals.append(trial_individual)
                            print(
                                f"     ✅ 接受改进个体: {trial_individual.fitness:.4f} > {target_individual.fitness:.4f}"
                            )
                        else:
                            new_individuals.append(target_individual)
                            print(
                                f"     ❌ 保留原个体: {trial_individual.fitness:.4f} <= {target_individual.fitness:.4f}"
                            )

                        batch_count += 1
                    else:
                        new_individuals.append(target_individual)
                        print("     ⚠️ 变异失败，保留原个体")
                else:
                    new_individuals.append(target_individual)
                    print("     ⚠️ 候选不足，保留原个体")

            # 更新种群
            population = Population(new_individuals)

            # 记录本代结果
            prompt_tracker.log_population(
                population.individuals,
                generation=generation,
                operation="sample_feedback_generation_complete",
            )

            gen_time = time.time() - gen_start_time
            print(f"   第{generation}代完成: {gen_time:.1f}秒")
            print(f"   本代最佳: {population.best().fitness:.4f}")

            # 保存中间结果
            intermediate_file = exp_dir / f"generation_{generation}_results.json"
            intermediate_data = {
                "generation": generation,
                "duration": gen_time,
                "best_fitness": population.best().fitness,
                "best_prompt": population.best().prompt,
                "fitness_history": best_fitness_history,
                "sample_batches_processed": batch_count,
            }
            with open(intermediate_file, "w", encoding="utf-8") as f:
                json.dump(intermediate_data, f, indent=2, ensure_ascii=False)

        # 最终结果
        final_best = population.best()
        total_time = time.time() - start_time

        print("\n🎉 样本级反馈进化完成!")
        print(f"   总耗时: {total_time:.2f}秒")
        print(f"   最终最佳适应度: {final_best.fitness:.4f}")

        if best_fitness_history:
            improvement = final_best.fitness - best_fitness_history[0]
            print(f"   总体提升: {improvement:+.4f}")

        # 保存样本统计
        sample_tracker.save_statistics()

        final_results = {
            "experiment_id": config["experiment_id"],
            "best_prompt": final_best.prompt,
            "best_fitness": final_best.fitness,
            "fitness_history": best_fitness_history,
            "total_time": total_time,
            "algorithm": config["algorithm"],
            "population_size": config["population_size"],
            "sample_wise_feedback": True,
            "training_samples": len(train_samples),
        }

        # 保存最终结果
        prompt_tracker.save_summary(final_results)

        return final_results, exp_dir

    except Exception as e:
        print(f"❌ 样本级反馈进化出错: {e}")
        import traceback

        traceback.print_exc()
        raise


def create_mutant_prompt(
    target_prompt: str, parent_prompts: List[str], llm_client, config: dict
) -> str:
    """使用LLM创建变异prompt"""
    mutation_instruction = f"""
Create an improved version of the target prompt by incorporating ideas from the parent prompts.

Target Prompt:
{target_prompt}

Parent Prompts:
1. {parent_prompts[0]}
2. {parent_prompts[1]}  
3. {parent_prompts[2]}

Task: Create a new prompt that combines the best aspects of these prompts for vulnerability detection. The new prompt should:
- Maintain the same input format {{input}}
- Respond with 'vulnerable' or 'benign' 
- Be more effective at detecting security issues
- Incorporate different analysis approaches from the parents

Generate only the improved prompt, nothing else:
"""

    try:
        response = llm_client.generate(mutation_instruction, temperature=0.8)
        # 确保包含{input}占位符
        if "{input}" not in response:
            response = response + "\n\nCode: {input}\n\nSecurity assessment:"
        return response.strip()
    except Exception as e:
        print(f"     ⚠️ 变异操作失败: {e}")
        return target_prompt


def sample_wise_feedback_training(
    initial_prompt: str,
    train_samples,
    llm_client,
    sample_tracker: SampleWiseTracker,
    config: dict,
    generation: int,
    prompt_id: str,
    batch_idx: int,
) -> str:
    """使用训练样本进行样本级反馈训练（支持批处理）"""
    current_prompt = initial_prompt
    batch_size = config.get("feedback_batch_size", 10)
    enable_batch = config.get("enable_batch_processing", False)
    llm_batch_size = config.get("llm_batch_size", 8)
    enable_concurrent = config.get("enable_concurrent", True)

    # 随机选择一批训练样本
    selected_samples = random.sample(train_samples, min(batch_size, len(train_samples)))

    print(f"     📝 样本级反馈训练: {len(selected_samples)} 个样本")
    if enable_batch:
        concurrent_text = "并发" if enable_concurrent else "顺序"
        print(
            f"     🚀 使用批处理模式，LLM batch_size={llm_batch_size} ({concurrent_text})"
        )

    improvements_count = 0

    if enable_batch and len(selected_samples) > 1:
        # 批处理模式：先批量预测所有样本
        try:
            # 准备批量预测数据
            batch_queries = []
            sample_metadata = []

            for sample_idx, sample in enumerate(selected_samples):
                code = sample.input_text
                ground_truth_binary = int(sample.target)

                # 从样本的CWE代码获取真实的CWE大类
                cwe_codes = sample.metadata.get("cwe", [])
                if ground_truth_binary == 1 and cwe_codes:
                    ground_truth_category = map_cwe_to_major(cwe_codes)
                else:
                    ground_truth_category = "Benign"

                query = safe_format(current_prompt, input=code)
                batch_queries.append(query)
                sample_metadata.append(
                    {
                        "sample_idx": sample_idx,
                        "sample": sample,
                        "code": code,
                        "ground_truth_binary": ground_truth_binary,
                        "ground_truth_category": ground_truth_category,
                        "cwe_codes": cwe_codes,
                    }
                )

            # 批量调用LLM进行预测
            prediction_texts = llm_client.batch_generate(
                batch_queries,
                temperature=0.1,
                max_tokens=20,
                batch_size=llm_batch_size,
                concurrent=enable_concurrent,
            )

            # 处理批量预测结果
            incorrect_samples = []  # 收集需要改进的样本

            for metadata, prediction_text in zip(sample_metadata, prediction_texts):
                if prediction_text == "error":
                    print(f"       ⚠️ 样本 {metadata['sample_idx']+1}: 预测失败")
                    continue

                # 规范化模型输出到CWE大类
                predicted_category = canonicalize_category(prediction_text)
                if predicted_category is None:
                    if any(
                        word in prediction_text.lower()
                        for word in ["vulnerable", "vulnerability", "vuln", "exploit"]
                    ):
                        predicted_category = "Other"
                    else:
                        predicted_category = "Benign"

                correct = predicted_category == metadata["ground_truth_category"]

                # 记录样本结果
                sample_data = {
                    "func": metadata["sample"].input_text,
                    "target": metadata["ground_truth_binary"],
                    "project": metadata["sample"].metadata.get("project", ""),
                    "cwe": metadata["cwe_codes"],
                    "cve": metadata["sample"].metadata.get("cve", "None"),
                    "cve_desc": metadata["sample"].metadata.get("cve_desc", "None"),
                    "func_hash": metadata["sample"].metadata.get("func_hash", ""),
                    "file_name": metadata["sample"].metadata.get("file_name", ""),
                    "ground_truth_category": metadata["ground_truth_category"],
                    "predicted_category": predicted_category,
                }

                sample_tracker.log_sample_result(
                    prompt_id=f"{prompt_id}_feedback_{batch_idx}",
                    sample_idx=metadata["sample_idx"],
                    sample_data=sample_data,
                    prediction=prediction_text,
                    ground_truth=metadata["ground_truth_binary"],
                    correct=correct,
                    generation=generation,
                    feedback_applied=True,
                )

                # 收集错误的样本用于改进
                if not correct:
                    incorrect_samples.append(
                        {
                            "metadata": metadata,
                            "prediction_text": prediction_text,
                            "predicted_category": predicted_category,
                            "sample_data": sample_data,
                        }
                    )
                else:
                    print(f"       ✅ 样本 {metadata['sample_idx']+1}: 预测正确")

            # 批量生成改进指令（对于错误的样本）
            if incorrect_samples:
                improvement_instructions = []

                for item in incorrect_samples:
                    metadata = item["metadata"]
                    sample_data = item["sample_data"]

                    # 构建反馈信息
                    cwe_info = ""
                    if sample_data.get("cwe") and sample_data["cwe"]:
                        cwe_list = ", ".join(sample_data["cwe"])
                        cwe_info = f"\nCWE Categories: {cwe_list}"

                    cve_info = ""
                    if sample_data.get("cve") and sample_data["cve"] != "None":
                        cve_info = f"\nCVE ID: {sample_data['cve']}"

                    project_info = ""
                    if sample_data.get("project"):
                        project_info = f"\nProject: {sample_data['project']}"

                    feedback_instruction = f"""
The current prompt made an incorrect CWE major category classification. Please improve it based on the specific vulnerability information.

Current Prompt:
{current_prompt}

Code Sample:
{metadata['code'][:500]}...

Ground Truth Category: {metadata['ground_truth_category']}
Predicted Category: {item['predicted_category']}{project_info}{cwe_info}{cve_info}

Create an improved prompt that would correctly classify this sample into the correct CWE major category. Focus on:
1. The specific CWE categories: {metadata['ground_truth_category']} characteristics
2. The vulnerability patterns that distinguish {metadata['ground_truth_category']} from other categories
3. Common {metadata['ground_truth_category']} issues in {sample_data.get('project', 'this type of')} code
4. Ensure the prompt can distinguish between all CWE major categories: {", ".join(CWE_MAJOR_CATEGORIES)}

Improved prompt:
"""
                    improvement_instructions.append(feedback_instruction)

                # 批量生成改进的prompt
                try:
                    improved_prompts = llm_client.batch_generate(
                        improvement_instructions,
                        temperature=0.7,
                        batch_size=llm_batch_size,
                        concurrent=enable_concurrent,
                    )

                    # 选择最好的改进（这里简单选择第一个成功的）
                    for i, improved_prompt in enumerate(improved_prompts):
                        if (
                            improved_prompt != "error"
                            and "{input}" in improved_prompt
                            and len(improved_prompt.strip()) > 50
                        ):
                            current_prompt = improved_prompt.strip()
                            improvements_count += 1
                            print(f"       ⚡ 批量改进成功，应用改进 {i+1}")
                            break  # 使用第一个有效的改进

                except Exception as e:
                    print(f"       ⚠️ 批量改进失败: {e}")

        except Exception as e:
            print(f"     ❌ 批处理模式失败: {e}，回退到单个处理模式")
            enable_batch = False

    if not enable_batch:
        # 单个处理模式（原有逻辑）
        for sample_idx, sample in enumerate(selected_samples):
            try:
                # 使用当前prompt预测
                code = sample.input_text
                ground_truth_binary = int(sample.target)

                # 从样本的CWE代码获取真实的CWE大类
                cwe_codes = sample.metadata.get("cwe", [])
                if ground_truth_binary == 1 and cwe_codes:
                    ground_truth_category = map_cwe_to_major(cwe_codes)
                else:
                    ground_truth_category = "Benign"

                query = safe_format(current_prompt, input=code)
                prediction_text = llm_client.generate(
                    query, temperature=0.1, max_tokens=20
                )

                # 规范化模型输出到CWE大类
                predicted_category = canonicalize_category(prediction_text)
                if predicted_category is None:
                    if any(
                        word in prediction_text.lower()
                        for word in ["vulnerable", "vulnerability", "vuln", "exploit"]
                    ):
                        predicted_category = "Other"
                    else:
                        predicted_category = "Benign"

                correct = predicted_category == ground_truth_category

                # 转换Sample对象为字典格式
                sample_data = {
                    "func": sample.input_text,
                    "target": int(sample.target),
                    "project": sample.metadata.get("project", ""),
                    "cwe": sample.metadata.get("cwe", []),
                    "cve": sample.metadata.get("cve", "None"),
                    "cve_desc": sample.metadata.get("cve_desc", "None"),
                    "func_hash": sample.metadata.get("func_hash", ""),
                    "file_name": sample.metadata.get("file_name", ""),
                    "ground_truth_category": ground_truth_category,
                    "predicted_category": predicted_category,
                }

                # 记录样本结果
                sample_tracker.log_sample_result(
                    prompt_id=f"{prompt_id}_feedback_{batch_idx}",
                    sample_idx=sample_idx,
                    sample_data=sample_data,
                    prediction=prediction_text,
                    ground_truth=ground_truth_binary,
                    correct=correct,
                    generation=generation,
                    feedback_applied=True,
                )

                # 如果预测错误，尝试改进prompt
                if not correct:
                    # 构建CWE相关的反馈信息
                    cwe_info = ""
                    if sample_data.get("cwe") and sample_data["cwe"]:
                        cwe_list = ", ".join(sample_data["cwe"])
                        cwe_info = f"\nCWE Categories: {cwe_list}"

                    cve_info = ""
                    if sample_data.get("cve") and sample_data["cve"] != "None":
                        cve_info = f"\nCVE ID: {sample_data['cve']}"

                    project_info = ""
                    if sample_data.get("project"):
                        project_info = f"\nProject: {sample_data['project']}"

                    feedback_instruction = f"""
The current prompt made an incorrect CWE major category classification. Please improve it based on the specific vulnerability information.

Current Prompt:
{current_prompt}

Code Sample:
{code[:500]}...

Ground Truth Category: {ground_truth_category}
Predicted Category: {predicted_category}{project_info}{cwe_info}{cve_info}

Create an improved prompt that would correctly classify this sample into the correct CWE major category. Focus on:
1. The specific CWE categories: {ground_truth_category} characteristics
2. The vulnerability patterns that distinguish {ground_truth_category} from other categories
3. Common {ground_truth_category} issues in {sample_data.get('project', 'this type of')} code
4. Ensure the prompt can distinguish between all CWE major categories: {", ".join(CWE_MAJOR_CATEGORIES)}

Improved prompt:
"""

                    try:
                        improved_prompt = llm_client.generate(
                            feedback_instruction, temperature=0.7
                        )
                        if (
                            "{input}" in improved_prompt
                            and len(improved_prompt.strip()) > 50
                        ):
                            current_prompt = improved_prompt.strip()
                            improvements_count += 1
                            print(f"       ⚡ 样本 {sample_idx+1}: prompt已改进")
                    except Exception as e:
                        print(f"       ⚠️ 样本 {sample_idx+1}: 改进失败 - {e}")
                else:
                    print(f"       ✅ 样本 {sample_idx+1}: 预测正确")

            except Exception as e:
                print(f"       ❌ 样本 {sample_idx+1}: 处理失败 - {e}")

    print(
        f"     📈 反馈训练完成: {improvements_count}/{len(selected_samples)} 个样本触发改进"
    )
    return current_prompt


def evaluate_on_dataset(
    prompt: str,
    dataset,
    llm_client,
    prompt_id: str,
    sample_tracker: SampleWiseTracker,
    generation: int,
    config: dict = None,
) -> float:
    """在数据集上评估prompt性能（支持CWE大类多分类和批处理）"""
    correct = 0
    samples = dataset.get_samples()
    total = len(samples)

    # 检查是否启用批处理
    enable_batch = config.get("enable_batch_processing", False) if config else False
    batch_size = config.get("llm_batch_size", 8) if config else 8
    enable_concurrent = config.get("enable_concurrent", True) if config else True

    if enable_batch and total > 1:
        # 批处理模式
        print(f"     🚀 启用批处理评估: {total} 个样本, batch_size={batch_size}")

        # 准备批处理数据
        batch_queries = []
        batch_samples = []
        batch_metadata = []

        for idx, sample in enumerate(samples):
            code = sample.input_text
            ground_truth_binary = int(sample.target)

            # 从样本的CWE代码获取真实的CWE大类
            cwe_codes = sample.metadata.get("cwe", [])
            if ground_truth_binary == 1 and cwe_codes:
                ground_truth_category = map_cwe_to_major(cwe_codes)
            else:
                ground_truth_category = "Benign"

            query = safe_format(prompt, input=code)
            batch_queries.append(query)
            batch_samples.append(sample)
            batch_metadata.append(
                {
                    "idx": idx,
                    "ground_truth_binary": ground_truth_binary,
                    "ground_truth_category": ground_truth_category,
                }
            )

        # 批量调用LLM
        try:
            prediction_texts = llm_client.batch_generate(
                batch_queries,
                temperature=0.1,
                max_tokens=20,
                batch_size=batch_size,
                concurrent=enable_concurrent,
            )

            # 处理批处理结果
            for idx, (sample, metadata, prediction_text) in enumerate(
                zip(batch_samples, batch_metadata, prediction_texts)
            ):
                if prediction_text == "error":
                    print(f"     ⚠️ 样本 {metadata['idx']} 预测失败")
                    continue

                # 规范化模型输出到CWE大类
                predicted_category = canonicalize_category(prediction_text)
                if predicted_category is None:
                    if any(
                        word in prediction_text.lower()
                        for word in ["vulnerable", "vulnerability", "vuln", "exploit"]
                    ):
                        predicted_category = "Other"
                    else:
                        predicted_category = "Benign"

                is_correct = predicted_category == metadata["ground_truth_category"]

                if is_correct:
                    correct += 1

                # 记录评估结果
                sample_data = {
                    "func": sample.input_text,
                    "target": metadata["ground_truth_binary"],
                    "project": sample.metadata.get("project", ""),
                    "cwe": sample.metadata.get("cwe", []),
                    "cve": sample.metadata.get("cve", "None"),
                    "cve_desc": sample.metadata.get("cve_desc", "None"),
                    "func_hash": sample.metadata.get("func_hash", ""),
                    "file_name": sample.metadata.get("file_name", ""),
                    "ground_truth_category": metadata["ground_truth_category"],
                    "predicted_category": predicted_category,
                }

                sample_tracker.log_sample_result(
                    prompt_id=prompt_id,
                    sample_idx=metadata["idx"],
                    sample_data=sample_data,
                    prediction=prediction_text,
                    ground_truth=metadata["ground_truth_binary"],
                    correct=is_correct,
                    generation=generation,
                    feedback_applied=False,
                )

        except Exception as e:
            print(f"     ❌ 批处理评估失败: {e}")
            # 回退到单个处理模式
            enable_batch = False

    if not enable_batch:
        # 单个处理模式（原有逻辑）
        print(f"     🔄 使用单个处理评估: {total} 个样本")

        for idx, sample in enumerate(samples):
            try:
                code = sample.input_text
                ground_truth_binary = int(sample.target)

                # 从样本的CWE代码获取真实的CWE大类
                cwe_codes = sample.metadata.get("cwe", [])
                if ground_truth_binary == 1 and cwe_codes:
                    ground_truth_category = map_cwe_to_major(cwe_codes)
                else:
                    ground_truth_category = "Benign"

                query = safe_format(prompt, input=code)
                prediction_text = llm_client.generate(
                    query, temperature=0.1, max_tokens=20
                )

                # 规范化模型输出到CWE大类
                predicted_category = canonicalize_category(prediction_text)
                if predicted_category is None:
                    if any(
                        word in prediction_text.lower()
                        for word in ["vulnerable", "vulnerability", "vuln", "exploit"]
                    ):
                        predicted_category = "Other"
                    else:
                        predicted_category = "Benign"

                is_correct = predicted_category == ground_truth_category

                if is_correct:
                    correct += 1

                # 记录评估结果
                sample_data = {
                    "func": sample.input_text,
                    "target": int(sample.target),
                    "project": sample.metadata.get("project", ""),
                    "cwe": sample.metadata.get("cwe", []),
                    "cve": sample.metadata.get("cve", "None"),
                    "cve_desc": sample.metadata.get("cve_desc", "None"),
                    "func_hash": sample.metadata.get("func_hash", ""),
                    "file_name": sample.metadata.get("file_name", ""),
                    "ground_truth_category": ground_truth_category,
                    "predicted_category": predicted_category,
                }

                sample_tracker.log_sample_result(
                    prompt_id=prompt_id,
                    sample_idx=idx,
                    sample_data=sample_data,
                    prediction=prediction_text,
                    ground_truth=ground_truth_binary,
                    correct=is_correct,
                    generation=generation,
                    feedback_applied=False,
                )

            except Exception as e:
                print(f"     ⚠️ 样本 {idx} 评估失败: {e}")

    accuracy = correct / total if total > 0 else 0
    print(f"     📊 CWE大类评估完成: {correct}/{total} = {accuracy:.4f}")
    return accuracy


def main():
    """主函数"""
    print("⚡ Primevul 1% 样本级反馈高并发进化实验")
    print("=" * 60)

    # 设置随机种子
    random.seed(42)

    # 设置日志
    logger = setup_logging()

    # 检查API配置
    api_key = check_api_configuration()
    if not api_key:
        return 1

    # 路径配置
    primevul_dir = "./data/primevul/primevul"
    sample_output_dir = "./data/primevul_1percent_sample"

    try:
        # 1. 准备数据（如果需要）
        if not os.path.exists(sample_output_dir):
            if not os.path.exists(primevul_dir):
                print(f"❌ Primevul数据目录不存在: {primevul_dir}")
                print("请确保Primevul数据已下载到正确位置")
                return 1

            print("📊 准备1%采样数据...")
            sample_result = sample_primevul_1percent(
                primevul_dir, sample_output_dir, seed=42
            )
            print(f"✅ 采样完成: {sample_result['total_samples']} 样本")
        else:
            print(f"✅ 使用已存在的采样数据: {sample_output_dir}")

        # 2. 创建样本级反馈配置
        config = create_optimized_config()
        config["api_key"] = api_key

        print("\n⚙️ 样本级反馈实验配置:")
        print(f"   实验ID: {config['experiment_id']}")
        print(f"   算法: {config['algorithm'].upper()}")
        print(f"   种群大小: {config['population_size']}")
        print(f"   进化代数: {config['max_generations']}")
        print(f"   最大并发: {config['max_concurrency']}")
        print(f"   训练集打乱: {config['shuffle_training_data']}")
        print(f"   样本级反馈: {config['sample_wise_feedback']}")
        print(f"   反馈批大小: {config['feedback_batch_size']}")
        print(f"   记录所有样本: {config['record_all_samples']}")
        print(f"   LLM批处理: {config['enable_batch_processing']}")
        print(f"   LLM批大小: {config['llm_batch_size']}")
        print(f"   批次内并发: {config['enable_concurrent']}")

        # 3. 运行样本级反馈进化
        results, exp_dir = run_concurrent_evolution_with_feedback(
            config, sample_output_dir
        )

        print("\n✅ 样本级反馈实验完成!")
        print(f"📂 结果目录: {exp_dir}")
        print(f"🎯 最佳适应度: {results['best_fitness']:.4f}")
        print("📈 性能统计:")
        print(f"   总耗时: {results['total_time']:.2f}秒")
        print(f"   训练样本: {results['training_samples']}")
        print(f"   样本级反馈: {results['sample_wise_feedback']}")

        if results.get("fitness_history"):
            initial_fitness = results["fitness_history"][0]
            final_fitness = results["best_fitness"]
            improvement = final_fitness - initial_fitness
            print(
                f"   适应度提升: {initial_fitness:.4f} → {final_fitness:.4f} (+{improvement:.4f})"
            )

        # 4. 显示生成的文件
        print("\n📁 生成的分析文件:")
        analysis_files = [
            "sample_feedback.jsonl",  # 样本级反馈记录
            "sample_statistics.json",  # 样本统计
            "prompt_evolution.jsonl",  # prompt进化记录
            "experiment_config.json",  # 实验配置
            "initial_prompts.txt",  # 初始prompts
            "experiment_summary.json",  # 实验总结
        ]

        for filename in analysis_files:
            filepath = exp_dir / filename
            if filepath.exists():
                size = filepath.stat().st_size
                print(f"   ✅ {filename} ({size:,} bytes)")
            else:
                print(f"   ❌ {filename} (missing)")

        return 0

    except Exception as e:
        logger.error(f"样本级反馈实验失败: {e}")
        import traceback

        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
