#!/usr/bin/env python3
"""
在Primevul数据集的1%均衡样本上运行EvoPrompt，记录完整的prompt更新过程
"""

import os
import sys
import json
import time
from pathlib import Path
from datetime import datetime

# 添加src路径
sys.path.insert(0, "src")

from evoprompt.data.sampler import sample_primevul_1percent
from evoprompt.workflows import VulnerabilityDetectionWorkflow
from evoprompt.algorithms.differential import DifferentialEvolution
from evoprompt.algorithms.base import Population


def setup_logging():
    """设置日志"""
    import logging

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler("primevul_1percent_evolution.log", encoding="utf-8"),
        ],
    )

    return logging.getLogger(__name__)


def check_api_key():
    """检查API密钥（SVEN风格配置）"""
    # 加载.env文件中的环境变量
    from src.evoprompt.llm.client import load_env_vars

    load_env_vars()

    api_key = os.getenv("API_KEY")
    if not api_key:
        print("❌ 请设置 API_KEY 环境变量")
        print("   在.env文件中设置: API_KEY='your-api-key-here'")
        print("   或者设置环境变量: export API_KEY='your-api-key-here'")
        return None

    # 检查其他必要的配置
    api_base = os.getenv("API_BASE_URL", "https://newapi.pockgo.com/v1")
    model_name = os.getenv("MODEL_NAME", "kimi-k2-code")

    print("✅ SVEN风格API配置检查通过:")
    print(f"   API_BASE_URL: {api_base}")
    print(f"   MODEL_NAME: {model_name}")
    print(f"   API_KEY: {api_key[:10]}...")

    return api_key


def prepare_sample_data(primevul_dir: str, output_dir: str):
    """准备1%均衡采样数据"""
    print("📊 准备Primevul 1%均衡采样数据...")

    sample_result = sample_primevul_1percent(
        primevul_dir=primevul_dir, output_dir=output_dir, seed=42
    )

    print("✅ 采样完成!")
    print(f"   训练样本: {sample_result['train_samples']}")
    print(f"   开发样本: {sample_result['dev_samples']}")
    print(f"   总样本: {sample_result['total_samples']}")

    # 显示标签分布
    stats = sample_result["statistics"]
    print(f"   原始数据: {stats['total_samples']} 样本")
    print(f"   采样比例: {stats['sample_ratio']:.1%}")

    for key, value in stats.items():
        if key.startswith("sampled_"):
            label = key.split("_")[1]
            print(f"   标签 {label}: {value} 样本")

    return sample_result


def create_detailed_config():
    """创建详细的实验配置"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    config = {
        # 实验标识
        "experiment_id": f"primevul_1pct_{timestamp}",
        "experiment_name": "Primevul 1% Balanced Sample Evolution",
        "timestamp": timestamp,
        # 数据配置
        "dataset": "primevul",
        "sample_ratio": 0.01,
        "balanced_sampling": True,
        # 算法配置 - 使用较小的参数适合小数据集
        "algorithm": "de",  # 差分进化
        "population_size": 8,  # 较小的种群
        "max_generations": 6,  # 较少的代数
        "mutation_rate": 0.15,
        "crossover_probability": 0.8,
        # LLM配置
        "llm_type": "gpt-3.5-turbo",
        "max_tokens": 200,
        "temperature": 0.7,
        # 评估配置 - 使用所有样本
        "sample_size": None,  # 使用所有dev样本
        "test_sample_size": None,  # 使用所有train样本作为测试
        # 输出配置
        "output_dir": "./outputs/primevul_1percent",
        "save_population": True,
        "detailed_logging": True,
        # 追踪配置
        "track_every_evaluation": True,
        "save_intermediate_results": True,
        "export_top_k": 10,
        # 启用CWE大类模式
        "use_cwe_major": True,
    }

    return config


def create_custom_initial_prompts():
    """创建针对漏洞检测的初始prompt集合"""
    initial_prompts = [
        # 基础安全分析prompt
        "Analyze the following code for security vulnerabilities. Look for common issues like buffer overflows, injection attacks, memory corruption, and unsafe function usage. Respond 'vulnerable' if you find security issues, 'benign' if the code appears safe.\n\nCode to analyze:\n{input}\n\nSecurity assessment:",
        # 专家角色prompt
        "You are a cybersecurity expert conducting a code security review. Examine this code snippet for potential vulnerabilities including but not limited to: SQL injection, buffer overflow, use-after-free, null pointer dereference, and input validation issues. Classify as 'vulnerable' or 'benign'.\n\n{input}\n\nYour expert assessment:",
        # 结构化分析prompt
        "Perform a systematic security analysis of this code:\n1. Check for unsafe function calls\n2. Analyze input validation\n3. Look for memory management issues\n4. Identify potential attack vectors\n\nCode: {input}\n\nBased on your analysis, is this code 'vulnerable' or 'benign'?",
        # CWE导向prompt
        "Review this code for Common Weakness Enumeration (CWE) patterns such as CWE-120 (buffer overflow), CWE-79 (XSS), CWE-89 (SQL injection), CWE-476 (null pointer dereference), and other security weaknesses. Answer 'vulnerable' if any CWE patterns are found, 'benign' otherwise.\n\n{input}\n\nCWE-based assessment:",
        # 防御性prompt
        "As a security-focused code reviewer, examine this code with a defensive mindset. Consider: Are there any unsafe operations? Is input properly validated? Could this code be exploited by an attacker? Respond with 'vulnerable' for unsafe code or 'benign' for secure code.\n\nCode under review:\n{input}\n\nDefensive analysis result:",
        # 简洁实用prompt
        "Check this code for security vulnerabilities. Focus on real exploitable issues. Answer 'vulnerable' or 'benign':\n\n{input}\n\nResult:",
        # 多层次分析prompt
        "Evaluate this code's security on multiple levels:\n- Syntax level: unsafe functions, operations\n- Logic level: control flow vulnerabilities\n- Data level: input/output handling issues\n\nCode: {input}\n\nOverall security verdict ('vulnerable' or 'benign'):",
        # 攻击者视角prompt
        "Think like an attacker: could you exploit this code? Look for entry points, unsafe operations, and potential attack surfaces. If you can find a way to exploit it, answer 'vulnerable'. If not, answer 'benign'.\n\n{input}\n\nAttacker's assessment:",
    ]

    return initial_prompts


def run_evolution_with_tracking(config: dict, sample_data_dir: str):
    """运行带有详细追踪的进化过程"""
    print(f"🧬 开始Prompt进化实验: {config['experiment_id']}")
    if config.get("use_cwe_major"):
        print("🔎 已启用 CWE 大类模式：固定要求模型只输出大类（或Benign）作为评估依据")

    # 创建自定义工作流程
    workflow = VulnerabilityDetectionWorkflow(config)

    # 设置数据路径
    config["dev_file"] = str(Path(sample_data_dir) / "dev.txt")
    config["test_file"] = str(Path(sample_data_dir) / "train.txt")  # 使用train作为test

    print("📁 数据文件:")
    print(f"   开发集: {config['dev_file']}")
    print(f"   测试集: {config['test_file']}")

    # 验证数据文件
    for file_type, file_path in [
        ("开发集", config["dev_file"]),
        ("测试集", config["test_file"]),
    ]:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"{file_type}文件不存在: {file_path}")

        with open(file_path, "r", encoding="utf-8") as f:
            lines = len(f.readlines())
            print(f"   {file_type}: {lines} 样本")

    # 保存实验配置
    config_file = Path(workflow.exp_dir) / "experiment_config.json"
    with open(config_file, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)

    # 创建自定义初始prompts
    initial_prompts = create_custom_initial_prompts()

    # 保存初始prompts
    initial_prompts_file = Path(workflow.exp_dir) / "initial_prompts.txt"
    with open(initial_prompts_file, "w", encoding="utf-8") as f:
        f.write("Initial Prompts for Primevul 1% Evolution\n")
        f.write("=" * 50 + "\n\n")
        for i, prompt in enumerate(initial_prompts, 1):
            f.write(f"Prompt {i}:\n")
            f.write("-" * 20 + "\n")
            f.write(prompt + "\n\n")

    print(f"💾 初始prompts已保存: {initial_prompts_file}")
    print(f"🎯 使用 {len(initial_prompts)} 个初始prompt")

    # 运行进化
    print("🚀 开始进化过程...")
    print(f"   算法: {config['algorithm'].upper()}")
    print(f"   种群大小: {config['population_size']}")
    print(f"   迭代次数: {config['max_generations']}")

    start_time = time.time()

    try:
        # 准备数据
        dev_dataset, test_dataset = workflow.prepare_data()

        # 创建组件
        llm_client, evaluator, algorithm = workflow.create_components(dev_dataset)

        # 记录初始prompts到追踪器
        for i, prompt in enumerate(initial_prompts):
            workflow.prompt_tracker.log_prompt(
                prompt=prompt,
                generation=0,
                individual_id=f"initial_{i}",
                operation="initialization",
                metadata={"prompt_index": i, "prompt_type": "manual_design"},
            )

        # 手动运行进化以获得更详细的控制
        population = algorithm.initialize_population(initial_prompts)

        print("📊 初始种群评估...")
        population = algorithm.evaluate_population(population, evaluator)

        # 记录初始种群
        workflow.prompt_tracker.log_population(
            population.individuals, generation=0, operation="initial_evaluation"
        )

        best_fitness_history = []

        # 进化循环
        for generation in range(1, config["max_generations"] + 1):
            print(f"\n🔄 第 {generation} 代进化...")

            # 记录当前最佳
            current_best = population.best()
            best_fitness_history.append(current_best.fitness)
            print(f"   当前最佳适应度: {current_best.fitness:.4f}")

            # DE算法特定的进化步骤
            if isinstance(algorithm, DifferentialEvolution):
                new_individuals = []

                for i, target_individual in enumerate(population.individuals):
                    print(f"   进化个体 {i+1}/{len(population.individuals)}")

                    # 选择三个不同的个体
                    candidates = [
                        ind for j, ind in enumerate(population.individuals) if j != i
                    ]
                    if len(candidates) >= 3:
                        parents = algorithm.select_parents(Population(candidates))

                        # 创建试验向量
                        trial_individuals = algorithm.crossover(parents, llm_client)
                        if trial_individuals:
                            trial = trial_individuals[0]

                            # 评估试验向量
                            result = evaluator.evaluate(trial.prompt)
                            trial.fitness = result.score

                            # 记录新个体
                            workflow.prompt_tracker.log_prompt(
                                prompt=trial.prompt,
                                fitness=trial.fitness,
                                generation=generation,
                                individual_id=f"gen{generation}_trial_{i}",
                                operation="differential_evolution",
                                metadata={
                                    "target_fitness": target_individual.fitness,
                                    "parent_ids": [
                                        f"gen{generation-1}_ind_{j}" for j in range(3)
                                    ],
                                },
                            )

                            # 选择保留
                            if trial.fitness > target_individual.fitness:
                                new_individuals.append(trial)
                                print(
                                    f"     ✅ 接受新个体 (适应度: {trial.fitness:.4f} > {target_individual.fitness:.4f})"
                                )
                            else:
                                new_individuals.append(target_individual)
                                print(
                                    f"     ❌ 保留原个体 (适应度: {trial.fitness:.4f} <= {target_individual.fitness:.4f})"
                                )
                        else:
                            new_individuals.append(target_individual)
                    else:
                        new_individuals.append(target_individual)

                population = Population(new_individuals)

            # 记录这一代的种群
            workflow.prompt_tracker.log_population(
                population.individuals,
                generation=generation,
                operation="generation_complete",
            )

            # 保存中间结果
            if config.get("save_intermediate_results", True):
                intermediate_file = (
                    Path(workflow.exp_dir) / f"generation_{generation}_results.json"
                )
                intermediate_results = {
                    "generation": generation,
                    "best_fitness": population.best().fitness,
                    "best_prompt": population.best().prompt,
                    "population_fitness": [
                        ind.fitness for ind in population.individuals
                    ],
                    "fitness_history": best_fitness_history,
                }
                with open(intermediate_file, "w", encoding="utf-8") as f:
                    json.dump(intermediate_results, f, indent=2, ensure_ascii=False)

        # 最终结果
        final_best = population.best()
        end_time = time.time()
        duration = end_time - start_time

        final_results = {
            "best_prompt": final_best.prompt,
            "best_fitness": final_best.fitness,
            "fitness_history": best_fitness_history,
            "final_population": [ind.prompt for ind in population.individuals],
            "duration_seconds": duration,
            "total_generations": config["max_generations"],
            "algorithm": config["algorithm"],
            "population_size": config["population_size"],
        }

        print("\n🎉 进化完成!")
        print(f"   耗时: {duration:.1f} 秒")
        print(f"   最佳适应度: {final_best.fitness:.4f}")
        print(
            f"   适应度提升: {best_fitness_history[-1] - best_fitness_history[0]:.4f}"
        )

        # 保存结果
        workflow.save_results(final_results, test_dataset, llm_client)

        return final_results, workflow.exp_dir

    except Exception as e:
        print(f"❌ 进化过程出错: {e}")
        import traceback

        traceback.print_exc()
        raise


def analyze_results(exp_dir: Path):
    """分析实验结果"""
    print("\n📊 分析实验结果...")

    # 读取实验总结
    summary_file = exp_dir / "experiment_summary.json"
    if summary_file.exists():
        with open(summary_file, "r", encoding="utf-8") as f:
            summary = json.load(f)

        print("📋 实验总结:")
        print(f"   实验ID: {summary.get('experiment_id', 'N/A')}")
        print(f"   持续时间: {summary.get('duration_seconds', 0):.1f} 秒")
        print(f"   总快照数: {summary.get('total_snapshots', 0)}")
        print(f"   最佳适应度: {summary.get('best_fitness', 0):.4f}")
        print(f"   迭代代数: {summary.get('total_generations', 0)}")

    # 分析prompt进化轨迹
    log_file = exp_dir / "prompt_evolution.jsonl"
    if log_file.exists():
        fitness_by_gen = {}
        operation_counts = {}

        with open(log_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    data = json.loads(line.strip())

                    # 统计适应度
                    if data.get("fitness") is not None:
                        gen = data["generation"]
                        if gen not in fitness_by_gen:
                            fitness_by_gen[gen] = []
                        fitness_by_gen[gen].append(data["fitness"])

                    # 统计操作类型
                    op = data.get("operation", "unknown")
                    operation_counts[op] = operation_counts.get(op, 0) + 1

        print("\n📈 进化轨迹:")
        for gen in sorted(fitness_by_gen.keys()):
            fitnesses = fitness_by_gen[gen]
            avg_fitness = sum(fitnesses) / len(fitnesses)
            max_fitness = max(fitnesses)
            print(
                f"   第{gen}代: 平均适应度 {avg_fitness:.4f}, 最佳适应度 {max_fitness:.4f}"
            )

        print("\n🔧 操作统计:")
        for op, count in operation_counts.items():
            print(f"   {op}: {count} 次")

    # 列出生成的文件
    print("\n📁 生成的文件:")
    important_files = [
        "experiment_config.json",
        "initial_prompts.txt",
        "prompt_evolution.jsonl",
        "best_prompts.txt",
        "top_prompts.txt",
        "experiment_summary.json",
        "test_results.json",
    ]

    for filename in important_files:
        filepath = exp_dir / filename
        if filepath.exists():
            size = filepath.stat().st_size
            print(f"   ✅ {filename} ({size} bytes)")
        else:
            print(f"   ❌ {filename} (missing)")


def main():
    """主函数"""
    print("🧬 Primevul 1%数据 EvoPrompt 进化实验")
    print("=" * 60)

    # 设置日志
    logger = setup_logging()

    # 检查API密钥
    api_key = check_api_key()
    if not api_key:
        return 1

    # 配置路径
    primevul_dir = "./data/primevul/primevul"
    sample_output_dir = "./data/primevul_1percent_sample"

    try:
        # 1. 准备采样数据
        if not os.path.exists(sample_output_dir):
            if not os.path.exists(primevul_dir):
                print(f"❌ Primevul数据目录不存在: {primevul_dir}")
                print("请确保Primevul数据已下载到正确位置")
                return 1

            prepare_sample_data(primevul_dir, sample_output_dir)
        else:
            print(f"✅ 发现已存在的采样数据: {sample_output_dir}")
            # 读取已存在的统计信息
            stats_file = Path(sample_output_dir) / "sampling_stats.json"
            if stats_file.exists():
                with open(stats_file, "r", encoding="utf-8") as f:
                    stats = json.load(f)
                print(f"   总样本: {stats.get('total_samples', 'N/A')}")
                print(f"   采样比例: {stats.get('sample_ratio', 0):.1%}")

        print()

        # 2. 创建实验配置
        config = create_detailed_config()
        # SVEN风格API配置已通过.env文件加载，无需额外配置
        config["api_key"] = api_key

        print("⚙️ 实验配置:")
        print(f"   实验ID: {config['experiment_id']}")
        print(f"   算法: {config['algorithm'].upper()}")
        print(f"   种群大小: {config['population_size']}")
        print(f"   迭代次数: {config['max_generations']}")
        print(f"   LLM模型: {config['llm_type']}")
        print(f"   CWE大类模式: {config.get('use_cwe_major', False)}")
        print()

        # 3. 运行进化实验
        results, exp_dir = run_evolution_with_tracking(config, sample_output_dir)

        # 4. 分析结果
        analyze_results(exp_dir)

        print("\n✅ 实验完成!")
        print(f"📂 结果保存在: {exp_dir}")
        print(f"🎯 最佳prompt适应度: {results['best_fitness']:.4f}")

        return 0

    except Exception as e:
        logger.error(f"实验失败: {e}")
        import traceback

        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
