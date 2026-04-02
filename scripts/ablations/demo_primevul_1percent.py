#!/usr/bin/env python3
"""
演示版本：在Primevul 1%数据上进行prompt进化，使用模拟LLM展示完整流程
"""

import os
import sys
import json
import time
import random
from pathlib import Path
from datetime import datetime

# 添加src路径
sys.path.insert(0, "src")

from mulvul.data.sampler import sample_primevul_1percent
from mulvul.data.dataset import PrimevulDataset
from mulvul.core.prompt_tracker import PromptTracker
from mulvul.algorithms.differential import DifferentialEvolution
from mulvul.algorithms.base import Population
from mulvul.core.evaluator import Evaluator
from mulvul.metrics.base import AccuracyMetric


class MockLLMClient:
    """模拟LLM客户端，模拟真实的prompt进化过程"""

    def __init__(self):
        self.call_count = 0
        self.conversation_history = []

    def generate(self, prompt: str, **kwargs) -> str:
        self.call_count += 1

        # 记录调用历史
        self.conversation_history.append(
            {
                "call_id": self.call_count,
                "prompt": prompt[:200] + "..." if len(prompt) > 200 else prompt,
                "timestamp": datetime.now().isoformat(),
            }
        )

        # 模拟不同类型的响应
        prompt_lower = prompt.lower()

        # 如果是进化相关的prompt（包含两个或多个prompt的比较/组合）
        if "prompt 1" in prompt_lower and "prompt 2" in prompt_lower:
            # 模拟crossover/mutation操作
            if "combine" in prompt_lower or "crossover" in prompt_lower:
                return self._generate_evolved_prompt("crossover")
            elif "improve" in prompt_lower or "mutant" in prompt_lower:
                return self._generate_evolved_prompt("mutation")

        # 如果是单个prompt的改进
        elif "improve" in prompt_lower or "better" in prompt_lower:
            return self._generate_evolved_prompt("improvement")

        # 如果是代码分析（评估阶段）
        elif "{input}" in prompt or "analyze" in prompt_lower:
            # 模拟漏洞分析响应
            code_analysis_keywords = [
                "strcpy",
                "buffer",
                "overflow",
                "unsafe",
                "vulnerable",
                "injection",
            ]
            benign_keywords = ["safe", "secure", "printf", "return", "const"]

            # 简单的关键词匹配逻辑
            if any(keyword in prompt_lower for keyword in code_analysis_keywords):
                return "vulnerable" if random.random() > 0.3 else "benign"
            elif any(keyword in prompt_lower for keyword in benign_keywords):
                return "benign" if random.random() > 0.3 else "vulnerable"
            else:
                return "vulnerable" if random.random() > 0.5 else "benign"

        # 默认响应
        return "benign"

    def _generate_evolved_prompt(self, operation_type: str) -> str:
        """生成进化后的prompt"""

        base_templates = [
            "Analyze this code for security vulnerabilities. Look for {focus_areas}. Respond 'vulnerable' if unsafe, 'benign' if safe:\n\nCode: {{input}}\n\nAssessment:",
            "You are a security expert. Review this code for {focus_areas}. Answer 'vulnerable' or 'benign':\n\n{{input}}\n\nResult:",
            "Examine this code snippet for security issues including {focus_areas}. Classify as 'vulnerable' or 'benign':\n\n{{input}}\n\nClassification:",
            "Security analysis required. Check for {focus_areas} in this code. Reply 'vulnerable' if issues found, 'benign' otherwise:\n\n{{input}}\n\nFinding:",
        ]

        focus_options = [
            "buffer overflows, injection attacks, and memory corruption",
            "unsafe function calls, input validation issues, and race conditions",
            "SQL injection, XSS vulnerabilities, and authentication bypass",
            "memory leaks, null pointer dereference, and bounds checking",
            "cryptographic weaknesses, privilege escalation, and data exposure",
            "path traversal, command injection, and deserialization flaws",
        ]

        # 选择模板和焦点区域
        template = random.choice(base_templates)
        focus = random.choice(focus_options)

        return template.format(focus_areas=focus)

    def batch_generate(self, prompts, **kwargs):
        return [self.generate(p, **kwargs) for p in prompts]


def create_large_mock_primevul_data(output_dir: str, total_samples: int = 10000):
    """创建大规模模拟Primevul数据"""
    print(f"📊 创建大规模模拟数据: {total_samples} 样本...")

    os.makedirs(output_dir, exist_ok=True)

    # 生成各种类型的代码样本
    benign_templates = [
        "int safe_function_{i}(int a, int b) {{ return a + b; }}",
        'void print_message_{i}() {{ printf("Hello World %d\\n", {i}); }}',
        'const char* get_version_{i}() {{ return "1.{i}.0"; }}',
        "bool is_valid_{i}(int value) {{ return value > 0 && value < 1000; }}",
        "double calculate_{i}(double x) {{ return x * 2.5 + {i}; }}",
    ]

    vulnerable_templates = [
        'void unsafe_copy_{i}(char* src) {{ char buf[10]; strcpy(buf, src); printf("%s", buf); }}',
        'int process_input_{i}(char* input) {{ char buffer[{i}]; sprintf(buffer, "%s", input); return strlen(buffer); }}',
        'void handle_request_{i}(char* query) {{ system(query); printf("Executed %s\\n", query); }}',
        'char* read_file_{i}(char* filename) {{ FILE* f = fopen(filename, "r"); /* no bounds checking */ char* data = malloc(1000); fread(data, 1, 2000, f); return data; }}',
        'void authenticate_{i}(char* password) {{ if(strcmp(password, "admin{i}") == 0) {{ /* hardcoded password */ access_granted(); }} }}',
    ]

    projects = [
        "Chrome",
        "Firefox",
        "Linux",
        "OpenSSL",
        "Apache",
        "nginx",
        "MySQL",
        "PostgreSQL",
        "MongoDB",
        "Redis",
    ]
    cwes = [
        "CWE-120",
        "CWE-79",
        "CWE-89",
        "CWE-476",
        "CWE-190",
        "CWE-416",
        "CWE-787",
        "CWE-125",
        "CWE-22",
        "CWE-78",
    ]

    mock_data = []

    # 生成60%的benign样本
    benign_count = int(total_samples * 0.6)
    for i in range(benign_count):
        template = random.choice(benign_templates)
        func_code = template.format(i=i % 1000)  # 限制数字大小

        sample = {
            "idx": i,
            "project": random.choice(projects),
            "commit_id": f"benign_commit_{i:06d}",
            "target": 0,  # benign
            "func": func_code,
            "cwe": [],
            "cve": "None",
            "func_hash": hash(func_code) % (2**31),
        }
        mock_data.append(sample)

    # 生成40%的vulnerable样本
    vulnerable_count = total_samples - benign_count
    for i in range(vulnerable_count):
        template = random.choice(vulnerable_templates)
        func_code = template.format(i=i % 1000)

        sample = {
            "idx": benign_count + i,
            "project": random.choice(projects),
            "commit_id": f"vuln_commit_{i:06d}",
            "target": 1,  # vulnerable
            "func": func_code,
            "cwe": [random.choice(cwes)],
            "cve": f"CVE-2024-{10000 + i}",
            "func_hash": hash(func_code) % (2**31),
        }
        mock_data.append(sample)

    # 打乱数据
    random.shuffle(mock_data)

    # 保存数据
    dev_file = Path(output_dir) / "dev.jsonl"
    with open(dev_file, "w", encoding="utf-8") as f:
        for item in mock_data:
            f.write(json.dumps(item) + "\n")

    print("✅ 模拟数据创建完成")
    print(f"   总样本: {total_samples}")
    print(f"   Benign: {benign_count} ({benign_count/total_samples:.1%})")
    print(f"   Vulnerable: {vulnerable_count} ({vulnerable_count/total_samples:.1%})")
    print(f"   文件: {dev_file}")

    return str(dev_file)


def run_demo_evolution():
    """运行演示版本的进化实验"""
    print("🧬 Primevul 1%数据 Prompt进化演示")
    print("=" * 60)

    # 创建输出目录
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_base = Path("./outputs/demo_primevul_1percent")
    output_base.mkdir(parents=True, exist_ok=True)

    experiment_id = f"demo_primevul_1pct_{timestamp}"
    exp_dir = output_base / experiment_id
    exp_dir.mkdir(exist_ok=True)

    try:
        # 1. 创建大规模模拟数据
        mock_data_dir = "./data/mock_primevul_large"
        if not os.path.exists(mock_data_dir):
            create_large_mock_primevul_data(mock_data_dir, total_samples=10000)
        else:
            print("✅ 发现已存在的大规模模拟数据")

        # 2. 进行1%均衡采样
        print("\n📊 进行1%均衡采样...")
        sample_output_dir = "./data/demo_primevul_1percent_sample"

        if not os.path.exists(sample_output_dir):
            sample_result = sample_primevul_1percent(
                primevul_dir=mock_data_dir, output_dir=sample_output_dir, seed=42
            )
        else:
            print("✅ 发现已存在的采样数据")
            # 读取统计信息
            stats_file = Path(sample_output_dir) / "sampling_stats.json"
            with open(stats_file, "r") as f:
                stats = json.load(f)
            sample_result = {
                "train_samples": stats.get("sampled_total", 0) * 0.7,
                "dev_samples": stats.get("sampled_total", 0) * 0.3,
                "total_samples": stats.get("sampled_total", 0),
            }

        print(f"✅ 采样完成: {sample_result['total_samples']} 总样本")
        print(f"   训练样本: {int(sample_result['train_samples'])}")
        print(f"   开发样本: {int(sample_result['dev_samples'])}")

        # 3. 设置进化实验
        print("\n⚙️ 设置进化实验...")

        # 创建数据集
        dev_file = Path(sample_output_dir) / "dev.txt"
        test_file = Path(sample_output_dir) / "train.txt"

        dev_dataset = PrimevulDataset(str(dev_file), "dev")
        test_dataset = PrimevulDataset(str(test_file), "test")

        print(f"   开发集样本: {len(dev_dataset)}")
        print(f"   测试集样本: {len(test_dataset)}")

        # 创建模拟LLM客户端
        llm_client = MockLLMClient()

        # 创建评估器
        metric = AccuracyMetric()
        evaluator = Evaluator(dataset=dev_dataset, metric=metric, llm_client=llm_client)

        # 创建prompt追踪器
        tracker = PromptTracker(str(output_base), experiment_id)
        tracker.set_config(
            {
                "algorithm": "de",
                "population_size": 6,
                "max_generations": 4,
                "sample_ratio": 0.01,
                "dataset": "primevul_mock",
            }
        )

        # 创建算法
        algorithm = DifferentialEvolution(
            {
                "population_size": 6,
                "max_generations": 4,
                "mutation_factor": 0.5,
                "crossover_probability": 0.8,
            }
        )

        # 4. 创建初始prompts
        print("\n🎯 创建初始prompts...")

        initial_prompts = [
            "Analyze this code for security vulnerabilities. Respond 'vulnerable' if unsafe, 'benign' if safe:\n\nCode: {input}\n\nAssessment:",
            "You are a security expert. Examine this code for potential security flaws. Answer 'vulnerable' or 'benign':\n\n{input}\n\nResult:",
            "Review this code for common vulnerabilities like buffer overflows and injection attacks. Classify as 'vulnerable' or 'benign':\n\n{input}\n\nClassification:",
            "Check this code for security issues. Focus on unsafe operations and input validation. Reply 'vulnerable' or 'benign':\n\n{input}\n\nFinding:",
            "Security analysis: Does this code contain exploitable vulnerabilities? Answer 'vulnerable' or 'benign':\n\n{input}\n\nAnalysis:",
            "Examine this code snippet for security weaknesses. Respond with 'vulnerable' if issues found, 'benign' otherwise:\n\n{input}\n\nVerdict:",
        ]

        print(f"   初始prompt数量: {len(initial_prompts)}")

        # 记录初始prompts
        for i, prompt in enumerate(initial_prompts):
            tracker.log_prompt(
                prompt=prompt,
                generation=0,
                individual_id=f"initial_{i}",
                operation="initialization",
                metadata={"prompt_type": "manual_design", "index": i},
            )

        # 5. 运行进化过程
        print("\n🚀 开始进化过程...")
        print("   算法: 差分进化 (DE)")
        print(f"   种群大小: {algorithm.population_size}")
        print(f"   迭代次数: {algorithm.max_generations}")

        start_time = time.time()

        # 初始化种群
        population = algorithm.initialize_population(initial_prompts)
        print(f"   初始种群创建: {len(population)} 个个体")

        # 评估初始种群
        print("\n📊 评估初始种群...")
        population = algorithm.evaluate_population(population, evaluator)

        # 记录初始评估结果
        for i, individual in enumerate(population.individuals):
            tracker.log_prompt(
                prompt=individual.prompt,
                fitness=individual.fitness,
                generation=0,
                individual_id=f"init_eval_{i}",
                operation="initial_evaluation",
                metadata={"population_index": i},
            )

        # 显示初始适应度
        initial_fitness = [ind.fitness for ind in population.individuals]
        print(f"   初始适应度: {[f'{f:.3f}' for f in initial_fitness]}")
        print(f"   初始最佳: {max(initial_fitness):.3f}")

        best_fitness_history = [max(initial_fitness)]

        # 进化循环
        for generation in range(1, algorithm.max_generations + 1):
            print(f"\n🔄 第 {generation} 代进化...")

            generation_start = time.time()
            new_individuals = []

            # DE算法的进化过程
            for i, target in enumerate(population.individuals):
                print(f"   处理个体 {i+1}/{len(population.individuals)}", end="")

                # 选择三个不同的个体作为父代
                candidates = [
                    ind for j, ind in enumerate(population.individuals) if j != i
                ]
                if len(candidates) >= 3:
                    parents = random.sample(candidates, 3)

                    # 创建变异个体
                    mutant_individuals = algorithm.crossover(parents, llm_client)
                    if mutant_individuals:
                        mutant = mutant_individuals[0]

                        # 评估变异个体
                        result = evaluator.evaluate(mutant.prompt)
                        mutant.fitness = result.score

                        # 记录变异个体
                        tracker.log_prompt(
                            prompt=mutant.prompt,
                            fitness=mutant.fitness,
                            generation=generation,
                            individual_id=f"gen{generation}_mutant_{i}",
                            operation="differential_evolution",
                            metadata={
                                "target_fitness": target.fitness,
                                "improvement": mutant.fitness - target.fitness
                                if target.fitness
                                else 0,
                            },
                        )

                        # 选择保留更好的个体
                        if mutant.fitness > target.fitness:
                            new_individuals.append(mutant)
                            print(
                                f" ✅ 改进 ({mutant.fitness:.3f} > {target.fitness:.3f})"
                            )
                        else:
                            new_individuals.append(target)
                            print(
                                f" ❌ 保持 ({mutant.fitness:.3f} <= {target.fitness:.3f})"
                            )
                    else:
                        new_individuals.append(target)
                        print(" ⚠️ 生成失败，保持原个体")
                else:
                    new_individuals.append(target)
                    print(" ⚠️ 候选不足，保持原个体")

            # 更新种群
            population = Population(new_individuals)

            # 记录这一代的结果
            generation_fitness = [ind.fitness for ind in population.individuals]
            best_fitness = max(generation_fitness)
            best_fitness_history.append(best_fitness)

            generation_time = time.time() - generation_start
            print(f"   第{generation}代完成 ({generation_time:.1f}秒)")
            print(f"   适应度: {[f'{f:.3f}' for f in generation_fitness]}")
            print(f"   最佳适应度: {best_fitness:.3f}")
            print(f"   改进程度: {best_fitness - best_fitness_history[0]:+.3f}")

        # 6. 总结结果
        total_time = time.time() - start_time
        final_best = population.best()

        print("\n🎉 进化完成!")
        print(f"   总耗时: {total_time:.1f} 秒")
        print(f"   LLM调用: {llm_client.call_count} 次")
        print(f"   最终最佳适应度: {final_best.fitness:.4f}")
        print(f"   总体改进: {final_best.fitness - best_fitness_history[0]:+.4f}")

        progress_str = " → ".join(f"{f:.3f}" for f in best_fitness_history)
        print(f"   适应度历程: {progress_str}")

        # 7. 保存详细结果
        print("\n💾 保存结果...")

        # 保存最终结果
        final_results = {
            "experiment_id": experiment_id,
            "best_prompt": final_best.prompt,
            "best_fitness": final_best.fitness,
            "fitness_history": best_fitness_history,
            "total_llm_calls": llm_client.call_count,
            "duration_seconds": total_time,
            "algorithm": "differential_evolution",
            "population_size": algorithm.population_size,
            "generations": algorithm.max_generations,
            "sample_info": {
                "total_samples": sample_result["total_samples"],
                "dev_samples": sample_result["dev_samples"],
                "train_samples": sample_result["train_samples"],
            },
        }

        # 保存到追踪器
        tracker.save_summary(final_results)

        # 导出top prompts
        tracker.export_prompts_by_fitness(str(exp_dir / "top_prompts.txt"), top_k=10)

        # 保存LLM调用历史
        llm_history_file = exp_dir / "llm_call_history.json"
        with open(llm_history_file, "w", encoding="utf-8") as f:
            json.dump(llm_client.conversation_history, f, indent=2, ensure_ascii=False)

        # 8. 展示最佳prompt
        print("\n🏆 最佳进化prompt:")
        print("=" * 80)
        print(final_best.prompt)
        print("=" * 80)

        # 9. 文件总结
        print("\n📁 生成的文件:")
        important_files = [
            "experiment_summary.json",
            "prompt_evolution.jsonl",
            "top_prompts.txt",
            "best_prompts.txt",
            "llm_call_history.json",
        ]

        for filename in important_files:
            filepath = exp_dir / filename
            if filepath.exists():
                size = filepath.stat().st_size
                print(f"   ✅ {filename} ({size} bytes)")
            else:
                print(f"   ❌ {filename} (missing)")

        print(f"\n📂 实验结果保存在: {exp_dir}")

        return {
            "success": True,
            "experiment_dir": str(exp_dir),
            "best_fitness": final_best.fitness,
            "improvement": final_best.fitness - best_fitness_history[0],
            "llm_calls": llm_client.call_count,
            "duration": total_time,
        }

    except Exception as e:
        print(f"\n❌ 演示实验失败: {e}")
        import traceback

        traceback.print_exc()
        return {"success": False, "error": str(e)}


if __name__ == "__main__":
    # 设置随机种子确保可重现
    random.seed(42)

    result = run_demo_evolution()

    if result["success"]:
        print("\n🎊 演示完成!")
        print("✨ 这个演示展示了完整的Primevul 1%数据prompt进化流程")
        print("🔧 在真实环境中，只需要设置OPENAI_API_KEY即可运行真实实验")
        print(f"📈 适应度改进: {result['improvement']:+.4f}")
        print(f"⚡ 效率: {result['llm_calls']} LLM调用，{result['duration']:.1f}秒")
    else:
        print(f"\n💥 演示失败: {result.get('error', 'Unknown error')}")
        sys.exit(1)
