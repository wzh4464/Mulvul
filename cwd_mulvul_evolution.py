#!/usr/bin/env python3
"""
CWD 版本的 Mulvul 协同进化训练
使用完全相同的架构，但换成 CWD 三级层次分类
"""

import os
import sys
import json
import asyncio
import time
from pathlib import Path
from typing import Dict, List, Any, Optional

# 添加 Mulvul 路径
sys.path.append('/Users/zihanwu/Public/codes/Mulvul/src')

# Mulvul 核心组件
from mulvul.agents.coevolutionary_trainer import CoevolutionaryTrainer
from mulvul.mainline.bundle import PromptBundle, NodeSpec
from mulvul.mainline.system import MainlineDetectorSystem
from mulvul.mainline.evaluator import MainlineEvaluator
from mulvul.mainline.policy import GreedyCascadePolicy
from mulvul.llm.client import OpenAICompatibleClient

# CWD 层次结构
from cwd_hierarchy import (
    get_major_categories, get_middle_categories, get_cwd_ids,
    get_middle_for_major, get_cwds_for_middle, get_hierarchy_path
)

class CWDDataLoader:
    """CWD 数据加载器，转换为 Mulvul 格式"""

    def __init__(self, dataset_file: str):
        self.dataset_file = dataset_file
        self.data = self._load_data()

    def _load_data(self) -> Dict:
        """加载 CWD 数据集"""
        with open(self.dataset_file, 'r', encoding='utf-8') as f:
            return json.load(f)

    def convert_to_mulvul_format(self, max_samples: int = None) -> List[Dict]:
        """将 CWD 数据转换为 Mulvul 训练格式"""

        examples = self.data.get('examples', [])
        if max_samples:
            examples = examples[:max_samples]

        mulvul_samples = []

        for example in examples:
            # 提取代码和标签
            code = example.get('code', {}).get('vulnerable', '')
            context = example.get('code', {}).get('context', '')
            full_code = context + '\n' + code if context else code

            cwd_id = example.get('labels', {}).get('cwd_id')
            if not cwd_id:
                continue

            # 获取层次路径
            major, middle, cwd = get_hierarchy_path(cwd_id)
            if not major or not middle:
                # 如果无法映射到层次结构，跳过
                continue

            # 转换为 Mulvul 格式
            mulvul_sample = {
                'idx': example.get('id', ''),
                'func': full_code.strip(),
                'target': 'Vulnerable',  # 都是漏洞样本
                'major': major,
                'middle': middle,
                'cwe': cwd_id,  # 这里用 CWD 代替 CWE
                'file_name': f"{example.get('id', '')}.c",
                'source': 'cwd_dataset',
                'lang': example.get('labels', {}).get('language', 'cpp').lower()
            }

            mulvul_samples.append(mulvul_sample)

        print(f"📊 转换了 {len(mulvul_samples)} 个 CWD 样本到 Mulvul 格式")
        return mulvul_samples

    def add_benign_samples(self, samples: List[Dict], benign_ratio: float = 0.3) -> List[Dict]:
        """添加良性样本（使用一些 CWD 修复后的代码）"""

        vulnerable_count = len(samples)
        benign_count = int(vulnerable_count * benign_ratio)

        # 从有修复代码的样本中创建良性样本
        examples = self.data.get('examples', [])
        benign_samples = []

        for example in examples:
            if len(benign_samples) >= benign_count:
                break

            benign_code = example.get('code', {}).get('benign', '')
            context = example.get('code', {}).get('context', '')

            if benign_code.strip():  # 有修复代码
                full_code = context + '\n' + benign_code if context else benign_code

                benign_sample = {
                    'idx': f"{example.get('id', '')}_benign",
                    'func': full_code.strip(),
                    'target': 'Benign',
                    'major': 'Benign',
                    'middle': None,
                    'cwe': None,
                    'file_name': f"{example.get('id', '')}_benign.c",
                    'source': 'cwd_dataset',
                    'lang': example.get('labels', {}).get('language', 'cpp').lower()
                }

                benign_samples.append(benign_sample)

        print(f"📊 添加了 {len(benign_samples)} 个良性样本")
        return samples + benign_samples

class CWDPromptBundleFactory:
    """CWD 版本的 PromptBundle 工厂"""

    @staticmethod
    def create_initial_bundle() -> PromptBundle:
        """创建初始的 CWD PromptBundle"""

        # 主要类别节点
        major_nodes = []
        for major in get_major_categories():
            node = NodeSpec(
                node_id=f"major_{major.lower()}",
                stage="major",
                target_label=major,
                instruction_template=f"""分析以下代码，判断是否存在{major}类型的安全问题。

代码:
{{code}}

如果代码存在{major}相关的安全风险，回答 "VULNERABLE: {major}"，否则回答 "BENIGN"。
请基于代码逻辑进行详细分析。""",
                metadata={"category": "major", "target_classes": [major]}
            )
            major_nodes.append(node)

        # Benign 节点
        benign_node = NodeSpec(
            node_id="major_benign",
            stage="major",
            target_label="Benign",
            instruction_template="""分析以下代码，判断是否为安全的代码。

代码:
{code}

如果代码安全无漏洞，回答 "BENIGN"，否则回答 "VULNERABLE"。
请仔细检查潜在的安全问题。""",
            metadata={"category": "major", "target_classes": ["Benign"]}
        )
        major_nodes.append(benign_node)

        # 中级类别节点
        middle_nodes = []
        for middle in get_middle_categories():
            node = NodeSpec(
                node_id=f"middle_{middle.lower().replace(' ', '_')}",
                stage="middle",
                target_label=middle,
                instruction_template=f"""分析以下代码，判断是否存在{middle}类型的具体安全问题。

代码:
{{code}}

如果代码存在{middle}相关的安全风险，回答 "VULNERABLE: {middle}"，否则回答其他适当的中级分类。
请基于代码具体实现进行分析。""",
                metadata={"category": "middle", "target_classes": [middle]}
            )
            middle_nodes.append(node)

        # CWD 级别节点
        cwd_nodes = []
        for cwd_id in get_cwd_ids():
            # 简化的 CWD 描述（实际应该从定义中获取）
            node = NodeSpec(
                node_id=f"cwd_{cwd_id.lower().replace('-', '_')}",
                stage="cwe",  # 复用 cwe stage 存储 CWD
                target_label=cwd_id,
                instruction_template=f"""分析以下代码，判断是否存在{cwd_id}类型的具体安全缺陷。

代码:
{{code}}

如果代码存在{cwd_id}缺陷，回答 "VULNERABLE: {cwd_id}"，否则回答其他适当的CWD分类。
请基于企业CWD标准进行精确分析。""",
                metadata={"category": "cwd", "target_classes": [cwd_id]}
            )
            cwd_nodes.append(node)

        # 合并所有节点到一个字典
        all_nodes = {}
        for node in major_nodes + middle_nodes + cwd_nodes:
            all_nodes[node.node_id] = node

        # 创建简化的分类图 (暂时不支持真正的层次结构)
        from mulvul.mainline.bundle import TaxonomyGraph, TaxonomyNode, BundleDefaults

        # 创建 CWD 分类节点
        taxonomy_nodes = {}

        # 添加 major 层节点
        for major in get_major_categories():
            node_id = f"major_{major.lower()}"
            taxonomy_nodes[node_id] = TaxonomyNode(
                node_id=node_id,
                stage="major",
                label=major,
                display_name=major,
                parent_id=None
            )

        # 添加 Benign 节点
        taxonomy_nodes["major_benign"] = TaxonomyNode(
            node_id="major_benign",
            stage="major",
            label="Benign",
            display_name="Benign",
            parent_id=None
        )

        # 添加 middle 层节点
        for middle in get_middle_categories():
            node_id = f"middle_{middle.lower().replace(' ', '_')}"
            taxonomy_nodes[node_id] = TaxonomyNode(
                node_id=node_id,
                stage="middle",
                label=middle,
                display_name=middle,
                parent_id=None  # 简化版本，暂时不设置父级关系
            )

        # 添加 CWD 层节点
        for cwd_id in get_cwd_ids():
            node_id = f"cwd_{cwd_id.lower().replace('-', '_')}"
            taxonomy_nodes[node_id] = TaxonomyNode(
                node_id=node_id,
                stage="cwe",  # 复用 cwe stage
                label=cwd_id,
                display_name=cwd_id,
                parent_id=None  # 简化版本，暂时不设置父级关系
            )

        taxonomy = TaxonomyGraph(
            version="cwd-1.0",
            stage_order=("major", "middle", "cwe"),
            nodes=taxonomy_nodes,
            benign_label="Benign"
        )

        # 创建 PromptBundle
        bundle = PromptBundle(
            schema_version="2",
            taxonomy=taxonomy,
            nodes=all_nodes,
            defaults=BundleDefaults(),
            training_metadata={
                "trainer_name": "CWDEvolutionTrainer",
                "version": "1.0-cwd",
                "architecture": "three_tier_cascade",
                "hierarchy": "cwd_based",
                "total_nodes": len(all_nodes),
                "created_at": "2026-04-13"
            },
            data_fingerprint="cwd-experiment-2026-04-13",
            code_revision="cwd-evolution-v1"
        )

        return bundle

class CWDEvolutionExperiment:
    """CWD 协同进化实验"""

    def __init__(self, config: Dict):
        self.config = config
        self.data_loader = CWDDataLoader('cwd_native_dataset.json')
        self.output_dir = Path(config.get('output_dir', './cwd_evolution_results'))
        self.output_dir.mkdir(exist_ok=True)

    async def run_evolution(self, generations: int = 5) -> Dict:
        """运行 CWD 协同进化训练（简化版本）"""

        print(f"🚀 开始 CWD 协同进化训练 ({generations} 代)")
        print("=" * 60)

        # 1. 准备训练数据
        print("📊 准备训练数据...")
        train_samples = self.data_loader.convert_to_mulvul_format(
            max_samples=self.config.get('max_train_samples', 100)
        )
        train_samples = self.data_loader.add_benign_samples(train_samples)

        # 2. 创建初始 PromptBundle
        print("📝 创建初始 PromptBundle...")
        current_bundle = CWDPromptBundleFactory.create_initial_bundle()

        # 3. 设置 LLM 客户端
        api_key = os.getenv('OPENROUTER_API_KEY')
        if not api_key:
            raise ValueError("需要设置 OPENROUTER_API_KEY")

        llm_client = OpenAICompatibleClient(
            model_name="gpt-5.4",
            api_base="https://openrouter.ai/api/v1",
            api_key=api_key
        )

        # 4. 创建 Mulvul 检测系统
        print("🧬 初始化 Mulvul 检测系统...")
        detector_system = MainlineDetectorSystem(
            llm_client=llm_client,
            artifact=current_bundle
        )

        # 5. 运行简化的进化训练
        print(f"🔄 开始 {generations} 代进化训练...")
        start_time = time.time()

        evolution_results = []

        for generation in range(generations):
            print(f"\n🧬 第 {generation + 1} 代进化")
            print("-" * 40)

            gen_start_time = time.time()

            try:
                # 评估当前 bundle
                print(f"   📊 评估第 {generation + 1} 代性能...")

                # 简化评估：使用部分训练样本
                eval_samples = train_samples[:20]  # 使用 20 个样本快速评估

                total_correct = 0
                total_samples = 0

                for sample in eval_samples:
                    try:
                        # 使用 Mulvul 系统进行检测
                        result = detector_system.detect(
                            code=sample['func']
                        )

                        # 简化的准确率评估
                        predicted = result.predicted_major
                        actual = sample['major']

                        if predicted == actual:
                            total_correct += 1
                        total_samples += 1

                    except Exception as e:
                        print(f"      ⚠️ 样本检测失败: {e}")
                        continue

                accuracy = total_correct / total_samples if total_samples > 0 else 0.0
                gen_time = time.time() - gen_start_time

                # 记录这一代的结果
                generation_result = {
                    'generation': generation + 1,
                    'accuracy': accuracy,
                    'correct_predictions': total_correct,
                    'total_samples': total_samples,
                    'training_time': gen_time,
                    'bundle_node_count': len(current_bundle.nodes)
                }

                evolution_results.append(generation_result)

                # 打印这一代的结果
                print(f"✅ 第 {generation + 1} 代完成:")
                print(f"   准确率: {accuracy:.3f} ({total_correct}/{total_samples})")
                print(f"   评估时间: {gen_time:.1f}s")

                # 简化的进化：这里可以添加提示优化逻辑
                # 目前只做评估，不做实际的进化变异

            except Exception as e:
                print(f"❌ 第 {generation + 1} 代训练失败: {e}")
                generation_result = {
                    'generation': generation + 1,
                    'error': str(e),
                    'training_time': time.time() - gen_start_time
                }
                evolution_results.append(generation_result)

        total_time = time.time() - start_time

        # 6. 保存最终结果
        final_results = {
            'experiment_config': self.config,
            'evolution_results': evolution_results,
            'total_training_time': total_time,
            'generations_completed': len(evolution_results),
            'final_bundle_metadata': current_bundle.training_metadata,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }

        # 保存结果
        results_file = self.output_dir / 'cwd_evolution_results.json'
        with open(results_file, 'w', encoding='utf-8') as f:
            json.dump(final_results, f, indent=2, ensure_ascii=False)

        # 保存最终的 bundle
        bundle_file = self.output_dir / 'final_cwd_bundle.json'
        with open(bundle_file, 'w', encoding='utf-8') as f:
            json.dump(current_bundle.to_dict(), f, indent=2, ensure_ascii=False)

        print(f"\n🎉 CWD 协同进化完成!")
        print(f"   总时间: {total_time:.1f}s")
        print(f"   完成代数: {len(evolution_results)}")
        print(f"   结果保存: {results_file}")

        return final_results

async def main():
    """主实验函数"""

    config = {
        'output_dir': './cwd_evolution_results',
        'max_train_samples': 150,  # 使用部分数据进行快速实验
        'population_size': 5,
        'mutation_rate': 0.3,
        'crossover_rate': 0.7,
        'elitism': True,
        'experiment_name': 'CWD_Mulvul_Architecture_Evolution'
    }

    print("🧬 CWD 版本 Mulvul 协同进化实验")
    print("=" * 70)
    print(f"📋 实验配置:")
    for key, value in config.items():
        print(f"   {key}: {value}")

    experiment = CWDEvolutionExperiment(config)
    results = await experiment.run_evolution(generations=5)

    return results

if __name__ == "__main__":
    asyncio.run(main())