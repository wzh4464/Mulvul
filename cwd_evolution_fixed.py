#!/usr/bin/env python3
"""
修复版本的 CWD 协同进化实验
使用真实的 LLM 调用进行 CWD 检测性能评估
"""

import os
import sys
import json
import time
import asyncio
from pathlib import Path
from typing import Dict, List, Any, Optional

# 添加 Mulvul 路径
sys.path.append('/Users/zihanwu/Public/codes/Mulvul/src')

# CWD 层次结构
from cwd_hierarchy import (
    get_major_categories, get_middle_categories, get_cwd_ids,
    get_hierarchy_path
)

# Mulvul 核心组件
from mulvul.mainline.bundle import PromptBundle, NodeSpec, TaxonomyGraph, TaxonomyNode, BundleDefaults
from mulvul.mainline.system import MainlineDetectorSystem
from mulvul.llm.client import OpenAICompatibleClient

class CWDDataLoader:
    """CWD 数据加载器"""

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
            if not major:
                # 简单映射
                major = 'Other'

            # 转换为 Mulvul 格式
            mulvul_sample = {
                'idx': example.get('id', ''),
                'func': full_code.strip(),
                'target': 'Vulnerable',
                'major': major,
                'middle': middle if middle else 'Other',
                'cwe': cwd_id,
                'file_name': f"{example.get('id', '')}.c",
                'source': 'cwd_dataset'
            }
            mulvul_samples.append(mulvul_sample)

        print(f"📊 转换了 {len(mulvul_samples)} 个 CWD 样本")
        return mulvul_samples

    def add_benign_samples(self, samples: List[Dict], benign_ratio: float = 0.3) -> List[Dict]:
        """添加良性样本"""
        vulnerable_count = len(samples)
        benign_count = int(vulnerable_count * benign_ratio)

        examples = self.data.get('examples', [])
        benign_samples = []

        for example in examples:
            if len(benign_samples) >= benign_count:
                break

            benign_code = example.get('code', {}).get('benign', '')
            context = example.get('code', {}).get('context', '')

            if benign_code.strip():
                full_code = context + '\n' + benign_code if context else benign_code
                benign_sample = {
                    'idx': f"{example.get('id', '')}_benign",
                    'func': full_code.strip(),
                    'target': 'Benign',
                    'major': 'Benign',
                    'middle': None,
                    'cwe': None,
                    'file_name': f"{example.get('id', '')}_benign.c",
                    'source': 'cwd_dataset'
                }
                benign_samples.append(benign_sample)

        print(f"📊 添加了 {len(benign_samples)} 个良性样本")
        return samples + benign_samples

class CWDPromptBundleFactory:
    """CWD PromptBundle 工厂"""

    @staticmethod
    def create_cwd_bundle() -> PromptBundle:
        """创建 CWD PromptBundle"""

        print("📝 创建 CWD PromptBundle...")

        all_nodes = {}
        taxonomy_nodes = {}

        # 1. Major 级别节点
        major_categories = get_major_categories()
        for major in major_categories:
            node_id = f"major_{major.lower()}"

            # NodeSpec
            node = NodeSpec(
                node_id=node_id,
                stage="major",
                target_label=major,
                instruction_template=f"""分析以下代码，判断是否存在 {major} 类型的安全问题。

代码:
{{code}}

如果代码存在 {major} 相关的安全风险，回答"VULNERABLE"，否则回答"BENIGN"。""",
                metadata={"category": "major"}
            )
            all_nodes[node_id] = node

            # TaxonomyNode
            taxonomy_nodes[node_id] = TaxonomyNode(
                node_id=node_id,
                stage="major",
                label=major,
                display_name=major,
                parent_id=None
            )

        # 2. Benign 节点
        benign_node_id = "major_benign"
        all_nodes[benign_node_id] = NodeSpec(
            node_id=benign_node_id,
            stage="major",
            target_label="Benign",
            instruction_template="""分析以下代码，判断是否为安全的代码。

代码:
{code}

如果代码安全无漏洞，回答"BENIGN"，否则回答"VULNERABLE"。""",
            metadata={"category": "major"}
        )

        taxonomy_nodes[benign_node_id] = TaxonomyNode(
            node_id=benign_node_id,
            stage="major",
            label="Benign",
            display_name="Benign",
            parent_id=None
        )

        # 3. Middle 级别节点
        middle_categories = get_middle_categories()
        for middle in middle_categories:
            node_id = f"middle_{middle.lower().replace(' ', '_')}"

            all_nodes[node_id] = NodeSpec(
                node_id=node_id,
                stage="middle",
                target_label=middle,
                instruction_template=f"""分析以下代码，判断是否存在 {middle} 类型的具体安全问题。

代码:
{{code}}

如果代码存在 {middle} 相关的安全风险，回答"VULNERABLE"，否则分析其他中级分类。""",
                metadata={"category": "middle"}
            )

            taxonomy_nodes[node_id] = TaxonomyNode(
                node_id=node_id,
                stage="middle",
                label=middle,
                display_name=middle,
                parent_id=None
            )

        # 4. CWD 级别节点
        cwd_ids = get_cwd_ids()
        for cwd_id in cwd_ids:
            node_id = f"cwd_{cwd_id.lower().replace('-', '_')}"

            all_nodes[node_id] = NodeSpec(
                node_id=node_id,
                stage="cwe",  # 复用 cwe stage
                target_label=cwd_id,
                instruction_template=f"""分析以下代码，判断是否存在 {cwd_id} 类型的具体安全缺陷。

代码:
{{code}}

如果代码存在 {cwd_id} 缺陷，回答"VULNERABLE"，否则分析其他 CWD 分类。""",
                metadata={"category": "cwd"}
            )

            taxonomy_nodes[node_id] = TaxonomyNode(
                node_id=node_id,
                stage="cwe",
                label=cwd_id,
                display_name=cwd_id,
                parent_id=None
            )

        # 5. 创建分类图
        taxonomy = TaxonomyGraph(
            version="cwd-evolution-1.0",
            stage_order=("major", "middle", "cwe"),
            nodes=taxonomy_nodes,
            benign_label="Benign"
        )

        # 6. 创建 PromptBundle
        bundle = PromptBundle(
            schema_version="2",
            taxonomy=taxonomy,
            nodes=all_nodes,
            defaults=BundleDefaults(default_threshold=0.5),
            training_metadata={
                "trainer_name": "CWDEvolutionTrainer",
                "version": "evolution-1.0",
                "architecture": "three_tier_cascade_cwd",
                "total_nodes": len(all_nodes),
                "created_at": time.strftime('%Y-%m-%d %H:%M:%S')
            },
            data_fingerprint=f"cwd-evolution-{int(time.time())}",
            code_revision="cwd-evolution-v1"
        )

        print(f"✅ 创建了包含 {len(all_nodes)} 个节点的 CWD PromptBundle")
        return bundle

class CWDEvolutionExperiment:
    """CWD 进化实验"""

    def __init__(self, config: Dict):
        self.config = config
        self.data_loader = CWDDataLoader('cwd_native_dataset.json')
        self.output_dir = Path(config.get('output_dir', './cwd_evolution_results'))
        self.output_dir.mkdir(exist_ok=True)

    async def run_evolution_experiment(self, generations: int = 5) -> Dict:
        """运行 CWD 进化实验"""

        print(f"🚀 开始 CWD 进化实验 ({generations} 代)")
        print("=" * 60)

        try:
            # 1. 准备数据
            print("📊 准备训练数据...")
            train_samples = self.data_loader.convert_to_mulvul_format(
                max_samples=self.config.get('max_train_samples', 50)
            )
            train_samples = self.data_loader.add_benign_samples(train_samples)
            print(f"   总样本数: {len(train_samples)}")

            # 2. 创建 PromptBundle
            current_bundle = CWDPromptBundleFactory.create_cwd_bundle()

            # 验证 Bundle
            errors = current_bundle.validate(allow_partial=True)
            if errors:
                print(f"❌ PromptBundle 验证错误: {errors}")
                return {"error": "Bundle validation failed", "errors": errors}

            # 3. 设置 LLM 客户端
            api_key = os.getenv('OPENROUTER_API_KEY')
            if not api_key:
                raise ValueError("需要设置 OPENROUTER_API_KEY")

            llm_client = OpenAICompatibleClient(
                model_name="gpt-5.4",
                api_base="https://openrouter.ai/api/v1",
                api_key=api_key
            )

            # 4. 创建检测系统
            print("🧬 初始化 Mulvul 检测系统...")
            detector_system = MainlineDetectorSystem(
                llm_client=llm_client,
                artifact=current_bundle
            )

            # 5. 运行进化实验
            evolution_results = []
            start_time = time.time()

            for generation in range(generations):
                print(f"\n🧬 第 {generation + 1} 代进化")
                print("-" * 40)

                gen_start_time = time.time()

                try:
                    # 评估当前 bundle 性能
                    print(f"   📊 评估第 {generation + 1} 代性能...")

                    # 使用少量样本进行快速评估
                    eval_samples = train_samples[:10]  # 使用 10 个样本快速评估

                    total_correct = 0
                    total_samples = 0
                    errors = []

                    for i, sample in enumerate(eval_samples):
                        try:
                            print(f"      检测样本 {i+1}/{len(eval_samples)}...")

                            # 使用 Mulvul 系统检测
                            result = detector_system.detect(code=sample['func'])

                            # 评估准确性
                            predicted_major = result.detection_path.major
                            actual_major = sample['major']

                            if predicted_major == actual_major:
                                total_correct += 1

                            total_samples += 1

                            print(f"         预测: {predicted_major}, 实际: {actual_major}")

                        except Exception as e:
                            print(f"      ⚠️ 样本 {i+1} 检测失败: {e}")
                            errors.append(str(e))
                            continue

                    # 计算准确率
                    accuracy = total_correct / total_samples if total_samples > 0 else 0.0
                    gen_time = time.time() - gen_start_time

                    # 记录结果
                    generation_result = {
                        'generation': generation + 1,
                        'accuracy': accuracy,
                        'correct_predictions': total_correct,
                        'total_samples': total_samples,
                        'training_time': gen_time,
                        'bundle_node_count': len(current_bundle.nodes),
                        'errors': errors[:3]  # 记录前3个错误
                    }

                    evolution_results.append(generation_result)

                    # 显示结果
                    print(f"✅ 第 {generation + 1} 代完成:")
                    print(f"   准确率: {accuracy:.3f} ({total_correct}/{total_samples})")
                    print(f"   用时: {gen_time:.1f}s")
                    if errors:
                        print(f"   错误数: {len(errors)}")

                    # 保存当前代的 Bundle
                    bundle_file = self.output_dir / f'generation_{generation + 1}_bundle.json'
                    with open(bundle_file, 'w', encoding='utf-8') as f:
                        json.dump(current_bundle.to_dict(), f, indent=2, ensure_ascii=False)

                except Exception as e:
                    print(f"❌ 第 {generation + 1} 代失败: {e}")
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
                'final_bundle_stats': {
                    'total_nodes': len(current_bundle.nodes),
                    'major_categories': len([n for n in current_bundle.nodes.values() if n.stage == 'major']),
                    'middle_categories': len([n for n in current_bundle.nodes.values() if n.stage == 'middle']),
                    'cwd_categories': len([n for n in current_bundle.nodes.values() if n.stage == 'cwe'])
                },
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
            }

            # 保存结果文件
            results_file = self.output_dir / 'cwd_evolution_results.json'
            with open(results_file, 'w', encoding='utf-8') as f:
                json.dump(final_results, f, indent=2, ensure_ascii=False)

            # 保存最终 Bundle
            final_bundle_file = self.output_dir / 'final_cwd_bundle.json'
            with open(final_bundle_file, 'w', encoding='utf-8') as f:
                json.dump(current_bundle.to_dict(), f, indent=2, ensure_ascii=False)

            print(f"\n🎉 CWD 进化实验完成!")
            print(f"   总时间: {total_time:.1f}s")
            print(f"   完成代数: {len(evolution_results)}")
            print(f"   结果保存: {results_file}")

            return final_results

        except Exception as e:
            print(f"❌ 实验失败: {e}")
            import traceback
            traceback.print_exc()
            return {"error": str(e)}

async def main():
    """主实验函数"""

    config = {
        'output_dir': './cwd_evolution_results',
        'max_train_samples': 30,  # 使用较少样本进行快速实验
        'experiment_name': 'CWD_Mulvul_Evolution_Experiment'
    }

    print("🧬 CWD 协同进化实验")
    print("=" * 50)
    print(f"📋 实验配置:")
    for key, value in config.items():
        print(f"   {key}: {value}")

    experiment = CWDEvolutionExperiment(config)
    results = await experiment.run_evolution_experiment(generations=3)

    return results

if __name__ == "__main__":
    asyncio.run(main())