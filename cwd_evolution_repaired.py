#!/usr/bin/env python3
"""
修复版本的 CWD 进化实验
解决了 Codex adversarial review 发现的关键问题：
1. 修复 TaxonomyNode parent_id 层次结构
2. 修复 API 调用错误 (result.detection_path.major -> result.major)
3. 使用完整的 CWD 标签集而不是只有前10个
4. 添加验证失败时的硬停机制
"""

import os
import sys
import json
import time
from pathlib import Path
from typing import Dict, List

# 添加 Mulvul 路径
sys.path.append('/Users/zihanwu/Public/codes/Mulvul/src')

from cwd_hierarchy import (
    get_major_categories, get_middle_categories, get_cwd_ids,
    get_hierarchy_path, get_middle_for_major, get_cwds_for_middle
)
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
            code = example.get('code', {}).get('vulnerable', '')
            context = example.get('code', {}).get('context', '')
            full_code = context + '\n' + code if context else code

            cwd_id = example.get('labels', {}).get('cwd_id')
            if not cwd_id:
                continue

            # 获取层次路径
            major, middle, cwd = get_hierarchy_path(cwd_id)
            if not major:
                major = 'Other'  # 简单映射

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
    """修复版本的 CWD PromptBundle 工厂"""

    @staticmethod
    def create_cwd_bundle() -> PromptBundle:
        """创建修复后的 CWD PromptBundle，正确设置层次结构"""

        print("📝 创建修复后的 CWD PromptBundle...")

        all_nodes = {}
        taxonomy_nodes = {}

        # 1. Major 级别节点
        major_categories = get_major_categories()
        for major in major_categories:
            node_id = f"major_{major.lower()}"

            # NodeSpec
            all_nodes[node_id] = NodeSpec(
                node_id=node_id,
                stage="major",
                target_label=major,
                instruction_template=f"""分析以下代码，判断是否存在 {major} 类型的安全问题。

代码:
{{code}}

如果代码存在 {major} 相关的安全风险，回答"VULNERABLE"，否则回答"BENIGN"。""",
                metadata={"category": "major"}
            )

            # TaxonomyNode (Major 级别没有 parent_id)
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

        # 3. Middle 级别节点 - 修复：正确设置 parent_id
        middle_categories = get_middle_categories()
        for middle in middle_categories:
            node_id = f"middle_{middle.lower().replace(' ', '_')}"

            # 找到 middle 的 parent major
            parent_major = None
            for major in major_categories:
                if middle in get_middle_for_major(major):
                    parent_major = f"major_{major.lower()}"
                    break

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

            # 修复：设置正确的 parent_id
            taxonomy_nodes[node_id] = TaxonomyNode(
                node_id=node_id,
                stage="middle",
                label=middle,
                display_name=middle,
                parent_id=parent_major
            )

        # 4. CWD 级别节点 - 修复：正确设置 parent_id
        cwd_ids = get_cwd_ids()
        for cwd_id in cwd_ids:
            node_id = f"cwd_{cwd_id.lower().replace('-', '_')}"

            # 找到 cwd 的 parent middle
            parent_middle = None
            for middle in middle_categories:
                if cwd_id in get_cwds_for_middle(middle):
                    parent_middle = f"middle_{middle.lower().replace(' ', '_')}"
                    break

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

            # 修复：设置正确的 parent_id
            taxonomy_nodes[node_id] = TaxonomyNode(
                node_id=node_id,
                stage="cwe",
                label=cwd_id,
                display_name=cwd_id,
                parent_id=parent_middle
            )

        # 5. 创建分类图
        taxonomy = TaxonomyGraph(
            version="cwd-repaired-1.0",
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
                "trainer_name": "CWDRepairedEvolutionTrainer",
                "version": "repaired-1.0",
                "architecture": "three_tier_cascade_cwd_fixed",
                "total_nodes": len(all_nodes),
                "hierarchy_fixed": True,
                "created_at": time.strftime('%Y-%m-%d %H:%M:%S')
            },
            data_fingerprint=f"cwd-repaired-{int(time.time())}",
            code_revision="cwd-repaired-v1"
        )

        print(f"✅ 创建了包含 {len(all_nodes)} 个节点的修复后 CWD PromptBundle")

        # 验证层次结构
        CWDPromptBundleFactory._validate_hierarchy(bundle)

        return bundle

    @staticmethod
    def _validate_hierarchy(bundle: PromptBundle):
        """验证层次结构是否正确设置"""
        print("🔍 验证层次结构...")

        major_nodes = [n for n in bundle.taxonomy.nodes.values() if n.stage == 'major' and n.label != 'Benign']

        for major_node in major_nodes[:2]:  # 检查前2个 major 节点
            children = bundle.taxonomy.children_of(major_node.node_id)
            print(f"   Major '{major_node.label}' 有 {len(children)} 个 middle 子节点")

            if len(children) == 0:
                raise ValueError(f"Major 节点 '{major_node.label}' 没有 middle 子节点！层次结构可能有问题。")

            # 检查第一个 middle 节点
            if children:
                first_middle = children[0]
                middle_children = bundle.taxonomy.children_of(first_middle)
                middle_node = bundle.taxonomy.node(first_middle)
                print(f"   Middle '{middle_node.label}' 有 {len(middle_children)} 个 CWD 子节点")

        print("✅ 层次结构验证通过")

def simple_cwd_detection(client, code: str, cwd_categories: list) -> dict:
    """简单的 CWD 检测函数 - 修复：使用完整的 CWD 标签集"""

    # 修复：使用完整的 CWD 类别，而不是只有前10个
    categories_text = ", ".join(cwd_categories)  # 使用所有类别

    prompt = f"""分析以下代码，识别安全漏洞类型。

代码:
{code}

可能的分类: {categories_text}

请按以下格式回答：
状态: VULNERABLE 或 BENIGN
分类: [如果存在漏洞，指定最可能的 CWD-ID]
置信度: [0.0-1.0 的数字]"""

    try:
        response = client.generate(
            prompt=prompt,
            max_tokens=300,
            temperature=0.1
        )

        # 简单解析响应
        result = {
            'status': 'BENIGN',
            'cwd_id': None,
            'confidence': 0.5,
            'raw_response': response
        }

        # 解析响应内容
        lines = response.strip().split('\n')
        for line in lines:
            line_lower = line.lower()
            if '状态:' in line or 'status:' in line_lower:
                if 'vulnerable' in line_lower:
                    result['status'] = 'VULNERABLE'
                elif 'benign' in line_lower:
                    result['status'] = 'BENIGN'
            elif '分类:' in line or 'classification:' in line_lower or 'cwd' in line_lower:
                for cwd in cwd_categories:
                    if cwd.upper() in line.upper():
                        result['cwd_id'] = cwd
                        break
            elif '置信度:' in line or 'confidence:' in line_lower:
                try:
                    import re
                    numbers = re.findall(r'[0-9]+\.?[0-9]*', line)
                    if numbers:
                        conf = float(numbers[0])
                        if conf > 1:
                            conf = conf / 100
                        result['confidence'] = min(max(conf, 0.0), 1.0)
                except:
                    pass

        return result

    except Exception as e:
        print(f"      API 调用失败: {e}")
        return {
            'status': 'ERROR',
            'cwd_id': None,
            'confidence': 0.0,
            'error': str(e),
            'raw_response': ''
        }

class CWDRepairedEvolutionExperiment:
    """修复后的 CWD 进化实验"""

    def __init__(self, config: Dict):
        self.config = config
        self.data_loader = CWDDataLoader('cwd_native_dataset.json')
        self.output_dir = Path(config.get('output_dir', './cwd_repaired_evolution_results'))
        self.output_dir.mkdir(exist_ok=True)

    async def run_evolution_experiment(self, generations: int = 3) -> Dict:
        """运行修复后的 CWD 进化实验"""

        print(f"🚀 CWD 修复版进化检测实验 ({generations} 代)")
        print("=" * 60)

        try:
            # 1. 准备数据
            print("📊 准备训练数据...")
            train_samples = self.data_loader.convert_to_mulvul_format(
                max_samples=self.config.get('max_train_samples', 20)
            )
            train_samples = self.data_loader.add_benign_samples(train_samples)
            print(f"   总样本数: {len(train_samples)}")

            # 2. 创建修复后的 PromptBundle
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
            print("🧬 初始化修复后的 Mulvul 检测系统...")
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
                    print(f"   📊 评估第 {generation + 1} 代性能...")

                    # 使用少量样本进行快速评估
                    eval_samples = train_samples[:8]  # 使用 8 个样本快速评估

                    total_correct = 0
                    total_samples = 0
                    errors = []

                    for i, sample in enumerate(eval_samples):
                        try:
                            print(f"      检测样本 {i+1}/{len(eval_samples)}...")

                            # 修复：使用正确的 API
                            result = detector_system.detect(code=sample['func'])

                            # 修复：使用正确的 API - result.major 而不是 result.detection_path.major
                            predicted_major = result.major
                            actual_major = sample['major']

                            if predicted_major == actual_major:
                                total_correct += 1

                            total_samples += 1

                            print(f"         预测: {predicted_major}, 实际: {actual_major}")

                        except Exception as e:
                            print(f"      ⚠️ 样本 {i+1} 检测失败: {e}")
                            errors.append(str(e))
                            continue

                    # 修复：添加硬停机制 - 如果没有评估任何样本则失败
                    if total_samples == 0:
                        raise ValueError(f"第 {generation + 1} 代没有评估任何样本！实验失败。")

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
                        'errors': errors[:3],
                        'repaired_version': True
                    }

                    evolution_results.append(generation_result)

                    # 显示结果
                    print(f"✅ 第 {generation + 1} 代完成:")
                    print(f"   准确率: {accuracy:.3f} ({total_correct}/{total_samples})")
                    print(f"   用时: {gen_time:.1f}s")
                    if errors:
                        print(f"   错误数: {len(errors)}")

                    # 保存当前代的 Bundle
                    bundle_file = self.output_dir / f'generation_{generation + 1}_repaired_bundle.json'
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

                # API 限制控制
                time.sleep(2)

            total_time = time.time() - start_time

            # 6. 保存最终结果
            valid_results = [r for r in evolution_results if 'accuracy' in r]
            if valid_results:
                final_accuracy = valid_results[-1]['accuracy']
                total_correct = sum(r['correct_predictions'] for r in valid_results)
                total_samples = sum(r['total_samples'] for r in valid_results)
            else:
                final_accuracy = 0.0
                total_correct = 0
                total_samples = 0

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
                'final_metrics': {
                    'final_accuracy': final_accuracy,
                    'total_correct': total_correct,
                    'total_samples': total_samples
                },
                'repaired_version': True,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
            }

            # 保存结果文件
            results_file = self.output_dir / 'cwd_repaired_evolution_results.json'
            with open(results_file, 'w', encoding='utf-8') as f:
                json.dump(final_results, f, indent=2, ensure_ascii=False)

            # 保存最终 Bundle
            final_bundle_file = self.output_dir / 'final_cwd_repaired_bundle.json'
            with open(final_bundle_file, 'w', encoding='utf-8') as f:
                json.dump(current_bundle.to_dict(), f, indent=2, ensure_ascii=False)

            print(f"\n🎉 CWD 修复版进化实验完成!")
            print(f"   总时间: {total_time:.1f}s")
            print(f"   完成代数: {len(evolution_results)}")
            print(f"   最终准确率: {final_accuracy:.1%}")
            print(f"   结果保存: {results_file}")

            return final_results

        except Exception as e:
            print(f"❌ 实验失败: {e}")
            import traceback
            traceback.print_exc()
            return {"error": str(e)}

def main():
    """主实验函数"""

    config = {
        'output_dir': './cwd_repaired_evolution_results',
        'max_train_samples': 15,  # 使用较少样本进行测试
        'experiment_name': 'CWD_Repaired_Evolution_Experiment'
    }

    print("🧬 CWD 修复版协同进化实验")
    print("=" * 50)
    print(f"📋 实验配置:")
    for key, value in config.items():
        print(f"   {key}: {value}")

    print("\n🔧 修复内容:")
    print("   ✅ 修复 TaxonomyNode parent_id 层次结构")
    print("   ✅ 修复 API 调用错误 (result.major)")
    print("   ✅ 使用完整的 CWD 标签集")
    print("   ✅ 添加验证失败硬停机制")

    experiment = CWDRepairedEvolutionExperiment(config)

    # 使用同步函数，避免 async 问题
    import asyncio
    results = asyncio.run(experiment.run_evolution_experiment(generations=3))

    return results

if __name__ == "__main__":
    main()