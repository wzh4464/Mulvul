#!/usr/bin/env python3
"""
简化但功能完整的 CWD 进化实验
使用真实的 API 调用进行检测
"""

import os
import sys
import json
import time
import asyncio
from pathlib import Path

# 添加 Mulvul 路径
sys.path.append('/Users/zihanwu/Public/codes/Mulvul/src')

from cwd_hierarchy import get_major_categories, get_cwd_ids, get_hierarchy_path
from mulvul.llm.client import OpenAICompatibleClient

async def simple_cwd_detection(client, code: str, cwd_categories: list) -> dict:
    """简单的 CWD 检测函数"""

    # 构建检测提示
    categories_text = ", ".join(cwd_categories[:10])  # 使用前10个类别

    prompt = f"""分析以下代码，识别安全漏洞类型。

代码:
{code}

可能的分类: {categories_text}

请按以下格式回答：
1. 是否存在漏洞：VULNERABLE 或 BENIGN
2. 如果存在漏洞，最可能的 CWD 分类：[CWD-ID]
3. 置信度：0.0-1.0

回答格式：
状态: [VULNERABLE/BENIGN]
分类: [CWD-ID]
置信度: [0.0-1.0]"""

    try:
        response = await client.generate_async(
            prompt=prompt,
            max_tokens=200,
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
            if '状态:' in line or 'Status:' in line:
                if 'VULNERABLE' in line.upper():
                    result['status'] = 'VULNERABLE'
            elif '分类:' in line or 'Classification:' in line:
                for cwd in cwd_categories:
                    if cwd in line:
                        result['cwd_id'] = cwd
                        break
            elif '置信度:' in line or 'Confidence:' in line:
                try:
                    conf_str = line.split(':')[1].strip()
                    result['confidence'] = float(conf_str)
                except:
                    pass

        return result

    except Exception as e:
        print(f"API 调用失败: {e}")
        return {
            'status': 'ERROR',
            'cwd_id': None,
            'confidence': 0.0,
            'error': str(e)
        }

async def run_cwd_evolution_experiment():
    """运行 CWD 进化实验"""

    print("🚀 CWD 进化实验")
    print("=" * 50)

    # 1. 设置 LLM 客户端
    api_key = os.getenv('OPENROUTER_API_KEY')
    if not api_key:
        print("❌ 需要设置 OPENROUTER_API_KEY")
        return

    client = OpenAICompatibleClient(
        model_name="gpt-5.4",
        api_base="https://openrouter.ai/api/v1",
        api_key=api_key
    )
    print("✅ LLM 客户端初始化完成")

    # 2. 加载数据
    print("📊 加载 CWD 数据...")
    with open('cwd_native_dataset.json', 'r', encoding='utf-8') as f:
        data = json.load(f)

    examples = data.get('examples', [])
    cwd_categories = get_cwd_ids()

    print(f"   数据集大小: {len(examples)}")
    print(f"   CWD 类别数: {len(cwd_categories)}")

    # 3. 运行检测实验
    test_samples = examples[:5]  # 使用前5个样本进行测试
    results = []

    print(f"\n🔬 开始检测实验 (测试 {len(test_samples)} 个样本)")
    print("-" * 40)

    start_time = time.time()

    for i, example in enumerate(test_samples):
        print(f"检测样本 {i+1}/{len(test_samples)}...")

        # 提取代码
        code = example.get('code', {}).get('vulnerable', '')
        actual_cwd = example.get('labels', {}).get('cwd_id')

        if not code or not actual_cwd:
            print(f"   跳过：缺少代码或标签")
            continue

        # 进行检测
        detection_result = await simple_cwd_detection(client, code, cwd_categories)

        # 计算准确性
        predicted_cwd = detection_result.get('cwd_id')
        is_correct = (predicted_cwd == actual_cwd)

        result = {
            'sample_id': example.get('id'),
            'actual_cwd': actual_cwd,
            'predicted_cwd': predicted_cwd,
            'is_correct': is_correct,
            'confidence': detection_result.get('confidence'),
            'status': detection_result.get('status'),
            'raw_response': detection_result.get('raw_response', '')[:200]  # 截断响应
        }

        results.append(result)

        # 显示结果
        status_icon = "✅" if is_correct else "❌"
        print(f"   {status_icon} 实际: {actual_cwd}, 预测: {predicted_cwd}, 置信度: {detection_result.get('confidence'):.2f}")

        # 避免 API 限制
        await asyncio.sleep(1)

    total_time = time.time() - start_time

    # 4. 计算整体准确率
    correct_count = sum(1 for r in results if r['is_correct'])
    total_count = len(results)
    accuracy = correct_count / total_count if total_count > 0 else 0

    print(f"\n📊 实验结果")
    print("-" * 30)
    print(f"总样本数: {total_count}")
    print(f"正确预测: {correct_count}")
    print(f"准确率: {accuracy:.3f}")
    print(f"总时间: {total_time:.1f}s")
    print(f"平均每样本: {total_time/total_count:.1f}s")

    # 5. 保存结果
    output_dir = Path('./cwd_evolution_results')
    output_dir.mkdir(exist_ok=True)

    experiment_results = {
        'experiment_type': 'CWD_Detection_Experiment',
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'config': {
            'model': 'gpt-5.4',
            'test_samples': total_count,
            'cwd_categories': len(cwd_categories)
        },
        'metrics': {
            'accuracy': accuracy,
            'correct_predictions': correct_count,
            'total_samples': total_count,
            'total_time': total_time
        },
        'detailed_results': results,
        'cwd_categories_tested': cwd_categories[:10]
    }

    # 保存详细结果
    results_file = output_dir / 'cwd_detection_experiment.json'
    with open(results_file, 'w', encoding='utf-8') as f:
        json.dump(experiment_results, f, indent=2, ensure_ascii=False)

    print(f"\n💾 结果已保存: {results_file}")

    # 6. 生成简要报告
    report_file = output_dir / 'experiment_report.md'
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write("# CWD 检测实验报告\n\n")
        f.write(f"## 实验概述\n")
        f.write(f"- **时间**: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"- **模型**: gpt-5.4\n")
        f.write(f"- **测试样本**: {total_count}\n")
        f.write(f"- **CWD 类别**: {len(cwd_categories)}\n\n")

        f.write(f"## 核心结果\n")
        f.write(f"- **准确率**: {accuracy:.3f}\n")
        f.write(f"- **正确预测**: {correct_count}/{total_count}\n")
        f.write(f"- **平均检测时间**: {total_time/total_count:.1f}s/样本\n\n")

        f.write(f"## 详细结果\n")
        for result in results:
            f.write(f"- **{result['sample_id']}**: ")
            f.write(f"{result['actual_cwd']} → {result['predicted_cwd']} ")
            f.write(f"({'✅' if result['is_correct'] else '❌'})")
            f.write(f" 置信度: {result['confidence']:.2f}\n")

    print(f"📋 报告已生成: {report_file}")

    print(f"\n🎉 CWD 检测实验完成!")
    print(f"准确率: {accuracy:.3f} ({correct_count}/{total_count})")

    return experiment_results

if __name__ == "__main__":
    asyncio.run(run_cwd_evolution_experiment())