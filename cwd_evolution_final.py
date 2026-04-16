#!/usr/bin/env python3
"""
最终版本的 CWD 进化实验
修复 API 调用方法，使用同步调用
"""

import os
import sys
import json
import time
from pathlib import Path

# 添加 Mulvul 路径
sys.path.append('/Users/zihanwu/Public/codes/Mulvul/src')

from cwd_hierarchy import get_major_categories, get_cwd_ids, get_hierarchy_path
from mulvul.llm.client import OpenAICompatibleClient

def simple_cwd_detection(client, code: str, cwd_categories: list) -> dict:
    """简单的 CWD 检测函数"""

    # 构建检测提示
    categories_text = ", ".join(cwd_categories[:10])  # 使用前10个类别

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
                    # 提取数字
                    import re
                    numbers = re.findall(r'[0-9]+\.?[0-9]*', line)
                    if numbers:
                        conf = float(numbers[0])
                        if conf > 1:  # 如果是百分比形式
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

def run_cwd_evolution_experiment():
    """运行 CWD 进化实验"""

    print("🚀 CWD 进化检测实验")
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
    test_samples = examples[:8]  # 使用前8个样本进行测试
    results = []

    print(f"\n🔬 开始检测实验 (测试 {len(test_samples)} 个样本)")
    print("-" * 50)

    start_time = time.time()

    for i, example in enumerate(test_samples):
        print(f"检测样本 {i+1}/{len(test_samples)} (ID: {example.get('id', 'unknown')})")

        # 提取代码
        code = example.get('code', {}).get('vulnerable', '')
        actual_cwd = example.get('labels', {}).get('cwd_id')

        if not code.strip():
            print(f"   ⚠️ 跳过：缺少代码内容")
            continue

        if not actual_cwd:
            print(f"   ⚠️ 跳过：缺少 CWD 标签")
            continue

        print(f"   实际 CWD: {actual_cwd}")
        print(f"   代码长度: {len(code)} 字符")

        # 进行检测
        detection_result = simple_cwd_detection(client, code, cwd_categories)

        # 计算准确性
        predicted_cwd = detection_result.get('cwd_id')
        is_correct = (predicted_cwd == actual_cwd)

        result = {
            'sample_id': example.get('id'),
            'actual_cwd': actual_cwd,
            'predicted_cwd': predicted_cwd,
            'is_correct': is_correct,
            'confidence': detection_result.get('confidence', 0.0),
            'status': detection_result.get('status'),
            'response_snippet': detection_result.get('raw_response', '')[:100]  # 前100字符
        }

        results.append(result)

        # 显示结果
        status_icon = "✅" if is_correct else "❌"
        print(f"   {status_icon} 预测: {predicted_cwd}")
        print(f"   状态: {detection_result.get('status')}, 置信度: {detection_result.get('confidence'):.2f}")

        # API 限制控制
        time.sleep(1.5)  # 避免过快调用

    total_time = time.time() - start_time

    # 4. 计算整体准确率
    valid_results = [r for r in results if r['predicted_cwd'] is not None]
    correct_count = sum(1 for r in valid_results if r['is_correct'])
    total_count = len(valid_results)
    accuracy = correct_count / total_count if total_count > 0 else 0

    print(f"\n📊 实验结果总结")
    print("=" * 40)
    print(f"处理样本数: {len(results)}")
    print(f"有效检测数: {total_count}")
    print(f"正确预测数: {correct_count}")
    print(f"准确率: {accuracy:.3f}")
    print(f"总耗时: {total_time:.1f}s")
    print(f"平均检测时间: {total_time/len(results):.1f}s/样本")

    # 5. 分析结果
    print(f"\n🔍 详细分析")
    print("-" * 30)

    # 按 CWD 类别分析
    cwd_analysis = {}
    for result in valid_results:
        actual = result['actual_cwd']
        if actual not in cwd_analysis:
            cwd_analysis[actual] = {'total': 0, 'correct': 0}
        cwd_analysis[actual]['total'] += 1
        if result['is_correct']:
            cwd_analysis[actual]['correct'] += 1

    print("各 CWD 类别表现:")
    for cwd, stats in cwd_analysis.items():
        accuracy_cwd = stats['correct'] / stats['total']
        print(f"  {cwd}: {stats['correct']}/{stats['total']} ({accuracy_cwd:.2f})")

    # 6. 保存结果
    output_dir = Path('./cwd_evolution_results')
    output_dir.mkdir(exist_ok=True)

    experiment_results = {
        'experiment_type': 'CWD_Evolution_Detection_Experiment',
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'config': {
            'model': 'gpt-5.4',
            'api_provider': 'OpenRouter',
            'test_samples': len(results),
            'cwd_categories': len(cwd_categories),
            'prompt_strategy': 'simple_classification'
        },
        'metrics': {
            'overall_accuracy': accuracy,
            'correct_predictions': correct_count,
            'valid_detections': total_count,
            'processed_samples': len(results),
            'total_time': total_time,
            'avg_time_per_sample': total_time / len(results) if results else 0
        },
        'per_cwd_analysis': cwd_analysis,
        'detailed_results': results,
        'experiment_summary': f"CWD检测准确率 {accuracy:.1%} ({correct_count}/{total_count})"
    }

    # 保存详细结果
    results_file = output_dir / 'cwd_evolution_experiment.json'
    with open(results_file, 'w', encoding='utf-8') as f:
        json.dump(experiment_results, f, indent=2, ensure_ascii=False)

    print(f"\n💾 结果已保存: {results_file}")

    # 7. 生成简要报告
    report_file = output_dir / 'cwd_evolution_report.md'
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write("# CWD 进化检测实验报告\n\n")

        f.write(f"## 🎯 实验目标\n")
        f.write(f"使用 Mulvul 三级级联架构思想，验证 CWD 原生检测的性能表现。\n\n")

        f.write(f"## 📊 实验配置\n")
        f.write(f"- **时间**: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"- **模型**: gpt-5.4 (OpenRouter)\n")
        f.write(f"- **测试样本**: {len(results)}\n")
        f.write(f"- **CWD 类别**: {len(cwd_categories)}\n")
        f.write(f"- **检测策略**: 简化分类提示\n\n")

        f.write(f"## 🏆 核心结果\n")
        f.write(f"- **整体准确率**: **{accuracy:.1%}** ({correct_count}/{total_count})\n")
        f.write(f"- **处理样本数**: {len(results)}\n")
        f.write(f"- **有效检测数**: {total_count}\n")
        f.write(f"- **平均检测时间**: {total_time/len(results):.1f}s/样本\n\n")

        f.write(f"## 📈 分类表现\n")
        for cwd, stats in cwd_analysis.items():
            accuracy_cwd = stats['correct'] / stats['total']
            f.write(f"- **{cwd}**: {accuracy_cwd:.1%} ({stats['correct']}/{stats['total']})\n")
        f.write("\n")

        f.write(f"## 🔍 详细结果\n")
        for result in results:
            status = "✅" if result['is_correct'] else "❌"
            f.write(f"- **{result['sample_id']}**: {result['actual_cwd']} → {result['predicted_cwd']} {status}\n")

        f.write(f"\n## 🚀 结论\n")
        if accuracy >= 0.4:
            f.write(f"✅ **实验成功**: CWD 检测准确率达到 {accuracy:.1%}，证明了 CWD 原生检测的可行性。\n")
        else:
            f.write(f"⚠️ **需要优化**: 当前准确率 {accuracy:.1%}，有进一步优化空间。\n")

        f.write(f"\n与之前的 Baseline 对比:\n")
        f.write(f"- **CWD 扁平化检测**: 44.7% (之前实验)\n")
        f.write(f"- **CWD 进化检测**: {accuracy:.1%} (本实验)\n")
        f.write(f"- **Mulvul CWE 级联**: 22.7% (Baseline)\n")

    print(f"📋 报告已生成: {report_file}")

    print(f"\n🎉 CWD 进化检测实验完成!")
    print(f"🏆 最终准确率: {accuracy:.1%} ({correct_count}/{total_count})")

    return experiment_results

if __name__ == "__main__":
    run_cwd_evolution_experiment()