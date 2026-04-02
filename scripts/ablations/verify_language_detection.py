#!/usr/bin/env python3
"""验证语言检测功能的脚本"""

from collections import Counter
from src.evoprompt.data.dataset import PrimevulDataset

def main():
    print("=" * 60)
    print("验证 Primevul 数据集语言检测")
    print("=" * 60)

    # 加载数据集
    dataset = PrimevulDataset(
        data_path="data/demo_primevul_1percent_sample/dev_sample.jsonl",
        split="dev"
    )

    print(f"\n总样本数: {len(dataset)}")

    # 统计语言分布
    lang_counter = Counter()
    detection_method = {"from_filename": 0, "from_code": 0}

    samples_by_lang = {
        "c": [],
        "cpp": [],
        "java": [],
        "python": [],
        "javascript": [],
        "unknown": []
    }

    for sample in dataset.get_samples():
        lang = sample.metadata.get("lang", "unknown")
        lang_counter[lang] += 1

        # 记录检测方法
        file_name = sample.metadata.get("file_name")
        if file_name and file_name != "None":
            detection_method["from_filename"] += 1
        else:
            detection_method["from_code"] += 1

        # 收集样本用于展示
        if lang in samples_by_lang and len(samples_by_lang[lang]) < 3:
            samples_by_lang[lang].append(sample)

    # 打印统计结果
    print("\n" + "=" * 60)
    print("语言分布统计")
    print("=" * 60)
    for lang, count in sorted(lang_counter.items(), key=lambda x: -x[1]):
        percentage = count / len(dataset) * 100
        print(f"{lang:15s}: {count:4d} ({percentage:5.1f}%)")

    print("\n" + "=" * 60)
    print("检测方法统计")
    print("=" * 60)
    for method, count in detection_method.items():
        percentage = count / len(dataset) * 100
        print(f"{method:20s}: {count:4d} ({percentage:5.1f}%)")

    # 展示各语言的样本
    print("\n" + "=" * 60)
    print("各语言样本展示")
    print("=" * 60)

    for lang, samples in samples_by_lang.items():
        if not samples:
            continue

        print(f"\n【{lang.upper()}】")
        for i, sample in enumerate(samples[:2], 1):
            file_name = sample.metadata.get("file_name", "None")
            code_preview = sample.input_text[:100].replace("\n", " ")
            print(f"  样本{i}:")
            print(f"    文件名: {file_name}")
            print(f"    代码预览: {code_preview}...")

    # 验证无unknown样本（或展示unknown样本）
    print("\n" + "=" * 60)
    print("检测质量验证")
    print("=" * 60)

    unknown_count = lang_counter.get("unknown", 0)
    if unknown_count == 0:
        print("✅ 所有样本都成功检测到语言!")
    else:
        print(f"⚠️ 有 {unknown_count} 个样本未能识别语言")
        print("\n展示前3个未识别的样本:")
        for i, sample in enumerate(samples_by_lang.get("unknown", [])[:3], 1):
            print(f"\n  未识别样本{i}:")
            print(f"    文件名: {sample.metadata.get('file_name', 'None')}")
            print(f"    代码片段:\n{sample.input_text[:200]}")

if __name__ == "__main__":
    main()
