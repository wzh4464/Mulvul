"""
数据集批量修复与自动大括号转义脚本
======================================
Author: Zihan

本工具用于自动修复 jsonl/txt 数据集文件格式，同时将所有样本代码/输入字段中的 `{}` 替换为 `{{}}`。
主要用于批量 LLM 推理或 prompt 流程前，预防 `str.format()` 报 unmatched '{' 错误。

支持两类场景：
 1. 每行 JSON（.jsonl），input 字段为代码或文本
 2. TSV 文本（.txt），第一列为代码或文本

用法示例：
---------
cd /path/to/project
uv run python scripts/ablations/fix_dataset_braces.py 文件1 文件2 ...
如：
uv run python scripts/ablations/fix_dataset_braces.py data/primevul_1percent_sample/dev_sample.jsonl data/primevul_1percent_sample/train_sample.jsonl

脚本会生成同目录下 `_fixed` 结尾的新数据集文件，可以直接用于主流程。

返回值
-----
- 每个输入文件，会打印处理统计（处理成功/跳过行），并生成对应 _fixed 文件。

"""
import json
import sys
import os

def fix_jsonl(input_file):
    output_file = input_file.replace(".jsonl", "_fixed.jsonl")
    fixed = 0; skipped = 0
    with open(input_file, encoding="utf-8") as fin, open(output_file, "w", encoding="utf-8") as fout:
        for idx, line in enumerate(fin, 1):
            line = line.strip()
            if not line:
                continue
            try:
                j = json.loads(line)
                if "input" in j and isinstance(j["input"], str):
                    j["input"] = j["input"].replace("{", "{{").replace("}", "}}")
                else:
                    print(f"[跳过] 第{idx}行缺少'input'字段：{line}")
                fout.write(json.dumps(j, ensure_ascii=False) + "\n")
                fixed += 1
            except Exception:
                print(f"[无效格式] 第{idx}行：{line}")
                skipped += 1
    print(f"{input_file} 处理完成：有效{fixed}行，跳过{skipped}行，输出 {output_file}")

def fix_txt(input_file):
    output_file = input_file.replace(".txt", "_fixed.txt")
    fixed = 0; skipped = 0
    with open(input_file, encoding="utf-8") as fin, open(output_file, "w", encoding="utf-8") as fout:
        for idx, line in enumerate(fin, 1):
            line = line.strip()
            if not line:
                continue
            fields = line.split('\t')
            if len(fields) < 2:
                print(f"[无效格式] 第{idx}行：{line}")
                skipped += 1
                continue
            fields[0] = fields[0].replace("{", "{{").replace("}", "}}")
            fout.write('\t'.join(fields) + "\n")
            fixed += 1
    print(f"{input_file} 处理完成：有效{fixed}行，跳过{skipped}行，输出 {output_file}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python fix_dataset_braces.py 文件1 [文件2 文件3 ...]")
        sys.exit(1)
    for filename in sys.argv[1:]:
        if filename.endswith(".jsonl"):
            fix_jsonl(filename)
        elif filename.endswith(".txt"):
            fix_txt(filename)
        else:
            print(f"暂不支持文件类型: {filename}")
