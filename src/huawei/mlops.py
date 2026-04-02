###
# File: ./EvoPrompt/mlops.py
# Created Date: Monday, September 29th 2025
# Author: Zihan
# -----
# Last Modified: Monday, 29th September 2025 9:04:44 pm
# Modified By: the developer formerly known as Zihan at <wzh4464@gmail.com>
# -----
# HISTORY:
# Date      		By   	Comments
# ----------		------	---------------------------------------------------------
###

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import List, Dict, Any

from evoprompt.utils.text import safe_format

DEFAULT_TEMPLATE = """你是一个静态分析分类助手。
任务：基于给定的代码片段，从下列 Category 列表中选出所有适用的类别；若无匹配，返回 ["None"]。

Category 列表（只能从中逐字选择；不要发明新类名）：
{category_bullets}

输出要求（务必严格遵守）：
1) 仅输出 JSON，键名固定为 "categories"，值为字符串数组；
2) 不要输出解释、额外文本、前后缀或代码块标记；
3) 若无匹配，输出：{{"categories":["None"]}}。

示例：
输入代码: int x = 0; // 无风险
期望输出: {{"categories":["None"]}}

以下是待判定的代码片段（语言：{lang}）：
```{lang}
{code}

"""

def read_categories(csv_path: Path) -> List[str]:
    cats = []
    with csv_path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.reader(f)
        for row_idx, row in enumerate(reader):
            if not row:
                continue
            first = (row[0] or "").strip()
            if not first:
                continue
            # 跳过表头
            if row_idx == 0 and first.lower() in {"category", "categories"}:
                continue
            cats.append(first)
    # 去重但保持顺序
    seen = set()
    uniq = []
    for c in cats:
        if c not in seen:
            seen.add(c)
            uniq.append(c)
    return uniq

def load_A(input_json: Path) -> List[Dict[str, Any]]:
    with input_json.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError("输入 JSON 顶层应为数组。")
    return data

def build_prompt(template: str, categories: List[str], code: str, lang: str) -> str:
    # 规范化换行，避免 \r\n 带来的显示问题
    code_norm = code.replace("\r\n", "\n").replace("\r", "\n")
    category_bullets = "\n".join(f"- {c}" for c in categories)
    prompt = safe_format(
        template,
        category_bullets=category_bullets,
        code=code_norm,
        lang=(lang or "cpp"),
    )
    return prompt

def main():
    ap = argparse.ArgumentParser(description="Convert A.json to jsonl with classification prompts.")
    ap.add_argument("--input", "-i", type=Path, required=True, help="输入的 A.json（数组，每个对象包含 code/lang 等）")
    ap.add_argument("--categories", "-c", type=Path, required=True, help="分类列表 CSV（第一列为类名）")
    ap.add_argument("--output", "-o, --out", dest="output", type=Path, required=True, help="输出 jsonl 文件路径")
    ap.add_argument("--template", "-t", type=Path, help="可选：自定义 prompt 模板文件（使用 {category_bullets}、{code}、{lang} 占位）")
    ap.add_argument("--max_tokens", type=int, default=12000, help="写入每行的 max_tokens 值（默认 12000）")
    args = ap.parse_args()

    try:
        categories = read_categories(args.categories)
        if not categories:
            raise ValueError("CSV 中未读取到任何 category。请确认第一列包含类名。")
        items = load_A(args.input)

        if args.template:
            template_text = args.template.read_text(encoding="utf-8")
        else:
            template_text = DEFAULT_TEMPLATE

        # 写 jsonl
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("w", encoding="utf-8") as out:
            for obj in items:
                code = obj.get("code", "")
                lang = obj.get("lang", "cpp") or "cpp"
                prompt = build_prompt(template_text, categories, code, lang)

                line = {
                    "messages": [
                        {"role": "user", "content": prompt}
                    ],
                    "max_tokens": args.max_tokens
                }
                out.write(json.dumps(line, ensure_ascii=False))
                out.write("\n")

        print(f"✅ 转换完成，共写入 {len(items)} 行 -> {args.output}")
    except Exception as e:
        print(f"❌ 出错：{e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
