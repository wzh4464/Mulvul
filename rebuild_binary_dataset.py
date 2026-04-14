#!/usr/bin/env python3
"""
重建 binary_eval_dataset.json
修复：将 vulnerable_code.func 正确拼入 context，确保漏洞代码可见
"""
import json
import random
from pathlib import Path
from collections import defaultdict

SEED = 42
PER_CLASS = 2          # 每个 CWD 类最多取几个 vulnerable 样本
RAW_DATA = "/Users/zihanwu/Public/codes/Mulvul/data/enter/cwd_benchmark_2.json"
OUT_FILE = "binary_eval_dataset.json"
OLD_FILE = "binary_eval_dataset_old.json"


def combine_code(context: str, func: str, language: str) -> str:
    """把 func 正确插入 context，得到完整代码片段"""
    ctx = (context or "").strip()
    fn  = (func   or "").strip()

    if not ctx and not fn:
        return ""
    if not ctx:
        return fn
    if not fn:
        return ctx

    if language == "java":
        # Java: context 是类壳（末尾是 `}`），把 func 插入最后一个 `}` 之前
        last = ctx.rfind("}")
        if last == -1:
            return ctx + "\n\n" + fn
        indent = "    "
        return ctx[:last] + indent + fn + "\n}"
    else:
        # C/C++: context 是文件头，func 是 TGT 函数，直接拼接
        return ctx + "\n\n" + fn


def extract_code(code_obj: dict, language: str) -> str:
    """从 code_obj (vulnerable_code / benign_code) 提取最佳代码文本"""
    if not code_obj:
        return ""
    ctx  = code_obj.get("context") or ""
    func = code_obj.get("func")    or ""
    cls  = code_obj.get("class")   or ""

    # 有 func → 优先组合 context + func
    if func:
        return combine_code(ctx or cls, func, language)
    # 只有 context / class
    return ctx or cls


def main():
    random.seed(SEED)

    # ── 备份旧数据集 ───────────────────────────────────────────────
    old_path = Path(OLD_FILE)
    new_path = Path(OUT_FILE)
    if new_path.exists() and not old_path.exists():
        import shutil
        shutil.copy(new_path, old_path)
        print(f"已备份旧数据集 → {OLD_FILE}")

    # ── 加载原始数据 ──────────────────────────────────────────────
    with open(RAW_DATA) as f:
        raw = json.load(f)

    vuln_samples  = []   # {"label","cwd","code","lang"}
    benign_samples = []

    for lang, cwd_dict in raw.items():
        for cwd_id, entries in cwd_dict.items():
            vuln_for_cwd  = []
            benign_for_cwd = []

            for entry in entries:
                # ── 漏洞样本 ───────────────────────────────────────
                vc = entry.get("vulnerable_code") or {}
                v_code = extract_code(vc, lang)
                if v_code.strip():
                    vuln_for_cwd.append({
                        "label": "Vulnerable",
                        "cwd":   cwd_id,
                        "lang":  lang,
                        "code":  v_code,
                    })

                # ── 良性样本 ───────────────────────────────────────
                bc = entry.get("benign_code") or {}
                b_code = extract_code(bc, lang)
                if b_code.strip():
                    benign_for_cwd.append({
                        "label": "Benign",
                        "cwd":   None,
                        "lang":  lang,
                        "code":  b_code,
                    })

            # 每个 CWD 最多取 PER_CLASS 个，随机洗牌后取前 N
            random.shuffle(vuln_for_cwd)
            random.shuffle(benign_for_cwd)
            vuln_samples.extend(vuln_for_cwd[:PER_CLASS])
            benign_samples.extend(benign_for_cwd[:PER_CLASS])

    # ── 平衡数据集 ────────────────────────────────────────────────
    n = min(len(vuln_samples), len(benign_samples))
    random.shuffle(vuln_samples)
    random.shuffle(benign_samples)
    vuln_samples   = vuln_samples[:n]
    benign_samples = benign_samples[:n]

    dataset = vuln_samples + benign_samples
    random.shuffle(dataset)

    # 写出
    with open(OUT_FILE, "w", encoding="utf-8") as f:
        json.dump(dataset, f, ensure_ascii=False, indent=2)

    # ── 统计报告 ──────────────────────────────────────────────────
    vuln_count   = sum(1 for s in dataset if s["label"] == "Vulnerable")
    benign_count = sum(1 for s in dataset if s["label"] == "Benign")
    from collections import Counter
    lang_dist = Counter(s["lang"] for s in dataset if s["label"] == "Vulnerable")
    cwd_dist  = Counter(s["cwd"]  for s in dataset if s["label"] == "Vulnerable")
    code_lens = [len(s["code"]) for s in dataset]

    print(f"\n{'='*55}")
    print(f"重建完成  →  {OUT_FILE}")
    print(f"{'='*55}")
    print(f"总样本:    {len(dataset)}")
    print(f"  Vulnerable: {vuln_count}  Benign: {benign_count}")
    print(f"  语言分布:  {dict(lang_dist)}")
    print(f"  CWD 类数:  {len(cwd_dist)}")
    print(f"代码长度:  avg={sum(code_lens)/len(code_lens):.0f}  "
          f"min={min(code_lens)}  max={max(code_lens)}")

    # 检查原来有问题的 Java FN 样本
    print(f"\n── Java 样本详情 ──")
    for s in dataset:
        if s["lang"] == "java" and s["label"] == "Vulnerable":
            has_func = any(kw in s["code"] for kw in
                           ["runtime.exec", "exec(", "eval(", "compile(", "KieHelper",
                            "XPath", "xpath", "Document", "ScriptEngine"])
            print(f"  {s['cwd']:12s}  len={len(s['code']):5d}  func_visible={has_func}")


if __name__ == "__main__":
    main()
