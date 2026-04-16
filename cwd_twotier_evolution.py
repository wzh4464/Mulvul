#!/usr/bin/env python3
"""
两级 CWD 进化实验: Major → CWD (跳过 Middle 层)
stage_order = ("major", "cwe")
使用正确的 ranking_v2 JSON 格式和阈值 0.34
"""

import os
import sys
import json
import time
from pathlib import Path
from typing import Dict, List, Optional

sys.path.append('/Users/zihanwu/Public/codes/Mulvul/src')

from cwd_hierarchy import (
    get_major_categories, get_hierarchy_path, MAJOR_TO_MIDDLE, MIDDLE_TO_CWD
)
from mulvul.mainline.bundle import (
    PromptBundle, NodeSpec, TaxonomyGraph, TaxonomyNode,
    BundleDefaults,
)
from mulvul.mainline.system import MainlineDetectorSystem
from mulvul.llm.client import OpenAICompatibleClient


# ── Major → CWD 直接映射 ──────────────────────────────────────────────
def _build_major_to_cwds() -> Dict[str, List[str]]:
    result = {}
    for major, middles in MAJOR_TO_MIDDLE.items():
        cwds = []
        for m in middles:
            cwds.extend(MIDDLE_TO_CWD.get(m, []))
        result[major] = sorted(set(cwds))
    return result


MAJOR_TO_CWDS = _build_major_to_cwds()

# Major 类别描述
MAJOR_GUIDANCE = {
    "Memory":   "Allocation, bounds, pointer lifetime, pointer arithmetic, or memory ownership defects.",
    "Injection": "Untrusted data reaches an interpreter, parser, command channel, or executable context.",
    "Logic":    "Incorrect control flow, state handling, or business-security decisions.",
    "Input":    "Insufficient validation, sanitization, normalization, or parsing of attacker-controlled input.",
    "Crypto":   "Weak cryptographic design, random generation, or secret handling.",
    "Resource": "Leaked or mismanaged resources, handles, locks, or capacity usage.",
    "Other":    "Security-relevant weakness that does not fit the higher-level families above.",
}


# ── CWD 描述加载 ──────────────────────────────────────────────────────
def _load_cwd_info(dataset_file: str) -> Dict[str, Dict]:
    """从数据集提取每个 CWD 的名称和描述"""
    info = {}
    try:
        with open(dataset_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        for ex in data.get('examples', []):
            labels = ex.get('labels', {})
            cid = labels.get('cwd_id')
            if cid and cid not in info:
                info[cid] = {
                    'name': labels.get('cwd_name', cid),
                    'desc': labels.get('cwd_description', '')[:200],
                }
    except Exception:
        pass
    return info


# ── 数据加载 ──────────────────────────────────────────────────────────
class CWDDataLoader:
    def __init__(self, dataset_file: str):
        with open(dataset_file, 'r', encoding='utf-8') as f:
            self.data = json.load(f)

    def get_stratified_samples(self, per_class: int = 5) -> List[Dict]:
        """每个 CWD 类别取最多 per_class 个样本，确保评估集多样性"""
        from collections import defaultdict

        # 按 CWD 分桶
        buckets: dict = defaultdict(list)
        for ex in self.data.get('examples', []):
            vuln_code = ex.get('code', {}).get('vulnerable', '').strip()
            ctx = ex.get('code', {}).get('context', '').strip()
            full_code = (ctx + '\n' + vuln_code).strip() if ctx else vuln_code
            cwd_id = ex.get('labels', {}).get('cwd_id')
            if not cwd_id or not full_code:
                continue
            major, _, _ = get_hierarchy_path(cwd_id)
            if not major:
                continue
            buckets[cwd_id].append({
                'idx': ex.get('id', ''),
                'func': full_code,
                'target': 'Vulnerable',
                'major': major,
                'cwe': cwd_id,
            })

        # 每类取最多 per_class 个
        samples = []
        for cwd_id, items in sorted(buckets.items()):
            samples.extend(items[:per_class])

        vuln_count = len(samples)

        # 按比例加 benign 样本（约 25%）
        benign_added = 0
        benign_target = max(1, vuln_count // 4)
        for ex in self.data.get('examples', []):
            if benign_added >= benign_target:
                break
            benign_code = ex.get('code', {}).get('benign', '').strip()
            ctx = ex.get('code', {}).get('context', '').strip()
            full_code = (ctx + '\n' + benign_code).strip() if ctx else benign_code
            if full_code:
                samples.append({
                    'idx': f"{ex.get('id','')}_benign",
                    'func': full_code,
                    'target': 'Benign',
                    'major': 'Benign',
                    'cwe': None,
                })
                benign_added += 1

        cwd_classes = len(buckets)
        print(f"📊 分层采样: {vuln_count} vulnerable ({cwd_classes} 类, 最多 {per_class}/类) + {benign_added} benign = {len(samples)} 总计")
        return samples


# ── Bundle 工厂（两级架构）───────────────────────────────────────────
class TwoTierBundleFactory:

    @staticmethod
    def create(cwd_info: Dict[str, Dict]) -> PromptBundle:
        nodes: Dict[str, NodeSpec] = {}
        tax_nodes: Dict[str, TaxonomyNode] = {}

        major_categories = get_major_categories()

        # ── 生成 Major 候选引导文字 ──────────────────────────────────
        major_guidance_lines = "\n".join(
            f"- {m}: {MAJOR_GUIDANCE.get(m, 'Security weakness in this category.')}"
            for m in major_categories
        )
        major_guidance_lines += "\n- Benign: No actionable security weakness is present."

        # ── Major 节点模板（ranking_v2 格式）────────────────────────
        MAJOR_TEMPLATE = (
            "STAGE: major\n"
            "TARGET_LABEL: {target_label}\n"
            "ALLOWED_LABELS: {candidates}\n\n"
            "Task:\n"
            "Decide the best high-level vulnerability family for the code. "
            "Focus on actionable security behavior.\n\n"
            "Candidate guidance:\n"
            + major_guidance_lines + "\n\n"
            "CODE_BEGIN\n{code}\nCODE_END\n\n"
            "Return JSON only. Do not add Markdown fences.\n"
            'Use this exact schema:\n'
            '{\n'
            '  "predictions": [\n'
            '    {"category": "<label>", "confidence": 0.82},\n'
            '    {"category": "<label>", "confidence": 0.14}\n'
            '  ]\n'
            '}\n\n'
            "Rules:\n"
            "- Use only labels from ALLOWED_LABELS.\n"
            "- Rank labels from most likely to least likely.\n"
            "- Confidence must be a float in [0.0, 1.0].\n"
            "- If the code is safe, rank \"Benign\" first.\n"
            "- Prefer a concrete vulnerability label over \"Benign\" when a "
            "clear vulnerability pattern is present."
        )

        for major in major_categories:
            nid = f"major_{major.lower()}"
            nodes[nid] = NodeSpec(
                node_id=nid,
                stage="major",
                target_label=major,
                instruction_template=MAJOR_TEMPLATE,
                metadata={"category": "major"},
            )
            tax_nodes[nid] = TaxonomyNode(
                node_id=nid, stage="major", label=major,
                display_name=major, parent_id=None,
            )

        # Benign 节点（复用同一 major 模板）
        nodes["major_benign"] = NodeSpec(
            node_id="major_benign", stage="major", target_label="Benign",
            instruction_template=MAJOR_TEMPLATE,
            metadata={"category": "major"},
        )
        tax_nodes["major_benign"] = TaxonomyNode(
            node_id="major_benign", stage="major", label="Benign",
            display_name="Benign", parent_id=None,
        )

        # ── CWD 节点（直接挂在 Major 下）────────────────────────────
        for major, cwd_ids in MAJOR_TO_CWDS.items():
            parent_nid = f"major_{major.lower()}"

            # 为这组 CWD 生成候选引导文字
            cwd_guidance_lines = "\n".join(
                "- {cwd}: {name} | {desc}".format(
                    cwd=cid,
                    name=cwd_info.get(cid, {}).get('name', cid),
                    desc=cwd_info.get(cid, {}).get('desc', '')[:150],
                )
                for cid in cwd_ids
            )
            cwd_guidance_lines += "\n- Benign: The snippet does not match any of the above."

            CWE_TEMPLATE = (
                "STAGE: cwe\n"
                "TARGET_LABEL: {target_label}\n"
                "PARENT_MAJOR: {parent_label}\n"
                "ALLOWED_LABELS: {candidates}\n\n"
                "Task:\n"
                "Choose the most likely specific CWD identifier for the vulnerability. "
                "Distinguish similar labels carefully.\n\n"
                "Candidate guidance:\n"
                + cwd_guidance_lines + "\n\n"
                "CODE_BEGIN\n{code}\nCODE_END\n\n"
                "Return JSON only. Do not add Markdown fences.\n"
                'Use this exact schema:\n'
                '{\n'
                '  "predictions": [\n'
                '    {"category": "<CWD-ID>", "confidence": 0.75},\n'
                '    {"category": "<CWD-ID>", "confidence": 0.20}\n'
                '  ]\n'
                '}\n\n'
                "Rules:\n"
                "- Use only labels from ALLOWED_LABELS.\n"
                "- Rank from most to least likely.\n"
                "- Confidence in [0.0, 1.0].\n"
                "- If no specific CWD fits, rank \"Benign\" first."
            )

            for cwd_id in cwd_ids:
                nid = f"cwe_{cwd_id.lower().replace('-', '_')}"
                nodes[nid] = NodeSpec(
                    node_id=nid,
                    stage="cwe",
                    target_label=cwd_id,
                    instruction_template=CWE_TEMPLATE,
                    metadata={"category": "cwd", "major": major},
                )
                tax_nodes[nid] = TaxonomyNode(
                    node_id=nid, stage="cwe", label=cwd_id,
                    display_name=cwd_id, parent_id=parent_nid,
                )

        taxonomy = TaxonomyGraph(
            version="cwd-twotier-2.0",
            stage_order=("major", "cwe"),
            nodes=tax_nodes,
            benign_label="Benign",
        )

        bundle = PromptBundle(
            schema_version="2",
            taxonomy=taxonomy,
            nodes=nodes,
            defaults=BundleDefaults(
                default_threshold=0.34,   # 与真实 CWE bundle 一致
            ),
            training_metadata={
                "trainer_name": "CWDTwoTierTrainer",
                "version": "twotier-2.0",
                "architecture": "two_tier_cascade_major_cwd",
            },
            data_fingerprint=f"cwd-twotier-{int(time.time())}",
            code_revision="cwd-twotier-v2",
        )

        _validate(bundle, major_categories)
        return bundle


def _validate(bundle: PromptBundle, major_categories: List[str]):
    print("🔍 验证两级层次结构...")
    for major in major_categories:
        nid = f"major_{major.lower()}"
        children = bundle.taxonomy.children_of(nid)
        expected = len(MAJOR_TO_CWDS.get(major, []))
        if expected > 0 and len(children) == 0:
            raise ValueError(f"Major '{major}' 有 {expected} 个 CWD 但层次结构断开！")
        print(f"   {major}: {len(children)} 个 CWD 子节点")
    print("✅ 验证通过")


# ── 主实验 ────────────────────────────────────────────────────────────
def run_experiment(
    generations: int = 5,
    per_class: int = 5,
    output_dir: str = "./cwd_twotier_results",
):
    out = Path(output_dir)
    out.mkdir(exist_ok=True)

    print("🧬 CWD 两级进化实验 (Major → CWD)")
    print("=" * 60)

    cwd_info = _load_cwd_info('cwd_native_dataset.json')
    print(f"📖 加载了 {len(cwd_info)} 个 CWD 描述")

    loader = CWDDataLoader('cwd_native_dataset.json')
    # 分层采样：每个 CWD 类别最多 per_class 个样本
    samples = loader.get_stratified_samples(per_class=per_class)

    bundle = TwoTierBundleFactory.create(cwd_info)
    print(f"📦 Bundle: {len(bundle.nodes)} 节点, stage_order={bundle.taxonomy.stage_order}, threshold={bundle.defaults.default_threshold}")

    api_key = os.getenv('OPENROUTER_API_KEY')
    if not api_key:
        raise ValueError("需要 OPENROUTER_API_KEY")

    llm_client = OpenAICompatibleClient(
        model_name="gpt-5.4",
        api_base="https://openrouter.ai/api/v1",
        api_key=api_key,
    )

    detector = MainlineDetectorSystem(llm_client=llm_client, artifact=bundle)

    # 评估集 = 全部分层样本（覆盖所有 CWD 类别）
    eval_samples = samples
    evolution_results = []
    t0 = time.time()

    for gen in range(1, generations + 1):
        print(f"\n🧬 第 {gen} 代")
        print("-" * 40)
        gen_t0 = time.time()

        correct_major = 0
        correct_cwe = 0
        total = 0
        errors = []

        for i, sample in enumerate(eval_samples):
            try:
                result = detector.detect(code=sample['func'])
                pred_major = result.major
                pred_cwe = result.cwe

                actual_major = sample['major']
                actual_cwe = sample.get('cwe')

                major_ok = (pred_major == actual_major)
                cwe_ok = (actual_cwe is not None and pred_cwe == actual_cwe)

                if major_ok:
                    correct_major += 1
                if cwe_ok:
                    correct_cwe += 1
                total += 1

                status = f"major={'✓' if major_ok else '✗'} cwe={'✓' if cwe_ok else '✗'}"
                print(f"   [{i+1}/{len(eval_samples)}] {status}  pred={pred_major}/{pred_cwe}  actual={actual_major}/{actual_cwe}")

            except Exception as e:
                errors.append(str(e))
                print(f"   [{i+1}] 错误: {e}")

        if total == 0:
            raise ValueError(f"第 {gen} 代：0 个样本被评估，实验中止。")

        major_acc = correct_major / total
        cwe_acc = correct_cwe / total
        gen_time = time.time() - gen_t0

        print(f"✅ 第 {gen} 代: major_acc={major_acc:.3f}  cwe_acc={cwe_acc:.3f}  ({total} 样本, {gen_time:.1f}s)")

        gen_result = {
            "generation": gen,
            "major_accuracy": major_acc,
            "cwe_accuracy": cwe_acc,
            "correct_major": correct_major,
            "correct_cwe": correct_cwe,
            "total_samples": total,
            "time": gen_time,
            "errors": errors[:3],
        }
        evolution_results.append(gen_result)

        with open(out / f"gen{gen:02d}_bundle.json", 'w', encoding='utf-8') as f:
            json.dump(bundle.to_dict(), f, indent=2, ensure_ascii=False)

        time.sleep(1)

    total_time = time.time() - t0
    final = evolution_results[-1]

    summary = {
        "experiment": "CWD Two-Tier Cascade (Major → CWD)",
        "architecture": "two_tier",
        "stage_order": ["major", "cwe"],
        "threshold": bundle.defaults.default_threshold,
        "generations": generations,
        "eval_samples_per_gen": len(eval_samples),
        "evolution_results": evolution_results,
        "final_major_accuracy": final["major_accuracy"],
        "final_cwe_accuracy": final["cwe_accuracy"],
        "total_time": total_time,
        "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
        "comparison": {
            "flat_cwd_baseline": 0.447,
            "mulvul_cwe_baseline": 0.227,
            "our_major_acc": final["major_accuracy"],
            "our_cwe_acc": final["cwe_accuracy"],
        },
    }

    results_file = out / "cwd_twotier_results.json"
    with open(results_file, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    print(f"\n{'='*60}")
    print(f"🎉 实验完成  总时间: {total_time:.1f}s")
    print(f"   Major 准确率: {final['major_accuracy']:.1%}")
    print(f"   CWD 准确率:   {final['cwe_accuracy']:.1%}")
    print(f"   对比基线: 扁平CWD={0.447:.1%}  Mulvul CWE={0.227:.1%}")
    print(f"   结果: {results_file}")

    return summary


if __name__ == "__main__":
    run_experiment(generations=5, per_class=5)
