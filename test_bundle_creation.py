#!/usr/bin/env python3
"""
简单测试 PromptBundle 创建过程
"""

import os
import sys

# 添加 Mulvul 路径
sys.path.append('/Users/zihanwu/Public/codes/Mulvul/src')

# CWD 层次结构
from cwd_hierarchy import (
    get_major_categories, get_middle_categories, get_cwd_ids,
    get_middle_for_major, get_cwds_for_middle, get_hierarchy_path
)

from mulvul.mainline.bundle import PromptBundle, NodeSpec, TaxonomyGraph, TaxonomyNode, BundleDefaults

def test_bundle_creation():
    """测试 CWD PromptBundle 创建"""

    print("🧪 开始测试 CWD PromptBundle 创建...")

    try:
        # 1. 创建节点
        print("1️⃣ 创建 NodeSpec 节点...")

        all_nodes = {}

        # 主要类别节点
        for major in get_major_categories():
            node = NodeSpec(
                node_id=f"major_{major.lower()}",
                stage="major",
                target_label=major,
                instruction_template=f"分析代码，判断是否存在{major}类型的安全问题。",
                metadata={"category": "major", "target_classes": [major]}
            )
            all_nodes[node.node_id] = node
            print(f"   ✅ 创建主要类别节点: {node.node_id}")

        # Benign 节点
        benign_node = NodeSpec(
            node_id="major_benign",
            stage="major",
            target_label="Benign",
            instruction_template="分析代码，判断是否为安全的代码。",
            metadata={"category": "major", "target_classes": ["Benign"]}
        )
        all_nodes["major_benign"] = benign_node
        print(f"   ✅ 创建 Benign 节点: major_benign")

        # 中级类别节点
        for middle in get_middle_categories()[:3]:  # 限制为前 3 个
            node = NodeSpec(
                node_id=f"middle_{middle.lower().replace(' ', '_')}",
                stage="middle",
                target_label=middle,
                instruction_template=f"分析代码，判断是否存在{middle}类型的具体安全问题。",
                metadata={"category": "middle", "target_classes": [middle]}
            )
            all_nodes[node.node_id] = node
            print(f"   ✅ 创建中级类别节点: {node.node_id}")

        # CWD 级别节点 (限制数量)
        for cwd_id in get_cwd_ids()[:5]:  # 限制为前 5 个
            node = NodeSpec(
                node_id=f"cwd_{cwd_id.lower().replace('-', '_')}",
                stage="cwe",  # 复用 cwe stage
                target_label=cwd_id,
                instruction_template=f"分析代码，判断是否存在{cwd_id}类型的具体安全缺陷。",
                metadata={"category": "cwd", "target_classes": [cwd_id]}
            )
            all_nodes[node.node_id] = node
            print(f"   ✅ 创建 CWD 节点: {node.node_id}")

        print(f"   📊 总计创建 {len(all_nodes)} 个节点")

        # 2. 创建分类图
        print("2️⃣ 创建 TaxonomyGraph...")

        taxonomy_nodes = {}

        # 添加主要类别节点到分类图
        for major in get_major_categories():
            node_id = f"major_{major.lower()}"
            taxonomy_nodes[node_id] = TaxonomyNode(
                node_id=node_id,
                stage="major",
                label=major,
                display_name=major,
                parent_id=None
            )

        # 添加 Benign 节点到分类图
        taxonomy_nodes["major_benign"] = TaxonomyNode(
            node_id="major_benign",
            stage="major",
            label="Benign",
            display_name="Benign",
            parent_id=None
        )

        # 添加中级类别节点到分类图
        for middle in get_middle_categories()[:3]:
            node_id = f"middle_{middle.lower().replace(' ', '_')}"
            taxonomy_nodes[node_id] = TaxonomyNode(
                node_id=node_id,
                stage="middle",
                label=middle,
                display_name=middle,
                parent_id=None
            )

        # 添加 CWD 节点到分类图
        for cwd_id in get_cwd_ids()[:5]:
            node_id = f"cwd_{cwd_id.lower().replace('-', '_')}"
            taxonomy_nodes[node_id] = TaxonomyNode(
                node_id=node_id,
                stage="cwe",
                label=cwd_id,
                display_name=cwd_id,
                parent_id=None
            )

        taxonomy = TaxonomyGraph(
            version="cwd-test-1.0",
            stage_order=("major", "middle", "cwe"),
            nodes=taxonomy_nodes,
            benign_label="Benign"
        )

        print(f"   ✅ 创建分类图，包含 {len(taxonomy_nodes)} 个分类节点")

        # 3. 创建 PromptBundle
        print("3️⃣ 创建 PromptBundle...")

        bundle = PromptBundle(
            schema_version="2",
            taxonomy=taxonomy,
            nodes=all_nodes,
            defaults=BundleDefaults(),
            training_metadata={
                "trainer_name": "CWDTestTrainer",
                "version": "test-1.0",
                "architecture": "three_tier_cascade",
                "hierarchy": "cwd_based",
                "total_nodes": len(all_nodes),
                "created_at": "2026-04-13"
            },
            data_fingerprint="cwd-test-2026-04-13",
            code_revision="cwd-test-v1"
        )

        print(f"   ✅ 创建 PromptBundle 成功!")

        # 4. 验证 Bundle
        print("4️⃣ 验证 PromptBundle...")
        errors = bundle.validate(allow_partial=True)
        if errors:
            print(f"   ⚠️ 验证错误:")
            for error in errors:
                print(f"      - {error}")
        else:
            print(f"   ✅ PromptBundle 验证成功!")

        # 5. 保存 Bundle
        print("5️⃣ 保存 PromptBundle...")
        bundle_file = './test_cwd_bundle.json'
        with open(bundle_file, 'w', encoding='utf-8') as f:
            import json
            json.dump(bundle.to_dict(), f, indent=2, ensure_ascii=False)
        print(f"   ✅ 保存到: {bundle_file}")

        print("\n🎉 CWD PromptBundle 创建测试成功!")
        print(f"📊 统计信息:")
        print(f"   - NodeSpec 节点: {len(all_nodes)}")
        print(f"   - 分类节点: {len(taxonomy_nodes)}")
        print(f"   - Major 类别: {len([n for n in all_nodes.values() if n.stage == 'major'])}")
        print(f"   - Middle 类别: {len([n for n in all_nodes.values() if n.stage == 'middle'])}")
        print(f"   - CWD 类别: {len([n for n in all_nodes.values() if n.stage == 'cwe'])}")

        return bundle

    except Exception as e:
        print(f"❌ PromptBundle 创建失败: {e}")
        import traceback
        traceback.print_exc()
        return None

if __name__ == "__main__":
    test_bundle_creation()