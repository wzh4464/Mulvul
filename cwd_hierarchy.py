#!/usr/bin/env python3
"""
CWD 层次结构模块，模仿 Mulvul 的 cwe_hierarchy.py
为协同进化实验提供 CWD 三级级联架构
"""

import json
from typing import Dict, List, Set
from pathlib import Path

def load_cwd_hierarchy():
    """加载 CWD 层次结构"""
    hierarchy_file = Path(__file__).parent / 'cwd_hierarchy.json'

    try:
        with open(hierarchy_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError(f"CWD hierarchy file not found: {hierarchy_file}")

# 加载层次结构
_hierarchy = load_cwd_hierarchy()

# 主要到中级的映射
MAJOR_TO_MIDDLE = _hierarchy['MAJOR_TO_MIDDLE']

# 中级到 CWD 的映射
MIDDLE_TO_CWD = _hierarchy['MIDDLE_TO_CWD']

# 反向映射（从下往上）
CWD_TO_MIDDLE = {}
for middle, cwds in MIDDLE_TO_CWD.items():
    for cwd in cwds:
        CWD_TO_MIDDLE[cwd] = middle

MIDDLE_TO_MAJOR = {}
for major, middles in MAJOR_TO_MIDDLE.items():
    for middle in middles:
        MIDDLE_TO_MAJOR[middle] = major

def get_major_categories() -> List[str]:
    """获取所有主要类别"""
    return list(MAJOR_TO_MIDDLE.keys())

def get_middle_categories() -> List[str]:
    """获取所有中级类别"""
    return list(MIDDLE_TO_CWD.keys())

def get_cwd_ids() -> List[str]:
    """获取所有 CWD ID"""
    cwds = []
    for cwd_list in MIDDLE_TO_CWD.values():
        cwds.extend(cwd_list)
    return sorted(set(cwds))

def get_middle_for_major(major: str) -> List[str]:
    """获取指定主要类别的中级类别"""
    return MAJOR_TO_MIDDLE.get(major, [])

def get_cwds_for_middle(middle: str) -> List[str]:
    """获取指定中级类别的 CWD"""
    return MIDDLE_TO_CWD.get(middle, [])

def get_hierarchy_path(cwd_id: str) -> tuple:
    """获取 CWD 的完整层次路径"""
    middle = CWD_TO_MIDDLE.get(cwd_id)
    if not middle:
        return None, None, cwd_id

    major = MIDDLE_TO_MAJOR.get(middle)
    return major, middle, cwd_id

def is_valid_cwd(cwd_id: str) -> bool:
    """检查 CWD ID 是否有效"""
    return cwd_id in CWD_TO_MIDDLE

def get_hierarchy_stats():
    """获取层次结构统计信息"""
    return {
        'major_count': len(MAJOR_TO_MIDDLE),
        'middle_count': len(MIDDLE_TO_CWD),
        'cwd_count': len(get_cwd_ids()),
        'total_classes': len(MAJOR_TO_MIDDLE) + len(MIDDLE_TO_CWD) + len(get_cwd_ids())
    }

# 打印层次结构信息
if __name__ == "__main__":
    print("🏗️ CWD 层次结构信息")
    print("=" * 50)

    stats = get_hierarchy_stats()
    print(f"📊 统计信息:")
    print(f"   Major 类别: {stats['major_count']}")
    print(f"   Middle 类别: {stats['middle_count']}")
    print(f"   CWD 分类: {stats['cwd_count']}")
    print(f"   总类别数: {stats['total_classes']}")

    print(f"\n🗂️ 层次结构:")
    for major in get_major_categories():
        middles = get_middle_for_major(major)
        print(f"\n{major} ({len(middles)} 个 Middle)")

        for middle in middles:
            cwds = get_cwds_for_middle(middle)
            if cwds:
                print(f"  └─ {middle} ({len(cwds)} 个 CWD)")
                # 显示前几个 CWD
                for cwd in cwds[:3]:
                    print(f"      • {cwd}")
                if len(cwds) > 3:
                    print(f"      • ... (+{len(cwds)-3} 个)")

    print(f"\n✅ CWD 层次结构模块加载成功！")