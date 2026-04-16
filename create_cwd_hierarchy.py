#!/usr/bin/env python3
"""
基于 CWD 数据构建三级层次结构，模仿 Mulvul 架构
"""

import json
import sys
from typing import Dict, List, Set
from collections import defaultdict

# 添加 Mulvul 路径
sys.path.append('/Users/zihanwu/Public/codes/Mulvul/src')

def analyze_cwd_categories():
    """分析 CWD 数据，构建合理的层次结构"""

    # 加载 CWD 数据
    try:
        with open('cwd_native_dataset.json', 'r', encoding='utf-8') as f:
            data = json.load(f)
    except:
        print("❌ 无法加载 CWD 数据")
        return None

    examples = data.get('examples', [])
    definitions = data.get('cwd_definitions', {})

    print(f"📊 分析 {len(examples)} 个样本和 {len(definitions)} 个 CWD 定义")

    # 统计 CWD 分布
    cwd_counts = defaultdict(int)
    for example in examples:
        cwd_id = example.get('labels', {}).get('cwd_id')
        if cwd_id:
            cwd_counts[cwd_id] += 1

    print(f"📋 发现 {len(cwd_counts)} 个不同的 CWD")

    # 根据 CWD 特征进行分类
    major_categories = {
        'Memory': {
            'description': '内存相关漏洞',
            'keywords': ['内存', '分配', '释放', '泄漏', '越界', '指针', '缓冲区'],
            'cwds': []
        },
        'Injection': {
            'description': '注入类漏洞',
            'keywords': ['注入', '执行', 'SQL', '命令', '表达式'],
            'cwds': []
        },
        'Logic': {
            'description': '逻辑错误漏洞',
            'keywords': ['逻辑', '控制', '条件', '状态', '检查'],
            'cwds': []
        },
        'Input': {
            'description': '输入验证漏洞',
            'keywords': ['输入', '验证', '校验', '过滤', '边界'],
            'cwds': []
        },
        'Crypto': {
            'description': '密码学漏洞',
            'keywords': ['加密', '密码', '算法', '密钥', '随机'],
            'cwds': []
        },
        'Resource': {
            'description': '资源管理漏洞',
            'keywords': ['资源', '文件', '句柄', '连接', '锁'],
            'cwds': []
        },
        'Other': {
            'description': '其他类型漏洞',
            'keywords': [],
            'cwds': []
        }
    }

    # 为每个 CWD 分配主要类别
    for cwd_id, count in cwd_counts.items():
        definition = definitions.get(cwd_id, {})
        name = definition.get('name', '')
        description = definition.get('description', '')

        # 基于名称和描述进行分类
        text = (name + ' ' + description).lower()

        assigned = False
        for major, info in major_categories.items():
            if major == 'Other':
                continue
            for keyword in info['keywords']:
                if keyword.lower() in text:
                    info['cwds'].append({
                        'cwd_id': cwd_id,
                        'name': name,
                        'count': count,
                        'description': description
                    })
                    assigned = True
                    break
            if assigned:
                break

        # 如果没有匹配到，放入 Other 类别
        if not assigned:
            major_categories['Other']['cwds'].append({
                'cwd_id': cwd_id,
                'name': name,
                'count': count,
                'description': description
            })

    # 打印分类结果
    print("\n🗂️ CWD 主要类别分布:")
    total_samples = sum(cwd_counts.values())

    for major, info in major_categories.items():
        cwds = info['cwds']
        if not cwds:
            continue

        category_samples = sum(c['count'] for c in cwds)
        percentage = (category_samples / total_samples) * 100

        print(f"\n**{major}** ({len(cwds)} 个 CWD, {category_samples} 个样本, {percentage:.1f}%)")
        print(f"   描述: {info['description']}")

        # 显示前几个 CWD
        sorted_cwds = sorted(cwds, key=lambda x: x['count'], reverse=True)
        for cwd in sorted_cwds[:5]:
            print(f"   - {cwd['cwd_id']}: {cwd['name']} ({cwd['count']} 样本)")

    return major_categories

def create_mulvul_hierarchy():
    """创建符合 Mulvul 格式的 CWD 层次结构"""

    categories = analyze_cwd_categories()
    if not categories:
        return

    # 构建 Mulvul 风格的层次映射
    hierarchy = {
        'MAJOR_TO_MIDDLE': {},
        'MIDDLE_TO_CWD': {},
        'metadata': {
            'total_majors': 0,
            'total_middles': 0,
            'total_cwds': 0,
            'architecture': 'three_tier_cascade',
            'description': 'CWD-based hierarchy for Mulvul architecture'
        }
    }

    middle_categories = {
        # Memory 类的中级分类
        'Memory Management': ['内存分配', '内存释放', '内存管理'],
        'Buffer Errors': ['缓冲区', '越界', '溢出'],
        'Pointer Issues': ['指针', '解引用', '空指针'],

        # Injection 类的中级分类
        'Code Injection': ['代码注入', '命令注入', '脚本注入'],
        'Data Injection': ['SQL注入', '数据注入', '参数注入'],

        # Logic 类的中级分类
        'Control Flow': ['控制流', '条件', '分支'],
        'State Management': ['状态', '初始化', '生命周期'],

        # Input 类的中级分类
        'Input Validation': ['输入验证', '参数检查', '边界检查'],
        'Data Processing': ['数据处理', '格式化', '解析'],

        # Crypto 类的中级分类
        'Cryptographic Errors': ['加密错误', '密钥管理', '算法错误'],
        'Random Generation': ['随机数', '种子', '熵'],

        # Resource 类的中级分类
        'Resource Leaks': ['资源泄漏', '文件泄漏', '句柄泄漏'],
        'Resource Access': ['资源访问', '权限', '并发'],

        # Other
        'Miscellaneous': ['其他', '杂项', '未分类']
    }

    # 为每个 Major 类别分配 Middle 类别
    major_to_middle = {
        'Memory': ['Memory Management', 'Buffer Errors', 'Pointer Issues'],
        'Injection': ['Code Injection', 'Data Injection'],
        'Logic': ['Control Flow', 'State Management'],
        'Input': ['Input Validation', 'Data Processing'],
        'Crypto': ['Cryptographic Errors', 'Random Generation'],
        'Resource': ['Resource Leaks', 'Resource Access'],
        'Other': ['Miscellaneous']
    }

    hierarchy['MAJOR_TO_MIDDLE'] = major_to_middle

    # 将 CWD 分配到 Middle 类别
    middle_to_cwd = defaultdict(list)

    for major, info in categories.items():
        middle_cats = major_to_middle.get(major, ['Miscellaneous'])

        for cwd_info in info['cwds']:
            cwd_id = cwd_info['cwd_id']
            name = cwd_info['name'].lower()

            # 基于名称特征分配到具体的 Middle 类别
            assigned = False

            for middle in middle_cats:
                middle_keywords = middle_categories.get(middle, [])
                for keyword in middle_keywords:
                    if keyword.lower() in name:
                        middle_to_cwd[middle].append(cwd_id)
                        assigned = True
                        break
                if assigned:
                    break

            # 如果没有匹配，分配到该 Major 的第一个 Middle 类别
            if not assigned:
                middle_to_cwd[middle_cats[0]].append(cwd_id)

    hierarchy['MIDDLE_TO_CWD'] = dict(middle_to_cwd)

    # 更新元数据
    hierarchy['metadata']['total_majors'] = len([k for k, v in major_to_middle.items() if v])
    hierarchy['metadata']['total_middles'] = len(middle_to_cwd)
    hierarchy['metadata']['total_cwds'] = sum(len(v) for v in middle_to_cwd.values())

    # 保存层次结构
    with open('cwd_hierarchy.json', 'w', encoding='utf-8') as f:
        json.dump(hierarchy, f, indent=2, ensure_ascii=False)

    print(f"\n✅ 创建 CWD 层次结构:")
    print(f"   📁 Major 类别: {hierarchy['metadata']['total_majors']} 个")
    print(f"   📂 Middle 类别: {hierarchy['metadata']['total_middles']} 个")
    print(f"   📄 CWD 分类: {hierarchy['metadata']['total_cwds']} 个")
    print(f"\n📁 保存到: cwd_hierarchy.json")

    return hierarchy

if __name__ == "__main__":
    print("🚀 开始构建 CWD 三级层次结构")
    print("=" * 60)

    hierarchy = create_mulvul_hierarchy()

    if hierarchy:
        print(f"\n🎯 层次结构概览:")
        for major, middles in hierarchy['MAJOR_TO_MIDDLE'].items():
            print(f"\n{major} → {middles}")
            for middle in middles:
                cwds = hierarchy['MIDDLE_TO_CWD'].get(middle, [])
                if cwds:
                    print(f"  {middle} → {len(cwds)} 个 CWD")

        print(f"\n✅ CWD 层次结构创建完成，准备集成到 Mulvul 架构！")
    else:
        print(f"\n❌ 层次结构创建失败")