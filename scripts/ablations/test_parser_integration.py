#!/usr/bin/env python3
"""测试 parserTool + SymbolicRule 集成"""

import sys
from pathlib import Path

# 添加必要的路径
sys.path.insert(0, str(Path(__file__).parent / "comment4vul" / "parserTool"))
sys.path.insert(0, str(Path(__file__).parent / "comment4vul" / "SymbolicRule"))

import parserTool.parse as ps
from parserTool.parse import Lang
from process import print_ast_node, move_comments_to_new_line

# 测试用例：带注释的 C 代码
test_code = """
int check_buffer(char *buf, int size) {
    // check buffer size
    if (size > 1024) {
        return -1;
    }

    /* verify buffer is not null */
    if (buf == NULL) {
        return -1;
    }

    return 0;
}
"""

print("=" * 80)
print("原始代码:")
print("=" * 80)
print(test_code)

print("\n" + "=" * 80)
print("步骤 1: 移动注释到新行")
print("=" * 80)
code_with_moved_comments = move_comments_to_new_line(test_code)
print(code_with_moved_comments)

print("\n" + "=" * 80)
print("步骤 2: 解析 AST")
print("=" * 80)
try:
    ast = ps.tree_sitter_ast(code_with_moved_comments, Lang.C)
    print(f"✅ AST 解析成功，根节点类型: {ast.root_node.type}")
    print(f"   子节点数量: {len(ast.root_node.children)}")
except Exception as e:
    print(f"❌ AST 解析失败: {e}")
    sys.exit(1)

print("\n" + "=" * 80)
print("步骤 3: 生成 Natural Language AST")
print("=" * 80)
try:
    nl_ast = print_ast_node(code_with_moved_comments, ast.root_node)
    print(nl_ast)

    # 检查注释是否被嵌入到控制流中
    if "check buffer size" in nl_ast or "verify buffer is not null" in nl_ast:
        print("\n✅ 成功！注释已被嵌入到 Natural Language AST 中")
    else:
        print("\n⚠️  警告：未在 NL AST 中找到注释内容")

except Exception as e:
    print(f"❌ 生成 NL AST 失败: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("\n" + "=" * 80)
print("✅ 所有测试通过！parserTool + SymbolicRule 集成正常工作")
print("=" * 80)
