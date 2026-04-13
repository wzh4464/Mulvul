#!/usr/bin/env python3
"""
清理文件中的敏感公司信息
"""

import os
import re
import glob

def clean_file(file_path):
    """清理单个文件中的敏感信息"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        original_content = content

        # 替换公司名称
        content = re.sub(r'企业', '企业', content)
        content = re.sub(r'Enterprise|Enterprise', 'Enterprise', content)

        # 替换特定的企业相关描述
        content = re.sub(r'企业 CWD', '企业 CWD', content)
        content = re.sub(r'企业 CWD', '企业 CWD', content)
        content = re.sub(r'企业内部', '企业内部', content)
        content = re.sub(r'企业标准', '企业标准', content)
        content = re.sub(r'企业开发规范', '企业开发规范', content)
        content = re.sub(r'企业开发流程', '企业开发流程', content)
        content = re.sub(r'企业质量标准', '企业质量标准', content)

        # 如果内容有变化，写回文件
        if content != original_content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"已清理: {file_path}")
        else:
            print(f"无需清理: {file_path}")

    except Exception as e:
        print(f"处理文件 {file_path} 时出错: {e}")

def main():
    """清理所有相关文件"""

    # 获取所有需要清理的文件
    files_to_clean = []

    # Python 文件
    files_to_clean.extend(glob.glob("*.py"))

    # Markdown 文件
    files_to_clean.extend(glob.glob("*.md"))

    # JSON 文件 (结果文件)
    files_to_clean.extend(glob.glob("*results*.json"))
    files_to_clean.extend(glob.glob("*comparison*.md"))

    print(f"准备清理 {len(files_to_clean)} 个文件...")

    for file_path in files_to_clean:
        if os.path.isfile(file_path):
            clean_file(file_path)

    print("清理完成!")

if __name__ == "__main__":
    main()