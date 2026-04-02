# CWE漏洞类型统计程序

这个项目包含两个Python程序，用于统计JSONL文件中CWE（Common Weakness Enumeration）漏洞类型的分布情况。

## 程序说明

### 1. cwe_statistics.py - 完整版统计程序

功能完整的CWE统计程序，提供详细的统计信息和多种输出选项。

**特性：**
- 详细的统计报告
- 支持输出到文件
- 错误处理和警告信息
- 命令行参数支持
- 百分比计算

**使用方法：**
```bash
# 基本使用
python3 cwe_statistics.py data/primevul_1percent_sample/train_sample.jsonl

# 保存结果到文件
python3 cwe_statistics.py data/primevul_1percent_sample/train_sample.jsonl -o results.txt

# 显示详细信息
python3 cwe_statistics.py data/primevul_1percent_sample/train_sample.jsonl -v

# 查看帮助
python3 cwe_statistics.py -h
```

**输出示例：**
```
============================================================
CWE漏洞类型统计报告
============================================================

总体统计:
  总记录数: 168
  包含CWE的记录数: 162
  不包含CWE的记录数: 6
  唯一CWE类型数: 42

CWE类型分布 (按数量降序排列):
----------------------------------------
 1. CWE-787         :     25 ( 14.9%)
 2. CWE-125         :     19 ( 11.3%)
 3. CWE-476         :     12 (  7.1%)
...
```

### 2. quick_cwe_stats.py - 快速统计程序

简化版本的CWE统计程序，用于快速获取统计结果。

**特性：**
- 快速统计
- 简洁输出
- 轻量级设计

**使用方法：**
```bash
python3 quick_cwe_stats.py data/primevul_1percent_sample/train_sample.jsonl
```

**输出示例：**
```
文件: data/primevul_1percent_sample/train_sample.jsonl
总记录数: 168
唯一CWE类型数: 42

CWE类型统计:
------------------------------
CWE-787              :   25 ( 14.9%)
CWE-125              :   19 ( 11.3%)
CWE-476              :   12 (  7.1%)
...
```

## 数据格式要求

程序期望的JSONL文件格式：
- 每行一个JSON对象
- 每个JSON对象包含`cwe`字段
- `cwe`字段是一个字符串数组，包含CWE标识符

**示例数据：**
```json
{"idx": 210536, "cwe": ["CWE-416"], "cve": "CVE-2020-36557"}
{"idx": 280221, "cwe": [], "cve": "None"}
{"idx": 213483, "cwe": ["CWE-20"], "cve": "CVE-2011-3603"}
```

## 统计结果说明

### 主要统计指标

1. **总记录数**: 文件中所有记录的数量
2. **包含CWE的记录数**: 有CWE信息的记录数量
3. **不包含CWE的记录数**: 没有CWE信息的记录数量
4. **唯一CWE类型数**: 不同CWE类型的总数

### CWE类型分布

- 按出现次数降序排列
- 显示每种CWE类型的出现次数
- 计算每种类型占总记录数的百分比

## 常见CWE类型说明

根据统计结果，最常见的CWE类型包括：

- **CWE-787**: 缓冲区溢出（Buffer Overflow）
- **CWE-125**: 越界读取（Out-of-bounds Read）
- **CWE-476**: 空指针解引用（NULL Pointer Dereference）
- **CWE-416**: 释放后使用（Use After Free）
- **CWE-190**: 整数溢出（Integer Overflow）
- **CWE-119**: 缓冲区操作不当（Improper Restriction of Operations within the Bounds of a Memory Buffer）

## 系统要求

- Python 3.6+
- 标准库（无需额外安装包）

## 注意事项

1. 确保输入文件是有效的JSONL格式
2. 程序会自动跳过空行和格式错误的行
3. 对于大文件，程序会逐行处理以节省内存
4. 输出文件使用UTF-8编码

## 扩展功能

可以根据需要扩展程序功能：

- 添加CWE类型的中文描述
- 支持多种输出格式（CSV、JSON等）
- 添加时间序列分析
- 集成CVE信息统计
- 添加图表生成功能


