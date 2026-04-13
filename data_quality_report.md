# 第一阶段 CWD 数据提取报告

## 总体统计
- 提取数据集: 56 个
- 代码示例总数: 4,246 个
- 平均每数据集: 75.8 个示例

## 语言分布
- cpp: 2,315 个示例
- java: 1,931 个示例

## 分类映射分布

### 按主要分类
- Memory: 3,519 个示例
- Logic: 403 个示例
- Crypto: 143 个示例
- Input: 137 个示例
- Injection: 44 个示例

### 按中间分类
- Integer Errors: 1,269 个示例
- Buffer Errors: 1,014 个示例
- Pointer Dereference: 694 个示例
- Memory Management: 542 个示例
- Access Control: 240 个示例
- Cryptography Issues: 143 个示例
- Input Validation: 136 个示例
- Information Exposure: 127 个示例
- Injection: 44 个示例
- Resource Management: 16 个示例
- Concurrency Issues: 14 个示例
- Other: 6 个示例
- Path Traversal: 1 个示例

### 按 CWE 分类
- CWE-190: 1,249 个示例
- CWE-125: 858 个示例
- CWE-476: 694 个示例
- CWE-401: 415 个示例
- CWE-284: 199 个示例
- CWE-327: 137 个示例
- CWE-209: 113 个示例
- CWE-703: 108 个示例
- CWE-787: 90 个示例
- CWE-416: 74 个示例
- CWE-119: 56 个示例
- CWE-269: 41 个示例
- CWE-770: 31 个示例
- CWE-415: 31 个示例
- CWE-20: 28 个示例
- CWE-94: 24 个示例
- CWE-369: 20 个示例
- CWE-200: 14 个示例
- CWE-89: 13 个示例
- CWE-667: 13 个示例
- CWE-120: 9 个示例
- CWE-400: 6 个示例
- CWE-330: 6 个示例
- CWE-78: 4 个示例
- CWE-79: 3 个示例
- CWE-131: 1 个示例
- CWE-22: 1 个示例
- CWE-362: 1 个示例
- CWE-835: 1 个示例
- CWE-77: 0 个示例

## 置信度分布
- 0.9: 3,959 个示例
- 0.8: 287 个示例

## 数据集详细分布

| 数据集 | CWD ID | 语言 | 示例数 | 主分类 | 中分类 | CWE | 置信度 |
|--------|--------|------|--------|--------|--------|-----|--------|
| java_CWD-1031 | CWD-1031 | java | 742 | Memory | Integer Errors | CWE-190 | 0.95 |
| cpp_CWD-1028 | CWD-1028 | cpp | 594 | Memory | Buffer Errors | CWE-125 | 0.95 |
| cpp_CWD-1031 | CWD-1031 | cpp | 507 | Memory | Integer Errors | CWE-190 | 0.95 |
| java_CWD-1030 | CWD-1030 | java | 473 | Memory | Pointer Dereference | CWE-476 | 0.95 |
| cpp_CWD-1027 | CWD-1027 | cpp | 340 | Memory | Memory Management | CWE-401 | 0.95 |
| java_CWD-1028 | CWD-1028 | java | 240 | Memory | Buffer Errors | CWE-125 | 0.95 |
| cpp_CWD-1030 | CWD-1030 | cpp | 190 | Memory | Pointer Dereference | CWE-476 | 0.95 |
| cpp_CWD-1042 | CWD-1042 | cpp | 140 | Logic | Access Control | CWE-284 | 0.90 |
| java_CWD-1044 | CWD-1044 | java | 106 | Crypto | Cryptography Issues | CWE-327 | 0.90 |
| cpp_CWD-1040 | CWD-1040 | cpp | 103 | Input | Input Validation | CWE-703 | 0.85 |
| java_CWD-1101 | CWD-1101 | java | 96 | Logic | Information Exposure | CWE-209 | 0.85 |
| cpp_CWD-1016 | CWD-1016 | cpp | 90 | Memory | Buffer Errors | CWE-787 | 0.95 |
| cpp_CWD-1026 | CWD-1026 | cpp | 74 | Memory | Memory Management | CWE-416 | 0.95 |
| java_CWD-1027 | CWD-1027 | java | 73 | Memory | Memory Management | CWE-401 | 0.95 |
| java_CWD-1042 | CWD-1042 | java | 59 | Logic | Access Control | CWE-284 | 0.90 |
| cpp_CWD-1029 | CWD-1029 | cpp | 46 | Memory | Buffer Errors | CWE-119 | 0.90 |
| cpp_CWD-1019 | CWD-1019 | cpp | 31 | Memory | Pointer Dereference | CWE-476 | 0.85 |
| cpp_CWD-1044 | CWD-1044 | cpp | 31 | Crypto | Cryptography Issues | CWE-327 | 0.90 |
| cpp_CWD-1038 | CWD-1038 | cpp | 28 | Input | Input Validation | CWE-20 | 0.90 |
| java_CWD-1043 | CWD-1043 | java | 28 | Logic | Access Control | CWE-269 | 0.90 |

... 省略了 36 个数据集

## 数据质量评估

### 优点 ✅
- **高置信度**: 所有映射置信度 ≥ 0.8
- **数据丰富**: 4,246 个示例，足够训练使用
- **分类覆盖**: 覆盖 5 个主分类，30 个 CWE
- **多语言**: 支持 2 种编程语言

### 注意事项 ⚠️
- **分布不均**: 某些分类的示例数量较少，可能需要平衡
- **语言偏向**: 检查是否存在语言分布偏差
- **质量验证**: 建议对前 10% 的数据进行人工验证

### 推荐的下一步
1. 对示例数量 > 100 的数据集进行抽样验证
2. 检查代码示例的完整性和正确性
3. 验证漏洞代码与良性代码的配对关系
4. 确认映射分类的准确性

## 数据使用建议

### 训练策略
- **分层采样**: 按分类比例进行平衡采样
- **质量筛选**: 优先使用高质量评分的示例
- **渐进集成**: 先使用示例数量最多的前 10 个分类进行验证

### 风险控制
- **baseline 对比**: 与现有训练数据进行对比测试
- **A/B 测试**: 使用部分数据验证效果后再全量使用
- **监控指标**: 重点监控映射分类的检测准确率变化
