
# CWD 到 CWE 映射报告

## 总体统计
- 总示例数: 30,255
- 高质量映射 (置信度 > 0.7): 6 (0.0%)

## 按语言分布
- java: 19,020
- cpp: 11,235

## 按主要分类分布
- Logic: 29,422
- Memory: 784
- Injection: 47
- Input: 2

## 按中间分类分布
- Other: 29,422
- Memory Management: 510
- Pointer Dereference: 163
- Buffer Errors: 111
- Injection: 47
- Input Validation: 2

## 置信度分布
- 0.1: 29,422
- 0.6: 274
- 0.4: 235
- 0.3: 193
- 0.5: 117
- 0.7: 12
- 0.8: 2

## 高质量 CWE 映射 (置信度 > 0.7)
- CWE-401: 6

## 示例 CWD 映射

### Memory 分类示例:
- CWD-1002 -> CWE-401 (0.80)
  代码: int externalinputvalueasmallocsizeTGT(size_t mallocsize) {     char *buffer = (char *)kmalloc(malloc...
- CWD-1002 -> CWE-401 (0.80)
- CWD-1027 -> CWE-401 (0.70)
