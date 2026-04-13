# 第一阶段：精确映射数据增强实施计划

## 🎯 目标概述

将 41 个高置信度的 CWD 映射集成到 Mulvul 训练流程，增强现有 CWE 检测能力。

**核心指标**:
- 新增训练数据: ~8,200 个高质量代码示例
- 映射覆盖: 41 个 CWD 分类 (置信度 ≥ 0.8)
- 预期提升: CWE 检测准确率提升 5-15%

## 📅 实施时间表

### 第 1 周：数据准备与验证
**目标**: 完成数据转换和质量验证

#### Day 1-2: 数据提取与清洗
```bash
# 1. 提取高置信度映射的 CWD 数据
cd ~/.config/superpowers/worktrees/Mulvul/analyze-cwe-cwd-migration
python3 -c "
import json
with open('enhanced_cwd_mappings.json') as f:
    mappings = json.load(f)

high_conf = {k:v for k,v in mappings['semantic_mappings'].items() 
            if v['confidence'] >= 0.8}
print(f'高置信度映射: {len(high_conf)} 个')
"

# 2. 从原始 CWD 数据中提取对应示例
python3 extract_high_confidence_data.py
```

**交付物**:
- `phase1_cwd_data.json` - 高置信度 CWD 数据
- `data_quality_report.md` - 数据质量分析报告

#### Day 3-4: 格式转换与标准化
```bash
# 转换为 Mulvul PromptBundle 格式
python3 convert_to_prompt_bundle.py \
  --input phase1_cwd_data.json \
  --output phase1_prompt_bundles.json \
  --mapping enhanced_cwd_mappings.json
```

**交付物**:
- `phase1_prompt_bundles.json` - Mulvul 标准格式
- `conversion_validation.json` - 转换验证结果

#### Day 5: 数据验证与抽样检查
```bash
# 人工验证关键映射的准确性
python3 validate_mappings.py --sample-size 100
```

**验证重点**:
- 前 20 个最重要的 CWD 映射
- 每个主要分类 (Memory/Injection/Input) 的代表性样本
- 代码示例与 CWE 标签的一致性

### 第 2 周：集成与测试
**目标**: 集成到 Mulvul 训练流程并建立基准

#### Day 8-10: 训练流程集成

**修改 `src/mulvul/mainline/workflows.py`**:
```python
# 添加 CWD 数据加载器
def load_enhanced_training_data(base_data_path, cwd_data_path):
    """加载包含 CWD 增强数据的训练集"""
    base_data = load_standard_data(base_data_path)
    cwd_data = load_cwd_enhanced_data(cwd_data_path)
    
    # 合并数据集，保持标签一致性
    enhanced_data = merge_datasets(base_data, cwd_data)
    
    return enhanced_data

# 修改训练工作流
def run_enhanced_evolution(train_file, cwd_data_file, output_dir):
    # 加载增强数据
    enhanced_data = load_enhanced_training_data(train_file, cwd_data_file)
    
    # 使用现有训练流程
    return run_mainline_evolution(enhanced_data, output_dir)
```

#### Day 11-12: 基准测试建立
```bash
# 1. 建立 baseline (不含 CWD 数据)
uv run python scripts/run_mainline_evolution.py \
  --train-file data/primevul/train.jsonl \
  --output-dir results/baseline \
  --config configs/baseline.yaml

# 2. 运行 enhanced (含 CWD 数据)  
uv run python scripts/run_enhanced_evolution.py \
  --train-file data/primevul/train.jsonl \
  --cwd-file phase1_prompt_bundles.json \
  --output-dir results/enhanced \
  --config configs/enhanced.yaml
```

#### Day 13-14: 初步评估
```bash
# 在标准测试集上评估两个模型
uv run python scripts/run_mainline_evaluation.py \
  --eval-file data/primevul/test.jsonl \
  --prompts-path results/baseline/prompts.json \
  --output baseline_results.json

uv run python scripts/run_mainline_evaluation.py \
  --eval-file data/primevul/test.jsonl \
  --prompts-path results/enhanced/prompts.json \
  --output enhanced_results.json

# 性能对比分析
python3 analyze_performance_improvement.py \
  --baseline baseline_results.json \
  --enhanced enhanced_results.json
```

## 🛠️ 技术实现细节

### 1. 数据提取工具

**`extract_high_confidence_data.py`**:
```python
#!/usr/bin/env python3
"""提取高置信度 CWD 数据"""

def extract_high_confidence_examples():
    # 加载映射配置
    with open('enhanced_cwd_mappings.json') as f:
        mappings = json.load(f)
    
    # 筛选高置信度映射
    high_conf_cwds = [
        cwd_id for cwd_id, data in mappings['semantic_mappings'].items()
        if data['confidence'] >= 0.8
    ]
    
    # 从原始数据中提取对应示例
    cwd_data_files = [
        "/Users/zihanwu/codes/Mulvul/data/enter/cwd_benchmark_2.json",
        "/Users/zihanwu/codes/Mulvul/data/enter/checked_codehub_benchmark.json"
    ]
    
    extracted_data = {}
    for file_path in cwd_data_files:
        with open(file_path) as f:
            data = json.load(f)
            
        for lang in data:
            for cwd_id in high_conf_cwds:
                if cwd_id in data[lang]:
                    key = f"{lang}_{cwd_id}"
                    extracted_data[key] = {
                        'cwd_id': cwd_id,
                        'language': lang,
                        'examples': data[lang][cwd_id],
                        'mapping': mappings['semantic_mappings'][cwd_id]
                    }
    
    # 保存提取结果
    with open('phase1_cwd_data.json', 'w') as f:
        json.dump(extracted_data, f, indent=2, ensure_ascii=False)
    
    print(f"提取了 {len(extracted_data)} 个数据集")
    
    # 生成统计报告
    stats = analyze_extracted_data(extracted_data)
    with open('data_quality_report.md', 'w') as f:
        f.write(generate_quality_report(stats))

if __name__ == "__main__":
    extract_high_confidence_examples()
```

### 2. 格式转换工具

**`convert_to_prompt_bundle.py`**:
```python
#!/usr/bin/env python3
"""转换为 Mulvul PromptBundle 格式"""

from src.mulvul.mainline.bundle import PromptBundle
from src.mulvul.data.cwe_hierarchy import MAJOR_TO_MIDDLE, MIDDLE_TO_CWE

def convert_cwd_to_prompt_bundle(cwd_data, mappings):
    """将 CWD 数据转换为 PromptBundle 格式"""
    
    bundles = []
    
    for dataset_key, dataset in cwd_data.items():
        cwd_id = dataset['cwd_id']
        mapping = dataset['mapping']
        
        # 获取映射的分类信息
        major = mapping['major']
        middle = mapping['middle'] 
        cwe = mapping['cwe']
        
        for example in dataset['examples']:
            # 构建 PromptBundle 对象
            bundle = create_prompt_bundle(
                example=example,
                major=major,
                middle=middle, 
                cwe=cwe,
                cwd_id=cwd_id,
                language=dataset['language'],
                confidence=mapping['confidence']
            )
            
            bundles.append(bundle)
    
    return bundles

def create_prompt_bundle(example, major, middle, cwe, cwd_id, language, confidence):
    """创建单个 PromptBundle"""
    
    # 提取代码内容
    vuln_code = example.get('vulnerable_code', {})
    benign_code = example.get('benign_code', {})
    
    # 构建标准化的代码内容
    code_content = format_code_content(vuln_code, benign_code, language)
    
    # 创建标签信息
    labels = {
        'major': major,
        'middle': middle if middle != 'Other' else None,
        'cwe': cwe if cwe else None,
        'cwd_source': cwd_id,
        'confidence': confidence
    }
    
    # 构建元数据
    metadata = {
        'source': 'cwd_enhanced',
        'language': language,
        'original_cwd': cwd_id,
        'mapping_confidence': confidence,
        'quality': example.get('quality'),
        'review_comment': example.get('review_comment')
    }
    
    return PromptBundle(
        content=code_content,
        labels=labels,
        metadata=metadata
    )
```

### 3. 性能评估工具

**`analyze_performance_improvement.py`**:
```python
#!/usr/bin/env python3
"""分析性能提升效果"""

def analyze_performance(baseline_results, enhanced_results):
    """对比分析性能提升"""
    
    metrics = ['precision', 'recall', 'f1_score', 'accuracy']
    levels = ['major', 'middle', 'cwe']
    
    improvements = {}
    
    for level in levels:
        for metric in metrics:
            baseline_val = baseline_results[level][metric]
            enhanced_val = enhanced_results[level][metric]
            
            improvement = enhanced_val - baseline_val
            improvement_pct = (improvement / baseline_val) * 100
            
            improvements[f"{level}_{metric}"] = {
                'baseline': baseline_val,
                'enhanced': enhanced_val,
                'absolute_improvement': improvement,
                'relative_improvement_pct': improvement_pct
            }
    
    # 特别关注 CWD 相关的分类
    cwd_related_analysis = analyze_cwd_specific_performance(
        baseline_results, enhanced_results
    )
    
    return {
        'overall_improvements': improvements,
        'cwd_specific': cwd_related_analysis,
        'summary': generate_performance_summary(improvements)
    }
```

## 📊 评估指标与成功标准

### 核心指标
1. **检测准确率提升**: 
   - Major 级别: +3-8%
   - Middle 级别: +5-12% 
   - CWE 级别: +8-15%

2. **特定类别提升**:
   - Memory 类漏洞: +10-20%
   - Injection 类漏洞: +15-25%
   - Input 类漏洞: +8-15%

3. **数据质量指标**:
   - 训练收敛速度: 10-20% 提升
   - 模型置信度: 平均提升 0.05-0.1

### 成功阈值
- **最低要求**: 任一级别准确率提升 ≥ 3%
- **目标效果**: CWE 级别准确率提升 ≥ 8%
- **理想效果**: 整体 F1-score 提升 ≥ 10%

## ⚠️ 风险控制

### 风险识别与缓解

#### 1. 数据质量风险
**风险**: CWD 数据与现有数据分布不匹配
**缓解措施**:
- 预训练阶段进行数据分布分析
- 使用分层采样保持平衡
- 建立数据验证检查点

#### 2. 性能下降风险  
**风险**: 新数据引入可能降低现有性能
**缓解措施**:
- 建立详细的 baseline 基准
- 实施 A/B 测试框架
- 保留完整的回滚方案

#### 3. 训练时间增长风险
**风险**: 数据量增加 27% 可能显著延长训练时间
**缓解措施**:
- 优化数据加载流程
- 使用增量训练策略
- 预设训练时间上限

### 回滚计划
```bash
# 如果性能下降超过 2%，立即回滚
if performance_drop > 0.02:
    # 1. 停止当前训练
    stop_training()
    
    # 2. 恢复 baseline 模型
    restore_baseline_model()
    
    # 3. 分析失败原因
    analyze_failure_causes()
    
    # 4. 调整数据或参数后重试
    adjust_and_retry()
```

## 📋 检查清单

### 开发完成检查
- [ ] 数据提取工具开发完成
- [ ] 格式转换工具开发完成  
- [ ] 性能评估工具开发完成
- [ ] 集成测试通过
- [ ] 基准测试建立

### 部署前检查
- [ ] 数据质量验证通过
- [ ] 映射准确性人工验证
- [ ] 训练流程兼容性确认
- [ ] 回滚方案测试通过
- [ ] 监控告警配置完成

### 上线后监控
- [ ] 训练过程监控正常
- [ ] 性能指标达到预期
- [ ] 无明显回归问题
- [ ] 用户反馈收集

## 📞 团队协调

### 角色分工
- **数据工程师**: 负责数据提取和转换工具开发
- **算法工程师**: 负责训练流程集成和性能优化
- **测试工程师**: 负责质量验证和性能测试
- **项目经理**: 负责进度协调和风险管控

### 沟通机制
- **日会**: 每日进度同步 (15 分钟)
- **周会**: 里程碑回顾和风险评估 (1 小时)
- **关键节点**: 重要决策点的技术评审

## 🎯 预期产出

### 第 1 周产出
1. `phase1_cwd_data.json` - 清洗后的高质量 CWD 数据
2. `phase1_prompt_bundles.json` - Mulvul 标准格式数据
3. `data_quality_report.md` - 数据质量分析报告

### 第 2 周产出  
1. 集成的训练流程代码
2. Baseline vs Enhanced 性能对比报告
3. 第一阶段实施总结和改进建议

### 长期价值
1. 可复用的 CWD 数据处理工具链
2. 验证了 CWD-CWE 映射的有效性
3. 为第二阶段扩展奠定了技术基础

---

**总结**: 第一阶段计划在 2 周内完成，风险可控，预期能带来显著的检测性能提升，为 CWD 迁移的全面推进提供有力支撑。