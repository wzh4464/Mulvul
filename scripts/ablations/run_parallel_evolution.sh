#!/bin/bash

# 并行分层漏洞检测进化实验
# 使用 seed prompts + score-based evaluation + checkpoint resume

echo "🚀 并行分层漏洞检测进化实验"
echo "======================================================================"
echo ""
echo "功能:"
echo "  - Seed prompts 输出 CONFIDENCE score (0.0-1.0)"
echo "  - Score parsing 解析模型响应"
echo "  - 进度条显示评估进度"
echo "  - 实时保存每代结果"
echo "  - Checkpoint resume 支持 (中断后可恢复)"
echo ""
echo "配置:"
echo "  - 种群大小: ${POPULATION_SIZE:-5}"
echo "  - 进化代数: ${MAX_GENERATIONS:-3}"
echo "  - 评估样本: ${EVAL_SAMPLES:-50}"
echo "  - Score 阈值: ${SCORE_THRESHOLD:-0.5}"
echo "  - 目标类别: ${CATEGORIES:-Memory}"
echo ""
echo "======================================================================"
echo ""

# 默认参数
POPULATION_SIZE=${POPULATION_SIZE:-5}
MAX_GENERATIONS=${MAX_GENERATIONS:-3}
EVAL_SAMPLES=${EVAL_SAMPLES:-50}
SCORE_THRESHOLD=${SCORE_THRESHOLD:-0.5}
CATEGORIES=${CATEGORIES:-Memory}
OUTPUT_DIR=${OUTPUT_DIR:-./outputs/parallel_evolution}

# 解析命令行参数
while [[ $# -gt 0 ]]; do
    case $1 in
        --no-resume)
            NO_RESUME="--no-resume"
            shift
            ;;
        --categories)
            CATEGORIES="$2"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

# 运行实验
PYTHONUNBUFFERED=1 uv run python scripts/ablations/run_parallel_hierarchical_evolution.py \
    --population-size $POPULATION_SIZE \
    --max-generations $MAX_GENERATIONS \
    --eval-samples $EVAL_SAMPLES \
    --score-threshold $SCORE_THRESHOLD \
    --categories $CATEGORIES \
    --output-dir $OUTPUT_DIR \
    $NO_RESUME \
    2>&1 | tee "${OUTPUT_DIR}/log_$(date +%Y%m%d_%H%M%S).txt"

echo ""
echo "======================================================================"
echo "✅ 实验完成!"
echo "结果保存在: $OUTPUT_DIR/"
echo "  - checkpoints/: checkpoint 文件 (可恢复)"
echo "  - results/: 每代评估结果"
echo "  - evolution_summary_*.json: 最终汇总"
echo "======================================================================"
