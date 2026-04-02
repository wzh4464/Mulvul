#!/bin/bash

# 全量训练脚本 - 5代进化，所有数据
# 预计时间：2-4小时

echo "🚀 启动全量训练"
echo "======================================================================"
echo ""
echo "配置:"
echo "  - 进化代数: 5 generations"
echo "  - 种群大小: 5"
echo "  - 评估样本: 所有数据（不限制）"
echo "  - RAG: 启用"
echo "  - Scale: 启用"
echo "  - 知识库: 从训练集自动构建"
echo ""
echo "预计时间: 2-4小时"
echo "======================================================================"
echo ""

# 使用unbuffered Python输出以便实时查看进度
PYTHONUNBUFFERED=1 uv run python scripts/train_three_layer.py \
    --train \
    --use-rag \
    --use-scale \
    --kb-from-dataset \
    --kb-samples-per-category 5 \
    --population-size 5 \
    --max-generations 5 \
    --eval-samples 1000 \
    --batch-size 20 \
    --elite-size 2 \
    --mutation-rate 0.3 \
    --meta-improve-interval 2 \
    --meta-improve-count 3 \
    --output-dir ./outputs/full_training_5gen \
    2>&1 | tee training_log_$(date +%Y%m%d_%H%M%S).txt

echo ""
echo "======================================================================"
echo "✅ 训练完成！"
echo "结果保存在: ./outputs/full_training_5gen/"
echo "日志文件: training_log_*.txt"
echo "======================================================================"
