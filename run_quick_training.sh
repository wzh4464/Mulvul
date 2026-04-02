#!/bin/bash

# 快速训练测试 - 验证功能
# 预计时间：15-30分钟

echo "🧪 启动快速训练测试"
echo "======================================================================"
echo ""
echo "配置:"
echo "  - 进化代数: 2 generations"
echo "  - 种群大小: 3"
echo "  - 评估样本: 50"
echo "  - RAG: 启用"
echo "  - Scale: 启用"
echo ""
echo "预计时间: 15-30分钟"
echo "======================================================================"
echo ""

# 使用unbuffered Python输出
PYTHONUNBUFFERED=1 uv run python scripts/train_three_layer.py \
    --train \
    --use-rag \
    --use-scale \
    --kb-from-dataset \
    --population-size 3 \
    --max-generations 2 \
    --eval-samples 50 \
    --batch-size 10 \
    --elite-size 1 \
    --mutation-rate 0.3 \
    --output-dir ./outputs/quick_training_test \
    2>&1 | tee quick_training_log_$(date +%Y%m%d_%H%M%S).txt

echo ""
echo "======================================================================"
echo "✅ 快速训练完成！"
echo "结果保存在: ./outputs/quick_training_test/"
echo "======================================================================"
