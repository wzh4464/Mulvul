#!/usr/bin/env python3
"""
Checkpoint 机制测试脚本

测试场景:
1. 保存和加载 checkpoint
2. API 重试机制
3. Batch checkpoint
4. 实验恢复
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, "src")

from evoprompt.utils.checkpoint import (
    CheckpointManager,
    RetryManager,
    BatchCheckpointer,
    ExperimentRecovery,
    with_retry,
)


def test_checkpoint_manager():
    """测试 Checkpoint Manager"""
    print("="*60)
    print("测试 1: CheckpointManager")
    print("="*60)

    # 创建临时实验目录
    exp_dir = Path("result/test_checkpoint")
    exp_dir.mkdir(parents=True, exist_ok=True)

    checkpoint_mgr = CheckpointManager(exp_dir, auto_save=True)

    # 模拟种群数据
    population = [{"prompt": f"test prompt {i}", "fitness": 0.5 + i*0.1} for i in range(3)]
    best_results = [{"accuracy": 0.7}, {"accuracy": 0.8}]

    # 保存 checkpoint
    print("\n📝 保存 checkpoint...")
    checkpoint_mgr.save_checkpoint(
        generation=1,
        batch_idx=5,
        population=population,
        best_results=best_results,
        metadata={"test": "checkpoint_test"}
    )
    print("✅ Checkpoint 保存成功")

    # 加载 checkpoint
    print("\n📖 加载 checkpoint...")
    checkpoint = checkpoint_mgr.load_checkpoint()
    if checkpoint:
        print(f"✅ Checkpoint 加载成功:")
        print(f"   代数: {checkpoint['generation']}")
        print(f"   Batch: {checkpoint['batch_idx']}")
        print(f"   最佳适应度: {checkpoint['best_fitness']:.4f}")
    else:
        print("❌ Checkpoint 加载失败")

    # 加载完整状态
    print("\n📖 加载完整状态...")
    state = checkpoint_mgr.load_full_state()
    if state:
        print(f"✅ 完整状态加载成功:")
        print(f"   种群大小: {len(state['population'])}")
        print(f"   历史结果数: {len(state['best_results'])}")
    else:
        print("❌ 完整状态加载失败")

    # 列出历史 checkpoint
    print("\n📋 历史 checkpoint:")
    checkpoints = checkpoint_mgr.list_checkpoints()
    for ckpt in checkpoints:
        print(f"   - {ckpt.name}")

    print("\n✅ CheckpointManager 测试通过\n")


def test_retry_manager():
    """测试重试管理器"""
    print("="*60)
    print("测试 2: RetryManager")
    print("="*60)

    retry_mgr = RetryManager(max_retries=3, base_delay=0.5, exponential_backoff=True)

    # 模拟不稳定的 API 调用
    call_count = [0]

    def unstable_api():
        call_count[0] += 1
        print(f"  API 调用 {call_count[0]}...")
        if call_count[0] < 3:
            raise Exception("API temporary failure")
        return "success"

    print("\n🔄 测试重试机制...")
    try:
        result = retry_mgr.retry_with_backoff(unstable_api)
        print(f"✅ 重试成功: {result}")
    except Exception as e:
        print(f"❌ 重试失败: {e}")

    # 统计信息
    stats = retry_mgr.get_stats()
    print(f"\n📊 重试统计:")
    print(f"   成功: {stats['success_count']}")
    print(f"   失败: {stats['failure_count']}")

    print("\n✅ RetryManager 测试通过\n")


def test_with_retry_decorator():
    """测试重试装饰器"""
    print("="*60)
    print("测试 3: with_retry 装饰器")
    print("="*60)

    attempt_count = [0]

    @with_retry(max_retries=3, base_delay=0.3)
    def decorated_function():
        attempt_count[0] += 1
        print(f"  尝试 {attempt_count[0]}...")
        if attempt_count[0] < 2:
            raise Exception("Simulated error")
        return f"成功 (尝试了 {attempt_count[0]} 次)"

    print("\n🎨 测试装饰器...")
    try:
        result = decorated_function()
        print(f"✅ {result}")
    except Exception as e:
        print(f"❌ 失败: {e}")

    print("\n✅ with_retry 装饰器测试通过\n")


def test_batch_checkpointer():
    """测试 Batch Checkpointer"""
    print("="*60)
    print("测试 4: BatchCheckpointer")
    print("="*60)

    exp_dir = Path("result/test_checkpoint")
    batch_checkpointer = BatchCheckpointer(exp_dir / "checkpoints", batch_size=16)

    # 保存 batch 结果
    print("\n📝 保存 batch 结果...")
    predictions = ["Benign", "Buffer Errors", "Injection"] * 5
    ground_truths = ["Benign", "Buffer Errors", "Other"] * 5
    batch_analysis = {
        "batch_idx": 3,
        "accuracy": 0.867,
        "correct": 13,
        "batch_size": 15,
        "error_patterns": {"Injection -> Other": 2}
    }

    batch_checkpointer.save_batch_result(
        generation=1,
        batch_idx=3,
        predictions=predictions,
        ground_truths=ground_truths,
        batch_analysis=batch_analysis,
        prompt="test prompt"
    )
    print("✅ Batch 结果保存成功")

    # 加载 batch 结果
    print("\n📖 加载 batch 结果...")
    loaded = batch_checkpointer.load_batch_result(generation=1, batch_idx=3)
    if loaded:
        print(f"✅ Batch 结果加载成功:")
        print(f"   准确率: {loaded['analysis']['accuracy']:.2%}")
        print(f"   预测数: {len(loaded['predictions'])}")
    else:
        print("❌ Batch 结果加载失败")

    # 检查 batch 是否存在
    print("\n🔍 检查 batch 存在性...")
    exists = batch_checkpointer.has_batch(generation=1, batch_idx=3)
    print(f"   Batch 1-3 存在: {'是' if exists else '否'}")

    # 获取已完成的 batch
    print("\n📋 已完成的 batch:")
    completed = batch_checkpointer.get_completed_batches(generation=1)
    print(f"   第 1 代: {completed}")

    print("\n✅ BatchCheckpointer 测试通过\n")


def test_experiment_recovery():
    """测试实验恢复"""
    print("="*60)
    print("测试 5: ExperimentRecovery")
    print("="*60)

    exp_dir = Path("result/test_checkpoint")
    recovery = ExperimentRecovery(exp_dir)

    print("\n🔍 检查是否可恢复...")
    if recovery.can_recover():
        print("✅ 检测到可恢复的实验")

        print("\n🔄 尝试恢复实验...")
        state = recovery.recover_experiment()
        if state:
            print("✅ 实验恢复成功:")
            if state.get("full_state"):
                print(f"   类型: 完整状态")
                print(f"   代数: {state['generation']}")
                print(f"   种群: {len(state['population'])} 个体")
            else:
                print(f"   类型: 基础信息")
                print(f"   代数: {state['checkpoint']['generation']}")
        else:
            print("❌ 实验恢复失败")
    else:
        print("⚠️ 未检测到可恢复的实验")

    print("\n✅ ExperimentRecovery 测试通过\n")


def cleanup_test_files():
    """清理测试文件"""
    print("="*60)
    print("清理测试文件")
    print("="*60)

    import shutil
    test_dir = Path("result/test_checkpoint")

    if test_dir.exists():
        print(f"\n🗑️ 删除测试目录: {test_dir}")
        shutil.rmtree(test_dir)
        print("✅ 清理完成")
    else:
        print("\n⚠️ 测试目录不存在，无需清理")


def main():
    """运行所有测试"""
    print("\n" + "="*60)
    print("🧪 Checkpoint 机制测试")
    print("="*60 + "\n")

    try:
        # 运行测试
        test_checkpoint_manager()
        time.sleep(0.5)

        test_retry_manager()
        time.sleep(0.5)

        test_with_retry_decorator()
        time.sleep(0.5)

        test_batch_checkpointer()
        time.sleep(0.5)

        test_experiment_recovery()
        time.sleep(0.5)

        print("\n" + "="*60)
        print("✅ 所有测试通过!")
        print("="*60 + "\n")

    except Exception as e:
        print(f"\n❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return 1

    finally:
        # 询问是否清理
        user_input = input("\n是否清理测试文件? (y/n): ").strip().lower()
        if user_input == 'y':
            cleanup_test_files()

    return 0


if __name__ == "__main__":
    sys.exit(main())
