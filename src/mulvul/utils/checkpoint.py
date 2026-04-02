"""
Checkpoint 管理模块 - 处理实验断点保存和恢复

功能:
1. 自动保存 checkpoint (每个 batch、每代进化后)
2. 从 checkpoint 恢复实验
3. API 失败重试机制
4. 多级备份策略
"""

import json
import shutil
import time
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime
import pickle


class CheckpointManager:
    """Checkpoint 管理器"""

    def __init__(self, exp_dir: Path, auto_save: bool = True):
        """
        Args:
            exp_dir: 实验目录
            auto_save: 是否自动保存 checkpoint
        """
        self.exp_dir = Path(exp_dir)
        self.checkpoint_dir = self.exp_dir / "checkpoints"
        self.checkpoint_dir.mkdir(exist_ok=True, parents=True)
        self.auto_save = auto_save

        # Checkpoint 文件
        self.latest_checkpoint = self.checkpoint_dir / "latest.json"
        self.backup_checkpoint = self.checkpoint_dir / "backup.json"
        self.state_file = self.checkpoint_dir / "state.pkl"

        print(f"✅ Checkpoint 管理器初始化")
        print(f"   Checkpoint 目录: {self.checkpoint_dir}")

    def save_checkpoint(
        self,
        generation: int,
        batch_idx: int,
        population: List[Any],
        best_results: List[Dict[str, Any]],
        metadata: Optional[Dict[str, Any]] = None
    ) -> Path:
        """
        保存 checkpoint

        Args:
            generation: 当前代数
            batch_idx: 当前 batch 索引
            population: 种群
            best_results: 最佳结果历史
            metadata: 额外元数据

        Returns:
            checkpoint 文件路径
        """
        checkpoint_data = {
            "timestamp": datetime.now().isoformat(),
            "generation": generation,
            "batch_idx": batch_idx,
            "num_individuals": len(population),
            "best_fitness": population[0][0].fitness if population else 0.0,
            "metadata": metadata or {},
        }

        # 保存轻量级 JSON checkpoint (用于快速恢复)
        try:
            # 备份当前 latest 到 backup
            if self.latest_checkpoint.exists():
                shutil.copy(self.latest_checkpoint, self.backup_checkpoint)

            with open(self.latest_checkpoint, "w", encoding="utf-8") as f:
                json.dump(checkpoint_data, f, indent=2, ensure_ascii=False)

            # 保存完整状态 (pickle)
            state = {
                "generation": generation,
                "batch_idx": batch_idx,
                "population": population,
                "best_results": best_results,
                "metadata": metadata,
            }

            with open(self.state_file, "wb") as f:
                pickle.dump(state, f)

            # 保存带时间戳的历史 checkpoint
            history_checkpoint = self.checkpoint_dir / f"gen{generation}_batch{batch_idx}.json"
            with open(history_checkpoint, "w", encoding="utf-8") as f:
                json.dump(checkpoint_data, f, indent=2, ensure_ascii=False)

            return self.latest_checkpoint

        except Exception as e:
            print(f"⚠️ Checkpoint 保存失败: {e}")
            return None

    def load_checkpoint(self) -> Optional[Dict[str, Any]]:
        """
        加载最新的 checkpoint

        Returns:
            checkpoint 数据，如果不存在返回 None
        """
        # 首先尝试加载 latest
        if self.latest_checkpoint.exists():
            try:
                with open(self.latest_checkpoint, "r", encoding="utf-8") as f:
                    checkpoint = json.load(f)
                print(f"✅ 从 checkpoint 恢复:")
                print(f"   代数: {checkpoint['generation']}")
                print(f"   Batch: {checkpoint['batch_idx']}")
                print(f"   最佳适应度: {checkpoint['best_fitness']:.4f}")
                return checkpoint
            except Exception as e:
                print(f"⚠️ Latest checkpoint 加载失败: {e}")

        # 如果 latest 失败，尝试 backup
        if self.backup_checkpoint.exists():
            try:
                with open(self.backup_checkpoint, "r", encoding="utf-8") as f:
                    checkpoint = json.load(f)
                print(f"✅ 从 backup checkpoint 恢复:")
                print(f"   代数: {checkpoint['generation']}")
                print(f"   Batch: {checkpoint['batch_idx']}")
                return checkpoint
            except Exception as e:
                print(f"⚠️ Backup checkpoint 加载失败: {e}")

        return None

    def load_full_state(self) -> Optional[Dict[str, Any]]:
        """
        加载完整状态 (包括种群)

        Returns:
            完整状态，如果不存在返回 None
        """
        if not self.state_file.exists():
            return None

        try:
            with open(self.state_file, "rb") as f:
                state = pickle.load(f)
            print(f"✅ 完整状态恢复成功")
            return state
        except Exception as e:
            print(f"⚠️ 完整状态加载失败: {e}")
            return None

    def has_checkpoint(self) -> bool:
        """检查是否存在 checkpoint"""
        return self.latest_checkpoint.exists() or self.backup_checkpoint.exists()

    def list_checkpoints(self) -> List[Path]:
        """列出所有历史 checkpoint"""
        return sorted(self.checkpoint_dir.glob("gen*_batch*.json"))

    def cleanup_old_checkpoints(self, keep_last_n: int = 10):
        """清理旧的 checkpoint，保留最近 N 个"""
        checkpoints = self.list_checkpoints()
        if len(checkpoints) > keep_last_n:
            for ckpt in checkpoints[:-keep_last_n]:
                try:
                    ckpt.unlink()
                    print(f"  🗑️ 清理旧 checkpoint: {ckpt.name}")
                except Exception as e:
                    print(f"  ⚠️ 清理失败 {ckpt.name}: {e}")


class RetryManager:
    """API 调用重试管理器"""

    def __init__(
        self,
        max_retries: int = 3,
        base_delay: float = 1.0,
        exponential_backoff: bool = True
    ):
        """
        Args:
            max_retries: 最大重试次数
            base_delay: 基础延迟时间（秒）
            exponential_backoff: 是否使用指数退避
        """
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.exponential_backoff = exponential_backoff
        self.retry_count = 0
        self.success_count = 0
        self.failure_count = 0

    def retry_with_backoff(self, func, *args, **kwargs):
        """
        使用重试和退避策略执行函数

        Args:
            func: 要执行的函数
            *args, **kwargs: 函数参数

        Returns:
            函数返回值

        Raises:
            最后一次失败的异常
        """
        last_exception = None

        for attempt in range(self.max_retries):
            try:
                result = func(*args, **kwargs)
                self.success_count += 1
                self.retry_count = 0  # 重置重试计数
                return result

            except Exception as e:
                last_exception = e
                self.retry_count += 1
                self.failure_count += 1

                if attempt < self.max_retries - 1:
                    # 计算延迟时间
                    if self.exponential_backoff:
                        delay = self.base_delay * (2 ** attempt)
                    else:
                        delay = self.base_delay

                    print(f"      ⚠️ API 调用失败 (尝试 {attempt + 1}/{self.max_retries}): {e}")
                    print(f"      ⏳ 等待 {delay:.1f}秒 后重试...")
                    time.sleep(delay)
                else:
                    print(f"      ❌ API 调用失败，已达最大重试次数: {e}")

        raise last_exception

    def get_stats(self) -> Dict[str, int]:
        """获取重试统计信息"""
        return {
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "current_retry_count": self.retry_count,
        }


class BatchCheckpointer:
    """Batch 级别的 checkpoint 管理"""

    def __init__(self, checkpoint_dir: Path, batch_size: int):
        """
        Args:
            checkpoint_dir: Checkpoint 目录
            batch_size: Batch 大小
        """
        self.checkpoint_dir = Path(checkpoint_dir)
        self.batch_dir = self.checkpoint_dir / "batches"
        self.batch_dir.mkdir(exist_ok=True, parents=True)
        self.batch_size = batch_size

    def save_batch_result(
        self,
        generation: int,
        batch_idx: int,
        predictions: List[str],
        ground_truths: List[str],
        batch_analysis: Dict[str, Any],
        prompt: str
    ):
        """
        保存单个 batch 的结果

        Args:
            generation: 代数
            batch_idx: Batch 索引
            predictions: 预测结果
            ground_truths: 真实标签
            batch_analysis: Batch 分析结果
            prompt: 使用的 prompt
        """
        batch_file = self.batch_dir / f"gen{generation}_batch{batch_idx}.json"

        batch_data = {
            "generation": generation,
            "batch_idx": batch_idx,
            "timestamp": datetime.now().isoformat(),
            "predictions": predictions,
            "ground_truths": ground_truths,
            "analysis": batch_analysis,
            "prompt": prompt,
        }

        try:
            with open(batch_file, "w", encoding="utf-8") as f:
                json.dump(batch_data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"      ⚠️ Batch checkpoint 保存失败: {e}")

    def load_batch_result(self, generation: int, batch_idx: int) -> Optional[Dict[str, Any]]:
        """
        加载单个 batch 的结果

        Args:
            generation: 代数
            batch_idx: Batch 索引

        Returns:
            Batch 数据，如果不存在返回 None
        """
        batch_file = self.batch_dir / f"gen{generation}_batch{batch_idx}.json"

        if not batch_file.exists():
            return None

        try:
            with open(batch_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"      ⚠️ Batch checkpoint 加载失败: {e}")
            return None

    def has_batch(self, generation: int, batch_idx: int) -> bool:
        """检查是否存在 batch checkpoint"""
        batch_file = self.batch_dir / f"gen{generation}_batch{batch_idx}.json"
        return batch_file.exists()

    def get_completed_batches(self, generation: int) -> List[int]:
        """获取已完成的 batch 索引列表"""
        pattern = f"gen{generation}_batch*.json"
        batch_files = self.batch_dir.glob(pattern)

        completed = []
        for batch_file in batch_files:
            # 从文件名提取 batch_idx
            try:
                batch_idx = int(batch_file.stem.split("_batch")[1])
                completed.append(batch_idx)
            except (IndexError, ValueError):
                continue

        return sorted(completed)


class ExperimentRecovery:
    """实验恢复管理器"""

    def __init__(self, exp_dir: Path):
        """
        Args:
            exp_dir: 实验目录
        """
        self.exp_dir = Path(exp_dir)
        self.checkpoint_manager = CheckpointManager(exp_dir)
        self.recovery_log = self.exp_dir / "recovery.log"

    def can_recover(self) -> bool:
        """检查是否可以恢复实验"""
        return self.checkpoint_manager.has_checkpoint()

    def recover_experiment(self) -> Optional[Dict[str, Any]]:
        """
        恢复实验

        Returns:
            恢复的状态，如果无法恢复返回 None
        """
        if not self.can_recover():
            print("⚠️ 未找到可恢复的 checkpoint")
            return None

        # 尝试加载完整状态
        state = self.checkpoint_manager.load_full_state()

        if state:
            self._log_recovery(state)
            return state

        # 如果完整状态加载失败，至少加载基础信息
        checkpoint = self.checkpoint_manager.load_checkpoint()
        if checkpoint:
            self._log_recovery(checkpoint)
            return {"checkpoint": checkpoint, "full_state": False}

        return None

    def _log_recovery(self, state: Dict[str, Any]):
        """记录恢复日志"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "recovered_state": {
                "generation": state.get("generation"),
                "batch_idx": state.get("batch_idx"),
            }
        }

        try:
            with open(self.recovery_log, "a", encoding="utf-8") as f:
                f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")
        except Exception as e:
            print(f"⚠️ 恢复日志写入失败: {e}")


def with_retry(max_retries: int = 3, base_delay: float = 1.0):
    """
    装饰器：为函数添加重试机制

    Args:
        max_retries: 最大重试次数
        base_delay: 基础延迟时间

    Example:
        @with_retry(max_retries=3, base_delay=2.0)
        def api_call():
            return llm_client.generate(prompt)
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            retry_manager = RetryManager(max_retries, base_delay)
            return retry_manager.retry_with_backoff(func, *args, **kwargs)
        return wrapper
    return decorator
