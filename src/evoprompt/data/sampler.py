"""Data sampling utilities for balanced dataset creation."""

import random
import json
from typing import List, Dict, Any, Tuple, Optional
from pathlib import Path
import logging

from .cwe_categories import map_cwe_to_major
from .cwe_layer1 import map_cwe_to_layer1

logger = logging.getLogger(__name__)


class BalancedSampler:
    """Creates balanced samples from datasets."""

    def __init__(self, seed: int = 42):
        self.seed = seed
        random.seed(seed)

    def _determine_label(
        self,
        item: Dict[str, Any],
        balance_mode: str,
        target_field: str,
    ) -> Optional[str]:
        """Determine the grouping label based on the requested balance mode."""
        target_raw = item.get(target_field, 0)
        try:
            target_int = int(target_raw)
        except (TypeError, ValueError):
            target_int = 0

        if balance_mode == "target":
            return str(target_int)

        if balance_mode in ("major", "layer1"):
            # "layer1" is an alias for "major" — both use simplified category names
            if target_int == 0:
                return "Benign"

            cwe_codes = item.get("cwe", [])
            if isinstance(cwe_codes, str):
                cwe_codes = [cwe_codes] if cwe_codes else []
            elif not isinstance(cwe_codes, list):
                cwe_codes = []

            major = map_cwe_to_major(cwe_codes) if cwe_codes else "Other"
            return major or "Other"

        raise ValueError(f"Unsupported balance_mode: {balance_mode}")

    def sample_primevul_balanced(
        self,
        data_file: str,
        sample_ratio: float = 0.01,
        target_field: str = "target",
        balance_mode: str = "target",
    ) -> Tuple[List[Dict], Dict[str, int]]:
        """
        从Primevul数据集中采样均衡的数据。

        Args:
            data_file: JSONL格式的数据文件路径
            sample_ratio: 采样比例 (0.01 = 1%)
            target_field: 目标标签字段名
        balance_mode: 均衡模式，"target" 按 0/1，"major" 按旧 CWE 大类，"layer1" 按层级根节点

        Returns:
            (sampled_data, statistics)
        """
        logger.info(f"Loading data from {data_file}")
        logger.info(f"Balance mode: {balance_mode}")

        # 加载所有数据
        all_data: List[Dict[str, Any]] = []
        with open(data_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        item = json.loads(line.strip())
                        all_data.append(item)
                    except json.JSONDecodeError as e:
                        logger.warning(
                            "Failed to parse line: %s... Error: %s", line[:100], e
                        )

        if not all_data:
            raise ValueError(f"No data loaded from {data_file}")

        logger.info("Loaded %d total samples", len(all_data))

        # 按标签分组
        label_groups: Dict[str, List[Dict[str, Any]]] = {}
        for item in all_data:
            label = self._determine_label(item, balance_mode, target_field)
            if label is None:
                continue
            item["_balance_label"] = label
            label_groups.setdefault(label, []).append(item)

        if not label_groups:
            raise ValueError("No samples grouped for balancing; check balance_mode input.")

        # 计算统计信息
        stats = {
            f"total_{label}": len(items) for label, items in label_groups.items()
        }
        stats["total_samples"] = len(all_data)

        logger.info("Original data distribution:")
        for label, items in label_groups.items():
            percentage = (len(items) / len(all_data)) * 100
            logger.info("  Label %s: %d samples (%.1f%%)", label, len(items), percentage)

        # 计算每个标签需要采样的数量
        total_target_samples = max(1, int(len(all_data) * sample_ratio))
        available_labels = {
            label: items for label, items in label_groups.items() if len(items) > 0
        }
        if not available_labels:
            raise ValueError("No labels available for sampling after filtering.")

        max_samples_per_label = max(1, int(total_target_samples / len(available_labels)))

        logger.info("Target total samples: %d", total_target_samples)
        logger.info("Initial max samples per label: %d", max_samples_per_label)

        sampled_data: List[Dict[str, Any]] = []
        sampled_stats: Dict[str, int] = {}

        for label, items in available_labels.items():
            sample_count = min(max_samples_per_label, len(items))
            if sample_count <= 0:
                logger.warning("Skipping label %s due to insufficient samples.", label)
                continue

            sampled_items = random.sample(items, sample_count)
            sampled_data.extend(sampled_items)
            sampled_stats[f"sampled_{label}"] = len(sampled_items)

            logger.info("Sampled %d samples from label %s", len(sampled_items), label)

        if not sampled_data:
            raise ValueError("Sampling produced no data; adjust sample_ratio or balance_mode.")

        # 打乱最终数据
        random.shuffle(sampled_data)

        # 更新统计信息
        sampled_stats["sampled_total"] = len(sampled_data)
        sampled_stats["sample_ratio"] = len(sampled_data) / len(all_data)
        sampled_stats.update(stats)  # 包含原始统计信息

        logger.info(
            "Final balanced sample: %d samples (%.3f of original)",
            len(sampled_data),
            sampled_stats["sample_ratio"],
        )

        return sampled_data, sampled_stats

    def save_sampled_data(
        self,
        sampled_data: List[Dict],
        output_file: str,
        format: str = "jsonl",
    ):
        """保存采样数据到文件。"""
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if format.lower() == "jsonl":
            with open(output_path, "w", encoding="utf-8") as f:
                for item in sampled_data:
                    f.write(json.dumps(item, ensure_ascii=False) + "\n")
        elif format.lower() == "tab":
            with open(output_path, "w", encoding="utf-8") as f:
                for item in sampled_data:
                    func = item.get("func", "").strip()
                    target = str(item.get("target", 0))
                    # 清理函数代码为单行
                    func_clean = func.replace("\n", " ").replace("\t", " ")
                    while "  " in func_clean:
                        func_clean = func_clean.replace("  ", " ")
                    f.write(f"{func_clean}\t{target}\n")

        logger.info("Saved %d samples to %s", len(sampled_data), output_path)
        return str(output_path)

    def create_train_dev_split(
        self,
        sampled_data: List[Dict],
        dev_ratio: float = 0.3,
        target_field: str = "target",
        label_field: Optional[str] = None,
        min_dev_per_label: int = 1,
    ) -> Tuple[List[Dict], List[Dict]]:
        """将采样数据分割为训练集和开发集，保持平衡。

        Args:
            min_dev_per_label: 每个标签在 dev 集中的最少样本数。
                对于样本数 >= 2 的标签，保证至少 min_dev_per_label 个进入 dev。
        """

        group_field = label_field or target_field

        # 按标签分组
        label_groups: Dict[str, List[Dict[str, Any]]] = {}
        for item in sampled_data:
            label = item.get(group_field, item.get(target_field, 0))
            label_groups.setdefault(str(label), []).append(item)

        train_data: List[Dict[str, Any]] = []
        dev_data: List[Dict[str, Any]] = []

        # 从每个标签组中分割
        for label, items in label_groups.items():
            random.shuffle(items)

            if len(items) >= 2:
                dev_count = max(min_dev_per_label, int(len(items) * dev_ratio))
            else:
                # 只有 1 个样本时放入 dev 以确保评估覆盖
                dev_count = 1
            dev_count = min(dev_count, len(items))  # 不超过总数
            train_count = len(items) - dev_count

            train_data.extend(items[:train_count])
            dev_data.extend(items[train_count:])

            logger.info("Label %s: %d train, %d dev", label, train_count, dev_count)

        # 打乱数据
        random.shuffle(train_data)
        random.shuffle(dev_data)

        logger.info(
            "Split complete: %d train, %d dev samples", len(train_data), len(dev_data)
        )

        return train_data, dev_data


def sample_primevul_1percent(
    primevul_dir: str,
    output_dir: str,
    seed: int = 42,
    balance_mode: str = "layer1",
    sample_ratio: float = 0.01,
    dev_ratio: float = 0.3,
    remove_benign_train: bool = False,
    min_dev_per_label: int = 1,
) -> Dict[str, Any]:
    """
    从Primevul数据集采样1%均衡数据的便捷函数。
    
    Args:
        primevul_dir: Primevul数据目录路径
        output_dir: 输出目录路径
        seed: 随机种子
        
    Returns:
        包含文件路径和统计信息的字典
    """
    sampler = BalancedSampler(seed=seed)
    
    # 检查数据文件
    primevul_path = Path(primevul_dir)
    dev_file = primevul_path / "dev.jsonl"
    
    if not dev_file.exists():
        # 尝试其他可能的文件名
        possible_files = [
            primevul_path / "primevul_train.jsonl",
            primevul_path / "train.jsonl",
            primevul_path / "primevul_valid.jsonl"
        ]
        
        for possible_file in possible_files:
            if possible_file.exists():
                dev_file = possible_file
                break
        else:
            raise FileNotFoundError(f"No Primevul data file found in {primevul_dir}")
    
    logger.info(f"Using data file: {dev_file}")
    
    # 采样数据
    sampled_data, stats = sampler.sample_primevul_balanced(
        data_file=str(dev_file),
        sample_ratio=sample_ratio,
        balance_mode=balance_mode,
    )
    
    # 创建输出目录
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # 分割为训练和开发集
    train_data, dev_data = sampler.create_train_dev_split(
        sampled_data,
        dev_ratio=dev_ratio,
        label_field="_balance_label",
        min_dev_per_label=min_dev_per_label,
    )

    removed_benign = 0
    if remove_benign_train:
        original_train_len = len(train_data)
        train_data = [item for item in train_data if item.get("_balance_label") != "Benign"]
        removed_benign = original_train_len - len(train_data)

        if removed_benign:
            logger.info(
                "Removed %d Benign samples from training split to focus on vulnerable categories",
                removed_benign,
            )

        if not train_data:
            raise ValueError("Training split is empty after removing Benign samples.")
    
    # 保存数据文件
    files = {}
    
    # 保存JSONL格式（用于分析）
    files["train_jsonl"] = sampler.save_sampled_data(
        train_data, 
        str(output_path / "train_sample.jsonl"), 
        format="jsonl"
    )
    files["dev_jsonl"] = sampler.save_sampled_data(
        dev_data,
        str(output_path / "dev_sample.jsonl"),
        format="jsonl"
    )
    
    # 保存Tab格式（用于EvoPrompt）
    files["train_tab"] = sampler.save_sampled_data(
        train_data,
        str(output_path / "train.txt"),
        format="tab"
    )
    files["dev_tab"] = sampler.save_sampled_data(
        dev_data,
        str(output_path / "dev.txt"),
        format="tab"
    )
    
    # 保存统计信息
    stats_file = output_path / "sampling_stats.json"
    stats["files"] = files
    stats["train_without_benign"] = len(train_data)
    stats["train_removed_benign"] = removed_benign
    stats["sampling_config"] = {
        "sample_ratio": sample_ratio,
        "dev_ratio": dev_ratio,
        "seed": seed,
        "source_file": str(dev_file),
        "balance_mode": balance_mode,
        "train_remove_benign": remove_benign_train,
        "removed_benign_train": removed_benign,
        "min_dev_per_label": min_dev_per_label,
    }
    
    with open(stats_file, 'w', encoding='utf-8') as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)
    
    files["stats"] = str(stats_file)
    
    logger.info("Sampling complete!")
    logger.info(f"Files created:")
    for name, path in files.items():
        logger.info(f"  {name}: {path}")
    
    return {
        "files": files,
        "statistics": stats,
        "train_samples": len(train_data),
        "dev_samples": len(dev_data),
        "total_samples": len(sampled_data)
    }


class ContrastiveSampler:
    """对比学习样本采样器

    为每个目标CWE/类别采样三类代码:
    1. target: 目标漏洞代码
    2. other_vuln: 其他类型漏洞代码
    3. benign: 安全代码
    """

    def __init__(self, seed: int = 42):
        self.seed = seed
        random.seed(seed)

    def sample_contrastive_triplet(
        self,
        target_cwe: str,
        dataset_items: List[Dict[str, Any]],
        samples_per_type: int = 3
    ) -> Dict[str, List[Dict[str, Any]]]:
        """采样对比三元组

        Args:
            target_cwe: 目标CWE (如 "CWE-120")
            dataset_items: 数据集项列表
            samples_per_type: 每类采样数量

        Returns:
            {
                "target": [目标CWE漏洞样本],
                "other_vuln": [其他CWE漏洞样本],
                "benign": [安全代码样本]
            }
        """
        target_samples = []
        other_vuln_samples = []
        benign_samples = []

        for item in dataset_items:
            target_val = item.get("target", 0)
            try:
                is_vuln = int(target_val) == 1
            except (TypeError, ValueError):
                is_vuln = False

            if not is_vuln:
                benign_samples.append(item)
            else:
                cwe_codes = item.get("cwe", [])
                if isinstance(cwe_codes, str):
                    cwe_codes = [cwe_codes] if cwe_codes else []

                if target_cwe in cwe_codes:
                    target_samples.append(item)
                else:
                    other_vuln_samples.append(item)

        # 随机采样
        result = {
            "target": random.sample(target_samples, min(samples_per_type, len(target_samples))) if target_samples else [],
            "other_vuln": random.sample(other_vuln_samples, min(samples_per_type, len(other_vuln_samples))) if other_vuln_samples else [],
            "benign": random.sample(benign_samples, min(samples_per_type, len(benign_samples))) if benign_samples else [],
        }

        return result

    def sample_contrastive_for_major_category(
        self,
        target_major: str,
        dataset_items: List[Dict[str, Any]],
        samples_per_type: int = 3
    ) -> Dict[str, List[Dict[str, Any]]]:
        """为Major Category采样对比三元组

        Args:
            target_major: 目标大类 (如 "Memory", "Injection")
            dataset_items: 数据集项列表
            samples_per_type: 每类采样数量

        Returns:
            对比三元组
        """
        target_samples = []
        other_vuln_samples = []
        benign_samples = []

        for item in dataset_items:
            target_val = item.get("target", 0)
            try:
                is_vuln = int(target_val) == 1
            except (TypeError, ValueError):
                is_vuln = False

            if not is_vuln:
                benign_samples.append(item)
            else:
                cwe_codes = item.get("cwe", [])
                if isinstance(cwe_codes, str):
                    cwe_codes = [cwe_codes] if cwe_codes else []

                item_major = map_cwe_to_major(cwe_codes) if cwe_codes else "Other"

                if item_major == target_major:
                    target_samples.append(item)
                else:
                    other_vuln_samples.append(item)

        result = {
            "target": random.sample(target_samples, min(samples_per_type, len(target_samples))) if target_samples else [],
            "other_vuln": random.sample(other_vuln_samples, min(samples_per_type, len(other_vuln_samples))) if other_vuln_samples else [],
            "benign": random.sample(benign_samples, min(samples_per_type, len(benign_samples))) if benign_samples else [],
        }

        return result

    def format_samples_for_prompt(
        self,
        samples: List[Dict[str, Any]],
        max_code_length: int = 500
    ) -> str:
        """格式化样本用于prompt

        Args:
            samples: 样本列表
            max_code_length: 代码最大长度

        Returns:
            格式化的字符串
        """
        if not samples:
            return "(No samples available)"

        formatted = []
        for i, sample in enumerate(samples, 1):
            code = sample.get("func", "")[:max_code_length]
            cwe = sample.get("cwe", [])
            if isinstance(cwe, list):
                cwe = ", ".join(cwe) if cwe else "N/A"

            formatted.append(f"Example {i} (CWE: {cwe}):\n```\n{code}\n```")

        return "\n\n".join(formatted)
