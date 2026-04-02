###
# File: ./EvoPrompt/src/huawei/dataset.py
# Created Date: Monday, September 29th 2025
# Author: Zihan
# -----
# Last Modified: Monday, 29th September 2025 9:06:26 pm
# Modified By: the developer formerly known as Zihan at <wzh4464@gmail.com>
# -----
# HISTORY:
# Date      		By   	Comments
# ----------		------	---------------------------------------------------------
###

"""华为安全缺陷检测数据集实现."""

import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

try:
    from ..evoprompt.data.dataset import Dataset, Sample
except ImportError:
    # 处理直接运行时的导入问题
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from evoprompt.data.dataset import Dataset, Sample

logger = logging.getLogger(__name__)


class HuaweiSecuritySample(Sample):
    """华为安全数据集的样本类."""

    def __init__(
        self,
        code: str,
        ground_truth: List[Dict],
        false_positives: List[Dict],
        metadata: Optional[Dict] = None
    ):
        # 构造target字符串 - 将GT转换为JSON字符串
        target = json.dumps({"vulnerabilities": ground_truth}, ensure_ascii=False)

        super().__init__(
            input_text=code,
            target=target,
            metadata=metadata or {}
        )

        self.code = code
        self.ground_truth = ground_truth
        self.false_positives = false_positives

    def has_vulnerabilities(self) -> bool:
        """检查是否包含真实漏洞."""
        return len(self.ground_truth) > 0

    def get_vulnerability_categories(self) -> List[str]:
        """获取所有漏洞类别."""
        return [vuln.get("category", "") for vuln in self.ground_truth]

    def get_cwe_ids(self) -> List[int]:
        """获取所有CWE ID."""
        return [vuln.get("cwe_id", 0) for vuln in self.ground_truth]


class HuaweiDataset(Dataset):
    """华为安全缺陷检测数据集."""

    def __init__(self, data_path: str, config_path: Optional[str] = None):
        super().__init__("huawei_security")
        self.data_path = Path(data_path)
        self.config_path = Path(config_path) if config_path else None
        self.config = self._load_config()
        self.categories = self._extract_categories()

    def _load_config(self) -> Dict[str, Any]:
        """加载配置文件."""
        if self.config_path and self.config_path.exists():
            with open(self.config_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        else:
            # 默认配置
            return {
                "categories": {},
                "prompt_templates": {},
                "evaluation_config": {"metrics": ["accuracy", "f1_score"]}
            }

    def _extract_categories(self) -> List[str]:
        """从配置中提取类别列表."""
        return list(self.config.get("categories", {}).keys())

    def load_data(self, data_path: str) -> List[HuaweiSecuritySample]:
        """加载华为数据集."""
        data_file = Path(data_path)
        if not data_file.exists():
            raise FileNotFoundError(f"数据文件不存在: {data_path}")

        with open(data_file, 'r', encoding='utf-8') as f:
            raw_data = json.load(f)

        if not isinstance(raw_data, list):
            raise ValueError("数据文件格式错误，应为JSON数组")

        samples = []
        for idx, item in enumerate(raw_data):
            try:
                sample = HuaweiSecuritySample(
                    code=item.get("code", ""),
                    ground_truth=item.get("gt", []),
                    false_positives=item.get("fp", []),
                    metadata={
                        "index": item.get("index", idx),
                        "lang": item.get("lang", "cpp"),
                        "source": item.get("source", "unknown")
                    }
                )
                samples.append(sample)
            except Exception as e:
                logger.warning(f"跳过格式错误的样本 {idx}: {e}")
                continue

        self._samples = samples
        logger.info(f"成功加载 {len(samples)} 个样本")
        return samples

    def get_categories(self) -> List[str]:
        """获取所有支持的漏洞类别."""
        return self.categories

    def get_category_info(self, category: str) -> Dict[str, Any]:
        """获取特定类别的详细信息."""
        return self.config.get("categories", {}).get(category, {})

    def get_samples_by_category(self, category: str) -> List[HuaweiSecuritySample]:
        """获取包含特定类别漏洞的样本."""
        return [
            sample for sample in self._samples
            if category in sample.get_vulnerability_categories()
        ]

    def get_vulnerable_samples(self) -> List[HuaweiSecuritySample]:
        """获取包含漏洞的样本."""
        return [sample for sample in self._samples if sample.has_vulnerabilities()]

    def get_clean_samples(self) -> List[HuaweiSecuritySample]:
        """获取不包含漏洞的样本."""
        return [sample for sample in self._samples if not sample.has_vulnerabilities()]

    def get_statistics(self) -> Dict[str, Any]:
        """获取数据集统计信息."""
        total_samples = len(self._samples)
        vulnerable_samples = len(self.get_vulnerable_samples())
        clean_samples = len(self.get_clean_samples())

        # 统计每个类别的样本数
        category_stats = {}
        for category in self.categories:
            category_samples = self.get_samples_by_category(category)
            category_stats[category] = len(category_samples)

        return {
            "total_samples": total_samples,
            "vulnerable_samples": vulnerable_samples,
            "clean_samples": clean_samples,
            "vulnerability_ratio": vulnerable_samples / total_samples if total_samples > 0 else 0,
            "category_distribution": category_stats,
            "supported_categories": self.categories
        }

    def sample_balanced(self, n_samples: int, random_seed: int = 42) -> List[HuaweiSecuritySample]:
        """均衡采样指定数量的样本."""
        import random
        random.seed(random_seed)

        vulnerable = self.get_vulnerable_samples()
        clean = self.get_clean_samples()

        # 计算每类的采样数量
        n_vulnerable = min(n_samples // 2, len(vulnerable))
        n_clean = min(n_samples - n_vulnerable, len(clean))

        # 随机采样
        sampled_vulnerable = random.sample(vulnerable, n_vulnerable)
        sampled_clean = random.sample(clean, n_clean)

        result = sampled_vulnerable + sampled_clean
        random.shuffle(result)

        logger.info(f"均衡采样完成: {len(sampled_vulnerable)} 个漏洞样本, {len(sampled_clean)} 个干净样本")
        return result

