"""华为数据集测试用例."""

import json
import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock

from ..dataset import HuaweiDataset, HuaweiSecuritySample


class TestHuaweiSecuritySample:
    """华为安全样本测试."""

    def test_sample_creation(self):
        """测试样本创建."""
        code = "int x = 0;"
        gt = [{"category": "函数指针参数未校验", "cwe_id": 476, "line": "int x = 0;", "lineno": 1}]
        fp = []

        sample = HuaweiSecuritySample(code, gt, fp)

        assert sample.code == code
        assert sample.ground_truth == gt
        assert sample.false_positives == fp
        assert sample.has_vulnerabilities() == True
        assert sample.get_vulnerability_categories() == ["函数指针参数未校验"]
        assert sample.get_cwe_ids() == [476]

    def test_sample_no_vulnerabilities(self):
        """测试无漏洞样本."""
        code = "int x = 0;"
        gt = []
        fp = []

        sample = HuaweiSecuritySample(code, gt, fp)

        assert sample.has_vulnerabilities() == False
        assert sample.get_vulnerability_categories() == []
        assert sample.get_cwe_ids() == []

    def test_sample_target_format(self):
        """测试目标格式."""
        code = "int x = 0;"
        gt = [{"category": "函数指针参数未校验", "cwe_id": 476}]
        fp = []

        sample = HuaweiSecuritySample(code, gt, fp)

        expected_target = json.dumps({"vulnerabilities": gt}, ensure_ascii=False)
        assert sample.target == expected_target


class TestHuaweiDataset:
    """华为数据集测试."""

    @pytest.fixture
    def sample_data(self):
        """示例数据."""
        return [
            {
                "code": "int getCacheDevpwd(VOS_CHAR* password)\\n{\\n  return memcpy_s(password, 10, src, 10);\\n}",
                "fp": [],
                "gt": [
                    {
                        "category": "函数指针参数未校验",
                        "cwe_id": 476,
                        "line": "memcpy_s(password, 10, src, 10)",
                        "lineno": 3
                    }
                ],
                "index": 0,
                "lang": "cpp",
                "source": "tp"
            },
            {
                "code": "int safe_function() { return 0; }",
                "fp": [],
                "gt": [],
                "index": 1,
                "lang": "cpp",
                "source": "tn"
            }
        ]

    @pytest.fixture
    def config_data(self):
        """示例配置."""
        return {
            "categories": {
                "函数指针参数未校验": {
                    "cwe_id": 476,
                    "description": "对函数指针参数未进行空指针检查",
                    "severity": "high"
                },
                "缓冲区溢出": {
                    "cwe_id": 120,
                    "description": "缓冲区边界检查不当导致的溢出",
                    "severity": "high"
                }
            }
        }

    def test_dataset_creation(self, config_data):
        """测试数据集创建."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.json"
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(config_data, f)

            dataset = HuaweiDataset(
                data_path="dummy_path",
                config_path=str(config_file)
            )

            assert dataset.name == "huawei_security"
            assert dataset.get_categories() == ["函数指针参数未校验", "缓冲区溢出"]

    def test_load_data(self, sample_data, config_data):
        """测试数据加载."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # 创建数据文件
            data_file = Path(temp_dir) / "data.json"
            with open(data_file, 'w', encoding='utf-8') as f:
                json.dump(sample_data, f)

            # 创建配置文件
            config_file = Path(temp_dir) / "config.json"
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(config_data, f)

            dataset = HuaweiDataset(
                data_path=str(data_file),
                config_path=str(config_file)
            )

            samples = dataset.load_data(str(data_file))

            assert len(samples) == 2
            assert isinstance(samples[0], HuaweiSecuritySample)
            assert samples[0].has_vulnerabilities() == True
            assert samples[1].has_vulnerabilities() == False

    def test_get_statistics(self, sample_data, config_data):
        """测试统计信息."""
        with tempfile.TemporaryDirectory() as temp_dir:
            data_file = Path(temp_dir) / "data.json"
            with open(data_file, 'w', encoding='utf-8') as f:
                json.dump(sample_data, f)

            config_file = Path(temp_dir) / "config.json"
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(config_data, f)

            dataset = HuaweiDataset(
                data_path=str(data_file),
                config_path=str(config_file)
            )
            dataset.load_data(str(data_file))

            stats = dataset.get_statistics()

            assert stats["total_samples"] == 2
            assert stats["vulnerable_samples"] == 1
            assert stats["clean_samples"] == 1
            assert stats["vulnerability_ratio"] == 0.5
            assert "函数指针参数未校验" in stats["category_distribution"]

    def test_sample_balanced(self, sample_data, config_data):
        """测试均衡采样."""
        # 创建更多样本用于测试采样
        extended_data = sample_data * 5  # 10个样本

        with tempfile.TemporaryDirectory() as temp_dir:
            data_file = Path(temp_dir) / "data.json"
            with open(data_file, 'w', encoding='utf-8') as f:
                json.dump(extended_data, f)

            config_file = Path(temp_dir) / "config.json"
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(config_data, f)

            dataset = HuaweiDataset(
                data_path=str(data_file),
                config_path=str(config_file)
            )
            dataset.load_data(str(data_file))

            sampled = dataset.sample_balanced(n_samples=6, random_seed=42)

            assert len(sampled) == 6
            # 检查是否有漏洞样本和干净样本
            vulnerable_count = sum(1 for s in sampled if s.has_vulnerabilities())
            clean_count = len(sampled) - vulnerable_count
            assert vulnerable_count > 0
            assert clean_count > 0

    def test_get_samples_by_category(self, sample_data, config_data):
        """测试按类别获取样本."""
        with tempfile.TemporaryDirectory() as temp_dir:
            data_file = Path(temp_dir) / "data.json"
            with open(data_file, 'w', encoding='utf-8') as f:
                json.dump(sample_data, f)

            config_file = Path(temp_dir) / "config.json"
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(config_data, f)

            dataset = HuaweiDataset(
                data_path=str(data_file),
                config_path=str(config_file)
            )
            dataset.load_data(str(data_file))

            category_samples = dataset.get_samples_by_category("函数指针参数未校验")
            assert len(category_samples) == 1
            assert category_samples[0].has_vulnerabilities() == True

            # 测试不存在的类别
            empty_samples = dataset.get_samples_by_category("不存在的类别")
            assert len(empty_samples) == 0

    def test_invalid_data_file(self):
        """测试无效数据文件."""
        dataset = HuaweiDataset("nonexistent_file.json")

        with pytest.raises(FileNotFoundError):
            dataset.load_data("nonexistent_file.json")

    def test_invalid_data_format(self, config_data):
        """测试无效数据格式."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # 创建无效的数据文件（不是数组）
            data_file = Path(temp_dir) / "invalid_data.json"
            with open(data_file, 'w', encoding='utf-8') as f:
                json.dump({"not": "array"}, f)

            config_file = Path(temp_dir) / "config.json"
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(config_data, f)

            dataset = HuaweiDataset(
                data_path=str(data_file),
                config_path=str(config_file)
            )

            with pytest.raises(ValueError, match="数据文件格式错误"):
                dataset.load_data(str(data_file))

    def test_get_category_info(self, config_data):
        """测试获取类别信息."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.json"
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(config_data, f)

            dataset = HuaweiDataset(
                data_path="dummy_path",
                config_path=str(config_file)
            )

            info = dataset.get_category_info("函数指针参数未校验")
            assert info["cwe_id"] == 476
            assert info["severity"] == "high"

            # 测试不存在的类别
            empty_info = dataset.get_category_info("不存在的类别")
            assert empty_info == {}

    def test_dataset_without_config(self):
        """测试无配置文件的数据集."""
        dataset = HuaweiDataset("dummy_path")

        assert dataset.config == {
            "categories": {},
            "prompt_templates": {},
            "evaluation_config": {"metrics": ["accuracy", "f1_score"]}
        }
        assert dataset.get_categories() == []