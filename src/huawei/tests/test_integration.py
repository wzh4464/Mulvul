"""华为数据集集成测试."""

import json
import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from ..dataset import HuaweiDataset
from ..prompt_manager import HuaweiPromptManager
from ..workflow import HuaweiWorkflow, HuaweiSecurityEvaluator


class MockLLMClient:
    """模拟 LLM 客户端."""

    def __init__(self):
        self.call_count = 0

    def generate(self, prompt: str, **kwargs) -> str:
        """模拟生成响应."""
        self.call_count += 1

        # 模拟不同类型的响应
        if "函数指针" in prompt or "memcpy_s" in prompt:
            return json.dumps({
                "vulnerabilities": [
                    {
                        "category": "函数指针参数未校验",
                        "line": "memcpy_s(password, 10, src, 10)",
                        "confidence": "high"
                    }
                ]
            }, ensure_ascii=False)
        else:
            return json.dumps({"vulnerabilities": []}, ensure_ascii=False)


class TestIntegration:
    """集成测试."""

    @pytest.fixture
    def complete_config(self):
        """完整配置."""
        return {
            "dataset": {
                "name": "huawei_security_benchmark",
                "description": "华为安全缺陷检测数据集",
                "data_path": "data/huawei/benchmark.json",
                "language": "cpp",
                "task_type": "vulnerability_detection"
            },
            "categories": {
                "函数指针参数未校验": {
                    "cwe_id": 476,
                    "description": "对函数指针参数未进行空指针检查",
                    "severity": "high"
                },
                "缓冲区溢出": {
                    "cwe_id": 120,
                    "description": "缓冲区边界检查不当",
                    "severity": "high"
                }
            },
            "prompt_templates": {
                "base_template": "分析{lang}代码安全问题：\\n{category_list}\\n```{lang}\\n{code}\\n```\\n结果：",
                "detailed_template": "详细分析{lang}代码：\\n类型：{category_list}\\n代码：\\n```{lang}\\n{code}\\n```\\n分析："
            },
            "evolution_config": {
                "population_size": 4,
                "max_generations": 2,
                "mutation_rate": 0.3,
                "crossover_rate": 0.7,
                "early_stopping": {
                    "enabled": True,
                    "patience": 2,
                    "min_improvement": 0.01
                }
            },
            "evaluation_config": {
                "metrics": ["accuracy", "precision", "recall", "f1_score"],
                "max_eval_samples": 10
            },
            "llm_config": {
                "temperature": 0.1,
                "max_tokens": 1000
            },
            "output_config": {
                "base_dir": "./outputs/test_huawei"
            }
        }

    @pytest.fixture
    def sample_dataset(self):
        """示例数据集."""
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
            },
            {
                "code": "void vulnerable_func(char* buf) { strcpy(buf, input); }",
                "fp": [],
                "gt": [
                    {
                        "category": "缓冲区溢出",
                        "cwe_id": 120,
                        "line": "strcpy(buf, input)",
                        "lineno": 1
                    }
                ],
                "index": 2,
                "lang": "cpp",
                "source": "tp"
            }
        ]

    def test_dataset_and_prompt_manager_integration(self, complete_config, sample_dataset):
        """测试数据集和 prompt 管理器集成."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # 创建文件
            config_file = Path(temp_dir) / "config.json"
            data_file = Path(temp_dir) / "data.json"

            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(complete_config, f)

            with open(data_file, 'w', encoding='utf-8') as f:
                json.dump(sample_dataset, f)

            # 初始化组件
            dataset = HuaweiDataset(str(data_file), str(config_file))
            prompt_manager = HuaweiPromptManager(str(config_file))

            # 加载数据
            samples = dataset.load_data(str(data_file))
            assert len(samples) == 3

            # 初始化 prompts
            prompts = prompt_manager.initialize_prompts(4)
            assert len(prompts) == 4

            # 构建完整 prompt
            test_sample = samples[0]
            built_prompt = prompt_manager.build_prompt(
                prompts[0], test_sample.code, "cpp"
            )

            assert "函数指针参数未校验" in built_prompt
            assert "memcpy_s" in built_prompt

    def test_evaluator_integration(self, complete_config, sample_dataset):
        """测试评估器集成."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.json"
            data_file = Path(temp_dir) / "data.json"

            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(complete_config, f)

            with open(data_file, 'w', encoding='utf-8') as f:
                json.dump(sample_dataset, f)

            # 初始化组件
            dataset = HuaweiDataset(str(data_file), str(config_file))
            dataset.load_data(str(data_file))

            mock_client = MockLLMClient()
            evaluator = HuaweiSecurityEvaluator(dataset, mock_client, complete_config)

            # 测试评估
            test_prompt = "分析{lang}代码：\\n{category_list}\\n```{lang}\\n{code}\\n```"
            metrics = evaluator.evaluate_prompt(test_prompt)

            assert "accuracy" in metrics
            assert "precision" in metrics
            assert "recall" in metrics
            assert "f1_score" in metrics
            assert mock_client.call_count > 0

    def test_response_parsing(self, complete_config, sample_dataset):
        """测试响应解析."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.json"
            data_file = Path(temp_dir) / "data.json"

            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(complete_config, f)

            with open(data_file, 'w', encoding='utf-8') as f:
                json.dump(sample_dataset, f)

            dataset = HuaweiDataset(str(data_file), str(config_file))
            mock_client = MockLLMClient()
            evaluator = HuaweiSecurityEvaluator(dataset, mock_client, complete_config)

            # 测试 JSON 响应解析
            json_response = '{"vulnerabilities": [{"category": "test", "line": "test"}]}'
            parsed = evaluator._parse_response(json_response)
            assert parsed["vulnerabilities"][0]["category"] == "test"

            # 测试嵌入式 JSON 响应解析
            embedded_response = '分析结果是：{"vulnerabilities": []} 完成。'
            parsed = evaluator._parse_response(embedded_response)
            assert parsed["vulnerabilities"] == []

            # 测试无效响应
            invalid_response = "这不是有效的JSON响应"
            parsed = evaluator._parse_response(invalid_response)
            assert parsed["vulnerabilities"] == []

    @patch('src.huawei.workflow.create_llm_client')
    def test_workflow_initialization(self, mock_create_client, complete_config, sample_dataset):
        """测试工作流程初始化."""
        mock_create_client.return_value = MockLLMClient()

        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.json"
            data_file = Path(temp_dir) / "data.json"

            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(complete_config, f)

            with open(data_file, 'w', encoding='utf-8') as f:
                json.dump(sample_dataset, f)

            # 初始化工作流程
            workflow = HuaweiWorkflow(str(config_file), str(data_file))

            assert workflow.config == complete_config
            assert workflow.dataset is not None
            assert workflow.prompt_manager is not None
            assert workflow.output_dir.exists()

            # 加载数据
            workflow.load_and_prepare_data(sample_size=2)
            assert len(workflow.dataset.get_samples()) >= 2

    def test_metrics_calculation(self, complete_config, sample_dataset):
        """测试指标计算."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.json"
            data_file = Path(temp_dir) / "data.json"

            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(complete_config, f)

            with open(data_file, 'w', encoding='utf-8') as f:
                json.dump(sample_dataset, f)

            dataset = HuaweiDataset(str(data_file), str(config_file))
            mock_client = MockLLMClient()
            evaluator = HuaweiSecurityEvaluator(dataset, mock_client, complete_config)

            # 模拟预测和真实标签
            predictions = [
                {"vulnerabilities": [{"category": "test"}]},  # 预测有漏洞
                {"vulnerabilities": []},  # 预测无漏洞
                {"vulnerabilities": [{"category": "test"}]},  # 预测有漏洞
            ]

            ground_truths = [
                {"vulnerabilities": [{"category": "true"}]},  # 真实有漏洞
                {"vulnerabilities": []},  # 真实无漏洞
                {"vulnerabilities": []},  # 真实无漏洞
            ]

            metrics = evaluator._calculate_metrics(predictions, ground_truths)

            # 验证指标计算
            assert "accuracy" in metrics
            assert "precision" in metrics
            assert "recall" in metrics
            assert "f1_score" in metrics
            assert metrics["tp"] == 1  # 正确预测有漏洞
            assert metrics["tn"] == 1  # 正确预测无漏洞
            assert metrics["fp"] == 1  # 误报
            assert metrics["fn"] == 0  # 漏报

    def test_dataset_statistics_integration(self, complete_config, sample_dataset):
        """测试数据集统计集成."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.json"
            data_file = Path(temp_dir) / "data.json"

            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(complete_config, f)

            with open(data_file, 'w', encoding='utf-8') as f:
                json.dump(sample_dataset, f)

            dataset = HuaweiDataset(str(data_file), str(config_file))
            dataset.load_data(str(data_file))

            stats = dataset.get_statistics()

            assert stats["total_samples"] == 3
            assert stats["vulnerable_samples"] == 2
            assert stats["clean_samples"] == 1
            assert stats["vulnerability_ratio"] == 2/3

            # 检查类别分布
            assert "函数指针参数未校验" in stats["category_distribution"]
            assert "缓冲区溢出" in stats["category_distribution"]
            assert stats["category_distribution"]["函数指针参数未校验"] == 1
            assert stats["category_distribution"]["缓冲区溢出"] == 1

    def test_prompt_evolution_strategies(self, complete_config):
        """测试 prompt 进化策略集成."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.json"

            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(complete_config, f)

            prompt_manager = HuaweiPromptManager(str(config_file))

            # 初始化种群
            population = prompt_manager.initialize_prompts(4)

            # 测试变异
            mutated = prompt_manager.mutate_prompt(population[0], mutation_rate=1.0)
            assert isinstance(mutated, str)

            # 测试交叉
            child1, child2 = prompt_manager.crossover_prompts(population[0], population[1])
            assert isinstance(child1, str)
            assert isinstance(child2, str)

            # 测试 prompt 构建
            built = prompt_manager.build_prompt(
                population[0],
                "int test() { return 0; }",
                "cpp"
            )
            assert "函数指针参数未校验" in built

    def test_error_handling_integration(self, complete_config, sample_dataset):
        """测试错误处理集成."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.json"
            data_file = Path(temp_dir) / "data.json"

            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(complete_config, f)

            with open(data_file, 'w', encoding='utf-8') as f:
                json.dump(sample_dataset, f)

            dataset = HuaweiDataset(str(data_file), str(config_file))

            # 测试处理损坏的样本
            corrupted_data = sample_dataset + [{"invalid": "sample"}]

            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump(corrupted_data, f)
                corrupted_file = f.name

            # 应该跳过损坏的样本
            samples = dataset.load_data(corrupted_file)
            assert len(samples) == 3  # 只加载有效样本

            Path(corrupted_file).unlink()  # 清理临时文件

    def test_configuration_validation(self):
        """测试配置验证."""
        # 测试空配置
        empty_config = {}

        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "empty_config.json"
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(empty_config, f)

            # 应该使用默认配置
            prompt_manager = HuaweiPromptManager(str(config_file))
            assert prompt_manager.categories == []
            assert prompt_manager.templates == {}

    def test_end_to_end_small_scale(self, complete_config, sample_dataset):
        """测试小规模端到端流程."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.json"
            data_file = Path(temp_dir) / "data.json"

            # 修改配置以进行快速测试
            test_config = complete_config.copy()
            test_config["evolution_config"]["population_size"] = 2
            test_config["evolution_config"]["max_generations"] = 1
            test_config["evaluation_config"]["max_eval_samples"] = 2

            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(test_config, f)

            with open(data_file, 'w', encoding='utf-8') as f:
                json.dump(sample_dataset[:2], f)  # 只使用前两个样本

            # 模拟完整流程
            dataset = HuaweiDataset(str(data_file), str(config_file))
            prompt_manager = HuaweiPromptManager(str(config_file))

            # 加载数据
            samples = dataset.load_data(str(data_file))
            assert len(samples) == 2

            # 初始化 prompts
            prompts = prompt_manager.initialize_prompts(2)
            assert len(prompts) == 2

            # 构建和评估 prompts
            mock_client = MockLLMClient()
            evaluator = HuaweiSecurityEvaluator(dataset, mock_client, test_config)

            for prompt in prompts:
                built_prompt = prompt_manager.build_prompt(
                    prompt, samples[0].code, "cpp"
                )
                metrics = evaluator.evaluate_prompt(built_prompt, samples[:1])
                assert "f1_score" in metrics

            # 测试进化操作
            child1, child2 = prompt_manager.crossover_prompts(prompts[0], prompts[1])
            mutated = prompt_manager.mutate_prompt(prompts[0])

            assert isinstance(child1, str)
            assert isinstance(child2, str)
            assert isinstance(mutated, str)