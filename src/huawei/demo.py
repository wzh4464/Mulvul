#!/usr/bin/env python3
"""华为安全检测数据集演示脚本."""

import json
import logging
import sys
from pathlib import Path

# 添加src路径
sys.path.insert(0, str(Path(__file__).parent.parent))

from huawei.dataset import HuaweiDataset
from huawei.prompt_manager import HuaweiPromptManager


def setup_logging():
    """设置日志."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    return logging.getLogger(__name__)


def demo_dataset_functionality():
    """演示数据集功能."""
    logger = setup_logging()
    logger.info("=== 华为数据集功能演示 ===")

    # 数据文件路径
    data_path = "data/huawei/benchmark.json"
    config_path = "src/huawei/config/huawei_config.json"

    try:
        # 检查文件是否存在
        if not Path(data_path).exists():
            logger.error(f"数据文件不存在: {data_path}")
            logger.info("请确保数据文件在正确位置")
            return

        if not Path(config_path).exists():
            logger.error(f"配置文件不存在: {config_path}")
            logger.info("请确保配置文件在正确位置")
            return

        # 初始化数据集
        logger.info("1. 初始化华为数据集...")
        dataset = HuaweiDataset(data_path, config_path)

        # 加载数据
        logger.info("2. 加载数据...")
        samples = dataset.load_data(data_path)
        logger.info(f"成功加载 {len(samples)} 个样本")

        # 显示数据集统计
        logger.info("3. 数据集统计信息:")
        stats = dataset.get_statistics()
        for key, value in stats.items():
            if isinstance(value, dict):
                logger.info(f"  {key}:")
                for sub_key, sub_value in value.items():
                    logger.info(f"    {sub_key}: {sub_value}")
            else:
                logger.info(f"  {key}: {value}")

        # 显示支持的类别
        logger.info("4. 支持的漏洞类别:")
        categories = dataset.get_categories()
        for category in categories:
            info = dataset.get_category_info(category)
            logger.info(f"  - {category} (CWE-{info.get('cwe_id', 'N/A')}): {info.get('description', 'N/A')}")

        # 展示样本示例
        logger.info("5. 样本示例:")
        if samples:
            sample = samples[0]
            logger.info(f"  代码: {sample.code[:100]}...")
            logger.info(f"  语言: {sample.metadata.get('lang', 'unknown')}")
            logger.info(f"  是否包含漏洞: {sample.has_vulnerabilities()}")
            if sample.has_vulnerabilities():
                logger.info(f"  漏洞类别: {sample.get_vulnerability_categories()}")
                logger.info(f"  CWE ID: {sample.get_cwe_ids()}")

        # 均衡采样演示
        logger.info("6. 均衡采样演示:")
        if len(samples) >= 6:
            sampled = dataset.sample_balanced(n_samples=6, random_seed=42)
            vulnerable_count = sum(1 for s in sampled if s.has_vulnerabilities())
            logger.info(f"  采样 6 个样本，其中 {vulnerable_count} 个包含漏洞，{6-vulnerable_count} 个干净样本")

        # 按类别筛选
        logger.info("7. 按类别筛选演示:")
        for category in categories[:2]:  # 只演示前两个类别
            category_samples = dataset.get_samples_by_category(category)
            logger.info(f"  {category}: {len(category_samples)} 个样本")

    except Exception as e:
        logger.error(f"演示过程中出错: {e}")
        import traceback
        traceback.print_exc()


def demo_prompt_manager_functionality():
    """演示 Prompt 管理器功能."""
    logger = setup_logging()
    logger.info("\\n=== Prompt 管理器功能演示 ===")

    config_path = "src/huawei/config/huawei_config.json"

    try:
        if not Path(config_path).exists():
            logger.error(f"配置文件不存在: {config_path}")
            return

        # 初始化 Prompt 管理器
        logger.info("1. 初始化 Prompt 管理器...")
        prompt_manager = HuaweiPromptManager(config_path)

        # 显示可用模板
        logger.info("2. 可用的 Prompt 模板:")
        templates = prompt_manager.get_all_templates()
        for name, template in templates.items():
            logger.info(f"  - {name}: {template[:80]}...")

        # 初始化 prompt 种群
        logger.info("3. 初始化 Prompt 种群...")
        population_size = 4
        prompts = prompt_manager.initialize_prompts(population_size)
        logger.info(f"成功初始化 {len(prompts)} 个 prompt")

        for i, prompt in enumerate(prompts):
            logger.info(f"  Prompt {i+1}: {prompt[:60]}...")

        # 演示 prompt 构建
        logger.info("4. 演示 Prompt 构建...")
        test_code = """int getCacheDevpwd(VOS_CHAR* password)
{
    SpsDbAdapter::tTblDevPwdRecord devpwdRecord = SpsDbAdapter::DevPwdCache::Instance().GetRecord();
    char* pwdStr = devpwdRecord.devPwdRecordInfo.password;
    VOS_UINT32 ret = memcpy_s(password, strlen(pwdStr) + 1, pwdStr, strlen(pwdStr) + 1);
    return ret == EOK ? VOS_OK : VOS_ERR;
}"""

        built_prompt = prompt_manager.build_prompt(
            templates["base_template"],
            test_code,
            "cpp"
        )
        logger.info("构建的完整 prompt (前200字符):")
        logger.info(f"  {built_prompt[:200]}...")

        # 演示变异操作
        logger.info("5. 演示 Prompt 变异...")
        original_prompt = prompts[0]
        mutated_prompt = prompt_manager.mutate_prompt(original_prompt, mutation_rate=1.0)
        logger.info("原始 prompt (前60字符):")
        logger.info(f"  {original_prompt[:60]}...")
        logger.info("变异后 prompt (前60字符):")
        logger.info(f"  {mutated_prompt[:60]}...")

        # 演示交叉操作
        logger.info("6. 演示 Prompt 交叉...")
        if len(prompts) >= 2:
            parent1 = prompts[0]
            parent2 = prompts[1]
            child1, child2 = prompt_manager.crossover_prompts(parent1, parent2)

            logger.info("父代1 (前50字符):")
            logger.info(f"  {parent1[:50]}...")
            logger.info("父代2 (前50字符):")
            logger.info(f"  {parent2[:50]}...")
            logger.info("子代1 (前50字符):")
            logger.info(f"  {child1[:50]}...")
            logger.info("子代2 (前50字符):")
            logger.info(f"  {child2[:50]}...")

        # 演示多样化策略
        logger.info("7. 演示多样化策略...")
        base_prompt = "分析代码安全问题"
        strategies = [
            ("添加强调", prompt_manager._add_emphasis),
            ("改变语气", prompt_manager._change_tone),
            ("语义变异", prompt_manager._semantic_mutation)
        ]

        for strategy_name, strategy_func in strategies:
            try:
                modified = strategy_func(base_prompt)
                logger.info(f"  {strategy_name}: {modified}")
            except Exception as e:
                logger.warning(f"  {strategy_name} 策略执行失败: {e}")

    except Exception as e:
        logger.error(f"Prompt 管理器演示过程中出错: {e}")
        import traceback
        traceback.print_exc()


def demo_mock_evaluation():
    """演示模拟评估流程."""
    logger = setup_logging()
    logger.info("\\n=== 模拟评估流程演示 ===")

    class MockLLMClient:
        """模拟 LLM 客户端."""
        def generate(self, prompt, **kwargs):
            # 简单的模拟逻辑
            if "memcpy_s" in prompt and "password" in prompt:
                return json.dumps({
                    "vulnerabilities": [
                        {
                            "category": "函数指针参数未校验",
                            "line": "memcpy_s(password, strlen(pwdStr) + 1, pwdStr, strlen(pwdStr) + 1)",
                            "confidence": "high"
                        }
                    ]
                }, ensure_ascii=False)
            else:
                return json.dumps({"vulnerabilities": []}, ensure_ascii=False)

    try:
        # 创建模拟数据
        sample_data = [
            {
                "code": "int getCacheDevpwd(VOS_CHAR* password) { return memcpy_s(password, 10, src, 10); }",
                "gt": [{"category": "函数指针参数未校验", "cwe_id": 476}],
                "fp": [],
                "lang": "cpp"
            },
            {
                "code": "int safe_function() { return 0; }",
                "gt": [],
                "fp": [],
                "lang": "cpp"
            }
        ]

        # 模拟评估过程
        mock_client = MockLLMClient()
        config_path = "src/huawei/config/huawei_config.json"

        if Path(config_path).exists():
            prompt_manager = HuaweiPromptManager(config_path)

            test_prompt = prompt_manager.get_template_by_name("base_template")
            if test_prompt:
                logger.info("1. 使用模拟 LLM 进行评估...")

                correct_predictions = 0
                total_predictions = 0

                for i, sample in enumerate(sample_data):
                    # 构建 prompt
                    full_prompt = prompt_manager.build_prompt(
                        test_prompt,
                        sample["code"],
                        sample["lang"]
                    )

                    # 获取预测
                    response = mock_client.generate(full_prompt)
                    logger.info(f"  样本 {i+1} 预测: {response}")

                    # 简单的正确性检查
                    predicted_has_vuln = "vulnerabilities" in response and len(json.loads(response)["vulnerabilities"]) > 0
                    actual_has_vuln = len(sample["gt"]) > 0

                    if predicted_has_vuln == actual_has_vuln:
                        correct_predictions += 1

                    total_predictions += 1

                accuracy = correct_predictions / total_predictions if total_predictions > 0 else 0
                logger.info(f"2. 模拟评估结果:")
                logger.info(f"  准确率: {accuracy:.2f} ({correct_predictions}/{total_predictions})")

    except Exception as e:
        logger.error(f"模拟评估演示过程中出错: {e}")
        import traceback
        traceback.print_exc()


def main():
    """主函数."""
    logger = setup_logging()

    logger.info("华为安全检测数据集 Prompt 管理系统演示")
    logger.info("=" * 50)

    # 检查必要文件
    required_files = [
        "data/huawei/benchmark.json",
        "src/huawei/config/huawei_config.json"
    ]

    missing_files = []
    for file_path in required_files:
        if not Path(file_path).exists():
            missing_files.append(file_path)

    if missing_files:
        logger.warning("以下文件缺失，部分演示可能无法运行:")
        for file_path in missing_files:
            logger.warning(f"  - {file_path}")
        logger.info("你可以使用项目中提供的示例文件，或者修改文件路径")

    try:
        # 运行各个演示
        demo_dataset_functionality()
        demo_prompt_manager_functionality()
        demo_mock_evaluation()

        logger.info("\\n" + "=" * 50)
        logger.info("演示完成！")
        logger.info("\\n要运行完整的进化实验，可以使用:")
        logger.info("  uv run python src/huawei/demo.py")
        logger.info("\\n要运行测试，可以使用:")
        logger.info("  uv run pytest src/huawei/tests/ -v")

    except KeyboardInterrupt:
        logger.info("\\n演示被用户中断")
    except Exception as e:
        logger.error(f"演示过程中发生未处理的错误: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()