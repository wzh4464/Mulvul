#!/usr/bin/env python3
"""华为数据集快速测试脚本."""

import sys
import json
import tempfile
from pathlib import Path

# 添加src路径
sys.path.insert(0, str(Path(__file__).parent.parent))

from huawei.dataset import HuaweiDataset
from huawei.prompt_manager import HuaweiPromptManager


def create_test_data():
    """创建测试数据."""
    sample_data = [
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

    config_data = {
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
        }
    }

    return sample_data, config_data


def test_dataset():
    """测试数据集功能."""
    print("测试数据集功能...")

    sample_data, config_data = create_test_data()

    with tempfile.TemporaryDirectory() as temp_dir:
        # 创建临时文件
        data_file = Path(temp_dir) / "test_data.json"
        config_file = Path(temp_dir) / "test_config.json"

        with open(data_file, 'w', encoding='utf-8') as f:
            json.dump(sample_data, f)

        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(config_data, f)

        # 测试数据集
        dataset = HuaweiDataset(str(data_file), str(config_file))
        samples = dataset.load_data(str(data_file))

        assert len(samples) == 2, f"期望2个样本，实际{len(samples)}个"
        assert samples[0].has_vulnerabilities(), "第一个样本应该包含漏洞"
        assert not samples[1].has_vulnerabilities(), "第二个样本应该不包含漏洞"

        stats = dataset.get_statistics()
        assert stats["total_samples"] == 2
        assert stats["vulnerable_samples"] == 1
        assert stats["clean_samples"] == 1

        print("✅ 数据集功能测试通过")


def test_prompt_manager():
    """测试 Prompt 管理器功能."""
    print("测试 Prompt 管理器功能...")

    _, config_data = create_test_data()

    with tempfile.TemporaryDirectory() as temp_dir:
        config_file = Path(temp_dir) / "test_config.json"

        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(config_data, f)

        # 测试 Prompt 管理器
        prompt_manager = HuaweiPromptManager(str(config_file))

        assert len(prompt_manager.categories) == 2
        assert "函数指针参数未校验" in prompt_manager.categories

        # 测试初始化 prompts
        prompts = prompt_manager.initialize_prompts(4)
        assert len(prompts) == 4
        assert all(isinstance(p, str) for p in prompts)

        # 测试 prompt 构建
        test_code = "int x = 0;"
        built_prompt = prompt_manager.build_prompt(
            prompts[0], test_code, "cpp"
        )
        assert "函数指针参数未校验" in built_prompt
        assert "int x = 0;" in built_prompt

        # 测试变异
        mutated = prompt_manager.mutate_prompt(prompts[0], mutation_rate=1.0)
        assert isinstance(mutated, str)

        # 测试交叉
        child1, child2 = prompt_manager.crossover_prompts(prompts[0], prompts[1])
        assert isinstance(child1, str)
        assert isinstance(child2, str)

        print("✅ Prompt 管理器功能测试通过")


def test_integration():
    """测试集成功能."""
    print("测试集成功能...")

    sample_data, config_data = create_test_data()

    with tempfile.TemporaryDirectory() as temp_dir:
        data_file = Path(temp_dir) / "test_data.json"
        config_file = Path(temp_dir) / "test_config.json"

        with open(data_file, 'w', encoding='utf-8') as f:
            json.dump(sample_data, f)

        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(config_data, f)

        # 集成测试
        dataset = HuaweiDataset(str(data_file), str(config_file))
        prompt_manager = HuaweiPromptManager(str(config_file))

        samples = dataset.load_data(str(data_file))
        prompts = prompt_manager.initialize_prompts(2)

        # 测试完整流程
        for sample in samples[:1]:  # 只测试第一个样本
            for prompt in prompts[:1]:  # 只测试第一个 prompt
                built_prompt = prompt_manager.build_prompt(
                    prompt, sample.code, sample.metadata.get("lang", "cpp")
                )
                assert len(built_prompt) > 0
                assert sample.code in built_prompt

        print("✅ 集成功能测试通过")


def main():
    """主测试函数."""
    print("华为数据集 Prompt 管理系统快速测试")
    print("=" * 40)

    try:
        test_dataset()
        test_prompt_manager()
        test_integration()

        print("\\n" + "=" * 40)
        print("🎉 所有测试通过！")
        print("\\n系统已准备就绪，可以进行以下操作：")
        print("1. 运行演示: uv run python src/huawei/demo.py")
        print("2. 运行完整测试: uv run pytest src/huawei/tests/ -v")
        print("3. 使用配置文件: src/huawei/config/huawei_config.json")

    except AssertionError as e:
        print(f"❌ 测试失败: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ 测试过程中出错: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()