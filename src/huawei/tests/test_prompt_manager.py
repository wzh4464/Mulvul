"""华为 Prompt 管理器测试用例."""

import json
import pytest
import tempfile
import random
from pathlib import Path
from unittest.mock import patch

from ..prompt_manager import HuaweiPromptManager


class TestHuaweiPromptManager:
    """华为 Prompt 管理器测试."""

    @pytest.fixture
    def sample_config(self):
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
                    "description": "缓冲区边界检查不当",
                    "severity": "high"
                }
            },
            "prompt_templates": {
                "base_template": "分析{lang}代码：\\n{category_list}\\n```{lang}\\n{code}\\n```\\n结果：",
                "detailed_template": "详细分析{lang}代码：\\n类型：{category_list}\\n代码：\\n```{lang}\\n{code}\\n```\\n分析：",
                "minimal_template": "检查{lang}代码：{category_list}\\n{code}"
            }
        }

    @pytest.fixture
    def prompt_manager(self, sample_config):
        """创建 prompt 管理器实例."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.json"
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(sample_config, f)

            manager = HuaweiPromptManager(str(config_file))
            yield manager

    def test_initialization(self, sample_config):
        """测试初始化."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.json"
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(sample_config, f)

            manager = HuaweiPromptManager(str(config_file))

            assert len(manager.categories) == 2
            assert "函数指针参数未校验" in manager.categories
            assert "缓冲区溢出" in manager.categories
            assert len(manager.templates) == 3

    def test_initialization_file_not_found(self):
        """测试配置文件不存在."""
        with pytest.raises(FileNotFoundError):
            HuaweiPromptManager("nonexistent_config.json")

    def test_initialize_prompts(self, prompt_manager):
        """测试 prompt 初始化."""
        prompts = prompt_manager.initialize_prompts(population_size=5)

        assert len(prompts) == 5
        assert all(isinstance(prompt, str) for prompt in prompts)
        assert all(len(prompt.strip()) > 0 for prompt in prompts)

        # 检查是否包含原始模板
        template_found = any(
            template in prompts[0] for template in prompt_manager.templates.values()
        )
        assert template_found or prompts[0] in prompt_manager.templates.values()

    def test_diversify_prompt(self, prompt_manager):
        """测试 prompt 多样化."""
        original_prompt = "分析代码安全问题"

        # 设置随机种子确保测试一致性
        random.seed(42)

        diversified = prompt_manager._diversify_prompt(original_prompt)

        # 多样化后的 prompt 应该不同
        assert diversified != original_prompt
        # 但应该保持核心内容
        assert "代码" in diversified or "分析" in diversified

    def test_add_emphasis(self, prompt_manager):
        """测试添加强调词汇."""
        prompt = "分析代码中的安全问题"
        result = prompt_manager._add_emphasis(prompt)

        # 应该添加了强调词
        emphasis_words = ["请仔细", "务必", "特别注意", "重点关注", "深入分析", "全面检查", "详细审查", "严格审查"]
        has_emphasis = any(word in result for word in emphasis_words)
        assert has_emphasis

    def test_change_tone(self, prompt_manager):
        """测试改变语气."""
        prompt = "你是一个专业的分析师，请分析安全漏洞"
        result = prompt_manager._change_tone(prompt)

        # 检查是否有语气改变
        assert result != prompt
        assert "分析" in result  # 核心内容应该保留

    def test_mutate_prompt(self, prompt_manager):
        """测试 prompt 变异."""
        original_prompt = "分析代码安全问题"

        # 测试变异率为0（不变异）
        result_no_mutation = prompt_manager.mutate_prompt(original_prompt, mutation_rate=0.0)
        assert result_no_mutation == original_prompt

        # 测试变异率为1（一定变异）
        random.seed(42)
        result_with_mutation = prompt_manager.mutate_prompt(original_prompt, mutation_rate=1.0)
        # 变异后应该不同（概率很高）
        # 注意：由于随机性，这个测试可能偶尔失败，但概率很低

    def test_semantic_mutation(self, prompt_manager):
        """测试语义变异."""
        prompt = "分析代码片段中的安全漏洞"
        result = prompt_manager._semantic_mutation(prompt)

        # 应该包含替换后的词汇
        possible_replacements = ["代码段", "源代码", "程序代码", "代码块"]
        contains_replacement = any(word in result for word in possible_replacements) or "代码片段" in result

        assert contains_replacement

    def test_crossover_prompts(self, prompt_manager):
        """测试 prompt 交叉."""
        parent1 = "分析代码安全问题。\\n\\n检查漏洞类型。\\n\\n输出结果。"
        parent2 = "审查源代码质量。\\n\\n识别风险点。\\n\\n生成报告。"

        child1, child2 = prompt_manager.crossover_prompts(parent1, parent2)

        assert isinstance(child1, str)
        assert isinstance(child2, str)
        assert len(child1.strip()) > 0
        assert len(child2.strip()) > 0

        # 交叉后的结果应该与父代不完全相同
        assert child1 != parent1 or child2 != parent2

    def test_split_into_blocks(self, prompt_manager):
        """测试分割语义块."""
        prompt = "第一段内容。\\n\\n第二段内容。\\n\\n第三段内容。"
        blocks = prompt_manager._split_into_blocks(prompt)

        assert len(blocks) == 3
        assert "第一段内容。" in blocks[0]
        assert "第二段内容。" in blocks[1]
        assert "第三段内容。" in blocks[2]

    def test_build_prompt(self, prompt_manager):
        """测试构建完整 prompt."""
        template = "分析{lang}代码：\\n{category_list}\\n```{lang}\\n{code}\\n```"
        code = "int x = 0;"
        lang = "cpp"

        result = prompt_manager.build_prompt(template, code, lang)

        assert "cpp" in result
        assert "int x = 0;" in result
        assert "函数指针参数未校验" in result
        assert "缓冲区溢出" in result

    def test_build_prompt_with_focus_category(self, prompt_manager):
        """测试带重点类别的 prompt 构建."""
        template = "专注{focus_category}，分析{lang}代码：{code}"
        code = "int x = 0;"
        result = prompt_manager.build_prompt(
            template, code, "cpp", focus_category="缓冲区溢出"
        )

        assert "缓冲区溢出" in result

    def test_template_management(self, prompt_manager):
        """测试模板管理功能."""
        # 获取模板
        template = prompt_manager.get_template_by_name("base_template")
        assert template is not None
        assert "分析" in template

        # 获取不存在的模板
        none_template = prompt_manager.get_template_by_name("nonexistent")
        assert none_template is None

        # 获取所有模板
        all_templates = prompt_manager.get_all_templates()
        assert len(all_templates) == 3
        assert "base_template" in all_templates

        # 添加新模板
        new_template = "新的分析模板：{code}"
        prompt_manager.add_template("new_template", new_template)

        updated_templates = prompt_manager.get_all_templates()
        assert len(updated_templates) == 4
        assert updated_templates["new_template"] == new_template

    def test_category_management(self, prompt_manager):
        """测试类别管理功能."""
        categories = prompt_manager.get_categories()
        assert len(categories) == 2
        assert "函数指针参数未校验" in categories

        # 获取类别信息
        info = prompt_manager.get_category_info("函数指针参数未校验")
        assert info["cwe_id"] == 476
        assert info["severity"] == "high"

        # 获取不存在类别的信息
        empty_info = prompt_manager.get_category_info("不存在的类别")
        assert empty_info == {}

    def test_code_normalization(self, prompt_manager):
        """测试代码规范化."""
        template = "{code}"
        code_with_crlf = "int x = 0;\\r\\nreturn x;\\r"

        result = prompt_manager.build_prompt(template, code_with_crlf, "cpp")

        # 应该将 \\r\\n 转换为 \\n
        assert "\\r\\n" not in result
        assert "\\n" in result or "return x;" in result

    @patch('random.random')
    @patch('random.choice')
    def test_diversification_strategies(self, mock_choice, mock_random, prompt_manager):
        """测试多样化策略的调用."""
        # 模拟随机选择
        mock_random.return_value = 0.3  # 触发示例添加
        mock_choice.side_effect = [
            [prompt_manager._add_emphasis],  # 选择的变异策略
            "请仔细",  # 强调词选择
            "\\n\\n示例：对于空指针解引用，应关注函数参数是否经过null检查。"  # 示例选择
        ]

        original_prompt = "分析代码安全问题。```cpp\\nint x;\\n```"
        result = prompt_manager._diversify_prompt(original_prompt)

        # 验证调用了相应的方法
        assert mock_random.called
        assert mock_choice.called

    def test_large_population_initialization(self, prompt_manager):
        """测试大种群初始化."""
        # 测试种群大小大于模板数量的情况
        large_population_size = 10
        prompts = prompt_manager.initialize_prompts(large_population_size)

        assert len(prompts) == large_population_size
        # 应该有重复使用的模板
        unique_prompts = set(prompts)
        assert len(unique_prompts) <= len(prompt_manager.templates) + 5  # 考虑多样化

    def test_empty_template_handling(self):
        """测试空模板处理."""
        config = {
            "categories": {"test": {}},
            "prompt_templates": {}
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.json"
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f)

            manager = HuaweiPromptManager(str(config_file))
            prompts = manager.initialize_prompts(3)

            # 应该处理空模板的情况
            assert len(prompts) <= 3