"""华为数据集的 Prompt 管理模块."""

import json
import random
import logging
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path

from evoprompt.utils.text import safe_format

logger = logging.getLogger(__name__)


class HuaweiPromptManager:
    """华为安全检测数据集的 Prompt 管理器."""

    def __init__(self, config_path: str):
        """初始化 Prompt 管理器.

        Args:
            config_path: 配置文件路径
        """
        self.config_path = Path(config_path)
        self.config = self._load_config()
        self.categories = list(self.config.get("categories", {}).keys())
        self.templates = self.config.get("prompt_templates", {})

    def _load_config(self) -> Dict[str, Any]:
        """加载配置文件."""
        if not self.config_path.exists():
            raise FileNotFoundError(f"配置文件不存在: {self.config_path}")

        with open(self.config_path, 'r', encoding='utf-8') as f:
            return json.load(f)

    def initialize_prompts(self, population_size: int = 8) -> List[str]:
        """初始化 prompt 种群.

        Args:
            population_size: 种群大小

        Returns:
            初始化的 prompt 列表
        """
        prompts = []

        # 使用配置中的所有模板作为基础
        base_templates = list(self.templates.values())

        # 如果模板数量不足，重复使用
        while len(prompts) < population_size:
            for template in base_templates:
                if len(prompts) >= population_size:
                    break
                prompts.append(template)

        # 对初始 prompts 进行小幅变异以增加多样性
        diversified_prompts = []
        for i, prompt in enumerate(prompts[:population_size]):
            if i > 0:  # 保留第一个原始模板
                diversified_prompt = self._diversify_prompt(prompt)
                diversified_prompts.append(diversified_prompt)
            else:
                diversified_prompts.append(prompt)

        logger.info(f"初始化了 {len(diversified_prompts)} 个 prompt")
        return diversified_prompts

    def _diversify_prompt(self, prompt: str) -> str:
        """对 prompt 进行多样化处理.

        Args:
            prompt: 原始 prompt

        Returns:
            多样化后的 prompt
        """
        # 定义一些变异策略
        variations = [
            self._add_emphasis,
            self._change_tone,
            self._add_examples,
            self._modify_instructions,
            self._adjust_format
        ]

        # 随机选择1-2个变异策略
        selected_variations = random.sample(variations, random.randint(1, 2))

        result = prompt
        for variation in selected_variations:
            result = variation(result)

        return result

    def _add_emphasis(self, prompt: str) -> str:
        """添加强调性词汇."""
        emphasis_words = [
            "请仔细", "务必", "特别注意", "重点关注", "深入分析",
            "全面检查", "详细审查", "严格审查"
        ]
        emphasis = random.choice(emphasis_words)

        # 在分析要求前添加强调
        if "分析" in prompt:
            prompt = prompt.replace("分析", f"{emphasis}分析")
        elif "检查" in prompt:
            prompt = prompt.replace("检查", f"{emphasis}检查")
        elif "审查" in prompt:
            prompt = prompt.replace("审查", f"{emphasis}审查")

        return prompt

    def _change_tone(self, prompt: str) -> str:
        """改变语气和风格."""
        tone_replacements = {
            "你是一个": random.choice([
                "作为一名专业的", "你是一位资深的", "作为经验丰富的", "你是专业的"
            ]),
            "请分析": random.choice([
                "请深入分析", "请详细检查", "请全面审查", "请系统分析"
            ]),
            "安全漏洞": random.choice([
                "安全缺陷", "安全问题", "安全风险", "潜在威胁"
            ])
        }

        result = prompt
        for old, new in tone_replacements.items():
            if old in result:
                result = result.replace(old, new)

        return result

    def _add_examples(self, prompt: str) -> str:
        """添加示例说明."""
        examples = [
            "\\n\\n示例：对于空指针解引用，应关注函数参数是否经过null检查。",
            "\\n\\n注意：缓冲区操作时要检查边界条件和长度验证。",
            "\\n\\n提示：内存分配后要检查是否有对应的释放操作。",
            "\\n\\n重点：用户输入要经过适当的验证和过滤。"
        ]

        # 随机添加一个示例
        if random.random() < 0.5:  # 50% 概率添加示例
            example = random.choice(examples)
            # 在代码块之前添加示例
            if "```" in prompt:
                prompt = prompt.replace("```", f"{example}\\n\\n```")

        return prompt

    def _modify_instructions(self, prompt: str) -> str:
        """修改指令措辞."""
        instruction_replacements = {
            "输出格式": random.choice([
                "返回格式", "结果格式", "响应格式", "答案格式"
            ]),
            "严格JSON": random.choice([
                "标准JSON", "规范JSON", "有效JSON", "合法JSON"
            ]),
            "置信度": random.choice([
                "可信度", "确信程度", "把握程度", "风险评级"
            ])
        }

        result = prompt
        for old, new in instruction_replacements.items():
            if old in result:
                result = result.replace(old, new)

        return result

    def _adjust_format(self, prompt: str) -> str:
        """调整输出格式要求."""
        if "JSON" in prompt and random.random() < 0.3:  # 30% 概率调整格式
            format_additions = [
                "，确保JSON格式正确",
                "，使用UTF-8编码",
                "，不要包含注释",
                "，保持结构清晰"
            ]
            addition = random.choice(format_additions)
            prompt = prompt.replace("JSON", f"JSON{addition}")

        return prompt

    def mutate_prompt(self, prompt: str, mutation_rate: float = 0.3) -> str:
        """对 prompt 进行变异.

        Args:
            prompt: 原始 prompt
            mutation_rate: 变异率

        Returns:
            变异后的 prompt
        """
        if random.random() > mutation_rate:
            return prompt

        # 选择变异策略
        mutation_strategies = [
            self._semantic_mutation,
            self._structure_mutation,
            self._template_fusion
        ]

        strategy = random.choice(mutation_strategies)
        return strategy(prompt)

    def _semantic_mutation(self, prompt: str) -> str:
        """语义变异 - 改变表达方式但保持含义."""
        semantic_replacements = {
            "代码片段": random.choice(["代码段", "源代码", "程序代码", "代码块"]),
            "安全漏洞": random.choice(["安全缺陷", "安全问题", "安全威胁", "安全风险"]),
            "漏洞类型": random.choice(["缺陷类型", "问题类型", "风险类型", "威胁类型"]),
            "分析结果": random.choice(["检测结果", "审查结果", "评估结果", "诊断结果"]),
            "仔细检查": random.choice(["深入检查", "全面检查", "详细审查", "系统检查"])
        }

        result = prompt
        # 随机选择1-3个替换
        replacements = random.sample(
            list(semantic_replacements.items()),
            min(3, len(semantic_replacements))
        )

        for old, new in replacements:
            if old in result:
                result = result.replace(old, new)

        return result

    def _structure_mutation(self, prompt: str) -> str:
        """结构变异 - 改变 prompt 的结构."""
        lines = prompt.split('\\n')

        # 随机调整行的顺序（保持关键部分）
        if len(lines) > 3:
            # 找到代码块的位置，不移动它们
            code_block_indices = []
            for i, line in enumerate(lines):
                if '```' in line:
                    code_block_indices.append(i)

            # 对非关键行进行小幅调整
            if len(code_block_indices) == 0:
                # 随机交换相邻的两行
                if len(lines) > 2:
                    idx = random.randint(0, len(lines) - 2)
                    lines[idx], lines[idx + 1] = lines[idx + 1], lines[idx]

        return '\\n'.join(lines)

    def _template_fusion(self, prompt: str) -> str:
        """模板融合 - 融合不同模板的特点."""
        # 从其他模板中随机选择一些特性
        other_templates = [t for t in self.templates.values() if t != prompt]

        if other_templates:
            other_template = random.choice(other_templates)

            # 提取其他模板的一些特性词汇
            other_words = other_template.split()
            useful_phrases = []

            for i in range(len(other_words) - 2):
                phrase = ' '.join(other_words[i:i+3])
                if any(keyword in phrase for keyword in ['分析', '检查', '输出', '格式']):
                    useful_phrases.append(phrase)

            # 随机添加一个有用的短语
            if useful_phrases:
                phrase = random.choice(useful_phrases)
                # 在适当位置插入
                if "分析" in prompt and phrase not in prompt:
                    prompt = prompt.replace("分析", f"分析（{phrase}）")

        return prompt

    def crossover_prompts(self, parent1: str, parent2: str) -> Tuple[str, str]:
        """对两个 prompt 进行交叉.

        Args:
            parent1: 父代 prompt 1
            parent2: 父代 prompt 2

        Returns:
            两个子代 prompt
        """
        # 分解 prompt 为语义块
        blocks1 = self._split_into_blocks(parent1)
        blocks2 = self._split_into_blocks(parent2)

        # 交换一些块
        child1_blocks = blocks1.copy()
        child2_blocks = blocks2.copy()

        # 随机选择交换点
        if len(blocks1) > 1 and len(blocks2) > 1:
            swap_point = random.randint(1, min(len(blocks1), len(blocks2)) - 1)

            # 交换尾部块
            child1_blocks[swap_point:] = blocks2[swap_point:len(child1_blocks)]
            child2_blocks[swap_point:] = blocks1[swap_point:len(child2_blocks)]

        child1 = '\\n\\n'.join(child1_blocks)
        child2 = '\\n\\n'.join(child2_blocks)

        return child1, child2

    def _split_into_blocks(self, prompt: str) -> List[str]:
        """将 prompt 分解为语义块."""
        # 按段落分割
        blocks = prompt.split('\\n\\n')

        # 进一步细分长块
        refined_blocks = []
        for block in blocks:
            if len(block) > 200:  # 长块进一步分割
                sentences = block.split('。')
                refined_blocks.extend([s + '。' for s in sentences if s.strip()])
            else:
                refined_blocks.append(block)

        return [block for block in refined_blocks if block.strip()]

    def build_prompt(self, template: str, code: str, lang: str = "cpp",
                    focus_category: Optional[str] = None) -> str:
        """根据模板构建完整的 prompt.

        Args:
            template: prompt 模板
            code: 代码片段
            lang: 编程语言
            focus_category: 重点关注的类别

        Returns:
            构建好的 prompt
        """
        # 构建类别列表
        category_list = '\\n'.join(f"- {category}" for category in self.categories)

        # 规范化代码（处理换行符）
        code_normalized = code.replace('\\r\\n', '\\n').replace('\\r', '\\n')

        # 替换模板变量
        prompt = safe_format(
            template,
            category_list=category_list,
            code=code_normalized,
            lang=lang,
            focus_category=focus_category or "所有类型",
        )

        return prompt

    def get_template_by_name(self, name: str) -> Optional[str]:
        """根据名称获取模板.

        Args:
            name: 模板名称

        Returns:
            模板字符串，如果不存在则返回 None
        """
        return self.templates.get(name)

    def get_all_templates(self) -> Dict[str, str]:
        """获取所有模板."""
        return self.templates.copy()

    def add_template(self, name: str, template: str) -> None:
        """添加新模板.

        Args:
            name: 模板名称
            template: 模板内容
        """
        self.templates[name] = template
        logger.info(f"添加新模板: {name}")

    def get_categories(self) -> List[str]:
        """获取所有支持的类别."""
        return self.categories.copy()

    def get_category_info(self, category: str) -> Dict[str, Any]:
        """获取类别详细信息.

        Args:
            category: 类别名称

        Returns:
            类别信息字典
        """
        return self.config.get("categories", {}).get(category, {})
