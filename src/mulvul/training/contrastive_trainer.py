"""对比学习Prompt训练器

使用三类代码(目标漏洞、其他漏洞、安全代码)进行对比学习来优化prompt。
"""

import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

from ..llm.client import LLMClient
from ..data.sampler import ContrastiveSampler
from ..prompts.hierarchical_three_layer import CONTRASTIVE_META_PROMPT

logger = logging.getLogger(__name__)


@dataclass
class ContrastiveTrainingConfig:
    """对比学习训练配置"""
    samples_per_type: int = 3  # 每类样本数
    max_code_length: int = 500  # 代码最大长度
    temperature: float = 0.7  # Meta-LLM温度
    max_iterations: int = 5  # 最大迭代次数


class ContrastivePromptTrainer:
    """对比学习Prompt训练器

    使用三类代码进行对比学习:
    1. target: 目标漏洞代码
    2. other_vuln: 其他类型漏洞代码
    3. benign: 安全代码
    """

    def __init__(
        self,
        meta_llm_client: LLMClient,
        sampler: Optional[ContrastiveSampler] = None,
        config: Optional[ContrastiveTrainingConfig] = None
    ):
        """初始化训练器

        Args:
            meta_llm_client: 用于生成改进prompt的LLM客户端
            sampler: 对比样本采样器
            config: 训练配置
        """
        self.meta_llm_client = meta_llm_client
        self.sampler = sampler or ContrastiveSampler()
        self.config = config or ContrastiveTrainingConfig()

    def train_prompt(
        self,
        current_prompt: str,
        target_category: str,
        contrastive_samples: Dict[str, List[Dict[str, Any]]]
    ) -> str:
        """使用对比样本训练/优化prompt

        Args:
            current_prompt: 当前prompt
            target_category: 目标类别 (CWE或Major Category)
            contrastive_samples: 对比样本 {"target": [...], "other_vuln": [...], "benign": [...]}

        Returns:
            改进后的prompt
        """
        # 格式化样本
        target_text = self.sampler.format_samples_for_prompt(
            contrastive_samples.get("target", []),
            self.config.max_code_length
        )
        other_vuln_text = self.sampler.format_samples_for_prompt(
            contrastive_samples.get("other_vuln", []),
            self.config.max_code_length
        )
        benign_text = self.sampler.format_samples_for_prompt(
            contrastive_samples.get("benign", []),
            self.config.max_code_length
        )

        # 构建meta-prompt
        meta_prompt = CONTRASTIVE_META_PROMPT.format(
            current_prompt=current_prompt,
            target_category=target_category,
            target_samples=target_text,
            other_vuln_samples=other_vuln_text,
            benign_samples=benign_text
        )

        # 调用meta-LLM生成改进的prompt
        try:
            improved_prompt = self.meta_llm_client.generate(
                meta_prompt,
                temperature=self.config.temperature
            )
            return self._clean_prompt(improved_prompt)
        except Exception as e:
            logger.error(f"Failed to generate improved prompt: {e}")
            return current_prompt

    def train_layer1_prompt(
        self,
        current_prompt: str,
        target_major: str,
        dataset_items: List[Dict[str, Any]]
    ) -> str:
        """训练Layer1 prompt

        Args:
            current_prompt: 当前Layer1 prompt
            target_major: 目标Major Category
            dataset_items: 数据集项

        Returns:
            改进后的prompt
        """
        # 采样对比样本
        contrastive_samples = self.sampler.sample_contrastive_for_major_category(
            target_major,
            dataset_items,
            self.config.samples_per_type
        )

        return self.train_prompt(current_prompt, target_major, contrastive_samples)

    def train_layer2_prompt(
        self,
        current_prompt: str,
        target_middle: str,
        dataset_items: List[Dict[str, Any]]
    ) -> str:
        """训练Layer2 prompt

        Args:
            current_prompt: 当前Layer2 prompt
            target_middle: 目标Middle Category
            dataset_items: 数据集项

        Returns:
            改进后的prompt
        """
        # 对于Layer2，使用Middle Category进行采样
        # 这里简化处理，使用CWE级别的采样
        contrastive_samples = self._sample_for_middle_category(
            target_middle,
            dataset_items
        )

        return self.train_prompt(current_prompt, target_middle, contrastive_samples)

    def train_layer3_prompt(
        self,
        current_prompt: str,
        target_cwe: str,
        dataset_items: List[Dict[str, Any]]
    ) -> str:
        """训练Layer3 prompt

        Args:
            current_prompt: 当前Layer3 prompt
            target_cwe: 目标CWE
            dataset_items: 数据集项

        Returns:
            改进后的prompt
        """
        contrastive_samples = self.sampler.sample_contrastive_triplet(
            target_cwe,
            dataset_items,
            self.config.samples_per_type
        )

        return self.train_prompt(current_prompt, target_cwe, contrastive_samples)

    def _sample_for_middle_category(
        self,
        target_middle: str,
        dataset_items: List[Dict[str, Any]]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """为Middle Category采样

        Args:
            target_middle: 目标Middle Category
            dataset_items: 数据集项

        Returns:
            对比样本
        """
        from ..prompts.hierarchical_three_layer import MIDDLE_TO_CWE, MiddleCategory

        # 获取该Middle Category对应的CWE列表
        try:
            middle_enum = MiddleCategory(target_middle)
            target_cwes = MIDDLE_TO_CWE.get(middle_enum, [])
        except ValueError:
            target_cwes = []

        target_samples = []
        other_vuln_samples = []
        benign_samples = []

        import random

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

                # 检查是否属于目标Middle Category
                if any(cwe in target_cwes for cwe in cwe_codes):
                    target_samples.append(item)
                else:
                    other_vuln_samples.append(item)

        n = self.config.samples_per_type
        return {
            "target": random.sample(target_samples, min(n, len(target_samples))) if target_samples else [],
            "other_vuln": random.sample(other_vuln_samples, min(n, len(other_vuln_samples))) if other_vuln_samples else [],
            "benign": random.sample(benign_samples, min(n, len(benign_samples))) if benign_samples else [],
        }

    def _clean_prompt(self, prompt: str) -> str:
        """清理生成的prompt

        Args:
            prompt: 原始prompt

        Returns:
            清理后的prompt
        """
        prompt = prompt.strip()

        # 移除可能的markdown代码块标记
        if prompt.startswith("```"):
            lines = prompt.split("\n")
            if len(lines) > 2:
                prompt = "\n".join(lines[1:-1])

        # 确保包含{input}占位符
        if "{input}" not in prompt:
            prompt += "\n\nCode to analyze:\n{input}"

        return prompt


class ContrastiveEvolutionTrainer:
    """结合进化算法的对比学习训练器

    在进化过程中使用对比学习来指导prompt改进。
    """

    def __init__(
        self,
        meta_llm_client: LLMClient,
        detection_llm_client: LLMClient,
        config: Optional[ContrastiveTrainingConfig] = None
    ):
        self.meta_llm_client = meta_llm_client
        self.detection_llm_client = detection_llm_client
        self.config = config or ContrastiveTrainingConfig()
        self.sampler = ContrastiveSampler()
        self.trainer = ContrastivePromptTrainer(
            meta_llm_client,
            self.sampler,
            self.config
        )

    def evolve_with_contrastive_learning(
        self,
        initial_prompts: Dict[str, str],
        dataset_items: List[Dict[str, Any]],
        generations: int = 5
    ) -> Dict[str, str]:
        """使用对比学习进行prompt进化

        Args:
            initial_prompts: 初始prompts {"layer1": ..., "layer2_Memory": ..., ...}
            dataset_items: 数据集项
            generations: 进化代数

        Returns:
            优化后的prompts
        """
        current_prompts = initial_prompts.copy()

        for gen in range(generations):
            logger.info(f"Generation {gen + 1}/{generations}")

            # 对每个prompt进行对比学习优化
            for key, prompt in current_prompts.items():
                if key == "layer1":
                    # Layer1: 对每个Major Category进行优化
                    for major in ["Memory", "Injection", "Logic", "Input", "Crypto"]:
                        improved = self.trainer.train_layer1_prompt(
                            prompt, major, dataset_items
                        )
                        # 这里简化处理，实际应该评估后选择更好的
                        current_prompts[key] = improved
                        break  # 简化：只用第一个major优化

                elif key.startswith("layer2_"):
                    middle = key.replace("layer2_", "")
                    improved = self.trainer.train_layer2_prompt(
                        prompt, middle, dataset_items
                    )
                    current_prompts[key] = improved

                elif key.startswith("layer3_"):
                    cwe = key.replace("layer3_", "")
                    improved = self.trainer.train_layer3_prompt(
                        prompt, cwe, dataset_items
                    )
                    current_prompts[key] = improved

        return current_prompts
