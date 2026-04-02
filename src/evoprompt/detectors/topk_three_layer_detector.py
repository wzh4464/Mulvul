"""Top-k三层检测器 - 减少错误传播

Layer1输出top-k个候选类别，每个都传给Layer2处理，最后聚合选择最佳路径。
"""

import json
import re
import logging
from typing import Optional, Tuple, Dict, List
from dataclasses import dataclass

from .three_layer_detector import ThreeLayerDetector
from ..llm.client import LLMClient
from ..prompts.hierarchical_three_layer import (
    ThreeLayerPromptSet,
    MajorCategory,
    MiddleCategory,
    MIDDLE_TO_CWE,
)

logger = logging.getLogger(__name__)


@dataclass
class CategoryPrediction:
    """单个类别预测结果"""
    category: MajorCategory
    confidence: float


@dataclass
class DetectionPath:
    """完整检测路径"""
    major: MajorCategory
    middle: Optional[MiddleCategory]
    cwe: Optional[str]
    confidence: float


class TopKThreeLayerDetector(ThreeLayerDetector):
    """Top-k三层检测器

    Layer1输出top-k个候选major category，每个都传给Layer2/Layer3处理，
    最后聚合选择置信度最高的完整路径。
    """

    def __init__(
        self,
        prompt_set: ThreeLayerPromptSet,
        llm_client: LLMClient,
        use_scale_enhancement: bool = False,
        layer1_top_k: int = 3
    ):
        super().__init__(prompt_set, llm_client, use_scale_enhancement)
        self.layer1_top_k = layer1_top_k
        self._topk_prompt = self._create_topk_layer1_prompt()

    def _create_topk_layer1_prompt(self) -> str:
        """创建支持top-k输出的Layer1 prompt"""
        return """You are a security expert analyzing code for vulnerabilities.

Classify this code and provide your TOP {k} most likely categories with confidence scores (0-100).
The confidence scores should sum to 100.

Categories:
1. Memory - Memory safety issues (buffer overflow, use-after-free, NULL pointer, memory leaks)
2. Injection - Injection attacks (SQL, XSS, command injection)
3. Logic - Logic flaws (authentication, authorization, race conditions)
4. Input - Input handling issues (validation, path traversal)
5. Crypto - Cryptographic weaknesses
6. Benign - Safe code with no vulnerabilities

Code to analyze:
{input}

Output ONLY valid JSON in this exact format:
{{"predictions": [{{"category": "CategoryName", "confidence": 85}}, {{"category": "CategoryName2", "confidence": 10}}, {{"category": "CategoryName3", "confidence": 5}}]}}"""

    def detect(
        self,
        code: str,
        return_intermediate: bool = False
    ) -> Tuple[Optional[str], Dict]:
        """使用top-k策略检测漏洞

        Args:
            code: 源代码
            return_intermediate: 是否返回中间结果

        Returns:
            (cwe, details) 元组
        """
        details = {
            "layer1_topk": [],
            "all_paths": [],
        }

        # Step 1: Scale enhancement (可选)
        if self.use_scale_enhancement and self.prompt_set.scale_enhancement:
            try:
                enhanced_code = self._enhance_code(code)
                details["enhanced_code"] = enhanced_code
                analysis_input = enhanced_code
            except Exception as e:
                logger.warning(f"Scale enhancement failed: {e}")
                analysis_input = code
        else:
            analysis_input = code

        # Step 2: Layer1 - 获取top-k个major category
        topk_predictions = self._classify_layer1_topk(analysis_input)
        details["layer1_topk"] = [
            {"category": p.category.value, "confidence": p.confidence}
            for p in topk_predictions
        ]

        if not topk_predictions:
            logger.warning("Layer 1 top-k classification failed")
            return (None, details)

        # Step 3: 对每个候选major category执行完整路径
        all_paths: List[DetectionPath] = []

        for pred in topk_predictions:
            # Layer2: Middle category
            middle = self._classify_layer2(analysis_input, pred.category)

            if middle is None:
                # 如果Layer2失败，跳过这个路径
                continue

            # Layer3: CWE
            cwe = self._classify_layer3(analysis_input, middle)

            path = DetectionPath(
                major=pred.category,
                middle=middle,
                cwe=cwe,
                confidence=pred.confidence
            )
            all_paths.append(path)

            details["all_paths"].append({
                "major": pred.category.value,
                "middle": middle.value if middle else None,
                "cwe": cwe,
                "confidence": pred.confidence
            })

        if not all_paths:
            logger.warning("No valid detection paths found")
            return (None, details)

        # Step 4: 选择最佳路径 (置信度最高)
        best_path = max(all_paths, key=lambda p: p.confidence)

        details["layer1"] = best_path.major.value
        details["layer2"] = best_path.middle.value if best_path.middle else "Unknown"
        details["layer3"] = best_path.cwe if best_path.cwe else "Unknown"
        details["best_confidence"] = best_path.confidence

        return (best_path.cwe, details)

    def _classify_layer1_topk(self, code: str) -> List[CategoryPrediction]:
        """Layer1: 返回top-k个major category及置信度

        Args:
            code: 代码

        Returns:
            CategoryPrediction列表，按置信度降序
        """
        prompt = self._topk_prompt.replace("{k}", str(self.layer1_top_k))
        prompt = prompt.replace("{input}", code)

        try:
            response = self.llm_client.generate(prompt, temperature=0.1)
            return self._parse_topk_response(response)
        except Exception as e:
            logger.error(f"Layer 1 top-k classification failed: {e}")
            return []

    def _parse_topk_response(self, response: str) -> List[CategoryPrediction]:
        """解析top-k响应

        Args:
            response: LLM响应

        Returns:
            CategoryPrediction列表
        """
        predictions = []

        # 尝试提取JSON
        try:
            # 查找JSON部分
            json_match = re.search(r'\{.*"predictions".*\}', response, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())

                for item in data.get("predictions", []):
                    category_str = item.get("category", "")
                    confidence = float(item.get("confidence", 0))

                    # 规范化类别名
                    category = self._normalize_major_category(category_str)
                    if category:
                        predictions.append(CategoryPrediction(
                            category=category,
                            confidence=confidence
                        ))
        except (json.JSONDecodeError, ValueError) as e:
            logger.warning(f"Failed to parse JSON response: {e}")
            # 回退: 尝试从文本中提取
            predictions = self._fallback_parse(response)

        # 按置信度降序排序
        predictions.sort(key=lambda p: p.confidence, reverse=True)

        # 限制为top-k
        return predictions[:self.layer1_top_k]

    def _fallback_parse(self, response: str) -> List[CategoryPrediction]:
        """回退解析方法

        当JSON解析失败时，尝试从文本中提取类别
        """
        predictions = []
        response_lower = response.lower()

        # 简单的关键词匹配
        category_keywords = {
            MajorCategory.MEMORY: ['memory', 'buffer', 'overflow', 'pointer'],
            MajorCategory.INJECTION: ['injection', 'sql', 'xss'],
            MajorCategory.LOGIC: ['logic', 'auth', 'race'],
            MajorCategory.INPUT: ['input', 'validation', 'path'],
            MajorCategory.CRYPTO: ['crypto', 'encryption'],
            MajorCategory.BENIGN: ['benign', 'safe'],
        }

        for category, keywords in category_keywords.items():
            if any(kw in response_lower for kw in keywords):
                # 给匹配到的类别一个默认置信度
                predictions.append(CategoryPrediction(
                    category=category,
                    confidence=50.0  # 默认置信度
                ))

        return predictions

    def detect_batch(
        self,
        codes: List[str],
        batch_size: int = 16
    ) -> List[Tuple[Optional[str], Dict]]:
        """批量检测

        Args:
            codes: 代码列表
            batch_size: 批大小

        Returns:
            (cwe, details)元组列表
        """
        results = []

        for i in range(0, len(codes), batch_size):
            batch = codes[i:i + batch_size]

            for code in batch:
                try:
                    result = self.detect(code)
                    results.append(result)
                except Exception as e:
                    logger.error(f"Detection failed: {e}")
                    results.append((None, {"error": str(e)}))

        return results
