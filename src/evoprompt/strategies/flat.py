"""Flat 11-class CWE major category classification strategy.

This is the default strategy extracted from PrimeVulLayer1Pipeline.batch_predict().
Single prompt classifies code into one of 11 categories directly.
"""

from __future__ import annotations

from typing import Any, Dict, List

from evoprompt.data.cwe_categories import canonicalize_category, map_cwe_to_major
from evoprompt.data.dataset import Sample
from evoprompt.utils.text import safe_format


class FlatStrategy:
    """Flat 11-class classification: one prompt → one category."""

    def __init__(self, llm_client: Any, config: Dict[str, Any] | None = None):
        self.llm_client = llm_client
        self.config = config or {}

    def get_ground_truth(self, sample: Sample) -> str:
        ground_truth_binary = int(sample.target)
        cwe_codes = sample.metadata.get("cwe", [])
        if ground_truth_binary == 1 and cwe_codes:
            return map_cwe_to_major(cwe_codes)
        return "Benign"

    @staticmethod
    def _split_system_user(prompt: str, code: str) -> tuple:
        """Split prompt into system instruction and user message at {input} marker.

        When using claude-max-api-proxy, the system message is forwarded via
        ``--system-prompt`` to override Claude Code's default system prompt.
        """
        marker = "{input}"
        if marker in prompt:
            idx = prompt.index(marker)
            system_part = prompt[:idx].rstrip()
            user_part = prompt[idx:].replace(marker, code)
            return system_part, user_part
        # Fallback: whole prompt is user message
        return None, safe_format(prompt, input=code)

    def predict_batch(
        self, prompt: str, samples: List[Sample], batch_idx: int
    ) -> List[str]:
        # Split system instructions from user content
        system_prompt, _ = self._split_system_user(prompt, "")
        queries = [safe_format(prompt, input=s.input_text) for s in samples]

        print(f"      🔍 批量预测 {len(queries)} 个样本...")
        kwargs: dict = dict(
            temperature=0.1,
            max_tokens=20,
            batch_size=min(8, len(queries)),
            concurrent=True,
        )
        if system_prompt:
            kwargs["system_prompt"] = system_prompt
        try:
            responses = self.llm_client.batch_generate(queries, **kwargs)
        except Exception as e:
            print(f"      ❌ 批量预测失败: {e}")
            return ["Other"] * len(samples)

        predictions: List[str] = []
        for idx, response in enumerate(responses):
            if response == "error":
                predictions.append("Other")
                continue

            cat = canonicalize_category(response)

            if batch_idx == 0 and idx < 3:
                print(f"        🔍 调试响应 {idx+1}: '{response[:100]}...'")
                print(f"        🎯 解析结果: '{cat}'")

            if cat is None:
                lower = response.lower()
                cat = canonicalize_category(lower)
                if cat is None:
                    if any(p in lower for p in (
                        "benign", "no vuln", "no security issue",
                        "not vulnerable", "safe", "secure code",
                    )):
                        cat = "Benign"
                    else:
                        cat = "Other"
                if batch_idx == 0 and idx < 3:
                    print(f"        ⚠️ 回退为: '{cat}'")

            predictions.append(cat)

        return predictions
