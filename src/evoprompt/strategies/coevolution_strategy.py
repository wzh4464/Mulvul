"""Coevolution strategy using multi-agent detection.

DetectionAgent handles batch prediction; MetaAgent handles prompt improvement
(wired separately in the evolution loop). This strategy focuses on the
prediction side only, conforming to the DetectionStrategy protocol.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from evoprompt.data.cwe_categories import canonicalize_category, map_cwe_to_major
from evoprompt.data.dataset import Sample
from evoprompt.multiagent.agents import (
    AgentConfig,
    AgentRole,
    DetectionAgent,
)
from evoprompt.utils.text import safe_format

logger = logging.getLogger(__name__)


class CoevolutionStrategy:
    """Multi-agent coevolution strategy: DetectionAgent evaluates samples.

    The strategy delegates batch prediction to a DetectionAgent, which already
    supports batched LLM calls. If the agent cannot be constructed (e.g. missing
    dependencies), it falls back to a plain ``llm_client.batch_generate`` call
    identical to :class:`FlatStrategy`.
    """

    def __init__(self, llm_client: Any, config: Dict[str, Any] | None = None):
        self.llm_client = llm_client
        self.config = config or {}

        # Try to build a DetectionAgent wrapping the same llm_client.
        self._detection_agent: Optional[DetectionAgent] = None
        self._setup_detection_agent()

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------

    def _setup_detection_agent(self) -> None:
        """Attempt to wrap *llm_client* in a DetectionAgent."""
        try:
            agent_cfg = AgentConfig(
                role=AgentRole.DETECTION,
                model_name=self.config.get("model_name", "default"),
                temperature=self.config.get("temperature", 0.1),
                max_tokens=self.config.get("max_tokens", 20),
                batch_size=self.config.get("batch_size", 8),
            )
            self._detection_agent = DetectionAgent(agent_cfg, self.llm_client)
            logger.info("CoevolutionStrategy: DetectionAgent initialised")
        except Exception as exc:
            logger.warning(
                "CoevolutionStrategy: DetectionAgent setup failed (%s), "
                "falling back to direct LLM calls",
                exc,
            )
            self._detection_agent = None

    # ------------------------------------------------------------------
    # Protocol: get_ground_truth
    # ------------------------------------------------------------------

    def get_ground_truth(self, sample: Sample) -> str:
        """Return ground-truth category for *sample* (same logic as FlatStrategy)."""
        ground_truth_binary = int(sample.target)
        cwe_codes = sample.metadata.get("cwe", [])
        if ground_truth_binary == 1 and cwe_codes:
            return map_cwe_to_major(cwe_codes)
        return "Benign"

    # ------------------------------------------------------------------
    # Protocol: predict_batch
    # ------------------------------------------------------------------

    def predict_batch(
        self, prompt: str, samples: List[Sample], batch_idx: int
    ) -> List[str]:
        """Return a predicted category for each sample.

        Uses DetectionAgent when available; otherwise falls back to a plain
        ``llm_client.batch_generate`` call.
        """
        if self._detection_agent is not None:
            return self._predict_via_agent(prompt, samples, batch_idx)
        return self._predict_fallback(prompt, samples, batch_idx)

    # ------------------------------------------------------------------
    # Agent path
    # ------------------------------------------------------------------

    def _predict_via_agent(
        self, prompt: str, samples: List[Sample], batch_idx: int
    ) -> List[str]:
        """Predict using the DetectionAgent.

        DetectionAgent.detect() returns raw LLM responses (normalised to
        'vulnerable'/'benign'). We feed formatted prompts through
        ``safe_format`` and then post-process responses into the 11-class
        category space used by the evolution loop.
        """
        code_samples = [s.input_text for s in samples]

        print(f"      [coevo] DetectionAgent batch predict {len(code_samples)} samples...")

        # DetectionAgent.detect() internally formats prompt via str.replace,
        # but we want the richer safe_format behaviour. So we build the
        # formatted queries ourselves and pass a trivial template.
        queries = [safe_format(prompt, input=code) for code in code_samples]

        # Use batch_generate directly via the agent's llm_client so we keep
        # the agent's temperature / batch_size settings while passing
        # pre-formatted queries.
        try:
            responses = self._detection_agent.llm_client.batch_generate(
                queries,
                temperature=self._detection_agent.config.temperature,
                max_tokens=self._detection_agent.config.max_tokens,
                batch_size=self._detection_agent.config.batch_size,
            )
        except Exception as e:
            print(f"      [coevo] DetectionAgent batch failed: {e}")
            return ["Other"] * len(samples)

        return self._parse_responses(responses, batch_idx)

    # ------------------------------------------------------------------
    # Fallback path (plain LLM)
    # ------------------------------------------------------------------

    def _predict_fallback(
        self, prompt: str, samples: List[Sample], batch_idx: int
    ) -> List[str]:
        """Fallback: predict using llm_client.batch_generate directly."""
        queries = [safe_format(prompt, input=s.input_text) for s in samples]

        print(f"      [coevo-fallback] batch predict {len(queries)} samples...")
        try:
            responses = self.llm_client.batch_generate(
                queries,
                temperature=0.1,
                max_tokens=20,
                batch_size=min(8, len(queries)),
                concurrent=True,
            )
        except Exception as e:
            print(f"      [coevo-fallback] batch predict failed: {e}")
            return ["Other"] * len(samples)

        return self._parse_responses(responses, batch_idx)

    # ------------------------------------------------------------------
    # Shared response parsing
    # ------------------------------------------------------------------

    def _parse_responses(
        self, responses: List[str], batch_idx: int
    ) -> List[str]:
        """Normalise raw LLM responses into the 11-class category space."""
        predictions: List[str] = []
        for idx, response in enumerate(responses):
            if response == "error":
                predictions.append("Other")
                continue

            cat = canonicalize_category(response)

            if batch_idx == 0 and idx < 3:
                print(f"        [coevo] response {idx + 1}: '{response[:100]}...'")
                print(f"        [coevo] parsed: '{cat}'")

            if cat is None:
                lower = response.lower()
                cat = canonicalize_category(lower)
                if cat is None:
                    if any(
                        p in lower
                        for p in (
                            "benign",
                            "no vuln",
                            "no security issue",
                            "not vulnerable",
                            "safe",
                            "secure code",
                        )
                    ):
                        cat = "Benign"
                    else:
                        cat = "Other"
                if batch_idx == 0 and idx < 3:
                    print(f"        [coevo] fallback category: '{cat}'")

            predictions.append(cat)

        return predictions
