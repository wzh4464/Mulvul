"""MulVul Multi-Agent Vulnerability Detector.

Implements the complete detection pipeline from method.md Algorithm 3:
1. Stage I: Coarse-grained Routing (Router Agent)
2. Stage II: Fine-grained Detection (Detector Agents)
3. Stage III: Decision Aggregation
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

from .base import (
    BENIGN_CATEGORY,
    UNKNOWN_CATEGORY,
    DetectionResult,
    RoutingResult,
)
from .router_agent import RouterAgent
from .detector_agent import DetectorAgent, DetectorAgentFactory
from .aggregator import DecisionAggregator


class MulVulDetector:
    """Complete MulVul detection pipeline.

    Implements Router-Detector architecture:
    - Router predicts ranked categories
    - Detector fan-out adapts to router confidence
    - Results are aggregated by confidence
    """

    def __init__(
        self,
        router: RouterAgent,
        detectors: Dict[str, DetectorAgent],
        aggregator: DecisionAggregator = None,
        parallel: bool = True,
        max_agents: int = 3,
        adaptive: bool = True,
        min_agents: int = 1,
        routing_confidence_threshold: float = 0.2,
        routing_relative_threshold: float = 0.6,
        benign_short_circuit_threshold: float = 0.8,
    ):
        """Initialize MulVul detector.

        Args:
            router: Router agent for category prediction
            detectors: Dict of category -> DetectorAgent
            aggregator: Decision aggregator (default: confidence-based)
            parallel: Whether to run detectors in parallel
            max_agents: Maximum number of detector agents to invoke
            adaptive: Whether to adapt detector fan-out using router confidence
            min_agents: Minimum number of detector agents to invoke when not
                short-circuiting to Benign
            routing_confidence_threshold: Absolute minimum confidence for
                adaptive detector fan-out
            routing_relative_threshold: Relative threshold against the highest
                vulnerable category confidence for adaptive fan-out
            benign_short_circuit_threshold: If Benign is the top route and is
                this confident, skip specialist detectors unless a vulnerable
                category remains competitive
        """
        self.router = router
        self.detectors = detectors
        self.aggregator = aggregator or DecisionAggregator()
        self.parallel = parallel
        self.max_agents = max(1, max_agents)
        self.k = self.max_agents
        self.adaptive = adaptive
        self.min_agents = max(1, min_agents)
        self.routing_confidence_threshold = routing_confidence_threshold
        self.routing_relative_threshold = routing_relative_threshold
        self.benign_short_circuit_threshold = benign_short_circuit_threshold

    def detect(self, code: str) -> DetectionResult:
        """Detect vulnerability in code.

        Args:
            code: Source code to analyze

        Returns:
            DetectionResult with prediction, confidence, and evidence
        """
        routing_result = self.router.route(code)
        selected_categories, _, final_result = self._run_detection(
            code, routing_result
        )
        final_result.raw_response = self._format_raw_response(
            selected_categories,
            routing_result,
            final_result.raw_response,
        )

        return final_result

    def detect_with_details(self, code: str) -> Dict:
        """Detect with full details including intermediate results.

        Returns:
            Dict with routing, detection, and aggregation details
        """
        routing_result = self.router.route(code)
        selected_categories, detector_results, final_result = self._run_detection(
            code, routing_result
        )

        return {
            "routing": {
                "top_k": routing_result.get_top_k(self.max_agents),
                "ranked": routing_result.categories,
                "selected": selected_categories,
                "selected_agent_count": len(selected_categories),
                "evidence_count": len(routing_result.evidence_used),
            },
            "detectors": [r.to_dict() for r in detector_results],
            "final": final_result.to_dict(),
        }

    def _select_detector_categories(
        self,
        routing_result: RoutingResult,
    ) -> List[tuple]:
        """Select detector categories from router output.

        The router returns a ranked list across all categories. When adaptive
        mode is enabled, specialist detector fan-out expands only when the
        router remains uncertain about the vulnerable category.
        """
        vulnerable_categories = self._filter_supported_categories(routing_result)

        if not vulnerable_categories:
            return []

        if not self.adaptive:
            return vulnerable_categories[:self.max_agents]

        if self._should_short_circuit_benign(
            routing_result, vulnerable_categories
        ):
            return []

        selected = self._apply_dynamic_threshold(vulnerable_categories)
        if not selected or len(selected) < self.min_agents:
            return self._fallback_min_vulnerable(vulnerable_categories)

        return selected

    def _filter_supported_categories(
        self,
        routing_result: RoutingResult,
    ) -> List[tuple]:
        """Keep only categories backed by specialist detectors."""
        return [
            (category, confidence)
            for category, confidence in routing_result.get_top_k()
            if category in self.detectors
        ]

    def _should_short_circuit_benign(
        self,
        routing_result: RoutingResult,
        vulnerable_categories: List[tuple],
    ) -> bool:
        """Return True when a Benign router result should skip specialists."""
        top_vulnerable_confidence = vulnerable_categories[0][1]
        return (
            routing_result.top_category == BENIGN_CATEGORY
            and routing_result.top_confidence
            >= self.benign_short_circuit_threshold
            and top_vulnerable_confidence
            < routing_result.top_confidence * self.routing_relative_threshold
        )

    def _apply_dynamic_threshold(
        self,
        vulnerable_categories: List[tuple],
    ) -> List[tuple]:
        """Select competitive vulnerable categories under the adaptive policy."""
        top_vulnerable_confidence = vulnerable_categories[0][1]
        dynamic_threshold = max(
            self.routing_confidence_threshold,
            top_vulnerable_confidence * self.routing_relative_threshold,
        )
        return [
            (category, confidence)
            for category, confidence in vulnerable_categories
            if confidence >= dynamic_threshold
        ][:self.max_agents]

    def _fallback_min_vulnerable(
        self,
        vulnerable_categories: List[tuple],
    ) -> List[tuple]:
        """Fallback to the highest-ranked vulnerable categories."""
        max_possible = min(len(vulnerable_categories), self.max_agents)
        min_required = min(max_possible, max(self.min_agents, 1))
        return vulnerable_categories[:min_required]

    def _handle_empty_selection(
        self,
        routing_result: RoutingResult,
    ) -> DetectionResult:
        """Handle cases where no specialist detector should be invoked."""
        if routing_result.top_category == BENIGN_CATEGORY:
            return DetectionResult(
                prediction=BENIGN_CATEGORY,
                confidence=routing_result.top_confidence,
                evidence=(
                    "Router predicted Benign, so no specialist detector "
                    "was invoked."
                ),
                category=BENIGN_CATEGORY,
                agent_id="router_benign",
                raw_response=routing_result.raw_response,
            )

        return DetectionResult(
            prediction=UNKNOWN_CATEGORY,
            confidence=0.0,
            evidence="Router did not return any supported detector category.",
            category=UNKNOWN_CATEGORY,
            agent_id="router_empty",
            raw_response=routing_result.raw_response,
        )

    def _run_detection(
        self,
        code: str,
        routing_result: RoutingResult,
    ) -> Tuple[List[tuple], List[DetectionResult], DetectionResult]:
        """Execute detector fan-out and aggregation for one routed sample."""
        selected_categories = self._select_detector_categories(routing_result)
        if not selected_categories:
            return [], [], self._handle_empty_selection(routing_result)

        if self.parallel:
            detector_results = self._detect_parallel(code, selected_categories)
        else:
            detector_results = self._detect_sequential(code, selected_categories)

        final_result = self.aggregator.aggregate(detector_results)
        return selected_categories, detector_results, final_result

    def _format_raw_response(
        self,
        selected_categories: List[tuple],
        routing_result: RoutingResult,
        raw_response: str,
    ) -> str:
        """Attach routing metadata to the final raw response."""
        return (
            f"Selected detectors: {[c[0] for c in selected_categories]}\n"
            f"Router ranking: {[c[0] for c in routing_result.categories]}\n"
            f"{raw_response}"
        )

    def _detect_parallel(
        self, code: str, categories: List[tuple]
    ) -> List[DetectionResult]:
        """Run detectors in parallel."""
        results = []

        if not categories:
            return results

        with ThreadPoolExecutor(max_workers=len(categories)) as executor:
            futures = {}
            for category, confidence in categories:
                if category in self.detectors:
                    future = executor.submit(
                        self.detectors[category].detect, code
                    )
                    futures[future] = category

            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    category = futures[future]
                    results.append(DetectionResult(
                        prediction="Error",
                        confidence=0.0,
                        evidence=str(e),
                        category=category,
                        agent_id=f"detector_{category.lower()}",
                    ))

        return results

    def _detect_sequential(
        self, code: str, categories: List[tuple]
    ) -> List[DetectionResult]:
        """Run detectors sequentially."""
        results = []

        for category, confidence in categories:
            if category in self.detectors:
                try:
                    result = self.detectors[category].detect(code)
                    results.append(result)
                except Exception as e:
                    results.append(DetectionResult(
                        prediction="Error",
                        confidence=0.0,
                        evidence=str(e),
                        category=category,
                        agent_id=f"detector_{category.lower()}",
                    ))

        return results

    @classmethod
    def create_default(
        cls,
        llm_client,
        retriever=None,
        max_agents: int = 3,
        parallel: bool = True,
        adaptive: bool = True,
        k: Optional[int] = None,
        min_agents: int = 1,
        routing_confidence_threshold: float = 0.2,
        routing_relative_threshold: float = 0.6,
        benign_short_circuit_threshold: float = 0.8,
    ) -> "MulVulDetector":
        """Create MulVul detector with default configuration.

        Args:
            llm_client: LLM client for all agents
            retriever: Optional retriever for evidence
            max_agents: Maximum number of detector agents
            parallel: Whether to run detectors in parallel
            adaptive: Whether to adapt detector fan-out using router confidence
            k: Backward-compatible alias for max_agents

        Returns:
            Configured MulVulDetector instance
        """
        if k is not None:
            max_agents = k

        router = RouterAgent(
            llm_client=llm_client,
            retriever=retriever,
        )

        detectors = DetectorAgentFactory.create_all_detectors(
            llm_client=llm_client,
            retriever=retriever,
        )

        aggregator = DecisionAggregator()

        return cls(
            router=router,
            detectors=detectors,
            aggregator=aggregator,
            parallel=parallel,
            max_agents=max_agents,
            adaptive=adaptive,
            min_agents=min_agents,
            routing_confidence_threshold=routing_confidence_threshold,
            routing_relative_threshold=routing_relative_threshold,
            benign_short_circuit_threshold=benign_short_circuit_threshold,
        )
