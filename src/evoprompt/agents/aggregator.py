"""Decision Aggregator for multi-agent results.

Implements Stage III from method.md Algorithm 3:
- If all detectors predict non-vulnerable: return Benign
- Otherwise: return prediction with highest confidence
"""

from typing import List, Optional

from .base import DetectionResult


class DecisionAggregator:
    """Aggregates decisions from multiple detector agents.

    Implements confidence-based selection:
    ŷ = argmax_m c_m · I[y_m ≠ non-vul]
    """

    def __init__(self, min_confidence: float = 0.3):
        """Initialize aggregator.

        Args:
            min_confidence: Minimum confidence threshold for vulnerability
        """
        self.min_confidence = min_confidence

    def aggregate(self, results: List[DetectionResult]) -> DetectionResult:
        """Aggregate results from multiple detectors.

        Args:
            results: List of DetectionResult from different detectors

        Returns:
            Final aggregated DetectionResult
        """
        if not results:
            return DetectionResult(
                prediction="Unknown",
                confidence=0.0,
                evidence="No detector results available",
            )

        # Separate vulnerable and benign predictions
        vuln_results = [r for r in results if r.is_vulnerable()]
        benign_results = [r for r in results if not r.is_vulnerable()]

        # If all predict benign, return benign with max confidence
        if not vuln_results:
            best_benign = max(benign_results, key=lambda r: r.confidence)
            return DetectionResult(
                prediction="Benign",
                confidence=best_benign.confidence,
                evidence="All detectors agree: no vulnerability detected",
                category="Benign",
                agent_id="aggregator",
            )

        # Filter by minimum confidence
        confident_vulns = [r for r in vuln_results if r.confidence >= self.min_confidence]

        if not confident_vulns:
            # No confident vulnerability predictions
            # Return highest confidence benign if available
            if benign_results:
                best_benign = max(benign_results, key=lambda r: r.confidence)
                return DetectionResult(
                    prediction="Benign",
                    confidence=best_benign.confidence,
                    evidence="Vulnerability predictions below confidence threshold",
                    category="Benign",
                    agent_id="aggregator",
                )
            # Otherwise return highest vuln even if low confidence
            confident_vulns = vuln_results

        # Select highest confidence vulnerability
        best = max(confident_vulns, key=lambda r: r.confidence)

        return DetectionResult(
            prediction=best.prediction,
            confidence=best.confidence,
            evidence=best.evidence,
            category=best.category,
            subcategory=best.subcategory,
            cwe=best.cwe,
            agent_id=f"aggregator({best.agent_id})",
            raw_response=best.raw_response,
        )

    def aggregate_with_voting(self, results: List[DetectionResult]) -> DetectionResult:
        """Alternative aggregation using weighted voting.

        Each detector votes for its prediction, weighted by confidence.
        """
        if not results:
            return DetectionResult(prediction="Unknown", confidence=0.0)

        # Count weighted votes per prediction
        votes = {}
        for r in results:
            pred = r.prediction
            if pred not in votes:
                votes[pred] = {"weight": 0.0, "results": []}
            votes[pred]["weight"] += r.confidence
            votes[pred]["results"].append(r)

        # Find prediction with highest weighted vote
        best_pred = max(votes.keys(), key=lambda p: votes[p]["weight"])
        best_results = votes[best_pred]["results"]
        best_result = max(best_results, key=lambda r: r.confidence)

        # Normalize confidence by number of agreeing detectors
        agreement_bonus = len(best_results) / len(results)
        final_confidence = min(best_result.confidence * (1 + agreement_bonus * 0.2), 1.0)

        return DetectionResult(
            prediction=best_pred,
            confidence=final_confidence,
            evidence=best_result.evidence,
            category=best_result.category,
            subcategory=best_result.subcategory,
            cwe=best_result.cwe,
            agent_id=f"voting({len(best_results)}/{len(results)})",
        )
