"""Hierarchical detector trainer with iterative feedback.

Training strategy:
1. Train each level detector with 1:1:1 sampling
2. Evaluate after each round
3. Collect error patterns and feedback to next round
4. Use evolutionary optimization for prompt improvement
"""

import json
import os
import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from .hierarchical_detector import (
    HierarchicalDetector, LevelDetector,
    MAJOR_TO_MIDDLE, MIDDLE_TO_CWE, CWE_TO_MIDDLE, MIDDLE_TO_MAJOR
)
from .hierarchical_sampler import HierarchicalSampler, TrainingSample


@dataclass
class EvalResult:
    """Evaluation result for a detector."""
    level: str
    target: str
    accuracy: float
    precision: float
    recall: float
    f1: float
    confusion: Dict[str, Dict[str, int]]
    errors: List[Dict]  # Sample errors for feedback


@dataclass
class TrainingRound:
    """Results from one training round."""
    round_num: int
    timestamp: str
    prompts: Dict[str, str]
    eval_results: Dict[str, EvalResult]
    feedback: str


class HierarchicalTrainer:
    """Trainer for hierarchical detector with iterative feedback."""

    def __init__(
        self,
        llm_client,
        meta_llm_client=None,  # For prompt evolution
        sampler: HierarchicalSampler = None,
        retriever=None,
        output_dir: str = "./outputs/hierarchical_training",
    ):
        self.llm_client = llm_client
        self.meta_llm = meta_llm_client or llm_client
        self.sampler = sampler
        self.retriever = retriever
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

        # Training history
        self.rounds: List[TrainingRound] = []
        self.best_prompts: Dict[str, str] = {}
        self.best_scores: Dict[str, float] = {}

    def train_all_levels(
        self,
        n_rounds: int = 3,
        n_samples_per_class: int = 50,
        max_workers: int = 8,
    ) -> Dict[str, str]:
        """Train all level detectors with iterative feedback.

        Returns:
            Dict of best prompts for each detector
        """
        print("=" * 70)
        print("🎯 Hierarchical Detector Training")
        print("=" * 70)

        for round_num in range(1, n_rounds + 1):
            print(f"\n{'#' * 70}")
            print(f"# Round {round_num}/{n_rounds}")
            print(f"{'#' * 70}")

            round_results = {}
            round_prompts = {}

            # Train Major detectors
            print("\n📊 Training Major Detectors...")
            for major in self.sampler.get_all_majors():
                result, prompt = self._train_single_detector(
                    level="major", target=major,
                    n_samples=n_samples_per_class,
                    round_num=round_num,
                )
                round_results[f"major_{major}"] = result
                round_prompts[f"major_{major}"] = prompt

            # Train Middle detectors
            print("\n📊 Training Middle Detectors...")
            for middle in self.sampler.get_all_middles():
                result, prompt = self._train_single_detector(
                    level="middle", target=middle,
                    n_samples=n_samples_per_class,
                    round_num=round_num,
                )
                round_results[f"middle_{middle}"] = result
                round_prompts[f"middle_{middle}"] = prompt

            # Train CWE detectors (only for CWEs with enough samples)
            print("\n📊 Training CWE Detectors...")
            for cwe in self.sampler.get_all_cwes():
                result, prompt = self._train_single_detector(
                    level="cwe", target=cwe,
                    n_samples=min(n_samples_per_class, 30),
                    round_num=round_num,
                )
                round_results[f"cwe_{cwe}"] = result
                round_prompts[f"cwe_{cwe}"] = prompt

            # Generate feedback
            feedback = self._generate_feedback(round_results)

            # Save round
            round_record = TrainingRound(
                round_num=round_num,
                timestamp=datetime.now().isoformat(),
                prompts=round_prompts,
                eval_results=round_results,
                feedback=feedback,
            )
            self.rounds.append(round_record)
            self._save_round(round_record)

            print(f"\n📝 Round {round_num} Feedback:")
            print(feedback[:500] + "..." if len(feedback) > 500 else feedback)

        # Return best prompts
        return self.best_prompts

    def _train_single_detector(
        self,
        level: str,
        target: str,
        n_samples: int,
        round_num: int,
    ) -> Tuple[EvalResult, str]:
        """Train a single detector and return evaluation result."""
        # Sample training data
        if level == "major":
            samples = self.sampler.sample_for_major(target, n_samples)
            candidates = list(MAJOR_TO_MIDDLE.keys()) + ["Benign"]
        elif level == "middle":
            samples = self.sampler.sample_for_middle(target, n_samples)
            major = MIDDLE_TO_MAJOR.get(target, "Logic")
            candidates = MAJOR_TO_MIDDLE.get(major, []) + ["Benign"]
        else:  # cwe
            samples = self.sampler.sample_for_cwe(target, n_samples)
            middle = CWE_TO_MIDDLE.get(target, "Other")
            candidates = MIDDLE_TO_CWE.get(middle, []) + ["Benign"]

        if not samples:
            return EvalResult(
                level=level, target=target,
                accuracy=0, precision=0, recall=0, f1=0,
                confusion={}, errors=[],
            ), ""

        # Get or generate prompt
        key = f"{level}_{target}"
        if round_num == 1 or key not in self.best_prompts:
            prompt = self._generate_initial_prompt(level, target, candidates)
        else:
            # Evolve prompt based on previous errors
            prev_result = self.rounds[-1].eval_results.get(key)
            prompt = self._evolve_prompt(
                self.best_prompts[key],
                prev_result.errors if prev_result else [],
                level, target, candidates,
            )

        # Create detector
        detector = LevelDetector(
            level=level, target=target,
            llm_client=self.llm_client,
            prompt=prompt,
            candidates=candidates,
            retriever=self.retriever,
        )

        # Evaluate
        result = self._evaluate_detector(detector, samples, level, target)

        # Update best if improved
        if key not in self.best_scores or result.f1 > self.best_scores[key]:
            self.best_scores[key] = result.f1
            self.best_prompts[key] = prompt

        print(f"   {level}/{target}: F1={result.f1:.2%}, Acc={result.accuracy:.2%}")

        return result, prompt

    def _evaluate_detector(
        self,
        detector: LevelDetector,
        samples: List[TrainingSample],
        level: str,
        target: str,
    ) -> EvalResult:
        """Evaluate detector on samples."""
        confusion = defaultdict(lambda: defaultdict(int))
        errors = []

        for sample in samples:
            try:
                results = detector.detect(sample.code, top_k=1)
                pred = results[0][0] if results else "Unknown"
            except Exception as e:
                pred = "Error"

            # Determine ground truth
            if sample.label == "target":
                gt = target
            elif sample.label == "benign":
                gt = "Benign"
            else:  # other_vul
                if level == "major":
                    gt = sample.major
                elif level == "middle":
                    gt = sample.middle
                else:
                    gt = sample.cwe

            confusion[gt][pred] += 1

            # Collect errors
            if pred != gt and len(errors) < 10:
                errors.append({
                    "code": sample.code[:500],
                    "expected": gt,
                    "predicted": pred,
                    "label": sample.label,
                })

        # Calculate metrics
        tp = confusion[target][target]
        fp = sum(confusion[gt][target] for gt in confusion if gt != target)
        fn = sum(confusion[target][pred] for pred in confusion[target] if pred != target)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        total = sum(sum(preds.values()) for preds in confusion.values())
        correct = sum(confusion[gt][gt] for gt in confusion)
        accuracy = correct / total if total > 0 else 0

        return EvalResult(
            level=level, target=target,
            accuracy=accuracy, precision=precision, recall=recall, f1=f1,
            confusion=dict(confusion),
            errors=errors,
        )

    def _generate_initial_prompt(self, level: str, target: str, candidates: List[str]) -> str:
        """Generate initial prompt for a detector."""
        candidates_str = ", ".join(candidates)

        if level == "major":
            return f"""You are a security expert specializing in {target} vulnerabilities.

## Task
Classify the code into one of these categories: {candidates_str}

## Evidence (similar vulnerable code):
{{evidence}}

## Code to analyze:
```
{{code}}
```

## Output (JSON):
{{{{
  "predictions": [
    {{{{"category": "{target}", "confidence": 0.85, "reason": "..."}}}}
  ]
}}}}"""

        elif level == "middle":
            return f"""You are a {target} vulnerability expert.

## Task
Identify if this code has a {target} vulnerability. Categories: {candidates_str}

## Evidence:
{{evidence}}

## Code:
```
{{code}}
```

## Output (JSON):
{{{{
  "predictions": [
    {{{{"category": "{target}", "confidence": 0.85, "reason": "..."}}}}
  ]
}}}}"""

        else:  # cwe
            return f"""You are a vulnerability expert. Identify if this code has {target}.

## Possible CWEs: {candidates_str}

## Evidence:
{{evidence}}

## Code:
```
{{code}}
```

## Output (JSON):
{{{{
  "predictions": [
    {{{{"cwe": "{target}", "confidence": 0.85, "reason": "..."}}}}
  ]
}}}}"""

    def _evolve_prompt(
        self,
        current_prompt: str,
        errors: List[Dict],
        level: str,
        target: str,
        candidates: List[str],
    ) -> str:
        """Evolve prompt based on errors."""
        if not errors:
            return current_prompt

        error_summary = "\n".join([
            f"- Expected {e['expected']}, got {e['predicted']}"
            for e in errors[:5]
        ])

        evolution_prompt = f"""You are a prompt engineer. Improve this vulnerability detection prompt.

## Current Prompt:
{current_prompt}

## Errors Made:
{error_summary}

## Requirements:
1. Keep the same JSON output format
2. Add hints to avoid the errors above
3. Keep the prompt concise

## Output the improved prompt only:"""

        try:
            improved = self.meta_llm.generate(evolution_prompt)
            # Extract prompt if wrapped
            if "```" in improved:
                improved = improved.split("```")[1].strip()
            return improved if len(improved) > 100 else current_prompt
        except Exception:
            return current_prompt

    def _generate_feedback(self, results: Dict[str, EvalResult]) -> str:
        """Generate feedback summary for the round."""
        lines = ["## Training Round Summary\n"]

        # Group by level
        by_level = defaultdict(list)
        for key, result in results.items():
            by_level[result.level].append(result)

        for level in ["major", "middle", "cwe"]:
            level_results = by_level.get(level, [])
            if not level_results:
                continue

            avg_f1 = sum(r.f1 for r in level_results) / len(level_results)
            lines.append(f"\n### {level.upper()} Level (avg F1: {avg_f1:.2%})")

            # Top errors
            all_errors = []
            for r in level_results:
                all_errors.extend(r.errors)

            if all_errors:
                lines.append("\nCommon errors:")
                error_patterns = defaultdict(int)
                for e in all_errors:
                    pattern = f"{e['expected']} -> {e['predicted']}"
                    error_patterns[pattern] += 1

                for pattern, count in sorted(error_patterns.items(), key=lambda x: -x[1])[:5]:
                    lines.append(f"  - {pattern}: {count} times")

        return "\n".join(lines)

    def _save_round(self, round_record: TrainingRound):
        """Save round results to file."""
        path = os.path.join(self.output_dir, f"round_{round_record.round_num}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({
                "round_num": round_record.round_num,
                "timestamp": round_record.timestamp,
                "prompts": round_record.prompts,
                "feedback": round_record.feedback,
                "eval_results": {
                    k: {
                        "level": v.level,
                        "target": v.target,
                        "accuracy": v.accuracy,
                        "precision": v.precision,
                        "recall": v.recall,
                        "f1": v.f1,
                    }
                    for k, v in round_record.eval_results.items()
                },
            }, f, indent=2, ensure_ascii=False)

    def save_best_prompts(self, path: str = None):
        """Save best prompts to file."""
        path = path or os.path.join(self.output_dir, "best_prompts.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({
                "prompts": self.best_prompts,
                "scores": self.best_scores,
            }, f, indent=2, ensure_ascii=False)
        print(f"💾 Best prompts saved to {path}")
