"""Cooperative coevolutionary trainer with population-level prompt evolution."""

from __future__ import annotations

import json
import logging
import os
import random
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

from mulvul.agents.hierarchical_detector import LevelDetector
from mulvul.agents.hierarchical_sampler import TrainingSample
from mulvul.data.cwe_hierarchy import (
    CWE_DESCRIPTIONS,
    CWE_TO_MIDDLE,
    MAJOR_DESCRIPTIONS,
    MAJOR_TO_MIDDLE,
    MIDDLE_DESCRIPTIONS,
    MIDDLE_TO_CWE,
    MIDDLE_TO_MAJOR,
)
from mulvul.mainline.artifacts import PromptArtifact
from mulvul.mainline.system import MainlineDetectorSystem

logger = logging.getLogger(__name__)


class EvolutionLog:
    """Append-only JSONL log with in-memory ring buffer for external monitoring.

    Each event is flushed immediately so an external process (or LLM) can
    tail the file to detect stalled fitness, low-diversity populations, or
    inefficient evolution patterns.
    """

    def __init__(self, path: Path | str, buffer_size: int = 200):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._buffer: deque[Dict[str, Any]] = deque(maxlen=buffer_size)
        self._handle = open(self._path, "a", encoding="utf-8")

    def emit(self, event: str, data: Dict[str, Any]) -> None:
        record = {
            "timestamp": datetime.now().isoformat(),
            "event": event,
            "data": data,
        }
        self._buffer.append(record)
        self._handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        self._handle.flush()

    def recent(self, n: int = 10) -> List[Dict[str, Any]]:
        items = list(self._buffer)
        return items[-n:]

    def summary(self) -> Dict[str, Dict[str, Any]]:
        latest: Dict[str, Dict[str, Any]] = {}
        for record in self._buffer:
            latest[record["event"]] = record
        return latest

    def close(self) -> None:
        self._handle.close()


@dataclass
class PromptIndividual:
    """A single prompt variant within a node's population."""

    prompt: str
    node_fitness: float = 0.0
    cascade_fitness: float = 0.0
    generation: int = 0
    origin: str = "seed"

    @property
    def combined_fitness(self) -> float:
        return 0.4 * self.node_fitness + 0.6 * self.cascade_fitness


@dataclass
class NodePopulation:
    """A taxonomy node's prompt population."""

    node_key: str
    stage: str
    individuals: List[PromptIndividual] = field(default_factory=list)

    @property
    def size(self) -> int:
        return len(self.individuals)

    def best(self) -> PromptIndividual:
        return max(self.individuals, key=lambda ind: ind.combined_fitness)

    def worst(self) -> PromptIndividual:
        return min(self.individuals, key=lambda ind: ind.combined_fitness)

    def tournament_select(
        self, k: int = 3, rng_seed: int | None = None
    ) -> PromptIndividual:
        rng = random.Random(rng_seed)
        contestants = rng.sample(self.individuals, min(k, len(self.individuals)))
        return max(contestants, key=lambda ind: ind.combined_fitness)


def attribute_cascade_error(
    *,
    true_major: str,
    pred_major: str,
    true_middle: str | None,
    pred_middle: str | None,
    true_cwe: str | None,
    pred_cwe: str | None,
) -> str | None:
    """Return the first cascade stage where prediction diverges from truth."""
    if pred_major != true_major:
        return "major"
    if pred_middle != true_middle:
        return "middle"
    if pred_cwe != true_cwe:
        return "cwe"
    return None


class CoevolutionaryTrainer:
    """Cooperative coevolutionary trainer with 4-phase generation loop.

    Each taxonomy node (major/middle/CWE) maintains its own population of
    prompt variants.  Every generation runs four phases:

    1. **Tournament** -- score all individuals locally and tournament-select
       a representative per node.
    2. **Cascade evaluation** -- assemble the representatives into a
       ``PromptArtifact``, run end-to-end detection via
       ``MainlineDetectorSystem``, and measure accuracy.
    3. **Fitness propagation** -- push cascade-level accuracy back to
       representatives as ``cascade_fitness``.
    4. **Evolution** -- mutate, crossover, and optionally migrate prompts
       within each population using error feedback.
    """

    def __init__(
        self,
        llm_client: Any,
        meta_llm_client: Any | None = None,
        sampler: Any | None = None,
        retriever: Any | None = None,
        output_dir: str = "./outputs/coevolution",
    ) -> None:
        self.llm_client = llm_client
        self.meta_llm = meta_llm_client or llm_client
        self.sampler = sampler
        self.retriever = retriever
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

        self.populations: Dict[str, NodePopulation] = {}
        self.best_prompts: Dict[str, str] = {}
        self.best_scores: Dict[str, float] = {}
        self._max_workers: int = 8
        self.log = EvolutionLog(Path(output_dir) / "evolution.jsonl")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def train_all_levels(
        self,
        n_rounds: int = 5,
        n_samples_per_class: int = 50,
        population_size: int = 5,
        tournament_k: int = 3,
        migration_rate: float = 0.1,
        max_workers: int = 8,
        phase1_only: bool = False,
    ) -> Dict[str, str]:
        """Run the full coevolutionary loop and return best prompts.

        Automatically resumes from the latest checkpoint if one exists in
        ``output_dir``.  A checkpoint is saved after every generation so
        long-running jobs can survive interruptions.
        """

        self._max_workers = max_workers
        start_gen = self._try_restore_checkpoint(population_size)

        for gen in range(start_gen, n_rounds):
            self.log.emit(
                "generation_start",
                {"generation": gen, "population_size": population_size},
            )

            # Phase 1 -- node-local tournaments
            representatives = self._phase1_tournament(
                n_samples=n_samples_per_class,
                tournament_k=tournament_k,
                gen=gen,
            )

            # Save intermediate checkpoint after Phase 1 so results are not lost
            for key, pop in self.populations.items():
                best_ind = pop.best()
                if key not in self.best_scores or best_ind.node_fitness > self.best_scores.get(key, 0):
                    self.best_prompts[key] = best_ind.prompt
                    self.best_scores[key] = best_ind.node_fitness
            self._save_checkpoint(gen, n_rounds, population_size)

            if phase1_only:
                self.log.emit("phase1_complete", {
                    "generation": gen,
                    "node_count": len(representatives),
                    "avg_node_f1": round(
                        sum(r.node_fitness for r in representatives.values()) / max(len(representatives), 1), 4
                    ),
                })
                continue

            # Phase 2 -- cascade evaluation
            e2e_accuracy, errors, detect_failures = self._phase2_cascade_eval(
                representatives, n_samples=n_samples_per_class
            )

            # Build error distribution by stage
            error_distribution: Dict[str, int] = defaultdict(int)
            for err in errors:
                error_distribution[err["stage"]] += 1

            self.log.emit(
                "cascade_eval_done",
                {
                    "generation": gen,
                    "e2e_accuracy": e2e_accuracy,
                    "error_count": len(errors),
                    "error_distribution": dict(error_distribution),
                    "detect_failures": detect_failures,
                },
            )

            # Phase 3 -- propagate cascade fitness
            self._phase3_propagate_fitness(representatives, e2e_accuracy, errors)

            # Phase 4 -- evolve populations
            self._phase4_evolve(errors, gen, migration_rate)

            # Update best prompts / scores from populations
            for key, pop in self.populations.items():
                best_ind = pop.best()
                if key not in self.best_scores or best_ind.combined_fitness > self.best_scores[key]:
                    self.best_prompts[key] = best_ind.prompt
                    self.best_scores[key] = best_ind.combined_fitness

            # Compute population diversity: ratio of unique prompts to total
            total_individuals = sum(p.size for p in self.populations.values())
            unique_prompts = len(
                {ind.prompt for p in self.populations.values() for ind in p.individuals}
            )
            diversity = unique_prompts / total_individuals if total_individuals > 0 else 0.0

            # Best fitness across all populations
            best_fitness = max(
                (p.best().combined_fitness for p in self.populations.values()),
                default=0.0,
            )

            self.log.emit(
                "generation_end",
                {
                    "generation": gen,
                    "e2e_accuracy": e2e_accuracy,
                    "best_scores": {k: round(v, 4) for k, v in self.best_scores.items()},
                    "population_diversity": round(diversity, 4),
                    "best_fitness": round(best_fitness, 4),
                },
            )

            self._save_checkpoint(gen + 1, n_rounds, population_size)

        self.log.close()
        return self.best_prompts

    def save_best_prompts(self, path: str | None = None) -> None:
        """Persist the best prompts and scores to disk."""
        save_path = Path(path) if path else Path(self.output_dir) / "best_prompts.json"
        save_path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "prompts": dict(self.best_prompts),
            "scores": {k: round(v, 6) for k, v in self.best_scores.items()},
        }
        with save_path.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def _save_incremental_prompts(self, gen: int) -> None:
        """Persist current best prompts after every node tournament.

        Written atomically so the file is always valid JSON even if the
        process is killed mid-write.  This ensures prompt texts survive
        interruptions without waiting for a full-generation checkpoint.
        """
        save_path = Path(self.output_dir) / "prompts_incremental.json"
        tmp_path = save_path.with_suffix(".tmp")
        data = {
            "generation": gen,
            "prompts": dict(self.best_prompts),
            "scores": {k: round(v, 6) for k, v in self.best_scores.items()},
            "timestamp": datetime.now().isoformat(),
            "node_count": len(self.best_prompts),
        }
        with tmp_path.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        tmp_path.rename(save_path)

    # ------------------------------------------------------------------
    # Checkpoint save / restore
    # ------------------------------------------------------------------

    def _checkpoint_path(self) -> Path:
        return Path(self.output_dir) / "checkpoint.json"

    def _save_checkpoint(
        self, next_gen: int, total_rounds: int, population_size: int
    ) -> None:
        """Persist full trainer state so training can resume after interruption."""
        populations_data: Dict[str, Any] = {}
        for key, pop in self.populations.items():
            populations_data[key] = {
                "node_key": pop.node_key,
                "stage": pop.stage,
                "individuals": [
                    {
                        "prompt": ind.prompt,
                        "node_fitness": ind.node_fitness,
                        "cascade_fitness": ind.cascade_fitness,
                        "generation": ind.generation,
                        "origin": ind.origin,
                    }
                    for ind in pop.individuals
                ],
            }

        checkpoint = {
            "next_generation": next_gen,
            "total_rounds": total_rounds,
            "population_size": population_size,
            "best_prompts": dict(self.best_prompts),
            "best_scores": {k: round(v, 8) for k, v in self.best_scores.items()},
            "populations": populations_data,
            "timestamp": datetime.now().isoformat(),
        }

        tmp_path = self._checkpoint_path().with_suffix(".tmp")
        with tmp_path.open("w", encoding="utf-8") as f:
            json.dump(checkpoint, f, indent=2, ensure_ascii=False)
        tmp_path.rename(self._checkpoint_path())

        self.log.emit(
            "checkpoint_saved",
            {"next_generation": next_gen, "total_rounds": total_rounds},
        )

    def _try_restore_checkpoint(self, population_size: int) -> int:
        """Restore from checkpoint if available. Returns the generation to start from."""
        ckpt_path = self._checkpoint_path()
        if not ckpt_path.exists():
            self._init_populations(population_size)
            return 0

        with ckpt_path.open("r", encoding="utf-8") as f:
            checkpoint = json.load(f)

        next_gen = checkpoint["next_generation"]
        self.best_prompts = checkpoint["best_prompts"]
        self.best_scores = {k: float(v) for k, v in checkpoint["best_scores"].items()}

        for key, pop_data in checkpoint["populations"].items():
            individuals = [
                PromptIndividual(
                    prompt=ind["prompt"],
                    node_fitness=ind["node_fitness"],
                    cascade_fitness=ind["cascade_fitness"],
                    generation=ind["generation"],
                    origin=ind["origin"],
                )
                for ind in pop_data["individuals"]
            ]
            self.populations[key] = NodePopulation(
                node_key=pop_data["node_key"],
                stage=pop_data["stage"],
                individuals=individuals,
            )

        self.log.emit(
            "checkpoint_restored",
            {
                "resumed_from_generation": next_gen,
                "node_count": len(self.populations),
                "best_prompts_count": len(self.best_prompts),
            },
        )
        logger.info(
            "Restored checkpoint: resuming from generation %d (%d nodes)",
            next_gen,
            len(self.populations),
        )
        return next_gen

    # ------------------------------------------------------------------
    # Initialisation helpers
    # ------------------------------------------------------------------

    def _init_populations(self, population_size: int) -> None:
        """Seed every canonical taxonomy node with *population_size* prompt variants.

        Uses the full taxonomy from ``MAJOR_TO_MIDDLE`` / ``MIDDLE_TO_CWE``
        rather than what the sampler happens to cover, so the output artifact
        is always complete even when the training dataset is sparse.
        """

        for major in MAJOR_TO_MIDDLE.keys():
            key = f"major_{major}"
            candidates = list(MAJOR_TO_MIDDLE.keys()) + ["Benign"]
            individuals = [
                PromptIndividual(
                    prompt=self._generate_seed_prompt("major", major, candidates),
                    origin="seed",
                )
                for _ in range(population_size)
            ]
            self.populations[key] = NodePopulation(
                node_key=key, stage="major", individuals=individuals
            )

        for middle in MIDDLE_TO_CWE.keys():
            key = f"middle_{middle}"
            parent_major = MIDDLE_TO_MAJOR.get(middle, "Logic")
            candidates = MAJOR_TO_MIDDLE.get(parent_major, []) + ["Benign"]
            individuals = [
                PromptIndividual(
                    prompt=self._generate_seed_prompt("middle", middle, candidates),
                    origin="seed",
                )
                for _ in range(population_size)
            ]
            self.populations[key] = NodePopulation(
                node_key=key, stage="middle", individuals=individuals
            )

        all_cwes = [cwe for cwe_list in MIDDLE_TO_CWE.values() for cwe in cwe_list]
        for cwe in all_cwes:
            key = f"cwe_{cwe}"
            parent_middle = CWE_TO_MIDDLE.get(cwe, "Other")
            candidates = MIDDLE_TO_CWE.get(parent_middle, []) + ["Benign"]
            individuals = [
                PromptIndividual(
                    prompt=self._generate_seed_prompt("cwe", cwe, candidates),
                    origin="seed",
                )
                for _ in range(population_size)
            ]
            self.populations[key] = NodePopulation(
                node_key=key, stage="cwe", individuals=individuals
            )

    def _generate_seed_prompt(
        self, stage: str, target: str, candidates: List[str]
    ) -> str:
        """Return an initial prompt template for *target* at the given *stage*.

        Prompts include semantic descriptions of candidates so the LLM can
        distinguish between similar taxonomy labels (e.g. CWE-119 vs CWE-121).
        """

        if stage == "major":
            target_desc = MAJOR_DESCRIPTIONS.get(target, "")
            target_info = f"{target} ({target_desc})" if target_desc else target
            candidates_with_desc = []
            for c in candidates:
                desc = MAJOR_DESCRIPTIONS.get(c, "")
                candidates_with_desc.append(f"{c}: {desc}" if desc else c)
            candidates_str = "\n- ".join(candidates_with_desc)
            return (
                f"You are a security expert specializing in {target_info}.\n"
                f"Classify the code into one of:\n- {candidates_str}\n\n"
                "## Evidence:\n{evidence}\n\n"
                "## Code:\n```\n{code}\n```\n\n"
                '## Output (JSON):\n{{"predictions":[{{"category":"...","confidence":0.0}}]}}'
            )
        if stage == "middle":
            target_desc = MIDDLE_DESCRIPTIONS.get(target, "")
            target_info = f"{target} ({target_desc})" if target_desc else target
            candidates_with_desc = []
            for c in candidates:
                desc = MIDDLE_DESCRIPTIONS.get(c, "")
                candidates_with_desc.append(f"{c}: {desc}" if desc else c)
            candidates_str = "\n- ".join(candidates_with_desc)
            return (
                f"You are a {target_info} vulnerability expert.\n"
                f"Classify the code into one of:\n- {candidates_str}\n\n"
                "## Evidence:\n{evidence}\n\n"
                "## Code:\n```\n{code}\n```\n\n"
                '## Output (JSON):\n{{"predictions":[{{"category":"...","confidence":0.0}}]}}'
            )
        # cwe
        target_desc = CWE_DESCRIPTIONS.get(target, "")
        target_info = f"{target} ({target_desc})" if target_desc else target
        candidates_with_desc = []
        for c in candidates:
            desc = CWE_DESCRIPTIONS.get(c, "")
            candidates_with_desc.append(f"{c}: {desc}" if desc else c)
        candidates_str = "\n- ".join(candidates_with_desc)
        return (
            f"Identify if this code has {target_info}.\n"
            f"Possible classifications:\n- {candidates_str}\n\n"
            "## Evidence:\n{evidence}\n\n"
            "## Code:\n```\n{code}\n```\n\n"
            '## Output (JSON):\n{{"predictions":[{{"cwe":"CWE-XXX","confidence":0.0}}]}}'
        )

    # ------------------------------------------------------------------
    # Phase 1 -- Node-local tournament
    # ------------------------------------------------------------------

    def _phase1_tournament(
        self,
        n_samples: int,
        tournament_k: int,
        gen: int,
    ) -> Dict[str, PromptIndividual]:
        """Score all individuals locally, then tournament-select a representative."""

        representatives: Dict[str, PromptIndividual] = {}
        scoring_failure_count = 0

        for key, pop in self.populations.items():
            stage = pop.stage
            # Derive the target label from the key
            target = key.split("_", 1)[1]

            # Gather evaluation samples
            if stage == "major":
                samples = self.sampler.sample_for_major(target, n_samples)
            elif stage == "middle":
                samples = self.sampler.sample_for_middle(target, n_samples)
            else:
                samples = self.sampler.sample_for_cwe(target, n_samples)

            # Skip scoring for nodes without training data; keep seed fitness 0
            if not samples:
                rep = pop.tournament_select(k=tournament_k)
                representatives[key] = rep
                self.log.emit(
                    "tournament_done",
                    {
                        "node": key,
                        "generation": gen,
                        "best_f1": 0.0,
                        "rep_f1": 0.0,
                        "skipped_no_data": True,
                        "scoring_failure_count": 0,
                    },
                )
                continue

            # Score every individual
            node_failures = 0
            for ind in pop.individuals:
                score, failures = self._score_individual(
                    ind, stage, target, samples
                )
                ind.node_fitness = score
                ind.generation = gen
                node_failures += failures
            scoring_failure_count += node_failures

            # Tournament select a representative
            rep = pop.tournament_select(k=tournament_k)
            representatives[key] = rep

            self.log.emit(
                "tournament_done",
                {
                    "node": key,
                    "generation": gen,
                    "best_f1": round(pop.best().node_fitness, 4),
                    "rep_f1": round(rep.node_fitness, 4),
                    "scoring_failure_count": node_failures,
                },
            )

            # Incremental save: persist best prompt per node immediately
            best_ind = pop.best()
            if key not in self.best_scores or best_ind.node_fitness > self.best_scores.get(key, 0):
                self.best_prompts[key] = best_ind.prompt
                self.best_scores[key] = best_ind.node_fitness
            self._save_incremental_prompts(gen)

        if scoring_failure_count > 0:
            logger.warning(
                "Phase 1: %d scoring exceptions across all nodes in gen %d",
                scoring_failure_count,
                gen,
            )

        return representatives

    def _score_individual(
        self,
        ind: PromptIndividual,
        stage: str,
        target: str,
        samples: List[TrainingSample],
    ) -> Tuple[float, int]:
        """Evaluate one individual's prompt on *samples*.

        Returns:
            A ``(f1_score, failure_count)`` tuple.  *failure_count* tracks how
            many samples raised exceptions during scoring so callers can surface
            backend health in logs.
        """

        if not samples:
            return 0.0, 0

        # Determine candidates for this detector
        if stage == "major":
            candidates = list(MAJOR_TO_MIDDLE.keys()) + ["Benign"]
        elif stage == "middle":
            parent_major = MIDDLE_TO_MAJOR.get(target, "Logic")
            candidates = MAJOR_TO_MIDDLE.get(parent_major, []) + ["Benign"]
        else:
            parent_middle = CWE_TO_MIDDLE.get(target, "Other")
            candidates = MIDDLE_TO_CWE.get(parent_middle, []) + ["Benign"]

        detector = LevelDetector(
            level=stage,
            target=target,
            llm_client=self.llm_client,
            prompt=ind.prompt,
            candidates=candidates,
            retriever=self.retriever,
        )

        def _score_one(sample: TrainingSample) -> Tuple[str, bool, bool]:
            """Score a single sample. Returns (predicted, is_target, failed)."""
            try:
                results = detector.detect(sample.code, top_k=1)
                predicted = results[0][0] if results else "Benign"
                return predicted, sample.label == "target", False
            except Exception:
                return "Benign", sample.label == "target", True

        # Concurrent sample scoring
        from concurrent.futures import ThreadPoolExecutor, as_completed

        tp = 0
        fp = 0
        fn = 0
        failure_count = 0

        with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
            futures = [executor.submit(_score_one, s) for s in samples]
            for future in as_completed(futures):
                predicted, is_target, failed = future.result()
                if failed:
                    failure_count += 1
                pred_is_target = predicted == target
                if is_target and pred_is_target:
                    tp += 1
                elif pred_is_target and not is_target:
                    fp += 1
                elif is_target and not pred_is_target:
                    fn += 1

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        if precision + recall > 0:
            return 2 * precision * recall / (precision + recall), failure_count
        return 0.0, failure_count

    # ------------------------------------------------------------------
    # Phase 2 -- End-to-end cascade evaluation
    # ------------------------------------------------------------------

    def _phase2_cascade_eval(
        self,
        representatives: Dict[str, PromptIndividual],
        n_samples: int,
    ) -> Tuple[float, List[Dict[str, Any]], int]:
        """Evaluate the assembled prompt artifact end-to-end.

        Returns:
            A ``(accuracy, errors, detect_failures)`` tuple where
            *detect_failures* counts how many ``system.detect()`` calls raised.
        """

        # Build the PromptArtifact from representative prompts
        prompt_mapping = {key: rep.prompt for key, rep in representatives.items()}
        try:
            artifact = PromptArtifact.from_mapping({"prompts": prompt_mapping})
            system = MainlineDetectorSystem(self.llm_client, artifact)
        except Exception as exc:
            logger.warning("Cascade eval failed to build system: %s", exc)
            return 0.0, [], 0

        # Gather a small evaluation set — keep it small since each sample
        # triggers a full 3-level cascade (3-6 LLM calls sequentially).
        cascade_eval_per_major = max(2, min(5, n_samples // 6))
        eval_samples: List[TrainingSample] = []
        for major in self.sampler.get_all_majors():
            eval_samples.extend(
                self.sampler.sample_for_major(major, cascade_eval_per_major)
            )

        if not eval_samples:
            return 0.0, [], 0

        correct = 0
        detect_failures = 0
        errors: List[Dict[str, Any]] = []

        for sample in eval_samples:
            try:
                result = system.detect(sample.code)
                pred_major = result.major
                pred_middle = result.middle
                pred_cwe = result.cwe
            except Exception:
                pred_major = "Benign"
                pred_middle = None
                pred_cwe = None
                detect_failures += 1

            true_major = sample.major
            true_middle = sample.middle if sample.middle != "Benign" else None
            true_cwe = sample.cwe if sample.cwe != "Benign" else None

            stage_err = attribute_cascade_error(
                true_major=true_major,
                pred_major=pred_major,
                true_middle=true_middle,
                pred_middle=pred_middle,
                true_cwe=true_cwe,
                pred_cwe=pred_cwe,
            )

            if stage_err is None:
                correct += 1
            else:
                errors.append(
                    {
                        "stage": stage_err,
                        "true_major": true_major,
                        "pred_major": pred_major,
                        "true_middle": true_middle,
                        "pred_middle": pred_middle,
                        "true_cwe": true_cwe,
                        "pred_cwe": pred_cwe,
                    }
                )

        if detect_failures > 0:
            logger.warning(
                "Phase 2: %d detect() failures out of %d samples",
                detect_failures,
                len(eval_samples),
            )

        accuracy = correct / len(eval_samples) if eval_samples else 0.0
        return accuracy, errors, detect_failures

    # ------------------------------------------------------------------
    # Error routing helper
    # ------------------------------------------------------------------

    def _route_error_to_node(self, err: Dict[str, Any]) -> str | None:
        """Route an error to the population that should receive mutation pressure.

        False positives are charged to the predicted node (it fired incorrectly).
        False negatives are charged to the true node (it failed to fire).
        """
        stage = err["stage"]
        true_label = err.get(f"true_{stage}")
        pred_label = err.get(f"pred_{stage}")

        # If true label is Benign at this stage, this is a false positive --
        # charge the predicted node (it shouldn't have fired)
        if true_label is None or true_label == "Benign":
            key = f"{stage}_{pred_label}" if pred_label else None
        else:
            # The true node failed to attract -- charge it
            key = f"{stage}_{true_label}"

        # Only route to nodes that have populations
        if key and key in self.populations:
            return key
        return None

    # ------------------------------------------------------------------
    # Phase 3 -- Fitness propagation
    # ------------------------------------------------------------------

    def _phase3_propagate_fitness(
        self,
        representatives: Dict[str, PromptIndividual],
        e2e_accuracy: float,
        errors: List[Dict[str, Any]],
    ) -> None:
        """Push cascade-level accuracy back to each representative."""

        # Count errors attributed to each node key
        error_counts: Dict[str, int] = defaultdict(int)
        for err in errors:
            node_key = self._route_error_to_node(err)
            if node_key is not None:
                error_counts[node_key] += 1

        total_errors = len(errors) if errors else 1

        for key, rep in representatives.items():
            # A node with many errors gets a lower cascade fitness
            node_error_rate = error_counts.get(key, 0) / total_errors
            rep.cascade_fitness = e2e_accuracy * (1.0 - node_error_rate)

    # ------------------------------------------------------------------
    # Phase 4 -- Evolution (mutation, crossover, migration)
    # ------------------------------------------------------------------

    def _phase4_evolve(
        self,
        errors: List[Dict[str, Any]],
        gen: int,
        migration_rate: float,
    ) -> None:
        """Mutate, crossover, and optionally migrate prompts."""

        # Group errors by node key using correct routing
        errors_by_node: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for err in errors:
            node_key = self._route_error_to_node(err)
            if node_key is not None:
                errors_by_node[node_key].append(err)

        # Per-population evolution
        for key, pop in self.populations.items():
            if pop.size < 2:
                continue

            node_errors = errors_by_node.get(key, [])

            # --- Mutation: rewrite worst individual using error feedback ---
            worst = pop.worst()
            mutated_prompt = self._mutate_prompt(worst.prompt, node_errors, key)
            worst.prompt = mutated_prompt
            worst.origin = "mutation"
            worst.generation = gen

            # --- Crossover: merge two tournament-selected parents ---
            if pop.size >= 3:
                parent_a = pop.tournament_select(k=2)
                parent_b = pop.tournament_select(k=2)
                child_prompt = self._crossover_prompts(
                    parent_a.prompt, parent_b.prompt, key
                )
                # Replace second-worst individual
                sorted_inds = sorted(
                    pop.individuals, key=lambda x: x.combined_fitness
                )
                if len(sorted_inds) >= 2:
                    target_ind = sorted_inds[1]
                    target_ind.prompt = child_prompt
                    target_ind.origin = "crossover"
                    target_ind.generation = gen

        # --- Migration: best-in-stage donates to worst-in-stage ---
        if random.random() < migration_rate:
            self._migrate_across_stage()

    def _mutate_prompt(
        self,
        prompt: str,
        errors: List[Dict[str, Any]],
        node_key: str,
    ) -> str:
        """Use the meta-LLM to rewrite *prompt* given cascade errors."""
        if not errors:
            return prompt

        error_summary = json.dumps(errors[:5], ensure_ascii=False)
        mutation_request = (
            f"The following prompt for node '{node_key}' produced cascade errors:\n"
            f"--- PROMPT ---\n{prompt[:1500]}\n"
            f"--- ERRORS ---\n{error_summary}\n\n"
            "Rewrite the prompt to fix the errors.  Keep {code} and {evidence} "
            "placeholders and JSON output format.  Return ONLY the new prompt."
        )
        try:
            result = self.meta_llm.generate(mutation_request)
            # Basic validation: the result should contain placeholders
            if "{code}" in result and len(result) > 50:
                return result
        except Exception:
            pass
        return prompt

    def _crossover_prompts(
        self, prompt_a: str, prompt_b: str, node_key: str
    ) -> str:
        """Use the meta-LLM to merge two parent prompts."""
        crossover_request = (
            f"Merge these two prompts for node '{node_key}' into a single "
            "improved prompt.  Keep {code} and {evidence} placeholders and "
            "JSON output format.  Return ONLY the merged prompt.\n\n"
            f"--- PROMPT A ---\n{prompt_a[:1000]}\n\n"
            f"--- PROMPT B ---\n{prompt_b[:1000]}"
        )
        try:
            result = self.meta_llm.generate(crossover_request)
            if "{code}" in result and len(result) > 50:
                return result
        except Exception:
            pass
        # Fallback: return the better prompt (by length heuristic, as we
        # can't score them here)
        return prompt_a

    def _migrate_across_stage(self) -> None:
        """Best-in-stage donates its prompt to the worst-in-stage."""
        by_stage: Dict[str, List[NodePopulation]] = defaultdict(list)
        for pop in self.populations.values():
            by_stage[pop.stage].append(pop)

        for stage, pops in by_stage.items():
            if len(pops) < 2:
                continue
            best_pop = max(pops, key=lambda p: p.best().combined_fitness)
            worst_pop = min(pops, key=lambda p: p.worst().combined_fitness)
            if best_pop is worst_pop:
                continue
            donor = best_pop.best()
            recipient = worst_pop.worst()
            try:
                migrate_request = (
                    f"Adapt the following donor prompt for node "
                    f"'{worst_pop.node_key}' (stage={stage}).\n\n"
                    f"--- DONOR ---\n{donor.prompt[:1000]}\n\n"
                    f"--- CURRENT ---\n{recipient.prompt[:1000]}\n\n"
                    "Return ONLY the adapted prompt. Keep {{code}} and "
                    "{{evidence}} placeholders."
                )
                result = self.meta_llm.generate(migrate_request)
                if "{code}" in result and len(result) > 50:
                    recipient.prompt = result
                    recipient.origin = "migration"
            except Exception:
                pass
