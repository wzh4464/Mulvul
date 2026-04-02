"""Prompt tracking and logging system for EvoPrompt."""

import json
import os
import time
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class PromptSnapshot:
    """Represents a snapshot of a prompt at a specific point in time."""
    
    def __init__(
        self,
        prompt: str,
        fitness: Optional[float] = None,
        generation: int = 0,
        individual_id: str = "",
        operation: str = "",
        metadata: Optional[Dict] = None
    ):
        self.prompt = prompt
        self.fitness = fitness
        self.generation = generation
        self.individual_id = individual_id
        self.operation = operation  # "init", "crossover", "mutation", "selection"
        self.metadata = metadata or {}
        self.timestamp = datetime.now()
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "prompt": self.prompt,
            "fitness": self.fitness,
            "generation": self.generation,
            "individual_id": self.individual_id,
            "operation": self.operation,
            "metadata": self.metadata,
            "timestamp": self.timestamp.isoformat()
        }
        
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PromptSnapshot':
        """Create from dictionary."""
        snapshot = cls(
            prompt=data["prompt"],
            fitness=data.get("fitness"),
            generation=data.get("generation", 0),
            individual_id=data.get("individual_id", ""),
            operation=data.get("operation", ""),
            metadata=data.get("metadata", {})
        )
        if "timestamp" in data:
            snapshot.timestamp = datetime.fromisoformat(data["timestamp"])
        return snapshot


class PromptTracker:
    """Tracks and logs prompt evolution during the optimization process."""
    
    def __init__(self, output_dir: str, experiment_id: Optional[str] = None):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.experiment_id = experiment_id or f"exp_{int(time.time())}"
        
        # Create experiment directory
        self.exp_dir = self.output_dir / self.experiment_id
        self.exp_dir.mkdir(exist_ok=True)
        
        # Initialize files
        self.prompt_log_file = self.exp_dir / "prompt_evolution.jsonl"
        self.summary_file = self.exp_dir / "experiment_summary.json"
        self.best_prompts_file = self.exp_dir / "best_prompts.txt"
        
        # In-memory storage
        self.snapshots: List[PromptSnapshot] = []
        self.generation_bests: Dict[int, PromptSnapshot] = {}
        self.overall_best: Optional[PromptSnapshot] = None
        
        # Experiment metadata
        self.experiment_start_time = datetime.now()
        self.experiment_config = {}
        
        logger.info(f"Initialized prompt tracker for experiment: {self.experiment_id}")
        logger.info(f"Output directory: {self.exp_dir}")
        
    def set_config(self, config: Dict[str, Any]):
        """Set experiment configuration."""
        self.experiment_config = config
        
    def log_prompt(
        self,
        prompt: str,
        fitness: Optional[float] = None,
        generation: int = 0,
        individual_id: str = "",
        operation: str = "",
        metadata: Optional[Dict] = None
    ):
        """Log a prompt snapshot."""
        snapshot = PromptSnapshot(
            prompt=prompt,
            fitness=fitness,
            generation=generation,
            individual_id=individual_id,
            operation=operation,
            metadata=metadata
        )
        
        # Add to in-memory storage
        self.snapshots.append(snapshot)
        
        # Update generation best
        if fitness is not None:
            if generation not in self.generation_bests or (self.generation_bests[generation].fitness is None or fitness > self.generation_bests[generation].fitness):
                self.generation_bests[generation] = snapshot
                
            # Update overall best
            if self.overall_best is None or (self.overall_best.fitness is None or fitness > self.overall_best.fitness):
                self.overall_best = snapshot
                logger.info(f"New best prompt found! Fitness: {fitness:.4f}, Generation: {generation}")
                self._save_best_prompt(snapshot)
        
        # Save to file immediately for real-time tracking
        self._append_to_log(snapshot)
        
    def log_population(
        self,
        population: List[Any],  # List of Individual objects
        generation: int,
        operation: str = "evaluation"
    ):
        """Log an entire population."""
        for i, individual in enumerate(population):
            self.log_prompt(
                prompt=individual.prompt,
                fitness=individual.fitness,
                generation=generation,
                individual_id=f"gen{generation}_ind{i}",
                operation=operation,
                metadata=getattr(individual, 'metadata', {})
            )
    
    def _append_to_log(self, snapshot: PromptSnapshot):
        """Append snapshot to JSONL log file."""
        try:
            with open(self.prompt_log_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(snapshot.to_dict(), ensure_ascii=False) + '\n')
        except Exception as e:
            logger.error(f"Failed to write to log file: {e}")
            
    def _save_best_prompt(self, snapshot: PromptSnapshot):
        """Save best prompt to text file."""
        try:
            with open(self.best_prompts_file, 'a', encoding='utf-8') as f:
                f.write(f"\n{'='*80}\n")
                f.write(f"Generation: {snapshot.generation}\n")
                f.write(f"Fitness: {snapshot.fitness:.6f}\n")
                f.write(f"Timestamp: {snapshot.timestamp.isoformat()}\n")
                f.write(f"Individual ID: {snapshot.individual_id}\n")
                f.write(f"Operation: {snapshot.operation}\n")
                f.write(f"{'='*80}\n")
                f.write(f"{snapshot.prompt}\n")
        except Exception as e:
            logger.error(f"Failed to save best prompt: {e}")
    
    def save_summary(self, final_results: Optional[Dict] = None):
        """Save experiment summary."""
        experiment_end_time = datetime.now()
        duration = experiment_end_time - self.experiment_start_time
        
        summary = {
            "experiment_id": self.experiment_id,
            "start_time": self.experiment_start_time.isoformat(),
            "end_time": experiment_end_time.isoformat(),
            "duration_seconds": duration.total_seconds(),
            "config": self.experiment_config,
            "total_snapshots": len(self.snapshots),
            "total_generations": max([s.generation for s in self.snapshots], default=0),
            "best_fitness": self.overall_best.fitness if self.overall_best else None,
            "best_prompt": self.overall_best.prompt if self.overall_best else None,
            "generation_bests": {
                gen: {
                    "fitness": snapshot.fitness,
                    "prompt": snapshot.prompt[:100] + "..." if len(snapshot.prompt) > 100 else snapshot.prompt
                }
                for gen, snapshot in self.generation_bests.items()
            }
        }
        
        if final_results:
            summary["final_results"] = final_results
            
        try:
            with open(self.summary_file, 'w', encoding='utf-8') as f:
                json.dump(summary, f, indent=2, ensure_ascii=False)
            logger.info(f"Experiment summary saved: {self.summary_file}")
        except Exception as e:
            logger.error(f"Failed to save summary: {e}")
    
    def get_fitness_history(self) -> List[float]:
        """Get fitness history over generations."""
        fitness_by_gen = {}
        for snapshot in self.snapshots:
            if snapshot.fitness is not None:
                gen = snapshot.generation
                if gen not in fitness_by_gen:
                    fitness_by_gen[gen] = []
                fitness_by_gen[gen].append(snapshot.fitness)
        
        # Return best fitness per generation
        return [max(fitness_by_gen.get(gen, [0])) for gen in sorted(fitness_by_gen.keys())]
    
    def get_best_prompts_by_generation(self) -> Dict[int, PromptSnapshot]:
        """Get best prompt for each generation."""
        return self.generation_bests.copy()
    
    def load_from_log(self, log_file: str):
        """Load snapshots from existing log file."""
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        data = json.loads(line.strip())
                        snapshot = PromptSnapshot.from_dict(data)
                        self.snapshots.append(snapshot)
                        
                        # Update bests
                        if snapshot.fitness is not None:
                            gen = snapshot.generation
                            if gen not in self.generation_bests or snapshot.fitness > self.generation_bests[gen].fitness:
                                self.generation_bests[gen] = snapshot
                                
                            if self.overall_best is None or snapshot.fitness > self.overall_best.fitness:
                                self.overall_best = snapshot
                                
            logger.info(f"Loaded {len(self.snapshots)} snapshots from {log_file}")
        except Exception as e:
            logger.error(f"Failed to load from log file: {e}")
    
    def export_prompts_by_fitness(self, output_file: str, top_k: int = 10):
        """Export top-k prompts by fitness to a text file."""
        # Sort snapshots by fitness
        valid_snapshots = [s for s in self.snapshots if s.fitness is not None]
        valid_snapshots.sort(key=lambda x: x.fitness, reverse=True)
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(f"Top {top_k} Prompts by Fitness\n")
                f.write(f"Experiment: {self.experiment_id}\n")
                f.write(f"Generated: {datetime.now().isoformat()}\n")
                f.write("=" * 100 + "\n\n")
                
                for i, snapshot in enumerate(valid_snapshots[:top_k], 1):
                    f.write(f"Rank {i}: Fitness {snapshot.fitness:.6f} (Gen {snapshot.generation})\n")
                    f.write("-" * 80 + "\n")
                    f.write(f"{snapshot.prompt}\n")
                    f.write("\n" + "=" * 100 + "\n\n")
                    
            logger.info(f"Exported top {top_k} prompts to {output_file}")
        except Exception as e:
            logger.error(f"Failed to export prompts: {e}")


class EvolutionLogger:
    """Extended logger for evolution process with file outputs."""
    
    def __init__(self, output_dir: str, experiment_id: str):
        self.output_dir = Path(output_dir)
        self.experiment_id = experiment_id
        
        # Create log file
        log_file = self.output_dir / f"{experiment_id}.log"
        
        # Set up logger
        self.logger = logging.getLogger(f"evolution_{experiment_id}")
        self.logger.setLevel(logging.INFO)
        
        # File handler
        fh = logging.FileHandler(log_file, encoding='utf-8')
        fh.setLevel(logging.INFO)
        
        # Console handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        
        self.logger.addHandler(fh) 
        self.logger.addHandler(ch)
        
    def info(self, message: str):
        self.logger.info(message)
        
    def warning(self, message: str):
        self.logger.warning(message)
        
    def error(self, message: str):
        self.logger.error(message)