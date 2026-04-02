"""Seed prompt loader for evolution pipeline integration.

Provides utilities to load and prepare seed prompts for evolutionary
optimization of vulnerability detection prompts.
"""

from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import random

from .seed_prompts import (
    LAYER1_SEED_PROMPTS,
    LAYER2_SEED_PROMPTS,
    LAYER3_SEED_PROMPTS,
    META_ENHANCEMENT_SEEDS,
    get_seed_prompts_for_category,
)


@dataclass
class SeedPromptConfig:
    """Configuration for seed prompt loading.
    
    Attributes:
        layer: Which layer to load seeds for (1, 2, 3, or None for all)
        categories: Specific categories to load (None for all)
        min_seeds_per_category: Minimum seeds per category (will duplicate if needed)
        shuffle: Whether to shuffle the loaded seeds
        include_variations: Whether to include slight variations
    """
    layer: Optional[int] = None
    categories: Optional[List[str]] = None
    min_seeds_per_category: int = 1
    shuffle: bool = True
    include_variations: bool = False


class SeedPromptLoader:
    """Loads and prepares seed prompts for evolution."""
    
    def __init__(self, config: Optional[SeedPromptConfig] = None):
        """Initialize loader with optional config.
        
        Args:
            config: Seed loading configuration
        """
        self.config = config or SeedPromptConfig()
    
    def load_layer1_seeds(
        self, 
        categories: Optional[List[str]] = None
    ) -> Dict[str, List[str]]:
        """Load Layer 1 (major category) seed prompts.
        
        Args:
            categories: Specific categories to load, or None for all
            
        Returns:
            Dict mapping category names to list of seed prompts
        """
        if categories is None:
            return LAYER1_SEED_PROMPTS.copy()
        
        return {
            cat: LAYER1_SEED_PROMPTS[cat] 
            for cat in categories 
            if cat in LAYER1_SEED_PROMPTS
        }
    
    def load_layer2_seeds(
        self, 
        major_category: Optional[str] = None
    ) -> Dict[str, Dict[str, List[str]]]:
        """Load Layer 2 (middle category) seed prompts.
        
        Args:
            major_category: Specific major category to load, or None for all
            
        Returns:
            Nested dict: major -> middle -> list of prompts
        """
        if major_category is None:
            return LAYER2_SEED_PROMPTS.copy()
        
        if major_category in LAYER2_SEED_PROMPTS:
            return {major_category: LAYER2_SEED_PROMPTS[major_category]}
        
        return {}
    
    def load_layer3_seeds(
        self, 
        middle_category: Optional[str] = None
    ) -> Dict[str, Dict[str, List[str]]]:
        """Load Layer 3 (CWE-specific) seed prompts.
        
        Args:
            middle_category: Specific middle category to load, or None for all
            
        Returns:
            Nested dict: middle -> CWE -> list of prompts
        """
        if middle_category is None:
            return LAYER3_SEED_PROMPTS.copy()
        
        if middle_category in LAYER3_SEED_PROMPTS:
            return {middle_category: LAYER3_SEED_PROMPTS[middle_category]}
        
        return {}
    
    def get_flat_seed_list(
        self, 
        layer: int = 1,
        category: Optional[str] = None
    ) -> List[str]:
        """Get a flat list of seed prompts for evolution.
        
        Args:
            layer: Layer number (1, 2, or 3)
            category: Optional category filter
            
        Returns:
            Flat list of seed prompt strings
        """
        seeds = []
        
        if layer == 1:
            data = self.load_layer1_seeds()
            if category:
                seeds = data.get(category, [])
            else:
                for prompts in data.values():
                    seeds.extend(prompts)
                    
        elif layer == 2:
            data = self.load_layer2_seeds(category)
            for major, middles in data.items():
                for middle, prompts in middles.items():
                    seeds.extend(prompts)
                    
        elif layer == 3:
            data = self.load_layer3_seeds(category)
            for middle, cwes in data.items():
                for cwe, prompts in cwes.items():
                    seeds.extend(prompts)
        
        if self.config.shuffle:
            random.shuffle(seeds)
        
        return seeds
    
    def get_seeds_for_evolution(
        self, 
        population_size: int,
        layer: int = 1,
        category: Optional[str] = None
    ) -> List[str]:
        """Get seed prompts sized for evolution population.
        
        Ensures we have exactly `population_size` prompts by either
        truncating or duplicating with variations.
        
        Args:
            population_size: Target population size
            layer: Layer number
            category: Optional category filter
            
        Returns:
            List of exactly `population_size` prompts
        """
        seeds = self.get_flat_seed_list(layer, category)
        
        if not seeds:
            raise ValueError(f"No seeds found for layer {layer}, category {category}")
        
        # Extend if needed
        while len(seeds) < population_size:
            base = random.choice(seeds[:len(LAYER1_SEED_PROMPTS.get(category, seeds))])
            if self.config.include_variations:
                # Add slight variation marker (evolution will handle actual variation)
                seeds.append(base)
            else:
                seeds.append(base)
        
        # Truncate if needed
        if len(seeds) > population_size:
            seeds = seeds[:population_size]
        
        return seeds


def load_seeds_for_ga(
    population_size: int = 10,
    layer: int = 1,
    category: Optional[str] = None,
) -> List[str]:
    """Convenience function to load seeds for genetic algorithm.
    
    Args:
        population_size: Target population size
        layer: Detection layer (1, 2, or 3)
        category: Optional category to focus on
        
    Returns:
        List of seed prompts ready for GA evolution
    """
    loader = SeedPromptLoader()
    return loader.get_seeds_for_evolution(population_size, layer, category)


def get_hierarchical_seeds() -> Dict[str, Dict]:
    """Get all seeds organized hierarchically.
    
    Returns:
        Dict with layer1, layer2, layer3 keys containing respective seeds
    """
    return {
        "layer1": LAYER1_SEED_PROMPTS,
        "layer2": LAYER2_SEED_PROMPTS,
        "layer3": LAYER3_SEED_PROMPTS,
        "meta": META_ENHANCEMENT_SEEDS,
    }
