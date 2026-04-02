"""Evolution engine for prompt optimization."""

from typing import Protocol, Dict, Any, Optional
from ..algorithms.base import EvolutionAlgorithm
from ..llm.client import LLMClient
from .evaluator import Evaluator


class EvolutionEngine:
    """Main engine for evolutionary prompt optimization."""
    
    def __init__(
        self,
        algorithm: EvolutionAlgorithm,
        evaluator: Evaluator,
        llm_client: LLMClient,
        config: Optional[Dict[str, Any]] = None
    ):
        self.algorithm = algorithm
        self.evaluator = evaluator
        self.llm_client = llm_client
        self.config = config or {}
        
    def evolve(self) -> Dict[str, Any]:
        """Run the evolution process."""
        return self.algorithm.evolve(
            evaluator=self.evaluator,
            llm_client=self.llm_client,
            **self.config
        )


def ape(args, evaluator):
    """Legacy APE wrapper for backward compatibility."""
    from ...legacy.evoluter import ParaEvoluter
    evoluter = ParaEvoluter(args, evaluator)
    evoluter.evolute(mode=args.para_mode)


def ga_evo(args, evaluator):
    """Legacy GA wrapper for backward compatibility."""
    from ...legacy.evoluter import GAEvoluter
    evoluter = GAEvoluter(args, evaluator)
    evoluter.evolute()


def de_evo(args, evaluator):
    """Legacy DE wrapper for backward compatibility.""" 
    from ...legacy.evoluter import DEEvoluter
    evoluter = DEEvoluter(args, evaluator)
    evoluter.evolute()