"""Code enhancement module for vulnerability detection.

Provides code enhancers that add analysis comments and annotations
to improve vulnerability detection accuracy.
"""

import asyncio
import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, List

from ..llm.async_client import AsyncLLMClient


logger = logging.getLogger(__name__)


# Comment4Vul-style enhancement prompt
COMMENT4VUL_PROMPT = """You are a security code analyst. Analyze the following code and add inline comments that highlight:

1. **Security-relevant operations**: Memory operations, input handling, authentication, cryptography
2. **Potential vulnerability patterns**: Buffer operations, pointer usage, SQL queries, user input
3. **Data flow**: Where data comes from, how it's used, and where it goes
4. **Critical control flow**: Conditional checks, error handling, authorization gates

Add comments using the format:
// [SECURITY] <brief observation>

Do NOT modify the code logic. Only add comments.
Return the enhanced code with your security analysis comments.

Code to analyze:
```
{code}
```

Return only the enhanced code with comments, no other text.
"""


@dataclass
class EnhancementConfig:
    """Configuration for code enhancement.
    
    Attributes:
        max_code_length: Maximum code length to process
        timeout_seconds: Timeout for enhancement
        cache_enabled: Whether to cache enhanced results
        fallback_on_error: Return original code on error
    """
    max_code_length: int = 10000
    timeout_seconds: float = 30.0
    cache_enabled: bool = True
    fallback_on_error: bool = True


class CodeEnhancerBase(ABC):
    """Abstract base class for code enhancers."""
    
    @abstractmethod
    def enhance(self, code: str) -> str:
        """Synchronously enhance code."""
        pass
    
    @abstractmethod
    async def enhance_async(self, code: str) -> str:
        """Asynchronously enhance code."""
        pass


class Comment4VulEnhancer(CodeEnhancerBase):
    """Code enhancer using Comment4Vul-style analysis.
    
    Adds security-focused comments to code using LLM analysis
    to improve subsequent vulnerability detection.
    """
    
    def __init__(
        self,
        llm_client: AsyncLLMClient,
        config: Optional[EnhancementConfig] = None,
        custom_prompt: Optional[str] = None,
    ):
        """Initialize Comment4Vul enhancer.
        
        Args:
            llm_client: LLM client for generating comments
            config: Enhancement configuration
            custom_prompt: Optional custom prompt template
        """
        self.llm_client = llm_client
        self.config = config or EnhancementConfig()
        self.prompt_template = custom_prompt or COMMENT4VUL_PROMPT
        
        # Simple in-memory cache
        self._cache: dict = {} if self.config.cache_enabled else None
    
    def enhance(self, code: str) -> str:
        """Synchronously enhance code with security comments.
        
        Args:
            code: Source code to enhance
            
        Returns:
            Enhanced code with security comments
        """
        return asyncio.run(self.enhance_async(code))
    
    async def enhance_async(self, code: str) -> str:
        """Asynchronously enhance code with security comments.
        
        Args:
            code: Source code to enhance
            
        Returns:
            Enhanced code with security comments
        """
        # Check cache
        if self._cache is not None and code in self._cache:
            logger.debug("Using cached enhancement")
            return self._cache[code]
        
        # Check code length
        if len(code) > self.config.max_code_length:
            logger.warning(f"Code too long ({len(code)} chars), truncating")
            code = code[:self.config.max_code_length]
        
        # Build prompt
        prompt = self.prompt_template.format(code=code)
        
        try:
            # Generate enhanced code
            response = await asyncio.wait_for(
                self.llm_client.generate_async(prompt),
                timeout=self.config.timeout_seconds
            )
            
            # Extract code from response
            enhanced = self._extract_code(response, code)
            
            # Cache result
            if self._cache is not None:
                self._cache[code] = enhanced
            
            return enhanced
            
        except asyncio.TimeoutError:
            logger.warning("Enhancement timed out, returning original")
            return code if self.config.fallback_on_error else ""
        except Exception as e:
            logger.error(f"Enhancement failed: {e}")
            return code if self.config.fallback_on_error else ""
    
    def _extract_code(self, response: str, original: str) -> str:
        """Extract enhanced code from LLM response.
        
        Args:
            response: Raw LLM response
            original: Original code for fallback
            
        Returns:
            Extracted enhanced code
        """
        if not response or response == "error":
            return original
        
        # Try to extract from code blocks
        patterns = [
            r"```(?:c|cpp|c\+\+|python|java|javascript|go)?\n?(.*?)```",
            r"```\n?(.*?)```",
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, response, re.DOTALL)
            if matches:
                return matches[0].strip()
        
        # If no code block, check if response looks like code
        if self._looks_like_code(response):
            return response.strip()
        
        return original
    
    def _looks_like_code(self, text: str) -> bool:
        """Check if text looks like code.
        
        Args:
            text: Text to check
            
        Returns:
            True if text appears to be code
        """
        code_indicators = [
            r'\{',           # Braces
            r'\}',
            r';$',           # Semicolons at end
            r'//.*',         # Single-line comments
            r'/\*.*\*/',     # Multi-line comments
            r'def\s+\w+',    # Python function
            r'function\s+',  # JavaScript function
            r'class\s+\w+',  # Class definition
            r'#include',     # C include
            r'import\s+',    # Import statement
        ]
        
        matches = sum(1 for p in code_indicators if re.search(p, text, re.MULTILINE))
        return matches >= 2
    
    def clear_cache(self) -> None:
        """Clear the enhancement cache."""
        if self._cache is not None:
            self._cache.clear()
            logger.info("Enhancement cache cleared")


class StaticAnalysisEnhancer(CodeEnhancerBase):
    """Code enhancer using static analysis hints.
    
    Adds comments based on static analysis tool results
    (e.g., Bandit for Python, Semgrep, etc.)
    """
    
    def __init__(self, analysis_tool: str = "bandit"):
        """Initialize static analysis enhancer.
        
        Args:
            analysis_tool: Static analysis tool to use
        """
        self.analysis_tool = analysis_tool
    
    def enhance(self, code: str) -> str:
        """Enhance code with static analysis comments.
        
        Args:
            code: Source code to enhance
            
        Returns:
            Enhanced code with analysis comments
        """
        # TODO: Integrate with static analysis tools
        # For now, return unchanged
        return code
    
    async def enhance_async(self, code: str) -> str:
        """Async wrapper for enhance."""
        return self.enhance(code)


class ChainedEnhancer(CodeEnhancerBase):
    """Chains multiple enhancers together.
    
    Applies enhancers in sequence, passing the output
    of each to the next.
    """
    
    def __init__(self, enhancers: List[CodeEnhancerBase]):
        """Initialize chained enhancer.
        
        Args:
            enhancers: List of enhancers to chain
        """
        self.enhancers = enhancers
    
    def enhance(self, code: str) -> str:
        """Apply all enhancers in sequence.
        
        Args:
            code: Source code to enhance
            
        Returns:
            Enhanced code
        """
        result = code
        for enhancer in self.enhancers:
            result = enhancer.enhance(result)
        return result
    
    async def enhance_async(self, code: str) -> str:
        """Apply all enhancers asynchronously in sequence.
        
        Args:
            code: Source code to enhance
            
        Returns:
            Enhanced code
        """
        result = code
        for enhancer in self.enhancers:
            result = await enhancer.enhance_async(result)
        return result


def create_comment4vul_enhancer(
    llm_client: AsyncLLMClient,
    **config_kwargs
) -> Comment4VulEnhancer:
    """Factory function to create Comment4Vul enhancer.
    
    Args:
        llm_client: LLM client
        **config_kwargs: EnhancementConfig parameters
        
    Returns:
        Configured Comment4VulEnhancer
    """
    config = EnhancementConfig(**config_kwargs)
    return Comment4VulEnhancer(llm_client, config)
