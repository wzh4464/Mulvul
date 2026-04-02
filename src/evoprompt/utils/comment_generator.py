"""
LLM-based comment generator for SCALE methodology.

This module implements Section 3.1 of the SCALE paper:
- Uses LLM to generate comments for code snippets
- Normalizes comments (remove blank lines, replace ''' with //)
- Prepares code for Comment Tree construction
"""

import logging
import re
from typing import Optional, Tuple
from pathlib import Path
import sys

logger = logging.getLogger(__name__)

# Import LLM client
try:
    from evoprompt.llm.client import SVENLLMClient
    LLM_AVAILABLE = True
except ImportError as e:
    logger.warning(f"LLM client not available: {e}")
    LLM_AVAILABLE = False
    SVENLLMClient = None


class CommentGenerator:
    """Generate comments for code using LLM (SCALE Section 3.1)"""

    def __init__(self, llm_client=None, model_name: Optional[str] = None):
        """
        Initialize comment generator.

        Args:
            llm_client: Pre-initialized LLM client (optional)
            model_name: Model name override (optional)
        """
        if llm_client is None and LLM_AVAILABLE:
            logger.info("Initializing LLM client for comment generation...")
            self.client = SVENLLMClient(model_name=model_name)
        else:
            self.client = llm_client

        self.model_name = model_name

    def generate_comments(
        self,
        code: str,
        language: str = "C",
        temperature: float = 0.1
    ) -> Tuple[str, bool]:
        """
        Generate inline comments for code using LLM.

        Implements SCALE paper Section 3.1:
        - Uses ChatGPT to generate comments
        - Returns commented code ready for normalization

        Args:
            code: Source code to comment
            language: Programming language (C, C++, Java, etc.)
            temperature: LLM temperature (lower = more deterministic)

        Returns:
            Tuple of (commented_code, success)
        """
        if not LLM_AVAILABLE or self.client is None:
            logger.error("LLM client not available")
            return code, False

        # Design prompt following SCALE methodology
        # Based on OpenAI's gpt-best-practices (role-based basic prompt)
        prompt = self._build_comment_prompt(code, language)

        try:
            # Use SVENLLMClient.generate method
            result = self.client.generate(
                prompt,
                temperature=temperature,
                max_tokens=4096  # Allow enough tokens for code + comments
            )

            if not result:
                logger.warning("LLM returned empty result")
                return code, False

            # Normalize the result
            commented_code = self._normalize_llm_output(result)

            # Validate that we got actual comments
            if self._has_meaningful_comments(code, commented_code):
                return commented_code, True
            else:
                logger.warning("LLM did not add meaningful comments")
                return code, False

        except Exception as e:
            logger.error(f"Error generating comments: {e}")
            return code, False

    def _build_comment_prompt(self, code: str, language: str) -> str:
        """
        Build prompt for comment generation.

        Optimized for SCALE methodology:
        - Single-line comments only
        - Placed directly above control flow statements
        - Concise and focused
        """
        return f"""You are a code analysis expert specializing in security vulnerability detection.

Add SINGLE-LINE comments ONLY for control flow statements in this {language} code.

IMPORTANT Rules:
1. Add ONE line comment DIRECTLY ABOVE these statements:
   - if/else statements
   - for/while loops
   - return statements
   - switch/case statements

2. Comment format:
   - MUST be single line starting with //
   - Maximum 80 characters
   - Focus on WHY, not WHAT
   - Mention security implications if relevant

3. Do NOT add comments for:
   - Function definitions
   - Variable declarations
   - Regular function calls
   - Closing braces

Example:
```c
int check(int x) {{
    // Validate input is positive to prevent underflow
    if (x < 0)
        // Early return on invalid input
        return -1;
    return 0;
}}
```

Code to comment:
```{language.lower()}
{code}
```

Commented code (single-line comments only):"""

    def _normalize_llm_output(self, llm_output: str) -> str:
        """
        Normalize LLM output following SCALE Section 3.1.

        Operations:
        1. Remove code block markers (```)
        2. Remove blank lines
        3. Replace triple quotes with //
        """
        # Remove code block markers
        result = llm_output.strip()

        # Remove markdown code blocks
        if result.startswith("```"):
            # Find the end of language specifier
            first_newline = result.find('\n')
            if first_newline != -1:
                result = result[first_newline + 1:]

        if result.endswith("```"):
            result = result[:-3]

        result = result.strip()

        # Replace triple single quotes with //
        # (Python-style docstrings to C-style comments)
        result = re.sub(r"'''(.+?)'''", r"// \1", result, flags=re.DOTALL)

        # Remove excessive blank lines (keep max 1)
        result = re.sub(r'\n\n+', '\n\n', result)

        return result

    def _has_meaningful_comments(self, original: str, commented: str) -> bool:
        """
        Check if LLM actually added comments.

        Returns True if commented version has significantly more comments.
        """
        # Count comment lines
        original_comments = original.count('//') + original.count('/*')
        commented_comments = commented.count('//') + commented.count('/*')

        # Should have at least 2 more comments than original
        return commented_comments >= original_comments + 2

    def batch_generate_comments(
        self,
        code_samples: list[str],
        language: str = "C",
        show_progress: bool = True
    ) -> list[Tuple[str, bool]]:
        """
        Generate comments for multiple code samples.

        Args:
            code_samples: List of code strings
            language: Programming language
            show_progress: Show progress bar

        Returns:
            List of (commented_code, success) tuples
        """
        results = []

        iterator = code_samples
        if show_progress:
            try:
                from tqdm import tqdm
                iterator = tqdm(code_samples, desc="Generating comments")
            except ImportError:
                pass

        for code in iterator:
            commented, success = self.generate_comments(code, language)
            results.append((commented, success))

        return results


def normalize_comments(code: str) -> str:
    """
    Standalone function to normalize comments in code.

    Implements SCALE Section 3.1 normalization:
    - Remove blank lines
    - Replace ''' with //
    """
    # Remove excessive blank lines
    code = re.sub(r'\n\n+', '\n', code)

    # Replace triple quotes with //
    code = re.sub(r"'''(.+?)'''", r"// \1", code, flags=re.DOTALL)

    return code.strip()


# Example usage and testing
if __name__ == "__main__":
    # Test code
    test_code = """
int buffer_check(char *buf, int size) {
    if (size > 1024) {
        return -1;
    }
    if (buf == NULL) {
        return -1;
    }
    return 0;
}
"""

    print("Testing Comment Generator...")
    print("=" * 80)

    if LLM_AVAILABLE:
        generator = CommentGenerator()
        commented, success = generator.generate_comments(test_code)

        print("\nOriginal Code:")
        print(test_code)

        print("\nCommented Code:")
        print(commented)

        print(f"\nSuccess: {success}")
    else:
        print("LLM client not available. Please ensure sven_llm_client.py is accessible.")
