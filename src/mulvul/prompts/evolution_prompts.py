"""Task-aware evolution prompts for vulnerability detection.

Provides crossover and mutation prompts that give the meta-prompter
full context about the vulnerability detection task.
"""

from dataclasses import dataclass
from typing import Optional, Dict, List


@dataclass
class TaskContext:
    """Context about the vulnerability detection task.
    
    Provides full description of what the evolved prompts should accomplish.
    
    Attributes:
        layer: Detection layer (1=major, 2=middle, 3=CWE)
        category: Target category (e.g., "Memory", "Buffer Overflow", "CWE-120")
        parent_category: Parent category for layer 2/3
        description: Human-readable task description
        indicators: Key vulnerability indicators to detect
        anti_patterns: Patterns that indicate safe code
        common_mistakes: Common false positive/negative patterns
    """
    layer: int
    category: str
    parent_category: Optional[str] = None
    description: str = ""
    indicators: List[str] = None
    anti_patterns: List[str] = None
    common_mistakes: List[str] = None
    
    def __post_init__(self):
        if self.indicators is None:
            self.indicators = []
        if self.anti_patterns is None:
            self.anti_patterns = []
        if self.common_mistakes is None:
            self.common_mistakes = []


# Pre-defined task contexts for each category
TASK_CONTEXTS: Dict[str, TaskContext] = {
    # Layer 1 categories
    "Memory": TaskContext(
        layer=1,
        category="Memory",
        description="Detect memory safety vulnerabilities in C/C++ code including buffer overflows, use-after-free, null pointer dereferences, and memory leaks.",
        indicators=[
            "Unbounded string operations (strcpy, strcat, sprintf, gets)",
            "Array access without bounds checking",
            "Pointer arithmetic without validation",
            "free() followed by pointer usage",
            "malloc() return value not checked",
            "Memory allocated but never freed",
        ],
        anti_patterns=[
            "strncpy with size limit",
            "Bounds checking before array access",
            "Null check after allocation",
            "Pointer set to NULL after free",
        ],
        common_mistakes=[
            "False positive: Safe wrapper functions misidentified",
            "False negative: Complex pointer aliasing missed",
        ],
    ),
    
    "Injection": TaskContext(
        layer=1,
        category="Injection",
        description="Detect injection vulnerabilities where untrusted input reaches sensitive sinks without proper sanitization.",
        indicators=[
            "String concatenation in SQL queries",
            "User input in system() or exec() calls",
            "Unescaped output in HTML context",
            "eval() with external input",
            "LDAP filters with user data",
        ],
        anti_patterns=[
            "Parameterized queries / prepared statements",
            "Input validation with allowlists",
            "Proper escaping functions",
            "ORM with bound parameters",
        ],
        common_mistakes=[
            "False positive: Escaped strings look like concatenation",
            "False negative: Indirect data flow through variables",
        ],
    ),
    
    "Logic": TaskContext(
        layer=1,
        category="Logic",
        description="Detect logic flaws including authentication bypass, authorization errors, and race conditions.",
        indicators=[
            "Missing authentication checks",
            "Weak comparison operators (== vs ===)",
            "TOCTOU (time-of-check to time-of-use) patterns",
            "Missing permission verification",
            "Default credentials or backdoors",
        ],
        anti_patterns=[
            "Proper session validation",
            "Consistent authorization checks",
            "Atomic operations for critical sections",
            "Strong comparison operators",
        ],
        common_mistakes=[
            "False positive: Intentional public endpoints",
            "False negative: Complex authorization logic",
        ],
    ),
    
    "Crypto": TaskContext(
        layer=1,
        category="Crypto",
        description="Detect cryptographic weaknesses including weak algorithms, hardcoded keys, and insecure random.",
        indicators=[
            "MD5, SHA1 for security purposes",
            "DES, 3DES, RC4 ciphers",
            "ECB mode encryption",
            "Hardcoded keys or IVs",
            "time() or predictable seeds for random",
            "Key size < 128 bits",
        ],
        anti_patterns=[
            "SHA-256, SHA-3, or stronger hashing",
            "AES-GCM, ChaCha20-Poly1305",
            "Proper key derivation (PBKDF2, Argon2)",
            "Cryptographically secure random (CSPRNG)",
        ],
        common_mistakes=[
            "False positive: Non-security hash usage (caching, checksums)",
            "False negative: Weak crypto in libraries",
        ],
    ),
    
    "Input": TaskContext(
        layer=1,
        category="Input",
        description="Detect input validation vulnerabilities including path traversal, format strings, and unvalidated redirects.",
        indicators=[
            "'../' patterns in file paths",
            "printf(user_input) without format string",
            "Unchecked integer arithmetic on sizes",
            "Open redirects in URL handling",
            "Missing input length validation",
        ],
        anti_patterns=[
            "Canonicalization and allowlist validation",
            "Explicit format specifiers",
            "Integer overflow checks",
            "URL allowlist for redirects",
        ],
        common_mistakes=[
            "False positive: Safe path joining functions",
            "False negative: Encoded traversal sequences",
        ],
    ),
    
    "Benign": TaskContext(
        layer=1,
        category="Benign",
        description="Identify code that follows security best practices and contains no vulnerabilities.",
        indicators=[
            "Input validation at entry points",
            "Parameterized database queries",
            "Proper error handling without info leakage",
            "Bounded buffer operations",
            "Secure defaults and configurations",
        ],
        anti_patterns=[
            "Any of the vulnerability patterns from other categories",
        ],
        common_mistakes=[
            "False positive: Over-cautious on safe patterns",
            "False negative: Subtle vulnerabilities overlooked",
        ],
    ),
    
    # Layer 2 categories
    "Buffer Overflow": TaskContext(
        layer=2,
        category="Buffer Overflow",
        parent_category="Memory",
        description="Detect buffer overflow vulnerabilities where data is written beyond allocated buffer boundaries.",
        indicators=[
            "strcpy, strcat, sprintf without size limits",
            "gets() function usage",
            "memcpy with unchecked size parameter",
            "Array index from untrusted source",
            "Off-by-one errors in loop bounds",
        ],
        anti_patterns=[
            "strncpy, strncat with proper size",
            "snprintf instead of sprintf",
            "fgets instead of gets",
            "Bounds checking before access",
        ],
        common_mistakes=[
            "False positive: Size already validated elsewhere",
            "False negative: Multi-step overflow through temp buffers",
        ],
    ),
    
    "Use After Free": TaskContext(
        layer=2,
        category="Use After Free",
        parent_category="Memory",
        description="Detect use-after-free vulnerabilities where freed memory is subsequently accessed.",
        indicators=[
            "free(ptr) followed by ptr->member access",
            "Dangling pointers in data structures",
            "Double-free conditions",
            "Missing pointer nullification after free",
            "Freed memory returned from function",
        ],
        anti_patterns=[
            "ptr = NULL after free",
            "Clear data structure references before free",
            "Use smart pointers (C++)",
            "Ownership tracking",
        ],
        common_mistakes=[
            "False positive: Pointer reassigned before use",
            "False negative: Aliased pointers not tracked",
        ],
    ),
    
    "SQL Injection": TaskContext(
        layer=2,
        category="SQL Injection",
        parent_category="Injection",
        description="Detect SQL injection where user input is incorporated into SQL queries without proper parameterization.",
        indicators=[
            "String concatenation: \"SELECT * FROM users WHERE id=\" + id",
            "f-string/format in SQL: f\"SELECT * FROM {table}\"",
            "execute() with string formatting",
            "Raw SQL with user input variables",
        ],
        anti_patterns=[
            "Parameterized queries: execute(\"SELECT * FROM users WHERE id=?\", (id,))",
            "ORM query builders with bound params",
            "Stored procedures with parameters",
            "Input type validation (integers only)",
        ],
        common_mistakes=[
            "False positive: Constant strings that look dynamic",
            "False negative: Input through multiple variables",
        ],
    ),
}


def get_task_context(category: str) -> Optional[TaskContext]:
    """Get task context for a category.
    
    Args:
        category: Category name
        
    Returns:
        TaskContext or None if not found
    """
    return TASK_CONTEXTS.get(category)


def build_crossover_prompt(
    parent1_prompt: str,
    parent2_prompt: str,
    context: TaskContext,
) -> str:
    """Build task-aware crossover prompt.
    
    Args:
        parent1_prompt: First parent prompt
        parent2_prompt: Second parent prompt
        context: Task context with full description
        
    Returns:
        Complete crossover prompt for meta-prompter
    """
    indicators_str = "\n".join(f"  - {ind}" for ind in context.indicators[:5])
    anti_patterns_str = "\n".join(f"  - {ap}" for ap in context.anti_patterns[:3])
    
    return f"""You are an expert prompt engineer optimizing prompts for vulnerability detection.

## Task Description
{context.description}

## Target Category: {context.category}
{f"Parent Category: {context.parent_category}" if context.parent_category else ""}
Detection Layer: {context.layer}

## Key Vulnerability Indicators to Detect:
{indicators_str}

## Safe Patterns (should NOT trigger detection):
{anti_patterns_str}

## Parent Prompts to Combine

**Parent 1:**
```
{parent1_prompt}
```

**Parent 2:**
```
{parent2_prompt}
```

## Your Task
Create a NEW prompt that combines the most effective elements from both parents for detecting {context.category} vulnerabilities.

Requirements:
1. Combine strengths from both prompts (specific patterns, clear instructions, effective structure)
2. The prompt must analyze code for {context.category} vulnerabilities
3. Maintain the {{CODE}} placeholder for code input
4. Output should request CONFIDENCE: <0.0-1.0> score
5. Be specific about vulnerability patterns to look for
6. Include guidance on distinguishing vulnerabilities from safe code

Output ONLY the new combined prompt, nothing else:
"""


def build_mutation_prompt(
    original_prompt: str,
    context: TaskContext,
    error_patterns: Optional[List[str]] = None,
) -> str:
    """Build task-aware mutation prompt.
    
    Args:
        original_prompt: Prompt to mutate
        context: Task context with full description
        error_patterns: Optional list of common errors to address
        
    Returns:
        Complete mutation prompt for meta-prompter
    """
    indicators_str = "\n".join(f"  - {ind}" for ind in context.indicators[:5])
    mistakes_str = "\n".join(f"  - {m}" for m in context.common_mistakes)
    
    error_section = ""
    if error_patterns:
        error_section = f"""
## Recent Detection Errors to Address:
{chr(10).join(f"  - {e}" for e in error_patterns[:3])}
"""
    
    return f"""You are an expert prompt engineer improving prompts for vulnerability detection.

## Task Description
{context.description}

## Target Category: {context.category}
{f"Parent Category: {context.parent_category}" if context.parent_category else ""}
Detection Layer: {context.layer}

## Key Vulnerability Indicators:
{indicators_str}

## Common Detection Mistakes:
{mistakes_str}
{error_section}
## Original Prompt to Improve:
```
{original_prompt}
```

## Your Task
Improve this prompt to better detect {context.category} vulnerabilities.

Consider:
1. Adding more specific vulnerability patterns
2. Clarifying the distinction between vulnerable and safe code
3. Adding step-by-step analysis instructions
4. Including contrastive examples (VULNERABLE vs SAFE)
5. Addressing the common detection mistakes listed above
6. Maintaining {{CODE}} placeholder and CONFIDENCE output format

Output ONLY the improved prompt, nothing else:
"""


def build_initialization_prompt(context: TaskContext) -> str:
    """Build prompt for generating initial population members.
    
    Args:
        context: Task context
        
    Returns:
        Prompt for generating a new detection prompt
    """
    indicators_str = "\n".join(f"  - {ind}" for ind in context.indicators)
    anti_patterns_str = "\n".join(f"  - {ap}" for ap in context.anti_patterns)
    
    return f"""You are an expert security analyst creating a prompt for automated vulnerability detection.

## Task
Create a prompt that will instruct an LLM to analyze code for {context.category} vulnerabilities.

## Context
{context.description}

## Vulnerability Indicators to Detect:
{indicators_str}

## Safe Patterns (should NOT trigger detection):
{anti_patterns_str}

## Requirements
1. The prompt should analyze code provided via {{CODE}} placeholder
2. Output must be CONFIDENCE: <0.0-1.0> indicating vulnerability likelihood
3. Include specific patterns to look for
4. Provide clear criteria for distinguishing vulnerable vs safe code
5. Be concise but comprehensive

Generate a detection prompt:
"""
