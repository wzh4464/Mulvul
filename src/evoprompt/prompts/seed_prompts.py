"""Seed prompts for vulnerability detection evolution.

These prompts are designed as initial population for evolutionary optimization,
following best practices from code review prompt engineering.
"""

from typing import Dict, List


# =============================================================================
# Layer 1: Major Category Classification Seeds
# =============================================================================

LAYER1_SEED_PROMPTS: Dict[str, List[str]] = {
    "Memory": [
        # Seed 1: Expert role + step-by-step
        """You are an expert memory safety analyst specializing in C/C++ vulnerabilities.

Follow these steps to analyze the code:
1. Identify all memory allocation/deallocation operations (malloc, free, new, delete)
2. Trace pointer lifecycles and ownership transfers
3. Check array/buffer access patterns against bounds
4. Verify null pointer checks before dereferences

Focus on:
- Buffer boundary violations
- Use-after-free patterns
- Double-free conditions
- Uninitialized memory access
- Memory leak paths

Respond with CONFIDENCE: <0.0-1.0> indicating likelihood of memory vulnerability.

Code:
{CODE}""",

        # Seed 2: Concise pattern-matching
        """Analyze for memory safety vulnerabilities.

RED FLAGS to check:
- strcpy/sprintf without bounds → Buffer Overflow
- free() followed by pointer use → Use-After-Free  
- malloc() without NULL check → Null Pointer Deref
- Array index from user input → Out-of-Bounds

Score 0.0 (safe) to 1.0 (vulnerable).
Format: CONFIDENCE: <score>

{CODE}""",

        # Seed 3: Contrastive examples
        """You are a security auditor. Determine if this code has memory vulnerabilities.

VULNERABLE patterns:
```c
char buf[10]; strcpy(buf, user_input);  // No bounds check
free(ptr); ptr->field = 1;              // Use after free
```

SAFE patterns:
```c
char buf[10]; strncpy(buf, input, sizeof(buf)-1);  // Bounded
free(ptr); ptr = NULL;                              // Nullified
```

Output CONFIDENCE: <0.0-1.0>

{CODE}""",
    ],

    "Injection": [
        # Seed 1: SQL/Command injection focus
        """You are a security expert detecting injection vulnerabilities.

Analysis steps:
1. Identify all external input sources (user input, files, network)
2. Trace data flow to sensitive sinks (SQL queries, system commands, eval)
3. Check for sanitization/validation at trust boundaries
4. Verify parameterized queries or proper escaping

Injection types to detect:
- SQL Injection: String concatenation in queries
- Command Injection: User data in system()/exec()
- XSS: Unescaped output in HTML context
- LDAP Injection: Unsanitized LDAP filters

CONFIDENCE: <0.0-1.0>

{CODE}""",

        # Seed 2: Taint analysis perspective
        """Perform taint analysis for injection vulnerabilities.

SOURCES (untrusted): request.params, user input, file reads, env vars
SINKS (dangerous): SQL execute, os.system, eval, innerHTML, document.write

Trace: SOURCE → transformations → SINK

If untrusted data reaches a sink without sanitization → VULNERABLE (0.7-1.0)
If properly escaped/parameterized → SAFE (0.0-0.3)

CONFIDENCE: <score>

{CODE}""",
    ],

    "Logic": [
        # Seed 1: Authentication/Authorization focus
        """You are an application security expert analyzing logic flaws.

Check for:
1. Authentication bypass:
   - Missing auth checks on sensitive endpoints
   - Weak comparison (== vs ===, timing attacks)
   - Default credentials or backdoors

2. Authorization flaws:
   - Missing permission checks (IDOR, privilege escalation)
   - Role confusion or improper access control

3. Race conditions:
   - TOCTOU (time-of-check to time-of-use)
   - Concurrent access without synchronization

CONFIDENCE: <0.0-1.0>

{CODE}""",
    ],

    "Crypto": [
        # Seed 1: Cryptographic weakness detection
        """You are a cryptography security analyst.

Analyze for cryptographic vulnerabilities:

WEAK (flag as vulnerable):
- MD5, SHA1 for security purposes
- DES, 3DES, RC4 ciphers
- ECB mode encryption
- Hardcoded keys/IVs
- Random from time() or predictable seeds
- Key size < 128 bits

SECURE (flag as safe):
- SHA-256/SHA-3 for hashing
- AES-GCM, ChaCha20-Poly1305
- Proper key derivation (PBKDF2, Argon2)
- Cryptographically secure random

CONFIDENCE: <0.0-1.0>

{CODE}""",
    ],

    "Input": [
        # Seed 1: Input validation focus
        """You are a security analyst checking input validation.

Analyze for:
1. Path Traversal: "../" patterns, unsanitized file paths
2. Format String: printf(user_input) without format specifier
3. Integer Overflow: Unchecked arithmetic on sizes/lengths
4. Unvalidated Redirects: Open redirects in URLs

Key questions:
- Is input validated before use?
- Are there allowlists or proper escaping?
- Can user control critical parameters?

CONFIDENCE: <0.0-1.0>

{CODE}""",
    ],

    "Benign": [
        # Seed 1: Safe code identification
        """Analyze if this code follows security best practices.

SAFE indicators:
- Input validation at entry points
- Parameterized queries for database operations
- Proper error handling without info leakage
- Bounded buffer operations
- Secure defaults

If code demonstrates defensive programming and no obvious vulnerabilities:
CONFIDENCE: 0.8-1.0 (likely benign)

If vulnerabilities present:
CONFIDENCE: 0.0-0.2

{CODE}""",
    ],
}


# =============================================================================
# Layer 2: Middle Category Seeds (examples for Memory subcategories)
# =============================================================================

LAYER2_SEED_PROMPTS: Dict[str, Dict[str, List[str]]] = {
    "Memory": {
        "Buffer Overflow": [
            """Given potential memory vulnerability, check specifically for buffer overflow.

Indicators:
- strcpy, strcat, sprintf, gets (unbounded)
- memcpy with unchecked size
- Array access with unchecked index
- Stack buffer with user-controlled size

Risk factors:
- User input → buffer size/index
- Missing length validation
- Off-by-one errors

CONFIDENCE: <0.0-1.0>

{CODE}""",
        ],

        "Use After Free": [
            """Check for use-after-free vulnerabilities.

Pattern: memory freed → pointer still used

Look for:
1. free(ptr) followed by ptr->member or *ptr
2. Dangling pointers in data structures
3. Double-free conditions
4. Missing pointer nullification after free

CONFIDENCE: <0.0-1.0>

{CODE}""",
        ],

        "Null Pointer": [
            """Check for null pointer dereference vulnerabilities.

Patterns:
- Pointer used without NULL check after allocation
- Pointer from function return used directly
- Pointer after error path might be NULL

Safe patterns:
- if (ptr != NULL) before use
- Early return on NULL

CONFIDENCE: <0.0-1.0>

{CODE}""",
        ],
    },

    "Injection": {
        "SQL Injection": [
            """Specifically check for SQL injection vulnerabilities.

VULNERABLE:
```
query = "SELECT * FROM users WHERE id = " + user_id
cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
```

SAFE:
```
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
cursor.execute("SELECT * FROM users WHERE name = %s", (name,))
```

CONFIDENCE: <0.0-1.0>

{CODE}""",
        ],

        "Command Injection": [
            """Check for OS command injection.

VULNERABLE:
- os.system("ping " + user_input)
- subprocess.call(f"ls {directory}", shell=True)
- exec() with user data

SAFE:
- subprocess.run(["ping", host], shell=False)
- Allowlist validation of input
- shlex.quote() for escaping

CONFIDENCE: <0.0-1.0>

{CODE}""",
        ],
    },
}


# =============================================================================
# Layer 3: CWE-specific Seeds
# =============================================================================

LAYER3_SEED_PROMPTS: Dict[str, Dict[str, List[str]]] = {
    "Buffer Overflow": {
        "CWE-120": [
            """Check for CWE-120: Buffer Copy without Checking Size of Input.

Specific pattern: Copying data to a buffer without ensuring the source 
data size fits within the destination buffer.

Vulnerable functions: strcpy, strcat, sprintf, gets, memcpy with unchecked size

Example vulnerability:
```c
char dest[10];
strcpy(dest, source);  // source length not checked
```

CONFIDENCE: <0.0-1.0> for CWE-120

{CODE}""",
        ],

        "CWE-787": [
            """Check for CWE-787: Out-of-bounds Write.

Pattern: Writing data past the end or before the beginning of a buffer.

Look for:
- Array index exceeds allocated size
- Negative array indices
- Loop bounds exceed array size
- Pointer arithmetic going out of bounds

CONFIDENCE: <0.0-1.0> for CWE-787

{CODE}""",
        ],
    },

    "SQL Injection": {
        "CWE-89": [
            """Check for CWE-89: SQL Injection.

The software constructs SQL queries using externally-influenced input 
without proper neutralization.

Detection:
1. Find SQL query construction
2. Check if external input is incorporated
3. Verify parameterization or escaping

VULNERABLE: String concatenation/interpolation in SQL
SAFE: Parameterized queries, prepared statements, ORM with proper binding

CONFIDENCE: <0.0-1.0> for CWE-89

{CODE}""",
        ],
    },
}


# =============================================================================
# Meta-learning Enhancement Seeds
# =============================================================================

META_ENHANCEMENT_SEEDS: List[str] = [
    # For generating contrastive examples
    """Based on the confusion between {predicted} and {actual}, generate a 
distinguishing feature that separates these categories.

The key difference is: {difference}

When you see {pattern_A}, classify as {category_A}.
When you see {pattern_B}, classify as {category_B}.""",

    # For error pattern correction
    """Previous errors show confusion with:
{confusion_patterns}

To improve accuracy:
1. First check for {distinguishing_feature}
2. Look for {specific_indicator}
3. If uncertain, consider {tiebreaker}""",
]


def get_seed_prompts_for_category(layer: int, category: str) -> List[str]:
    """Get seed prompts for a specific layer and category.
    
    Args:
        layer: Layer number (1, 2, or 3)
        category: Category name
        
    Returns:
        List of seed prompt strings
    """
    if layer == 1:
        return LAYER1_SEED_PROMPTS.get(category, [])
    elif layer == 2:
        for major, middles in LAYER2_SEED_PROMPTS.items():
            if category in middles:
                return middles[category]
        return []
    elif layer == 3:
        for middle, cwes in LAYER3_SEED_PROMPTS.items():
            if category in cwes:
                return cwes[category]
        return []
    return []


def get_all_layer1_seeds() -> Dict[str, List[str]]:
    """Get all Layer 1 seed prompts."""
    return LAYER1_SEED_PROMPTS.copy()
