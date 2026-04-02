"""Three-layer hierarchical prompt system for vulnerability detection.

Architecture:
1. Code → Scale Enhancement (optional)
2. Enhanced Code → Prompt1 (Layer 1: Major Category)
3. Major Category → Prompt2[category] (Layer 2: Middle Category)
4. Middle Category → Prompt3[subcategory] (Layer 3: Minor Category/CWE)

All prompts (Prompt1, Prompt2[], Prompt3[]) are trainable.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from enum import Enum
import json


class MajorCategory(Enum):
    """Layer 1: Major vulnerability categories."""
    MEMORY = "Memory"
    INJECTION = "Injection"
    LOGIC = "Logic"
    INPUT = "Input"
    CRYPTO = "Crypto"
    BENIGN = "Benign"


class MiddleCategory(Enum):
    """Layer 2: Middle-level categories."""
    # Memory subcategories
    BUFFER_OVERFLOW = "Buffer Overflow"
    USE_AFTER_FREE = "Use After Free"
    NULL_POINTER = "NULL Pointer"
    INTEGER_OVERFLOW = "Integer Overflow"
    MEMORY_LEAK = "Memory Leak"

    # Injection subcategories
    SQL_INJECTION = "SQL Injection"
    XSS = "Cross-Site Scripting"
    COMMAND_INJECTION = "Command Injection"
    LDAP_INJECTION = "LDAP Injection"

    # Logic subcategories
    AUTH_BYPASS = "Authentication Bypass"
    RACE_CONDITION = "Race Condition"
    INSECURE_DEFAULTS = "Insecure Defaults"

    # Input subcategories
    PATH_TRAVERSAL = "Path Traversal"
    INPUT_VALIDATION = "Input Validation"
    UNCONTROLLED_FORMAT = "Uncontrolled Format String"

    # Crypto subcategories
    WEAK_CRYPTO = "Weak Cryptography"
    INSECURE_RANDOM = "Insecure Randomness"

    # Benign
    SAFE_CODE = "Safe Code"


# Mapping: Major Category → Middle Categories
MAJOR_TO_MIDDLE = {
    MajorCategory.MEMORY: [
        MiddleCategory.BUFFER_OVERFLOW,
        MiddleCategory.USE_AFTER_FREE,
        MiddleCategory.NULL_POINTER,
        MiddleCategory.INTEGER_OVERFLOW,
        MiddleCategory.MEMORY_LEAK,
    ],
    MajorCategory.INJECTION: [
        MiddleCategory.SQL_INJECTION,
        MiddleCategory.XSS,
        MiddleCategory.COMMAND_INJECTION,
        MiddleCategory.LDAP_INJECTION,
    ],
    MajorCategory.LOGIC: [
        MiddleCategory.AUTH_BYPASS,
        MiddleCategory.RACE_CONDITION,
        MiddleCategory.INSECURE_DEFAULTS,
    ],
    MajorCategory.INPUT: [
        MiddleCategory.PATH_TRAVERSAL,
        MiddleCategory.INPUT_VALIDATION,
        MiddleCategory.UNCONTROLLED_FORMAT,
    ],
    MajorCategory.CRYPTO: [
        MiddleCategory.WEAK_CRYPTO,
        MiddleCategory.INSECURE_RANDOM,
    ],
    MajorCategory.BENIGN: [
        MiddleCategory.SAFE_CODE,
    ],
}

# Mapping: Middle Category → CWE IDs (Layer 3)
MIDDLE_TO_CWE = {
    MiddleCategory.BUFFER_OVERFLOW: ["CWE-120", "CWE-121", "CWE-122", "CWE-787"],
    MiddleCategory.USE_AFTER_FREE: ["CWE-416"],
    MiddleCategory.NULL_POINTER: ["CWE-476"],
    MiddleCategory.INTEGER_OVERFLOW: ["CWE-190", "CWE-191"],
    MiddleCategory.MEMORY_LEAK: ["CWE-401"],
    MiddleCategory.SQL_INJECTION: ["CWE-89"],
    MiddleCategory.XSS: ["CWE-79"],
    MiddleCategory.COMMAND_INJECTION: ["CWE-78"],
    MiddleCategory.LDAP_INJECTION: ["CWE-90"],
    MiddleCategory.AUTH_BYPASS: ["CWE-287", "CWE-288"],
    MiddleCategory.RACE_CONDITION: ["CWE-362"],
    MiddleCategory.INSECURE_DEFAULTS: ["CWE-453"],
    MiddleCategory.PATH_TRAVERSAL: ["CWE-22"],
    MiddleCategory.INPUT_VALIDATION: ["CWE-20"],
    MiddleCategory.UNCONTROLLED_FORMAT: ["CWE-134"],
    MiddleCategory.WEAK_CRYPTO: ["CWE-327", "CWE-328"],
    MiddleCategory.INSECURE_RANDOM: ["CWE-338"],
    MiddleCategory.SAFE_CODE: [],
}

# Reverse mapping: CWE → Middle Category
CWE_TO_MIDDLE = {}
for middle, cwes in MIDDLE_TO_CWE.items():
    for cwe in cwes:
        CWE_TO_MIDDLE[cwe] = middle

# Reverse mapping: Middle → Major
MIDDLE_TO_MAJOR = {}
for major, middles in MAJOR_TO_MIDDLE.items():
    for middle in middles:
        MIDDLE_TO_MAJOR[middle] = major


@dataclass
class ThreeLayerPromptSet:
    """Complete three-layer prompt set.

    Attributes:
        layer1_prompt: Single prompt for major category classification
        layer2_prompts: Dict mapping major categories to their middle-level prompts
        layer3_prompts: Dict mapping middle categories to their CWE-specific prompts
        scale_enhancement: Optional code enhancement/scale prompt
    """

    layer1_prompt: str  # 1 prompt
    layer2_prompts: Dict[MajorCategory, str] = field(default_factory=dict)  # N prompts
    layer3_prompts: Dict[MiddleCategory, str] = field(default_factory=dict)  # M prompts
    scale_enhancement: Optional[str] = None

    def get_layer2_prompt(self, major_category: MajorCategory) -> Optional[str]:
        """Get layer 2 prompt for a major category."""
        return self.layer2_prompts.get(major_category)

    def get_layer3_prompt(self, middle_category: MiddleCategory) -> Optional[str]:
        """Get layer 3 prompt for a middle category."""
        return self.layer3_prompts.get(middle_category)

    def to_dict(self) -> Dict:
        """Serialize to dictionary."""
        return {
            "layer1_prompt": self.layer1_prompt,
            "layer2_prompts": {
                cat.value: prompt for cat, prompt in self.layer2_prompts.items()
            },
            "layer3_prompts": {
                cat.value: prompt for cat, prompt in self.layer3_prompts.items()
            },
            "scale_enhancement": self.scale_enhancement,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "ThreeLayerPromptSet":
        """Deserialize from dictionary."""
        return cls(
            layer1_prompt=data["layer1_prompt"],
            layer2_prompts={
                MajorCategory(cat): prompt
                for cat, prompt in data.get("layer2_prompts", {}).items()
            },
            layer3_prompts={
                MiddleCategory(cat): prompt
                for cat, prompt in data.get("layer3_prompts", {}).items()
            },
            scale_enhancement=data.get("scale_enhancement"),
        )

    def count_prompts(self) -> Dict[str, int]:
        """Count prompts at each layer."""
        return {
            "layer1": 1,
            "layer2": len(self.layer2_prompts),
            "layer3": len(self.layer3_prompts),
            "total": 1 + len(self.layer2_prompts) + len(self.layer3_prompts),
        }


class ThreeLayerPromptFactory:
    """Factory for creating default three-layer prompt sets."""

    @staticmethod
    def create_default_layer1_prompt() -> str:
        """Create default Layer 1 prompt (major category routing)."""
        return """You are a security expert analyzing code for vulnerabilities.

Classify this code into ONE major vulnerability category:

Categories:
1. Memory - Memory safety issues (buffer overflow, use-after-free, NULL pointer dereference, double-free, memory leaks, integer overflow)
2. Injection - Code/Command/SQL/XSS injection where attacker input is executed or interpreted
3. Logic - Logic flaws (authentication bypass, authorization bypass, race conditions, insecure defaults)
4. Input - Input validation issues (path traversal, format string) - NOT injection
5. Crypto - Cryptographic weaknesses (weak algorithms, insecure random)
6. Benign - Safe code with no vulnerabilities

CRITICAL Classification Rules (CHECK IN ORDER):

1. INJECTION CHECK (HIGHEST PRIORITY - attacker input gets EXECUTED):
   - Command Injection: system(), popen(), exec(), shell_exec(), r_sys_cmd(), subprocess with user input → Injection
   - SQL Injection: SQL queries (SELECT, INSERT, UPDATE, DELETE) built with string concatenation → Injection
   - XSS: User input rendered in HTML/JavaScript without escaping → Injection
   - Code Injection: eval(), include(), require() with user input → Injection
   - LDAP/XPath Injection: Query strings built with user input → Injection
   KEY: If user input can be EXECUTED as code/command/query → Injection

2. INPUT CHECK (input is VALIDATED, not executed):
   - Path Traversal: File paths with "../" or user-controlled directory names → Input
   - Format String: printf-family with user-controlled format string → Input
   - Input Validation: Missing bounds/type checks on user input → Input
   KEY: If user input affects FILE PATHS or FORMAT STRINGS (not executed) → Input

3. CRYPTO CHECK:
   - Weak algorithms: MD5, SHA1, DES, RC4, ECB mode → Crypto
   - Weak random: rand(), srand(), mt_rand() for security purposes → Crypto
   - Key management issues → Crypto

4. LOGIC CHECK:
   - Authentication/Authorization bypass → Logic
   - Race conditions (TOCTOU) → Logic
   - Session/Token handling issues → Logic

5. MEMORY CHECK:
   - Pointer operations, malloc/free, buffer operations → Memory
   - Integer overflow, array bounds → Memory

6. BENIGN: Only if NO security issues exist

Code to analyze:
{input}

Respond with ONLY the category name (Memory/Injection/Logic/Input/Crypto/Benign):"""

    @staticmethod
    def create_default_layer2_prompts() -> Dict[MajorCategory, str]:
        """Create default Layer 2 prompts (middle category classification)."""
        return {
            MajorCategory.MEMORY: """This code has been classified as a MEMORY vulnerability.

Identify the specific type:
1. Buffer Overflow - Buffer overrun, out-of-bounds write
2. Use After Free - Using freed memory
3. NULL Pointer - NULL pointer dereference
4. Integer Overflow - Integer overflow/underflow
5. Memory Leak - Memory not freed

Code:
{input}

Specific type:""",

            MajorCategory.INJECTION: """This code has been classified as an INJECTION vulnerability.

Identify the specific type:
1. SQL Injection - SQL query manipulation
2. Cross-Site Scripting - XSS vulnerability
3. Command Injection - OS command injection
4. LDAP Injection - LDAP query injection

Code:
{input}

Specific type:""",

            MajorCategory.LOGIC: """This code has been classified as a LOGIC vulnerability.

Identify the specific type:
1. Authentication Bypass - Auth/login bypass
2. Race Condition - Timing/race condition
3. Insecure Defaults - Insecure default configuration

Code:
{input}

Specific type:""",

            MajorCategory.INPUT: """This code has been classified as an INPUT vulnerability.

Identify the specific type:
1. Path Traversal - Directory traversal
2. Input Validation - Improper input validation
3. Uncontrolled Format - Format string vulnerability

Code:
{input}

Specific type:""",

            MajorCategory.CRYPTO: """This code has been classified as a CRYPTO vulnerability.

Identify the specific type:
1. Weak Cryptography - Weak encryption algorithm
2. Insecure Randomness - Weak random number generation

Code:
{input}

Specific type:""",

            MajorCategory.BENIGN: """This code has been classified as BENIGN (safe).

Confirm it is safe code with no vulnerabilities.

Code:
{input}

Confirmation (Safe Code/Other):""",
        }

    @staticmethod
    def create_default_layer3_prompts() -> Dict[MiddleCategory, str]:
        """Create default Layer 3 prompts (CWE-specific detection)."""
        prompts = {}

        # Memory - Buffer Overflow
        prompts[MiddleCategory.BUFFER_OVERFLOW] = """Identify the specific CWE for this buffer overflow:
- CWE-120: Buffer Copy without Checking Size of Input
- CWE-121: Stack-based Buffer Overflow
- CWE-122: Heap-based Buffer Overflow
- CWE-787: Out-of-bounds Write

Code: {input}

CWE ID:"""

        # Memory - Use After Free
        prompts[MiddleCategory.USE_AFTER_FREE] = """Confirm this is CWE-416 (Use After Free).

Code: {input}

CWE: CWE-416"""

        # Memory - NULL Pointer
        prompts[MiddleCategory.NULL_POINTER] = """Confirm this is CWE-476 (NULL Pointer Dereference).

Code: {input}

CWE: CWE-476"""

        # Memory - Integer Overflow
        prompts[MiddleCategory.INTEGER_OVERFLOW] = """Identify the specific integer overflow CWE:
- CWE-190: Integer Overflow
- CWE-191: Integer Underflow

Code: {input}

CWE ID:"""

        # Injection - SQL
        prompts[MiddleCategory.SQL_INJECTION] = """Confirm this is CWE-89 (SQL Injection).

Code: {input}

CWE: CWE-89"""

        # Injection - XSS
        prompts[MiddleCategory.XSS] = """Confirm this is CWE-79 (Cross-Site Scripting).

Code: {input}

CWE: CWE-79"""

        # Injection - Command
        prompts[MiddleCategory.COMMAND_INJECTION] = """Confirm this is CWE-78 (OS Command Injection).

Code: {input}

CWE: CWE-78"""

        # Add remaining categories...
        prompts[MiddleCategory.PATH_TRAVERSAL] = """Confirm this is CWE-22 (Path Traversal).

Code: {input}

CWE: CWE-22"""

        prompts[MiddleCategory.INPUT_VALIDATION] = """Confirm this is CWE-20 (Improper Input Validation).

Code: {input}

CWE: CWE-20"""

        # ... Add more as needed

        return prompts

    @staticmethod
    def create_default_scale_enhancement() -> str:
        """Create default scale enhancement prompt for vulnerability detection."""
        return """Analyze this code and extract security-relevant information in a structured format.

Code:
{input}

Extract the following (be concise, use bullet points):

1. DANGEROUS FUNCTIONS CALLED:
   - List any: system(), popen(), exec(), eval(), shell_exec(), subprocess, SQL queries, file operations
   - Format: function_name(arguments)

2. USER INPUT SOURCES:
   - List variables that come from: function parameters, user input, network, files
   - Mark as [TAINTED] if they reach dangerous functions

3. DATA FLOW TO DANGEROUS SINKS:
   - Trace how user input flows to dangerous functions
   - Format: source → transformation → sink

4. SECURITY PATTERNS DETECTED:
   - Command Injection: user input in system/exec calls
   - SQL Injection: string concatenation in SQL queries
   - Path Traversal: user input in file paths
   - XSS: user input in HTML output
   - Buffer Overflow: unbounded copy/read operations
   - Use-After-Free: free() followed by use
   - NULL Dereference: pointer use without NULL check
   - Crypto Issues: weak algorithms (MD5, SHA1, DES, rand())

5. VULNERABILITY VERDICT:
   - State the most likely vulnerability type or "SAFE" if none found

Output the analysis:"""

    @staticmethod
    def create_injection_focused_scale() -> str:
        """Create SCALE prompt focused on injection detection."""
        return """Analyze this code for INJECTION vulnerabilities specifically.

Code:
{input}

Answer these questions:

Q1: Does this code execute external commands?
- Look for: system(), popen(), exec(), shell_exec(), subprocess, r_sys_cmd(), CreateProcess()
- If YES, list the function and its arguments

Q2: Does this code build SQL queries?
- Look for: SELECT, INSERT, UPDATE, DELETE, string concatenation with queries
- If YES, show how the query is constructed

Q3: Does this code output to HTML/JavaScript?
- Look for: innerHTML, document.write, echo, print with HTML
- If YES, show what user input reaches the output

Q4: Is user input sanitized before reaching dangerous functions?
- Look for: escaping, parameterized queries, input validation
- If NO sanitization found, mark as VULNERABLE

INJECTION VERDICT: [Command Injection / SQL Injection / XSS / LDAP Injection / SAFE]

Analysis:"""

    @classmethod
    def create_default_prompt_set(cls) -> ThreeLayerPromptSet:
        """Create a complete default three-layer prompt set."""
        return ThreeLayerPromptSet(
            layer1_prompt=cls.create_default_layer1_prompt(),
            layer2_prompts=cls.create_default_layer2_prompts(),
            layer3_prompts=cls.create_default_layer3_prompts(),
            scale_enhancement=cls.create_default_scale_enhancement(),
        )


def get_middle_category_from_cwe(cwe: str) -> Optional[MiddleCategory]:
    """Get middle category from CWE ID.

    Args:
        cwe: CWE identifier (e.g., "CWE-120")

    Returns:
        Middle category or None
    """
    return CWE_TO_MIDDLE.get(cwe)


def get_major_category_from_middle(middle: MiddleCategory) -> Optional[MajorCategory]:
    """Get major category from middle category.

    Args:
        middle: Middle category

    Returns:
        Major category or None
    """
    return MIDDLE_TO_MAJOR.get(middle)


def get_full_path(cwe: str) -> Tuple[Optional[MajorCategory], Optional[MiddleCategory], str]:
    """Get full classification path from CWE.

    Args:
        cwe: CWE identifier

    Returns:
        Tuple of (major_category, middle_category, cwe)
    """
    middle = get_middle_category_from_cwe(cwe)
    if middle:
        major = get_major_category_from_middle(middle)
        return (major, middle, cwe)
    return (None, None, cwe)


# Top-k Layer1 Prompt模板
TOPK_LAYER1_PROMPT = """You are a security expert analyzing code for vulnerabilities.

Classify this code and provide your TOP {k} most likely categories with confidence scores (0-100).
The confidence scores should sum to 100.

Categories:
1. Memory - Memory safety issues (buffer overflow, use-after-free, NULL pointer dereference, double-free, memory leaks, integer overflow)
2. Injection - Injection attacks (SQL, XSS, command injection, LDAP injection)
3. Logic - Logic flaws (authentication bypass, authorization bypass, race conditions, insecure defaults)
4. Input - Input handling issues (path traversal, format string, improper validation)
5. Crypto - Cryptographic weaknesses (weak algorithms, insecure random)
6. Benign - Safe code with no vulnerabilities

CRITICAL Classification Rules (CHECK IN ORDER):

1. INJECTION CHECK (highest priority for web/database code):
   - If code contains SQL keywords (SELECT, INSERT, UPDATE, DELETE, exec) with string concatenation → Injection
   - If code uses system/popen/exec/shell_exec with user input → Injection
   - If code generates HTML/JavaScript with user input → Injection

2. INPUT CHECK (file/path operations):
   - If code performs file operations (fopen, open, read, write) with user-controlled paths → Input
   - If code contains "../" patterns or path manipulation → Input
   - If code uses format strings (%s, %d) with user input in printf-like functions → Input

3. CRYPTO CHECK (cryptographic operations):
   - If code uses MD5, SHA1, DES, RC4, or weak ciphers → Crypto
   - If code uses rand(), srand(), or weak random generators → Crypto
   - If code handles encryption keys or certificates → Crypto

4. LOGIC CHECK (authentication/authorization):
   - If code handles login, session, token, or permission checks → Logic
   - If code has race conditions in authentication/authorization → Logic
   - If code has TOCTOU (time-of-check-time-of-use) issues → Logic

5. MEMORY CHECK (only if none of above match):
   - If code involves pointer operations (*, ->, NULL) → Memory
   - If code uses malloc/free/realloc → Memory
   - If code has array indexing without bounds check → Memory

6. BENIGN: Only if code has NO security issues at all

Code to analyze:
{input}

Output ONLY valid JSON in this exact format:
{{"predictions": [{{"category": "CategoryName", "confidence": 85}}, {{"category": "CategoryName2", "confidence": 10}}, {{"category": "CategoryName3", "confidence": 5}}]}}"""


# 对比学习Meta-Prompt模板
CONTRASTIVE_META_PROMPT = """You are an expert prompt engineer optimizing prompts for vulnerability detection.

Current prompt to improve:
{current_prompt}

I will show you three types of code samples to help you understand what the prompt needs to distinguish:

## Type 1: Target Vulnerability ({target_category})
These are the vulnerabilities the prompt should correctly identify:
{target_samples}

## Type 2: Other Vulnerabilities (Different CWE types)
The prompt should NOT confuse these with the target:
{other_vuln_samples}

## Type 3: Safe Code (Benign)
The prompt should correctly identify these as safe:
{benign_samples}

## Your Task
Improve the prompt so it can:
1. Correctly identify Type 1 (target vulnerabilities)
2. Distinguish Type 1 from Type 2 (different vulnerability types)
3. Distinguish Type 1 from Type 3 (vulnerabilities vs safe code)

Output ONLY the improved prompt, nothing else:"""

