"""Knowledge base for RAG-enhanced vulnerability detection.

Each category (major/middle/CWE) has 1-2 example code snippets.
Examples are used to enhance prompts via retrieval.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
import json
from pathlib import Path

from ..prompts.hierarchical_three_layer import (
    MajorCategory,
    MiddleCategory,
    MAJOR_TO_MIDDLE,
    MIDDLE_TO_CWE,
)


@dataclass
class CodeExample:
    """Single code example for a category.

    Attributes:
        code: Source code snippet
        category: Category this example belongs to
        description: Brief description of the vulnerability
        cwe: CWE ID (if applicable)
        severity: Severity level (high/medium/low)
    """

    code: str
    category: str  # Major, Middle, or CWE
    description: str
    cwe: Optional[str] = None
    severity: str = "medium"
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization."""
        return {
            "code": self.code,
            "category": self.category,
            "description": self.description,
            "cwe": self.cwe,
            "severity": self.severity,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "CodeExample":
        """Create from dictionary."""
        return cls(
            code=data["code"],
            category=data["category"],
            description=data["description"],
            cwe=data.get("cwe"),
            severity=data.get("severity", "medium"),
            metadata=data.get("metadata", {}),
        )


@dataclass
class KnowledgeBase:
    """Knowledge base containing examples for all categories.

    Organized by:
    - major_examples: Examples for major categories
    - middle_examples: Examples for middle categories
    - cwe_examples: Examples for specific CWEs
    """

    major_examples: Dict[str, List[CodeExample]] = field(default_factory=dict)
    middle_examples: Dict[str, List[CodeExample]] = field(default_factory=dict)
    cwe_examples: Dict[str, List[CodeExample]] = field(default_factory=dict)
    clean_examples: List[CodeExample] = field(default_factory=list)

    def add_major_example(self, category: MajorCategory, example: CodeExample):
        """Add example for major category."""
        cat_name = category.value
        if cat_name not in self.major_examples:
            self.major_examples[cat_name] = []
        self.major_examples[cat_name].append(example)

    def add_middle_example(self, category: MiddleCategory, example: CodeExample):
        """Add example for middle category."""
        cat_name = category.value
        if cat_name not in self.middle_examples:
            self.middle_examples[cat_name] = []
        self.middle_examples[cat_name].append(example)

    def add_cwe_example(self, cwe: str, example: CodeExample):
        """Add example for specific CWE."""
        if cwe not in self.cwe_examples:
            self.cwe_examples[cwe] = []
        self.cwe_examples[cwe].append(example)

    def add_clean_example(self, example: CodeExample):
        """Add a clean/benign example for contrastive retrieval."""
        self.clean_examples.append(example)

    def get_major_examples(self, category: MajorCategory) -> List[CodeExample]:
        """Get examples for major category."""
        return self.major_examples.get(category.value, [])

    def get_middle_examples(self, category: MiddleCategory) -> List[CodeExample]:
        """Get examples for middle category."""
        return self.middle_examples.get(category.value, [])

    def get_cwe_examples(self, cwe: str) -> List[CodeExample]:
        """Get examples for CWE."""
        return self.cwe_examples.get(cwe, [])

    def get_all_examples(self) -> List[CodeExample]:
        """Get all examples in the knowledge base."""
        all_examples = []
        for examples in self.major_examples.values():
            all_examples.extend(examples)
        for examples in self.middle_examples.values():
            all_examples.extend(examples)
        for examples in self.cwe_examples.values():
            all_examples.extend(examples)
        return all_examples

    def save(self, filepath: str):
        """Save knowledge base to file."""
        data = {
            "major_examples": {
                cat: [ex.to_dict() for ex in examples]
                for cat, examples in self.major_examples.items()
            },
            "middle_examples": {
                cat: [ex.to_dict() for ex in examples]
                for cat, examples in self.middle_examples.items()
            },
            "cwe_examples": {
                cwe: [ex.to_dict() for ex in examples]
                for cwe, examples in self.cwe_examples.items()
            },
            "clean_examples": [ex.to_dict() for ex in self.clean_examples],
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    @classmethod
    def load(cls, filepath: str) -> "KnowledgeBase":
        """Load knowledge base from file."""
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        kb = cls()

        # Load major examples
        for cat, examples in data.get("major_examples", {}).items():
            kb.major_examples[cat] = [CodeExample.from_dict(ex) for ex in examples]

        # Load middle examples
        for cat, examples in data.get("middle_examples", {}).items():
            kb.middle_examples[cat] = [CodeExample.from_dict(ex) for ex in examples]

        # Load CWE examples
        for cwe, examples in data.get("cwe_examples", {}).items():
            kb.cwe_examples[cwe] = [CodeExample.from_dict(ex) for ex in examples]

        # Load clean examples
        for ex in data.get("clean_examples", []):
            kb.clean_examples.append(CodeExample.from_dict(ex))

        return kb

    def statistics(self) -> Dict:
        """Get statistics about knowledge base."""
        return {
            "total_examples": len(self.get_all_examples()),
            "major_categories": len(self.major_examples),
            "middle_categories": len(self.middle_examples),
            "cwe_types": len(self.cwe_examples),
            "clean_examples": len(self.clean_examples),
            "examples_per_major": {
                cat: len(examples) for cat, examples in self.major_examples.items()
            },
            "examples_per_middle": {
                cat: len(examples) for cat, examples in self.middle_examples.items()
            },
            "examples_per_cwe": {
                cwe: len(examples) for cwe, examples in self.cwe_examples.items()
            },
        }


class KnowledgeBaseBuilder:
    """Builder for creating default knowledge base with examples."""

    @staticmethod
    def create_default_kb() -> KnowledgeBase:
        """Create default knowledge base with 1-2 examples per category."""
        kb = KnowledgeBase()

        # ========== Major Category Examples ==========

        # Memory examples
        kb.add_major_example(
            MajorCategory.MEMORY,
            CodeExample(
                code="""void copy_data(char* input) {
    char buffer[64];
    strcpy(buffer, input);  // No bounds checking
    printf("%s", buffer);
}""",
                category="Memory",
                description="Buffer overflow due to unsafe strcpy",
                cwe="CWE-120",
                severity="high",
            ),
        )

        kb.add_major_example(
            MajorCategory.MEMORY,
            CodeExample(
                code="""int* ptr = malloc(sizeof(int) * 10);
free(ptr);
*ptr = 5;  // Use after free""",
                category="Memory",
                description="Use-after-free vulnerability",
                cwe="CWE-416",
                severity="high",
            ),
        )

        # Injection examples
        kb.add_major_example(
            MajorCategory.INJECTION,
            CodeExample(
                code="""String query = "SELECT * FROM users WHERE username='" +
               userInput + "' AND password='" + password + "'";
stmt.executeQuery(query);""",
                category="Injection",
                description="SQL injection via string concatenation",
                cwe="CWE-89",
                severity="high",
            ),
        )

        kb.add_major_example(
            MajorCategory.INJECTION,
            CodeExample(
                code="""<script>
var search = location.search.substring(1);
document.write(search);  // XSS
</script>""",
                category="Injection",
                description="Cross-site scripting (XSS)",
                cwe="CWE-79",
                severity="medium",
            ),
        )

        # Logic examples
        kb.add_major_example(
            MajorCategory.LOGIC,
            CodeExample(
                code="""if (username.equals("admin")) {
    // Missing password check!
    grantAdminAccess();
}""",
                category="Logic",
                description="Authentication bypass - missing password verification",
                severity="high",
            ),
        )

        # Input examples
        kb.add_major_example(
            MajorCategory.INPUT,
            CodeExample(
                code="""String filename = request.getParameter("file");
File f = new File("/uploads/" + filename);
// Path traversal: filename could be "../../etc/passwd"
FileInputStream fis = new FileInputStream(f);""",
                category="Input",
                description="Path traversal vulnerability",
                cwe="CWE-22",
                severity="high",
            ),
        )

        # Crypto examples
        kb.add_major_example(
            MajorCategory.CRYPTO,
            CodeExample(
                code="""// Using deprecated MD5
MessageDigest md = MessageDigest.getInstance("MD5");
byte[] hash = md.digest(password.getBytes());""",
                category="Crypto",
                description="Using weak cryptographic algorithm (MD5)",
                cwe="CWE-327",
                severity="medium",
            ),
        )

        # Benign examples
        kb.add_major_example(
            MajorCategory.BENIGN,
            CodeExample(
                code="""int add(int a, int b) {
    return a + b;
}""",
                category="Benign",
                description="Safe arithmetic operation",
            ),
        )

        # ========== Middle Category Examples ==========

        # Buffer Overflow
        kb.add_middle_example(
            MiddleCategory.BUFFER_OVERFLOW,
            CodeExample(
                code="""char dest[10];
char src[20] = "This is too long";
strcpy(dest, src);  // Buffer overflow""",
                category="Buffer Overflow",
                description="Classic buffer overflow with strcpy",
                cwe="CWE-120",
            ),
        )

        kb.add_middle_example(
            MiddleCategory.BUFFER_OVERFLOW,
            CodeExample(
                code="""void process(int size, char* data) {
    char buffer[100];
    memcpy(buffer, data, size);  // Size not checked
}""",
                category="Buffer Overflow",
                description="Buffer overflow with memcpy",
                cwe="CWE-787",
            ),
        )

        # SQL Injection
        kb.add_middle_example(
            MiddleCategory.SQL_INJECTION,
            CodeExample(
                code="""String sql = "SELECT * FROM products WHERE id=" + productId;
ResultSet rs = stmt.executeQuery(sql);""",
                category="SQL Injection",
                description="SQL injection in SELECT query",
                cwe="CWE-89",
            ),
        )

        # XSS
        kb.add_middle_example(
            MiddleCategory.XSS,
            CodeExample(
                code="""<?php
echo "<div>" . $_GET['message'] . "</div>";
// Reflected XSS
?>""",
                category="Cross-Site Scripting",
                description="Reflected XSS vulnerability",
                cwe="CWE-79",
            ),
        )

        # Path Traversal
        kb.add_middle_example(
            MiddleCategory.PATH_TRAVERSAL,
            CodeExample(
                code="""String path = baseDir + File.separator + userInput;
File file = new File(path);  // userInput could contain "../"
FileReader fr = new FileReader(file);""",
                category="Path Traversal",
                description="Directory traversal vulnerability",
                cwe="CWE-22",
            ),
        )

        # NULL Pointer
        kb.add_middle_example(
            MiddleCategory.NULL_POINTER,
            CodeExample(
                code="""User user = findUserById(id);
String name = user.getName();  // user could be null""",
                category="NULL Pointer",
                description="Potential NULL pointer dereference",
                cwe="CWE-476",
            ),
        )

        # ========== CWE-Specific Examples ==========

        # CWE-120: Buffer Copy without Checking Size
        kb.add_cwe_example(
            "CWE-120",
            CodeExample(
                code="""void copyString(char* dest, char* src) {
    strcpy(dest, src);  // CWE-120: No size checking
}""",
                category="CWE-120",
                description="Buffer copy without checking size of input",
                cwe="CWE-120",
            ),
        )

        # CWE-89: SQL Injection
        kb.add_cwe_example(
            "CWE-89",
            CodeExample(
                code="""String query = "DELETE FROM users WHERE id=" + userId;
db.execute(query);  // CWE-89: SQL Injection""",
                category="CWE-89",
                description="Improper neutralization of SQL commands",
                cwe="CWE-89",
            ),
        )

        # CWE-79: XSS
        kb.add_cwe_example(
            "CWE-79",
            CodeExample(
                code="""document.getElementById('output').innerHTML =
    userInput;  // CWE-79: XSS""",
                category="CWE-79",
                description="Improper neutralization of input in web pages",
                cwe="CWE-79",
            ),
        )

        # CWE-22: Path Traversal
        kb.add_cwe_example(
            "CWE-22",
            CodeExample(
                code="""filename = req.params.get('file')
with open('/var/www/files/' + filename) as f:
    # CWE-22: Path traversal
    content = f.read()""",
                category="CWE-22",
                description="Improper limitation of pathname to restricted directory",
                cwe="CWE-22",
            ),
        )

        # CWE-476: NULL Pointer Dereference
        kb.add_cwe_example(
            "CWE-476",
            CodeExample(
                code="""char* ptr = get_config("key");
int len = strlen(ptr);  // CWE-476: ptr could be NULL""",
                category="CWE-476",
                description="NULL pointer dereference",
                cwe="CWE-476",
            ),
        )

        return kb


def create_knowledge_base_from_dataset(dataset, output_path: str, samples_per_category: int = 2):
    """Create knowledge base by sampling from dataset.

    Args:
        dataset: Dataset with labeled samples
        output_path: Path to save knowledge base
        samples_per_category: Number of samples per category
    """
    from collections import defaultdict
    from ..prompts.hierarchical_three_layer import get_full_path

    kb = KnowledgeBase()

    # Group samples by category
    major_samples = defaultdict(list)
    middle_samples = defaultdict(list)
    cwe_samples = defaultdict(list)

    samples = dataset.get_samples(None)  # Get all

    for sample in samples:
        # Get CWE
        if not hasattr(sample, 'metadata') or 'cwe' not in sample.metadata:
            continue

        cwes = sample.metadata['cwe']
        if not cwes:
            continue

        cwe = cwes[0]
        major, middle, _ = get_full_path(cwe)

        if major:
            major_samples[major.value].append((sample, cwe))
        if middle:
            middle_samples[middle.value].append((sample, cwe))
        cwe_samples[cwe].append((sample, cwe))

    # Sample from each category
    import random

    for major, samples_list in major_samples.items():
        selected = random.sample(samples_list, min(samples_per_category, len(samples_list)))
        for sample, cwe in selected:
            kb.add_major_example(
                MajorCategory(major),
                CodeExample(
                    code=sample.input_text,
                    category=major,
                    description=f"Example of {major} vulnerability",
                    cwe=cwe,
                )
            )

    for middle, samples_list in middle_samples.items():
        selected = random.sample(samples_list, min(samples_per_category, len(samples_list)))
        for sample, cwe in selected:
            kb.add_middle_example(
                MiddleCategory(middle),
                CodeExample(
                    code=sample.input_text,
                    category=middle,
                    description=f"Example of {middle}",
                    cwe=cwe,
                )
            )

    for cwe, samples_list in cwe_samples.items():
        selected = random.sample(samples_list, min(samples_per_category, len(samples_list)))
        for sample, _ in selected:
            kb.add_cwe_example(
                cwe,
                CodeExample(
                    code=sample.input_text,
                    category=cwe,
                    description=f"Example of {cwe}",
                    cwe=cwe,
                )
            )

    # Save
    kb.save(output_path)
    print(f"✅ Knowledge base created: {output_path}")
    print(f"   Statistics: {kb.statistics()}")

    return kb


def build_clean_pool_from_dataset(
    kb: KnowledgeBase,
    dataset,
    max_samples: int = 5000,
    seed: int = 42
) -> None:
    """Build clean/benign pool from dataset.

    Args:
        kb: KnowledgeBase to add clean examples to
        dataset: Dataset with samples (must have input_text, target, metadata)
        max_samples: Maximum number of clean samples to add
        seed: Random seed for reproducibility
    """
    import random
    rng = random.Random(seed)

    # Collect benign samples (target == "0" or target == 0)
    benign_samples = []
    for sample in dataset.get_samples():
        target = str(sample.target)
        if target == "0":
            benign_samples.append(sample)

    # Shuffle and limit
    rng.shuffle(benign_samples)
    selected = benign_samples[:max_samples]

    # Add to knowledge base
    for sample in selected:
        example = CodeExample(
            code=sample.input_text,
            category="Benign",
            description="Clean code sample from training set",
            metadata={"source_idx": sample.metadata.get("idx")}
        )
        kb.add_clean_example(example)
