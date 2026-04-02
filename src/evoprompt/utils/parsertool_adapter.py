"""
parserTool Adapter

This module provides a compatibility layer for comment4vul's parserTool
using the standard tree-sitter Python package.

It allows using tree-sitter without needing comment4vul's custom parserTool module.
"""

import os
from enum import Enum
from pathlib import Path
from typing import Optional
import logging

logger = logging.getLogger(__name__)


class Lang(Enum):
    """Language enumeration for parsing."""
    C = "c"
    CPP = "cpp"
    JAVA = "java"
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    GO = "go"
    RUST = "rust"


class TreeSitterAST:
    """Wrapper for tree-sitter parse tree to match parserTool interface."""

    def __init__(self, tree):
        self.tree = tree
        self.root_node = tree.root_node

    def __repr__(self):
        return f"TreeSitterAST(root={self.root_node.type})"


def build_languages(build_dir: Optional[Path] = None) -> Path:
    """
    Build tree-sitter language libraries.

    This function tries multiple methods to get C/C++ language support:
    1. Use pre-built tree-sitter-languages package
    2. Clone and build from grammar repositories
    3. Use bundled grammars (if available)

    Args:
        build_dir: Directory to store compiled libraries (default: project_root/build)

    Returns:
        Path to compiled libraries or None if using bundled languages
    """
    try:
        from tree_sitter import Language
    except ImportError:
        raise ImportError(
            "tree-sitter not installed. Run: uv add tree-sitter"
        )

    # Method 1: Try tree-sitter-languages (pre-built)
    try:
        from tree_sitter_languages import get_language
        # Test if it works
        c_lang = get_language('c')
        cpp_lang = get_language('cpp')
        logger.info("✓ Using tree-sitter-languages (pre-built)")
        return None  # Signal to use get_language() in get_parser()
    except ImportError:
        logger.debug("tree-sitter-languages not available, trying alternative methods")

    # Method 2: Build from source
    if build_dir is None:
        project_root = Path(__file__).parent.parent.parent.parent
        build_dir = project_root / "build" / "tree-sitter"

    build_dir.mkdir(parents=True, exist_ok=True)
    library_path = build_dir / "languages.so"

    # Check if already built
    if library_path.exists():
        logger.info(f"✓ Tree-sitter libraries already built: {library_path}")
        return library_path

    logger.info("Building tree-sitter language libraries from grammars...")

    # Clone grammar repositories if not exists
    vendor_dir = build_dir / "vendor"
    vendor_dir.mkdir(exist_ok=True)

    c_grammar = vendor_dir / "tree-sitter-c"
    cpp_grammar = vendor_dir / "tree-sitter-cpp"

    import subprocess

    # Clone grammars if needed
    if not c_grammar.exists():
        logger.info("Cloning tree-sitter-c grammar...")
        subprocess.run(
            ["git", "clone", "https://github.com/tree-sitter/tree-sitter-c", str(c_grammar)],
            check=True,
            capture_output=True
        )

    if not cpp_grammar.exists():
        logger.info("Cloning tree-sitter-cpp grammar...")
        subprocess.run(
            ["git", "clone", "https://github.com/tree-sitter/tree-sitter-cpp", str(cpp_grammar)],
            check=True,
            capture_output=True
        )

    # Build library
    try:
        Language.build_library(
            str(library_path),
            [str(c_grammar), str(cpp_grammar)]
        )
        logger.info(f"✓ Successfully built tree-sitter libraries: {library_path}")
        return library_path
    except Exception as e:
        logger.error(f"Failed to build languages: {e}")
        raise


def get_parser(lang: Lang, library_path: Optional[Path] = None):
    """
    Get a tree-sitter parser for the specified language.

    Args:
        lang: Language to parse
        library_path: Path to compiled language library (auto-detected if None)

    Returns:
        Configured Parser instance
    """
    try:
        from tree_sitter import Language, Parser
    except ImportError:
        raise ImportError(
            "tree-sitter not installed. Run: uv add tree-sitter"
        )

    lang_name = lang.value

    # Try tree-sitter-languages first
    try:
        from tree_sitter_languages import get_language
        language = get_language(lang_name)
        parser = Parser()
        parser.set_language(language)
        return parser
    except ImportError:
        pass  # Fall through to custom build

    # Build or locate library
    if library_path is None or not Path(library_path).exists():
        library_path = build_languages()

    # If build_languages returned None, tree-sitter-languages is available
    if library_path is None:
        # This shouldn't happen, but handle it gracefully
        raise RuntimeError("No language library available")

    # Load language from custom build
    try:
        language = Language(str(library_path), lang_name)
    except Exception as e:
        logger.error(f"Failed to load language '{lang_name}': {e}")
        logger.error(f"Library path: {library_path}")
        raise

    # Create parser
    parser = Parser()
    parser.set_language(language)

    return parser


def tree_sitter_ast(code: str, lang: Lang, library_path: Optional[Path] = None) -> TreeSitterAST:
    """
    Parse code using tree-sitter and return AST.

    This function matches the interface of parserTool.parse.tree_sitter_ast()

    Args:
        code: Source code to parse
        lang: Language of the code
        library_path: Path to compiled language library (optional)

    Returns:
        TreeSitterAST object with root_node attribute
    """
    parser = get_parser(lang, library_path)

    # Parse code
    tree = parser.parse(bytes(code, "utf8"))

    return TreeSitterAST(tree)


def parse_c_code(code: str) -> TreeSitterAST:
    """
    Convenience function to parse C code.

    Args:
        code: C source code

    Returns:
        TreeSitterAST object
    """
    return tree_sitter_ast(code, Lang.C)


def parse_cpp_code(code: str) -> TreeSitterAST:
    """
    Convenience function to parse C++ code.

    Args:
        code: C++ source code

    Returns:
        TreeSitterAST object
    """
    return tree_sitter_ast(code, Lang.CPP)


def verify_installation() -> bool:
    """
    Verify that tree-sitter is properly installed and configured.

    Returns:
        True if installation is valid, False otherwise
    """
    try:
        # Try to parse simple code
        test_code = "int main() { return 0; }"
        ast = tree_sitter_ast(test_code, Lang.C)

        # Verify AST structure
        assert ast.root_node is not None
        assert ast.root_node.type == "translation_unit"

        logger.info("✓ tree-sitter installation verified successfully")
        return True

    except Exception as e:
        logger.error(f"✗ tree-sitter installation verification failed: {e}")
        import traceback
        traceback.print_exc()
        return False


# Compatibility exports to match parserTool.parse interface
class parse:
    """Module-level namespace to match parserTool.parse imports."""

    Lang = Lang
    tree_sitter_ast = staticmethod(tree_sitter_ast)


if __name__ == "__main__":
    # Self-test
    import sys

    logging.basicConfig(level=logging.INFO)

    print("=" * 60)
    print("parserTool Adapter Self-Test")
    print("=" * 60)

    # Test 1: Check tree-sitter-languages availability
    print("\n[Test 1] Checking tree-sitter-languages...")
    try:
        from tree_sitter_languages import get_language
        c_lang = get_language('c')
        print(f"✓ tree-sitter-languages available")
    except ImportError as e:
        print(f"⚠ tree-sitter-languages not available: {e}")
        print("  Will try to build from source...")
        try:
            lib_path = build_languages()
            print(f"✓ Built from source: {lib_path}")
        except Exception as e2:
            print(f"✗ Failed to build: {e2}")
            sys.exit(1)

    # Test 2: Parse C code
    print("\n[Test 2] Parsing C code...")
    c_code = """
    int main() {
        int x = 10;
        if (x > 5) {
            return 1;
        }
        return 0;
    }
    """
    try:
        ast = tree_sitter_ast(c_code, Lang.C)
        print(f"✓ Parsed successfully")
        print(f"  Root node type: {ast.root_node.type}")
        print(f"  Child count: {ast.root_node.child_count}")
    except Exception as e:
        print(f"✗ Failed: {e}")
        sys.exit(1)

    # Test 3: Parse C++ code
    print("\n[Test 3] Parsing C++ code...")
    cpp_code = """
    class Foo {
    public:
        int bar() { return 42; }
    };
    """
    try:
        ast = tree_sitter_ast(cpp_code, Lang.CPP)
        print(f"✓ Parsed successfully")
        print(f"  Root node type: {ast.root_node.type}")
    except Exception as e:
        print(f"✗ Failed: {e}")
        sys.exit(1)

    # Test 4: Compatibility import
    print("\n[Test 4] Testing compatibility imports...")
    try:
        import evoprompt.utils.parsertool_adapter as ps
        from evoprompt.utils.parsertool_adapter import Lang

        test_ast = ps.tree_sitter_ast("int x;", Lang.C)
        print(f"✓ Compatibility imports work")
    except Exception as e:
        print(f"✗ Failed: {e}")
        sys.exit(1)

    print("\n" + "=" * 60)
    print("✓ All tests passed!")
    print("=" * 60)
    print("\nYou can now use the adapter in your scripts:")
    print("  import evoprompt.utils.parsertool_adapter as ps")
    print("  from evoprompt.utils.parsertool_adapter import Lang")
    print("  ast = ps.tree_sitter_ast(code, Lang.C)")
