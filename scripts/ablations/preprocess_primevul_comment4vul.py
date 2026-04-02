#!/usr/bin/env python3
"""
PrimeVul to comment4vul Preprocessor

This script converts PrimeVul dataset samples into comment4vul's Natural Language AST format.
It processes vulnerability detection data by:
1. Loading PrimeVul JSONL samples
2. Formatting them for comment4vul processing
3. Applying symbolic AST transformation
4. Generating Natural Language AST representations

Usage:
    uv run python scripts/ablations/preprocess_primevul_comment4vul.py \
        --primevul-path data/primevul_1percent_sample/train_sample.jsonl \
        --output outputs/primevul_nl_ast/train_nl_ast.jsonl \
        --limit 10
"""

import argparse
import json
import jsonlines
import re
import sys
from pathlib import Path
from typing import Dict, Any, Optional, List
from tqdm import tqdm
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def setup_comment4vul_imports(use_adapter: bool = False):
    """
    Setup imports for comment4vul SymbolicRule module.

    This attempts to import parserTool which is required for Tree-sitter AST parsing.
    If not available or use_adapter=True, falls back to tree-sitter adapter.

    Args:
        use_adapter: If True, use tree-sitter adapter instead of parserTool

    Returns:
        Tuple of (ps module, Lang enum) or (None, None) on failure
    """
    if use_adapter:
        logger.info("Using tree-sitter adapter instead of parserTool")
        try:
            # Add src to path for adapter import
            src_path = Path(__file__).parent.parent / "src"
            if str(src_path) not in sys.path:
                sys.path.insert(0, str(src_path))

            from evoprompt.utils import parsertool_adapter as ps
            from evoprompt.utils.parsertool_adapter import Lang

            # Verify installation
            if not ps.verify_installation():
                logger.error("tree-sitter adapter verification failed")
                return None, None

            logger.info("✓ Successfully loaded tree-sitter adapter")
            return ps, Lang

        except ImportError as e:
            logger.error(f"✗ Failed to import tree-sitter adapter: {e}")
            logger.error("Install tree-sitter with: uv add tree-sitter")
            return None, None

    # Try original parserTool first
    try:
        # Try to import from comment4vul submodule
        sys.path.insert(0, str(Path(__file__).parent.parent / "comment4vul" / "SymbolicRule"))

        import parserTool.parse as ps
        from parserTool.parse import Lang

        logger.info("✓ Successfully imported parserTool")
        return ps, Lang
    except ImportError as e:
        logger.warning(f"parserTool not found, falling back to adapter: {e}")

        # Fallback to adapter
        try:
            src_path = Path(__file__).parent.parent / "src"
            if str(src_path) not in sys.path:
                sys.path.insert(0, str(src_path))

            from evoprompt.utils import parsertool_adapter as ps
            from evoprompt.utils.parsertool_adapter import Lang

            if not ps.verify_installation():
                logger.error("tree-sitter adapter verification failed")
                logger.error("""
Setup options:
1. Install tree-sitter adapter: uv add tree-sitter
2. Or download parserTool: https://drive.google.com/file/d/1JMQbWIgN6GRGRAXW7UdYzD7OVScBK-Fq/view

Refer to docs/parsertool_setup.md for details.
                """)
                return None, None

            logger.info("✓ Using tree-sitter adapter as fallback")
            return ps, Lang

        except ImportError as e2:
            logger.error(f"✗ Both parserTool and adapter failed: {e2}")
            logger.error("""
Neither parserTool nor tree-sitter adapter available.

Option 1 (Recommended): Install tree-sitter adapter
  uv add tree-sitter
  uv run python -c "from evoprompt.utils.parsertool_adapter import build_languages; build_languages()"

Option 2: Setup parserTool
  Download from: https://drive.google.com/file/d/1JMQbWIgN6GRGRAXW7UdYzD7OVScBK-Fq/view
  See: docs/parsertool_setup.md

            """)
            return None, None


def move_comments_to_new_line(code: str) -> str:
    """
    Move inline comments to separate lines above the code.

    This preprocesses code with inline comments (e.g., "x = 1; // comment")
    to have comments on their own line (e.g., "// comment\\nx = 1;")

    Args:
        code: Source code string

    Returns:
        Code with comments moved to new lines
    """
    lines = code.split('\n')
    new_lines = []

    for line in lines:
        # Match code and comment parts
        match = re.match(r'(\s*)(.*?)(\s*\/\/.*|\/\*.*\*\/)?$', line)
        if match:
            spaces, code_part, comment_part = match.groups()
            if comment_part:
                new_lines.append(f'{spaces}{comment_part.strip()}')
            new_lines.append(f'{spaces}{code_part}')

    code = '\n'.join(new_lines)
    # Remove empty lines
    code = re.sub(r'^\s*?\n', '', code, flags=re.MULTILINE)
    return code


def print_ast_node(code: str, node, indent: str = "") -> str:
    """
    Recursively traverse AST and insert comments into control flow statements.

    This is the core transformation that creates Natural Language AST by:
    1. Finding comment lines before control flow statements
    2. Inserting comment content into the statement's parentheses/conditions
    3. Recursively processing child nodes

    Supported statement types: if, for, while, switch, case, break, return, goto, continue, else

    Args:
        code: Source code string
        node: Tree-sitter AST node
        indent: Current indentation level (for debugging)

    Returns:
        Modified code with comments inserted into AST structure
    """
    cpp_loc = code.split('\n')

    # Process different node types
    # Each block finds comments before the statement and inserts them into appropriate positions

    # If Statement
    if node.type == "if_statement":
        if node.start_point[0] > 0 and cpp_loc[node.start_point[0] - 1].strip().startswith("//"):
            comment_line = cpp_loc[node.start_point[0] - 1]
            comment = comment_line.strip().lstrip("//")

            for child in node.children:
                if child.type == "parenthesized_expression" and child.start_point[0] == node.start_point[0]:
                    Begin = cpp_loc[child.start_point[0]][:child.start_point[1]]
                    End = cpp_loc[child.start_point[0]][child.end_point[1]:]

                    New_line = Begin + "(" + comment[1:] + ") " + End
                    cpp_loc[node.start_point[0]] = New_line
                    code = "\n".join(cpp_loc)

        if node.start_point[0] > 1 and cpp_loc[node.start_point[0] - 2].strip().startswith("//") and cpp_loc[node.start_point[0] - 1].strip() == "}":
            comment_line = cpp_loc[node.start_point[0] - 2]
            comment = comment_line.strip().lstrip("//")

            for child in node.children:
                if child.type == "parenthesized_expression" and child.start_point[0] == node.start_point[0]:
                    Begin = cpp_loc[child.start_point[0]][:child.start_point[1]]
                    End = cpp_loc[child.start_point[0]][child.end_point[1]:]

                    New_line = Begin + "(" + comment + ") " + End
                    cpp_loc[node.start_point[0]] = New_line
                    code = "\n".join(cpp_loc)

    # For Statement
    if node.type == "for_statement":
        if node.start_point[0] > 0 and cpp_loc[node.start_point[0] - 1].strip().startswith("//"):
            comment_line = cpp_loc[node.start_point[0] - 1]
            comment = comment_line.strip().lstrip("//")

            for child in node.children:
                if child.type == "(" and child.start_point[0] == node.start_point[0]:
                    Begin = cpp_loc[child.start_point[0]][:child.end_point[1]]
                if child.type == ")" and child.start_point[0] == node.start_point[0]:
                    End = cpp_loc[child.start_point[0]][child.start_point[1]:]

                    New_line = Begin + comment[1:] + End
                    cpp_loc[node.start_point[0]] = New_line
                    code = "\n".join(cpp_loc)

    # While Statement
    if node.type == "while_statement":
        if node.start_point[0] > 0 and cpp_loc[node.start_point[0] - 1].strip().startswith("//"):
            comment_line = cpp_loc[node.start_point[0] - 1]
            comment = comment_line.strip().lstrip("//")

            for child in node.children:
                if child.type == "parenthesized_expression" and child.start_point[0] == node.start_point[0]:
                    Begin = cpp_loc[child.start_point[0]][:child.start_point[1]]
                    End = cpp_loc[child.start_point[0]][child.end_point[1]:]

                    New_line = Begin + " (" + comment[1:] + ") " + End
                    cpp_loc[node.start_point[0]] = New_line
                    code = "\n".join(cpp_loc)

    # Return Statement
    if node.type == "return_statement":
        if node.start_point[0] > 0 and cpp_loc[node.start_point[0] - 1].strip().startswith("//"):
            comment_line = cpp_loc[node.start_point[0] - 1]
            comment = comment_line.strip().lstrip("//")

            for child in node.children:
                if child.type == ";" and child.start_point[0] == node.start_point[0]:
                    Begin = cpp_loc[child.start_point[0]][:child.start_point[1]]
                    End = cpp_loc[child.start_point[0]][child.start_point[1]:]

                    New_line = Begin + " (" + comment[1:] + ") " + End
                    cpp_loc[node.start_point[0]] = New_line
                    code = "\n".join(cpp_loc)

    # Recursively process child nodes
    for child in node.children:
        code = print_ast_node(code, child, indent + "  ")

    return code


def remove_comments(code: str) -> str:
    """
    Remove all comments and empty lines from code.

    This final step removes the original comment syntax, leaving only
    the natural language content that was inserted into the AST structure.

    Args:
        code: Source code with comments

    Returns:
        Code with all comments removed
    """
    # Remove single-line comments
    code = re.sub(r'//.*', '', code)

    # Remove multi-line comments
    code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)

    # Remove empty lines
    code = re.sub(r'^\s*?\n', '', code, flags=re.MULTILINE)

    return code


def process_with_comment4vul(code: str, ps, Lang) -> Optional[str]:
    """
    Apply comment4vul's symbolic processing to generate Natural Language AST.

    This is the main processing pipeline that:
    1. Moves comments to new lines
    2. Parses code with Tree-sitter
    3. Traverses AST and inserts comments
    4. Removes original comment syntax

    Args:
        code: Source code (optionally with comments)
        ps: parserTool.parse module
        Lang: Language enum from parserTool

    Returns:
        Natural Language AST string, or None on error
    """
    # Move inline comments to separate lines
    code = move_comments_to_new_line(code)

    # Parse with Tree-sitter
    code_ast = ps.tree_sitter_ast(code, Lang.C)

    # Insert comments into AST structure
    updated_code = print_ast_node(code, code_ast.root_node)

    # Remove comment syntax, leaving NL content in AST
    cleaned_code = remove_comments(updated_code)

    return cleaned_code


def convert_primevul_to_comment4vul_format(
    primevul_record: Dict[str, Any],
    use_llm_comments: bool = False,
    comment_text: Optional[str] = None
) -> Dict[str, Any]:
    """
    Convert PrimeVul record to comment4vul input format.

    PrimeVul format:
        {
            "idx": 210536,
            "target": 1,
            "func": "static int vt_disallocate(...) {...}",
            "cwe": ["CWE-416"],
            ...
        }

    comment4vul format:
        {
            "idx": 210536,
            "target": 1,
            "func": "static int vt_disallocate(...) {...}",
            "choices": "// vulnerability check\\nstatic int vt_disallocate(...) {...}"
        }

    Args:
        primevul_record: Original PrimeVul record
        use_llm_comments: Whether to use LLM-generated comments (future feature)
        comment_text: Optional default comment to add

    Returns:
        Record in comment4vul format
    """
    result = {
        "idx": primevul_record["idx"],
        "target": primevul_record["target"],
        "func": primevul_record["func"]
    }

    # Check if input already has LLM-generated comments in 'choices' field
    if "choices" in primevul_record and primevul_record["choices"] != primevul_record["func"]:
        # Use existing LLM-generated commented code
        result["choices"] = primevul_record["choices"]
        logger.debug(f"Using existing commented code from 'choices' field for sample {result['idx']}")
    elif use_llm_comments:
        logger.warning("LLM comment generation not yet implemented, using original code")
        result["choices"] = primevul_record["func"]
    elif comment_text:
        # Add a default comment at the beginning
        result["choices"] = f"// {comment_text}\n{primevul_record['func']}"
    else:
        result["choices"] = primevul_record["func"]

    return result


def preprocess_primevul_dataset(
    input_path: Path,
    output_path: Path,
    ps,
    Lang,
    limit: Optional[int] = None,
    start_idx: int = 0,
    use_llm_comments: bool = False
):
    """
    Main preprocessing pipeline.

    Loads PrimeVul JSONL, processes each sample through comment4vul,
    and outputs JSONL with Natural Language AST.

    Args:
        input_path: Path to PrimeVul JSONL file
        output_path: Path to output JSONL file
        ps: parserTool.parse module
        Lang: Language enum
        limit: Optional limit on number of samples to process
        start_idx: Starting index for resumption
        use_llm_comments: Whether to generate LLM comments
    """
    # Ensure output directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Load input data
    logger.info(f"Loading PrimeVul data from: {input_path}")

    samples = []
    with jsonlines.open(input_path) as reader:
        for i, record in enumerate(reader):
            if i < start_idx:
                continue
            samples.append(record)
            if limit and len(samples) >= limit:
                break

    logger.info(f"Loaded {len(samples)} samples")

    # Process samples
    results = []
    errors = 0

    for record in tqdm(samples, desc="Processing samples"):
        # Convert to comment4vul format
        c4v_record = convert_primevul_to_comment4vul_format(
            record,
            use_llm_comments=use_llm_comments
        )

        # Apply symbolic processing
        clean_code = process_with_comment4vul(c4v_record["choices"], ps, Lang)

        if clean_code is None:
            errors += 1
            logger.warning(f"Failed to process sample {c4v_record['idx']}")
            continue

        # Create output record
        output_record = {
            "idx": c4v_record["idx"],
            "target": c4v_record["target"],
            "func": c4v_record["func"],
            "choices": c4v_record["choices"],
            "clean_code": clean_code,
            "natural_language_ast": clean_code,  # Alias for clarity
        }

        # Preserve original metadata if available
        if "cwe" in record:
            output_record["cwe"] = record["cwe"]
        if "project" in record:
            output_record["project"] = record["project"]

        results.append(output_record)

    # Write output
    logger.info(f"Writing {len(results)} processed samples to: {output_path}")

    with jsonlines.open(output_path, mode='w') as writer:
        writer.write_all(results)

    logger.info(f"✓ Processing complete!")
    logger.info(f"  Successful: {len(results)}")
    logger.info(f"  Errors: {errors}")
    logger.info(f"  Output: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Preprocess PrimeVul dataset to comment4vul Natural Language AST format",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Process 10 samples from train set
    uv run python scripts/ablations/preprocess_primevul_comment4vul.py \\
        --primevul-path data/primevul_1percent_sample/train_sample.jsonl \\
        --output outputs/primevul_nl_ast/train_nl_ast.jsonl \\
        --limit 10

    # Process full dev set
    uv run python scripts/ablations/preprocess_primevul_comment4vul.py \\
        --primevul-path data/primevul/primevul/dev.jsonl \\
        --output outputs/primevul_nl_ast/dev_nl_ast.jsonl

    # Resume from index 100
    uv run python scripts/ablations/preprocess_primevul_comment4vul.py \\
        --primevul-path data/primevul_1percent_sample/train_sample.jsonl \\
        --output outputs/primevul_nl_ast/train_nl_ast.jsonl \\
        --start-idx 100
        """
    )

    parser.add_argument(
        "--primevul-path",
        type=Path,
        required=True,
        help="Path to input PrimeVul JSONL file"
    )

    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Path to output JSONL file with Natural Language AST"
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Limit number of samples to process (for testing)"
    )

    parser.add_argument(
        "--start-idx",
        type=int,
        default=0,
        help="Starting index for resumption"
    )

    parser.add_argument(
        "--use-llm-comments",
        action="store_true",
        help="Generate LLM comments (not yet implemented)"
    )

    parser.add_argument(
        "--comment4vul-root",
        type=Path,
        default=Path(__file__).parent.parent / "comment4vul",
        help="Path to comment4vul submodule root"
    )

    parser.add_argument(
        "--use-adapter",
        action="store_true",
        help="Use tree-sitter adapter instead of parserTool (recommended)"
    )

    args = parser.parse_args()

    # Validate input file
    if not args.primevul_path.exists():
        logger.error(f"Input file not found: {args.primevul_path}")
        sys.exit(1)

    # Setup comment4vul imports
    ps, Lang = setup_comment4vul_imports(use_adapter=args.use_adapter)
    if ps is None or Lang is None:
        logger.error("Failed to setup comment4vul dependencies")
        sys.exit(1)

    # Run preprocessing
    preprocess_primevul_dataset(
        input_path=args.primevul_path,
        output_path=args.output,
        ps=ps,
        Lang=Lang,
        limit=args.limit,
        start_idx=args.start_idx,
        use_llm_comments=args.use_llm_comments
    )


if __name__ == "__main__":
    main()
