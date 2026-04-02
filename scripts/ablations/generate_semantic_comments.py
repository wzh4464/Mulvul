#!/usr/bin/env python3
"""
Generate semantic comments for code using LLM before NL AST processing.

This is the missing piece for true NL AST generation.
"""

import argparse
import jsonlines
from pathlib import Path
from tqdm import tqdm
import sys
import logging

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from evoprompt.llm.client import create_default_client

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


COMMENT_GENERATION_PROMPT = """You are a code analysis expert. Add concise semantic comments to the following C/C++ code to explain what each control flow statement does.

Rules:
1. Add comments ONLY before if/for/while/switch/return statements
2. Each comment should be ONE line starting with //
3. Focus on WHAT the condition/loop checks or WHAT is returned
4. Be concise (5-10 words per comment)
5. Do NOT add comments for variable declarations
6. Output ONLY the commented code, nothing else

Example:
Input:
if (ptr == NULL)
    return -1;
return process(ptr);

Output:
// Check if pointer is NULL
if (ptr == NULL)
    return -1;
// Process valid pointer
return process(ptr);

Now add comments to this code:
{code}

Output only the commented code:"""


def generate_comments_for_code(code: str, llm_client) -> str:
    """Generate semantic comments for code using LLM."""
    prompt = COMMENT_GENERATION_PROMPT.format(code=code)

    try:
        response = llm_client.generate(
            prompt,
            temperature=0.3,  # Lower temperature for more consistent output
            max_tokens=2000
        )

        # Clean up response
        commented_code = response.strip()

        # Remove markdown code blocks if present
        if commented_code.startswith("```"):
            lines = commented_code.split('\n')
            # Remove first and last lines if they're markdown markers
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].startswith("```"):
                lines = lines[:-1]
            commented_code = '\n'.join(lines)

        return commented_code

    except Exception as e:
        logger.error(f"Failed to generate comments: {e}")
        return code  # Fallback to original code


def main():
    parser = argparse.ArgumentParser(
        description="Generate semantic comments for code before NL AST processing"
    )

    parser.add_argument(
        "--input",
        type=Path,
        required=True,
        help="Input JSONL file with original PrimeVul data"
    )

    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Output JSONL file with commented code"
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Limit number of samples (for testing)"
    )

    args = parser.parse_args()

    # Create LLM client
    logger.info("Initializing LLM client...")
    llm_client = create_default_client()

    # Load input data
    logger.info(f"Loading data from {args.input}")
    samples = []
    with jsonlines.open(args.input) as reader:
        for record in reader:
            samples.append(record)
            if args.limit and len(samples) >= args.limit:
                break

    logger.info(f"Loaded {len(samples)} samples")

    # Generate comments
    args.output.parent.mkdir(parents=True, exist_ok=True)

    with jsonlines.open(args.output, mode='w') as writer:
        for record in tqdm(samples, desc="Generating comments"):
            # Generate comments for code
            commented_code = generate_comments_for_code(record['func'], llm_client)

            # Create output record
            output_record = {
                **record,  # Preserve all original fields
                'choices': commented_code  # Add commented version
            }

            writer.write(output_record)

    logger.info(f"✓ Complete! Wrote {len(samples)} samples to {args.output}")
    logger.info(f"Next step: Run preprocess_primevul_comment4vul.py on this file")


if __name__ == "__main__":
    main()
