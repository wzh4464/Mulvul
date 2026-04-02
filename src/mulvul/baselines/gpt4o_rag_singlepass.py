"""GPT-4o + RAG Single-Pass Baseline.

This baseline uses a single LLM call with contrastive RAG evidence.
No Router/Detectors, no multi-turn interaction.

This addresses Reviewer C's concern about fair comparison - it uses the same
RAG budget as MulVul but removes Router/Detectors and multi-turn interaction.
"""

import json
import re
import time
from typing import Dict, List, Optional, Any

from ..rag.retriever import CodeSimilarityRetriever
from ..utils.cost_tracker import CostTracker


GPT4O_RAG_PROMPT = """You are a security code auditor. Follow the output format exactly.

Given the following C/C++ code and retrieved vulnerability knowledge evidence, decide whether the code contains a vulnerability and identify the most likely CWE type.

Constraints:
- Use ONLY the retrieved evidence and the code. If evidence is insufficient, output "NONE".
- Do NOT guess. Prefer "NONE" when uncertain.
- Output must be JSON with keys: "cwe" (string "CWE-XXX" or "NONE"), "rationale" (1-3 sentences), "evidence_ids" (list of IDs used)

[CODE]
{code_snippet}

[EVIDENCE]
{packed_evidence_with_ids}"""


def parse_baseline_response(response: str) -> Dict[str, Any]:
    """Parse JSON response from baseline models.

    Args:
        response: LLM response text

    Returns:
        Dict with cwe, rationale, evidence_ids, raw_response
    """
    # Handle empty response
    if not response:
        return {
            'cwe': 'NONE',
            'rationale': '',
            'evidence_ids': [],
            'raw_response': response
        }

    # Try to extract JSON from response
    try:
        # Look for JSON block - handle nested braces by finding balanced {}
        json_match = re.search(r'\{[^{}]*\}', response, re.DOTALL)
        if json_match:
            data = json.loads(json_match.group())
            return {
                'cwe': data.get('cwe', 'NONE'),
                'rationale': data.get('rationale', ''),
                'evidence_ids': data.get('evidence_ids', []),
                'raw_response': response
            }
    except json.JSONDecodeError:
        pass

    # Fallback: extract CWE pattern
    cwe_match = re.search(r'CWE-\d+', response)
    if cwe_match:
        return {
            'cwe': cwe_match.group(),
            'rationale': response[:200],
            'evidence_ids': [],
            'raw_response': response
        }

    return {
        'cwe': 'NONE',
        'rationale': response[:200] if response else '',
        'evidence_ids': [],
        'raw_response': response
    }


async def run_gpt4o_rag_singlepass(
    samples: List[Any],
    retriever: CodeSimilarityRetriever,
    llm_client,
    cost_tracker: Optional[CostTracker] = None,
    vulnerable_top_k: int = 2,
    clean_top_k: int = 1,
    max_code_length: int = 4000
) -> List[Dict]:
    """Run GPT-4o + RAG single-pass baseline.

    This baseline performs:
    1. Single contrastive RAG retrieval (vulnerable + clean examples)
    2. Single LLM call with code + evidence
    3. Parse JSON response

    Args:
        samples: List of samples with input_text, target, metadata
        retriever: CodeSimilarityRetriever with contrastive mode
        llm_client: LLM client with generate_async method
        cost_tracker: Optional CostTracker for recording costs
        vulnerable_top_k: Number of vulnerable examples to retrieve
        clean_top_k: Number of clean examples to retrieve
        max_code_length: Maximum code length to send to LLM

    Returns:
        List of prediction dicts with keys:
        - cwe: Predicted CWE or "NONE"
        - rationale: Explanation
        - evidence_ids: List of evidence IDs used
        - sample_id: Sample identifier
        - ground_truth: Ground truth label
        - ground_truth_cwe: Ground truth CWE(s) if available
        - raw_response: Original LLM response
    """
    results = []

    for i, sample in enumerate(samples):
        sample_id = sample.metadata.get('idx', i)

        if cost_tracker:
            cost_tracker.start_sample(str(sample_id), 'gpt4o_rag_singlepass')

        # Retrieve contrastive evidence
        retrieval_start = time.perf_counter()
        evidence = retriever.retrieve_contrastive(
            sample.input_text,
            vulnerable_top_k=vulnerable_top_k,
            clean_top_k=clean_top_k
        )
        retrieval_time = (time.perf_counter() - retrieval_start) * 1000

        if cost_tracker:
            cost_tracker.log_retrieval_call(vulnerable_top_k + clean_top_k, retrieval_time)

        # Single LLM call
        prompt = GPT4O_RAG_PROMPT.format(
            code_snippet=sample.input_text[:max_code_length],
            packed_evidence_with_ids=evidence.formatted_text
        )

        llm_start = time.perf_counter()
        response = await llm_client.generate_async(prompt)
        llm_time = (time.perf_counter() - llm_start) * 1000

        # Log LLM call if we have cost tracker
        if cost_tracker:
            # Estimate tokens: ~4 chars per token
            in_tokens = len(prompt) // 4
            out_tokens = len(response) // 4 if response else 0
            cost_tracker.log_llm_call("gpt-4o", in_tokens, out_tokens, llm_time)

        # Parse response
        prediction = parse_baseline_response(response)
        prediction['sample_id'] = sample_id
        prediction['ground_truth'] = sample.target
        prediction['ground_truth_cwe'] = sample.metadata.get('cwe', [])
        results.append(prediction)

        if cost_tracker:
            cost_tracker.end_sample()

        if (i + 1) % 100 == 0:
            print(f"   Processed {i + 1}/{len(samples)} samples")

    return results
