# Buffer Parent-FP Rerun

- Model: `openai/gpt-5.4`
- Parent FP pool: `4` unique Memory-major false positives from historical traces

## CWD-1015
- Dev recipe: `{"selected_pos": 6, "selected_neg": 6, "neg_source_mix": {"other_memory_vuln": 3, "parent_fp": 2, "target_benign": 1}, "target_pos_available": 14, "target_benign_available": 10, "parent_fp_available": 4, "same_middle_vuln_available": 235, "other_memory_vuln_available": 438}`
- Holdout recipe: `{"selected_pos": 8, "selected_neg": 8, "neg_source_mix": {"other_memory_vuln": 4, "parent_fp": 2, "target_benign": 2}, "target_pos_available": 14, "target_benign_available": 10, "parent_fp_available": 4, "same_middle_vuln_available": 235, "other_memory_vuln_available": 438}`
- Best prompt: `v1`
- Dev metric: `75.00%` (`9/12`)
- Holdout metric: `75.00%` (`12/16`)
- Final status: `needs_more_iteration`
- Main error buckets (holdout): `{"false_negatives": 2, "fp_other_memory_vuln": 0, "fp_parent_fp": 1, "fp_target_benign": 1, "fp_other": 0}`

## CWD-1016
- Dev recipe: `{"selected_pos": 16, "selected_neg": 16, "neg_source_mix": {"other_memory_vuln": 8, "target_benign": 6, "parent_fp": 2}, "target_pos_available": 48, "target_benign_available": 43, "parent_fp_available": 4, "same_middle_vuln_available": 201, "other_memory_vuln_available": 438}`
- Holdout recipe: `{"selected_pos": 32, "selected_neg": 32, "neg_source_mix": {"target_benign": 14, "other_memory_vuln": 16, "parent_fp": 2}, "target_pos_available": 48, "target_benign_available": 43, "parent_fp_available": 4, "same_middle_vuln_available": 201, "other_memory_vuln_available": 438}`
- Best prompt: `v2`
- Dev metric: `96.88%` (`31/32`)
- Holdout metric: `76.56%` (`49/64`)
- Final status: `needs_more_iteration`
- Main error buckets (holdout): `{"false_negatives": 12, "fp_other_memory_vuln": 1, "fp_parent_fp": 1, "fp_target_benign": 1, "fp_other": 0}`

## CWD-1043
- Dev recipe: `{"selected_pos": 8, "selected_neg": 8, "neg_source_mix": {"other_memory_vuln": 4, "target_benign": 2, "parent_fp": 2}, "target_pos_available": 22, "target_benign_available": 20, "parent_fp_available": 4, "same_middle_vuln_available": 227, "other_memory_vuln_available": 438}`
- Holdout recipe: `{"selected_pos": 14, "selected_neg": 14, "neg_source_mix": {"target_benign": 5, "other_memory_vuln": 7, "parent_fp": 2}, "target_pos_available": 22, "target_benign_available": 20, "parent_fp_available": 4, "same_middle_vuln_available": 227, "other_memory_vuln_available": 438}`
- Best prompt: `v4`
- Dev metric: `93.75%` (`15/16`)
- Holdout metric: `100.00%` (`28/28`)
- Final status: `keep`
- Main error buckets (holdout): `{"false_negatives": 0, "fp_other_memory_vuln": 0, "fp_parent_fp": 0, "fp_target_benign": 0, "fp_other": 0}`
