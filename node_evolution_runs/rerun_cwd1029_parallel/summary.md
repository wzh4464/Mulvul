# CWD-1029 Parallel Rerun

- Model: `openai/gpt-5.4`
- Best prompt: `v2`
- Dev recipe: `{"selected_pos": 16, "selected_neg": 16, "neg_source_mix": {"parent_fp": 8, "other_memory_vuln": 8}}`
- Holdout recipe: `{"selected_pos": 24, "selected_neg": 24, "neg_source_mix": {"parent_fp": 12, "other_memory_vuln": 12}}`
- Parent FP pool: `43` unique samples
- Dev metric: `87.50%` (`28/32`)
- Holdout metric: `81.25%` (`39/48`)
- Final status: `needs_more_iteration`
- Holdout errors: `{"false_negatives": 2, "fp_other_memory_vuln": 3, "fp_parent_fp": 4, "fp_other": 0}`
