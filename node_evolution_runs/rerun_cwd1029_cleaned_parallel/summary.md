# CWD-1029 Cleaned Parallel Rerun

- Model: `openai/gpt-5.4`
- Best prompt: `v8`
- Removed noisy positives: `["cwd_000824::vuln"]`
- Filtered parent-FP idx: `[14, 34, 72, 75, 97]`
- Dev recipe: `{"selected_pos": 16, "selected_neg": 16, "neg_source_mix": {"parent_fp": 8, "other_memory_vuln": 8}}`
- Holdout recipe: `{"selected_pos": 24, "selected_neg": 22, "neg_source_mix": {"parent_fp": 10, "other_memory_vuln": 12}}`
- Parent FP pool: `36` unique samples
- Dev metric: `87.50%` (`28/32`)
- Holdout metric: `91.30%` (`42/46`)
- Final status: `keep`
- Holdout errors: `{"false_negatives": 3, "fp_other_memory_vuln": 1, "fp_parent_fp": 0, "fp_other": 0}`
- Scope note: `cleaned-node result; not raw-dataset pass`
