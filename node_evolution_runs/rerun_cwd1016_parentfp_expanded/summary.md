# CWD-1016 Expanded Parent-FP Rerun

- Model: `openai/gpt-5.4`
- Best prompt: `v5`
- Clean positive pool: `44` after removing `4 off-node/noisy positives`
- Removed noisy positives: `["cwd_000069::vuln", "cwd_000097::vuln", "cwd_000132::vuln", "cwd_000144::vuln"]`
- Parent FP pool: `45` unique samples from Memory major evolution + optimized traces
- Dev recipe: `{"selected_pos": 16, "selected_neg": 16, "neg_source_mix": {"parent_fp": 8, "other_memory_vuln": 8}}`
- Holdout recipe: `{"selected_pos": 28, "selected_neg": 28, "neg_source_mix": {"parent_fp": 14, "other_memory_vuln": 14}}`
- Dev metric: `100.00%` (`32/32`)
- Holdout metric: `92.86%` (`52/56`)
- Final status: `keep`
- Holdout errors: `{"false_negatives": 0, "fp_other_memory_vuln": 0, "fp_parent_fp": 4, "fp_other": 0}`
