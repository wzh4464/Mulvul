# CWD-1015 Parallel Rerun

- Model: `openai/gpt-5.4`
- Best prompt: `v3`
- Clean positive pool: `11` after removing `3 off-node/noisy positives`
- Removed noisy positives: `[{"sample_id": "cwd_000053::vuln", "reason": "destination-side write into sendMsg + packLen via memset_s; this is CWD-1016-style, not source-side read length"}, {"sample_id": "cwd_000061::vuln", "reason": "visible bound check keeps source read within packet; current snippet looks safe / mislabeled as vulnerable"}, {"sample_id": "cwd_000062::vuln", "reason": "destination-side destmax/count issue on memcpy_s(buffer, count, ...); this is CWD-1016-style, not source-side"}]`
- Parent FP pool: `28` unique samples from Memory major evolution + optimized traces
- Dev recipe: `{"selected_pos": 5, "selected_neg": 5, "neg_source_mix": {"parent_fp": 2, "other_memory_vuln": 3}, "sample_ids": ["cwd_000048::vuln", "cwd_000699::vuln", "cwd_000057::vuln", "cwd_001197::vuln", "cwd_000066::benign", "majorfp_74", "cwd_000040::vuln", "cwd_000046::vuln", "cwd_000060::vuln", "cwd_000138::vuln"]}`
- Holdout recipe: `{"selected_pos": 6, "selected_neg": 6, "neg_source_mix": {"parent_fp": 3, "other_memory_vuln": 3}, "sample_ids": ["cwd_000044::vuln", "cwd_000093::vuln", "cwd_001180::vuln", "cwd_000050::vuln", "cwd_000024::benign", "cwd_000043::vuln", "majorfp_96", "cwd_000056::vuln", "cwd_000055::vuln", "majorfp_91", "cwd_000059::vuln", "cwd_000662::vuln"]}`
- Dev metric: `90.00%` (`9/10`)
- Holdout metric: `75.00%` (`9/12`)
- Final status: `needs_more_iteration`
- Holdout errors: `{"false_negatives": 3, "fp_other_memory_vuln": 0, "fp_parent_fp": 0, "fp_other": 0}`
