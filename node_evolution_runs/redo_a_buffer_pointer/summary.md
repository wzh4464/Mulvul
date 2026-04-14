# Redo A Buffer/Pointer Summary

Model: `openai/gpt-5.4`

| Node | Prev | Recipe | Recovery | Dev | Holdout | Errors | Final |
|---|---|---|---:|---:|---:|---|---|
| CWD-1015 | needs_more_iteration | pos 8 / neg 8 | yes | 75.00% | 75.00% | false_negatives=1, fp_sibling_vuln=0, fp_target_hard_benign=1, fp_other=0 | needs_more_iteration |
| CWD-1016 | needs_more_iteration | pos 16 / neg 16 | yes | 81.25% | 75.00% | false_negatives=2, fp_sibling_vuln=0, fp_target_hard_benign=2, fp_other=0 | needs_more_iteration |
| CWD-1028 | needs_more_iteration | pos 12 / neg 12 | yes | 91.67% | 100.00% | false_negatives=0, fp_sibling_vuln=0, fp_target_hard_benign=0, fp_other=0 | keep |
| CWD-1043 | needs_more_iteration | pos 8 / neg 8 | yes | 62.50% | 75.00% | false_negatives=1, fp_sibling_vuln=0, fp_target_hard_benign=1, fp_other=0 | needs_more_iteration |
| CWD-1029 | needs_more_iteration | pos 12 / neg 12 | yes | 91.67% | 83.33% | false_negatives=2, fp_sibling_vuln=0, fp_target_hard_benign=0, fp_other=0 | needs_more_iteration |
| CWD-1030 | needs_more_iteration | pos 6 / neg 6 | yes | 80.00% | 71.43% | false_negatives=2, fp_sibling_vuln=0, fp_target_hard_benign=0, fp_other=0 | needs_more_iteration |
| CWD-1031 | needs_more_iteration | pos 16 / neg 16 | yes | 93.75% | 68.75% | false_negatives=1, fp_sibling_vuln=1, fp_target_hard_benign=3, fp_other=0 | needs_more_iteration |
| CWD-1038 | needs_more_iteration | pos 8 / neg 8 | yes | 87.50% | 50.00% | false_negatives=4, fp_sibling_vuln=0, fp_target_hard_benign=0, fp_other=0 | needs_more_iteration |

## Notes
- Buffer nodes now explicitly separate source-side vs destination-side behavior and include BENIGN guard patterns.
- Pointer nodes now explicitly separate offset, uninitialized, null, and incompatible-cast failures.
- WeaknessCase marker annotations were expanded into code snippets; codehub entries were comment-only and not used as code samples.
