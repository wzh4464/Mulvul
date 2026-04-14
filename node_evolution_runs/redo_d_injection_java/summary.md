# Redo D: Injection Java

- Model: `openai/gpt-5.4`
- API base: `https://openrouter.ai/api/v1`
- Seed: `42`

## CWD-1042
- Previous status: `blocked_by_samples`
- Revised recipe: {"positive": "12 target vulnerable samples", "negative": ["11 target benign samples", "14 sibling vulnerable hard negatives"], "selection": {"target_pos_available": 12, "target_neg_available": 11, "sibling_pos_available": {"CWD-1068": 9, "CWD-1070": 5, "CWD-1071": 58, "CWD-1081": 5, "CWD-1093": 2, "CWD-1096": 15, "CWD-1101": 19, "CWD-1115": 14}, "selected_pos": 12, "selected_neg": 25, "selected_total": 37, "neg_source_mix": {"target_benign": 11, "sibling_vuln": 14}}, "target_stats": {"unique_count": 23, "label_counts": {"VULNERABLE": 12, "BENIGN": 11}, "duplicate_count": 0, "conflict_count": 0, "conflicts": []}, "sibling_stats": {"unique_count": 127, "label_counts": {"VULNERABLE": 127}, "duplicate_count": 0, "conflict_count": 0, "conflicts": []}}
- Extra sample recovery: `yes`
- Best prompt version: `v1`
- Dev metric: `9/22 = 40.91%`
- Holdout metric: `7/15 = 46.67%`
- Main error buckets: `{"sibling_vuln": 6, "target_pos": 2}`
- Final status: `needs_more_iteration`

## CWD-1071
- Previous status: `needs_more_iteration`
- Revised recipe: {"positive": "58 target vulnerable samples", "negative": ["40 target benign samples", "20 sibling vulnerable hard negatives"], "selection": {"target_pos_available": 58, "target_neg_available": 40, "sibling_pos_available": {"CWD-1042": 12, "CWD-1068": 9, "CWD-1070": 5, "CWD-1081": 5, "CWD-1093": 2, "CWD-1096": 15, "CWD-1101": 19, "CWD-1115": 14}, "selected_pos": 58, "selected_neg": 60, "selected_total": 118, "neg_source_mix": {"target_benign": 40, "sibling_vuln": 20}}, "target_stats": {"unique_count": 98, "label_counts": {"VULNERABLE": 58, "BENIGN": 40}, "duplicate_count": 0, "conflict_count": 0, "conflicts": []}, "sibling_stats": {"unique_count": 81, "label_counts": {"VULNERABLE": 81}, "duplicate_count": 0, "conflict_count": 0, "conflicts": []}}
- Extra sample recovery: `yes`
- Best prompt version: `v3`
- Dev metric: `44/71 = 61.97%`
- Holdout metric: `32/47 = 68.09%`
- Main error buckets: `{"target_benign": 7, "sibling_vuln": 8}`
- Final status: `needs_more_iteration`

## CWD-1093
- Previous status: `blocked_by_samples`
- Revised recipe: {"positive": "2 target vulnerable samples", "negative": ["1 target benign samples", "10 sibling vulnerable hard negatives"], "selection": {"target_pos_available": 2, "target_neg_available": 1, "sibling_pos_available": {"CWD-1042": 12, "CWD-1068": 9, "CWD-1070": 5, "CWD-1071": 58, "CWD-1081": 5, "CWD-1096": 15, "CWD-1101": 19, "CWD-1115": 14}, "selected_pos": 2, "selected_neg": 11, "selected_total": 13, "neg_source_mix": {"target_benign": 1, "sibling_vuln": 10}}, "target_stats": {"unique_count": 3, "label_counts": {"VULNERABLE": 2, "BENIGN": 1}, "duplicate_count": 0, "conflict_count": 0, "conflicts": []}, "sibling_stats": {"unique_count": 137, "label_counts": {"VULNERABLE": 137}, "duplicate_count": 0, "conflict_count": 0, "conflicts": []}}
- Extra sample recovery: `yes`
- Best prompt version: `v1`
- Dev metric: `2/7 = 28.57%`
- Holdout metric: `1/6 = 16.67%`
- Main error buckets: `{"sibling_vuln": 5}`
- Final status: `blocked_by_samples`

## Notes
- `CWD-1042` and `CWD-1071` were re-cut from WeaknessCase method-level snippets, with sibling injection positives reused as hard negatives and marker text stripped from the snippet payloads.
- `CWD-1093` only had 2 vulnerable + 2 benign code samples in benchmark, so the node remains structurally underpowered even after recovery and stays blocked.
