# Redo C Low-Sample Logic

- Model: `openai/gpt-5.4`
- API base: `https://openrouter.ai/api/v1`

## CWD-1005 不正确的字节序
- Previous status: `blocked_by_samples`
- Revised recipe: `{"target_pos_available": 3, "target_neg_available": 3, "sibling_pos_available": {"CWD-1006": 6, "CWD-1007": 4, "CWD-1008": 4}, "selected_pos": 3, "selected_neg": 3, "selected_total": 6, "neg_source_mix": {"sibling_pos": 1, "target_neg": 2}}`
- Extra sample recovery: `yes`
- Best prompt: `contrastive`
- Dev metric: `0.6666666666666666`
- Holdout metric: `0.0`
- Main error buckets: `{"target_fn": 2, "sibling_pos": 0, "target_hard_benign": 1, "other": 0}`
- Final status: `blocked_by_samples`

## CWD-1006 依赖带位域的结构体的内存布局
- Previous status: `blocked_by_samples`
- Revised recipe: `{"target_pos_available": 3, "target_neg_available": 3, "sibling_pos_available": {"CWD-1005": 6, "CWD-1007": 4, "CWD-1008": 4}, "selected_pos": 3, "selected_neg": 3, "selected_total": 6, "neg_source_mix": {"sibling_pos": 1, "target_neg": 2}}`
- Extra sample recovery: `yes`
- Best prompt: `contrastive`
- Dev metric: `0.6666666666666666`
- Holdout metric: `1.0`
- Main error buckets: `{"target_fn": 0, "sibling_pos": 0, "target_hard_benign": 0, "other": 0}`
- Final status: `keep`

## CWD-1007 不正确的逐位操作
- Previous status: `blocked_by_samples`
- Revised recipe: `{"target_pos_available": 2, "target_neg_available": 2, "sibling_pos_available": {"CWD-1005": 6, "CWD-1006": 6, "CWD-1008": 4}, "selected_pos": 2, "selected_neg": 2, "selected_total": 4, "neg_source_mix": {"sibling_pos": 0, "target_neg": 0}}`
- Extra sample recovery: `yes`
- Best prompt: `null`
- Dev metric: `None`
- Holdout metric: `None`
- Main error buckets: `{"target_fn": 0, "sibling_pos": 0, "target_hard_benign": 0, "other": 0}`
- Final status: `blocked_by_samples`

## CWD-1008 使用可能导致内存布局不兼容的std::vector<bool>
- Previous status: `blocked_by_samples`
- Revised recipe: `{"target_pos_available": 2, "target_neg_available": 2, "sibling_pos_available": {"CWD-1005": 6, "CWD-1006": 6, "CWD-1007": 4}, "selected_pos": 2, "selected_neg": 2, "selected_total": 4, "neg_source_mix": {"sibling_pos": 0, "target_neg": 0}}`
- Extra sample recovery: `yes`
- Best prompt: `null`
- Dev metric: `None`
- Holdout metric: `None`
- Main error buckets: `{"target_fn": 0, "sibling_pos": 0, "target_hard_benign": 0, "other": 0}`
- Final status: `blocked_by_samples`

## CWD-1034 不受信任的指针解引用
- Previous status: `blocked_by_samples`
- Revised recipe: `{"target_pos_available": 4, "target_neg_available": 4, "sibling_pos_available": {"CWD-1029": 197, "CWD-1030": 44, "CWD-1031": 543, "CWD-1038": 63, "CWD-1039": 6}, "selected_pos": 4, "selected_neg": 4, "selected_total": 8, "neg_source_mix": {"sibling_pos": 2, "target_neg": 2}}`
- Extra sample recovery: `yes`
- Best prompt: `baseline`
- Dev metric: `0.4`
- Holdout metric: `0.6666666666666666`
- Main error buckets: `{"target_fn": 1, "sibling_pos": 0, "target_hard_benign": 0, "other": 0}`
- Final status: `needs_more_iteration`

## CWD-1039 整数与指针间的互相转化
- Previous status: `blocked_by_samples`
- Revised recipe: `{"target_pos_available": 3, "target_neg_available": 3, "sibling_pos_available": {"CWD-1029": 197, "CWD-1030": 44, "CWD-1031": 543, "CWD-1034": 8, "CWD-1038": 63}, "selected_pos": 3, "selected_neg": 3, "selected_total": 6, "neg_source_mix": {"sibling_pos": 1, "target_neg": 2}}`
- Extra sample recovery: `yes`
- Best prompt: `contrastive`
- Dev metric: `0.3333333333333333`
- Holdout metric: `0.3333333333333333`
- Main error buckets: `{"target_fn": 1, "sibling_pos": 1, "target_hard_benign": 0, "other": 0}`
- Final status: `blocked_by_samples`
