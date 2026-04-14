# Batch D Low-Sample CWD Node Evolution

- Model: `openai/gpt-5.4`
- API base: `https://openrouter.ai/api/v1`

## CWD-1003 用于内存分配的缓冲区大小计算错误
- Status: `blocked_by_samples`
- Best prompt: `baseline`
- Dev metric: `1.0` (13/13)
- Holdout metric: `0.8` (4/5)
- Main error buckets: `{"target_fn": 1, "sibling_pos": 0, "target_hard_benign": 0, "other": 0}`
- Recipe: `{"target_pos_available": 14, "target_neg_available": 4, "sibling_pos_available": {"CWD-1002": 0}, "selected_pos": 14, "selected_neg": 4, "selected_total": 18, "neg_source_mix": {"sibling_pos": 0, "target_neg": 4}}`

## CWD-1005 不正确的字节序
- Status: `blocked_by_samples`
- Best prompt: `baseline`
- Dev metric: `1.0` (1/1)
- Holdout metric: `0.0` (0/1)
- Main error buckets: `{"target_fn": 0, "sibling_pos": 0, "target_hard_benign": 0, "other": 1}`
- Recipe: `{"target_pos_available": 1, "target_neg_available": 1, "sibling_pos_available": {"CWD-1006": 1, "CWD-1007": 3, "CWD-1008": 1}, "selected_pos": 1, "selected_neg": 1, "selected_total": 2, "neg_source_mix": {"sibling_pos": 1, "target_neg": 0}}`

## CWD-1006 依赖带位域的结构体的内存布局
- Status: `blocked_by_samples`
- Best prompt: `baseline`
- Dev metric: `0.0` (0/1)
- Holdout metric: `1.0` (1/1)
- Main error buckets: `{"target_fn": 0, "sibling_pos": 0, "target_hard_benign": 0, "other": 0}`
- Recipe: `{"target_pos_available": 1, "target_neg_available": 3, "sibling_pos_available": {"CWD-1005": 1, "CWD-1007": 3, "CWD-1008": 1}, "selected_pos": 1, "selected_neg": 1, "selected_total": 2, "neg_source_mix": {"sibling_pos": 1, "target_neg": 0}}`

## CWD-1007 不正确的逐位操作
- Status: `blocked_by_samples`
- Best prompt: `baseline`
- Dev metric: `0.5` (2/4)
- Holdout metric: `0.5` (1/2)
- Main error buckets: `{"target_fn": 0, "sibling_pos": 0, "target_hard_benign": 0, "other": 1}`
- Recipe: `{"target_pos_available": 3, "target_neg_available": 1, "sibling_pos_available": {"CWD-1005": 1, "CWD-1006": 1, "CWD-1008": 1}, "selected_pos": 3, "selected_neg": 3, "selected_total": 6, "neg_source_mix": {"sibling_pos": 3, "target_neg": 0}}`

## CWD-1008 使用可能导致内存布局不兼容的std::vector<bool>
- Status: `blocked_by_samples`
- Best prompt: `baseline`
- Dev metric: `0.0` (0/1)
- Holdout metric: `0.0` (0/1)
- Main error buckets: `{"target_fn": 1, "sibling_pos": 0, "target_hard_benign": 0, "other": 0}`
- Recipe: `{"target_pos_available": 1, "target_neg_available": 1, "sibling_pos_available": {"CWD-1005": 1, "CWD-1006": 1, "CWD-1007": 3}, "selected_pos": 1, "selected_neg": 1, "selected_total": 2, "neg_source_mix": {"sibling_pos": 1, "target_neg": 0}}`

## CWD-1017 内存拷贝重叠
- Status: `blocked_by_samples`
- Best prompt: `baseline`
- Dev metric: `0.7777777777777778` (7/9)
- Holdout metric: `0.6666666666666666` (2/3)
- Main error buckets: `{"target_fn": 0, "sibling_pos": 0, "target_hard_benign": 0, "other": 1}`
- Recipe: `{"target_pos_available": 6, "target_neg_available": 4, "sibling_pos_available": {"CWD-1003": 14, "CWD-1015": 0, "CWD-1016": 0, "CWD-1022": 23, "CWD-1023": 11, "CWD-1025": 0, "CWD-1026": 0, "CWD-1027": 0, "CWD-1028": 0, "CWD-1031": 0, "CWD-1043": 0}, "selected_pos": 6, "selected_neg": 6, "selected_total": 12, "neg_source_mix": {"sibling_pos": 3, "target_neg": 3}}`

## CWD-1022 内存的申请和释放函数未配对
- Status: `needs_more_iteration`
- Best prompt: `baseline`
- Dev metric: `0.5714285714285714` (20/35)
- Holdout metric: `0.5454545454545454` (6/11)
- Main error buckets: `{"target_fn": 1, "sibling_pos": 0, "target_hard_benign": 3, "other": 1}`
- Recipe: `{"target_pos_available": 23, "target_neg_available": 21, "sibling_pos_available": {"CWD-1021": 0, "CWD-1023": 11, "CWD-1025": 0, "CWD-1026": 0}, "selected_pos": 23, "selected_neg": 23, "selected_total": 46, "neg_source_mix": {"sibling_pos": 6, "target_neg": 17}}`

## CWD-1023 释放未在缓冲区起始处的指针
- Status: `needs_more_iteration`
- Best prompt: `baseline`
- Dev metric: `0.6875` (11/16)
- Holdout metric: `0.6666666666666666` (4/6)
- Main error buckets: `{"target_fn": 0, "sibling_pos": 0, "target_hard_benign": 0, "other": 2}`
- Recipe: `{"target_pos_available": 11, "target_neg_available": 6, "sibling_pos_available": {"CWD-1021": 0, "CWD-1022": 23, "CWD-1025": 0, "CWD-1026": 0}, "selected_pos": 11, "selected_neg": 11, "selected_total": 22, "neg_source_mix": {"sibling_pos": 5, "target_neg": 6}}`

## CWD-1042 未受控的格式化字符串
- Status: `blocked_by_samples`
- Best prompt: `baseline`
- Dev metric: `0.7` (14/20)
- Holdout metric: `0.7142857142857143` (5/7)
- Main error buckets: `{"target_fn": 2, "sibling_pos": 0, "target_hard_benign": 0, "other": 0}`
- Recipe: `{"target_pos_available": 14, "target_neg_available": 13, "sibling_pos_available": {"CWD-1068": 0, "CWD-1070": 0, "CWD-1071": 0, "CWD-1081": 0, "CWD-1093": 0, "CWD-1096": 0, "CWD-1101": 0, "CWD-1115": 0}, "selected_pos": 14, "selected_neg": 13, "selected_total": 27, "neg_source_mix": {"sibling_pos": 0, "target_neg": 13}}`
