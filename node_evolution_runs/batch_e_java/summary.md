# Batch E Summary

Batch: `batch_e_java`

Dataset recipe: positives from WeaknessCase bad methods plus selected sample_selection vulnerable snippets; negatives from sibling vulnerable samples and paired benign/good methods when available.

## CWD-1068
- Status: `keep`
- Positive/negative recipe: {'positives': '12 CWD-1068 vulnerable samples (WeaknessCase + selected sample_selection snippets)', 'negatives': '97 sibling vulnerable samples + 10 paired benign samples', 'notes': 'Sibling pool is capped by the batch; 1093 has no usable sample pool.'}
- Best prompt: `p2`
- Dev metric: 48/48 = 100.00%
- Holdout metric: 71/71 = 100.00%
- Main error buckets: {}

## CWD-1070
- Status: `keep`
- Positive/negative recipe: {'positives': '2 CWD-1070 vulnerable samples (WeaknessCase + selected sample_selection snippets)', 'negatives': '107 sibling vulnerable samples + 0 paired benign samples', 'notes': 'Sibling pool is capped by the batch; 1093 has no usable sample pool.'}
- Best prompt: `p1`
- Dev metric: 44/44 = 100.00%
- Holdout metric: 65/65 = 100.00%
- Main error buckets: {}

## CWD-1071
- Status: `needs_more_iteration`
- Positive/negative recipe: {'positives': '34 CWD-1071 vulnerable samples (WeaknessCase + selected sample_selection snippets)', 'negatives': '75 sibling vulnerable samples + 27 paired benign samples', 'notes': 'Sibling pool is capped by the batch; 1093 has no usable sample pool.'}
- Best prompt: `p1`
- Dev metric: 52/55 = 94.55%
- Holdout metric: 68/81 = 83.95%
- Main error buckets: {"weaknesscase:benign": 2, "weaknesscase:vulnerable": 11}

## CWD-1081
- Status: `keep`
- Positive/negative recipe: {'positives': '8 CWD-1081 vulnerable samples (WeaknessCase + selected sample_selection snippets)', 'negatives': '101 sibling vulnerable samples + 6 paired benign samples', 'notes': 'Sibling pool is capped by the batch; 1093 has no usable sample pool.'}
- Best prompt: `p1`
- Dev metric: 46/46 = 100.00%
- Holdout metric: 69/69 = 100.00%
- Main error buckets: {}

## CWD-1084
- Status: `keep`
- Positive/negative recipe: {'positives': '3 CWD-1084 vulnerable samples (WeaknessCase + selected sample_selection snippets)', 'negatives': '106 sibling vulnerable samples + 1 paired benign samples', 'notes': 'Sibling pool is capped by the batch; 1093 has no usable sample pool.'}
- Best prompt: `p1`
- Dev metric: 44/44 = 100.00%
- Holdout metric: 66/66 = 100.00%
- Main error buckets: {}

## CWD-1093
- Status: `blocked_by_samples`
- Positive/negative recipe: {'positives': '0 CWD-1093 vulnerable samples (WeaknessCase + selected sample_selection snippets)', 'negatives': '109 sibling vulnerable samples + 0 paired benign samples', 'notes': 'Sibling pool is capped by the batch; 1093 has no usable sample pool.'}
- Best prompt: `p1`
- Dev metric: 22/44 = 50.00%
- Holdout metric: 48/65 = 73.85%
- Main error buckets: {"weaknesscase:vulnerable": 17}

## CWD-1096
- Status: `keep`
- Positive/negative recipe: {'positives': '17 CWD-1096 vulnerable samples (WeaknessCase + selected sample_selection snippets)', 'negatives': '92 sibling vulnerable samples + 8 paired benign samples', 'notes': 'Sibling pool is capped by the batch; 1093 has no usable sample pool.'}
- Best prompt: `p2`
- Dev metric: 44/47 = 93.62%
- Holdout metric: 69/70 = 98.57%
- Main error buckets: {"weaknesscase:benign": 1}

## CWD-1101
- Status: `keep`
- Positive/negative recipe: {'positives': '20 CWD-1101 vulnerable samples (WeaknessCase + selected sample_selection snippets)', 'negatives': '89 sibling vulnerable samples + 12 paired benign samples', 'notes': 'Sibling pool is capped by the batch; 1093 has no usable sample pool.'}
- Best prompt: `p2`
- Dev metric: 47/48 = 97.92%
- Holdout metric: 71/73 = 97.26%
- Main error buckets: {"false_negative_target": 1, "weaknesscase:benign": 1}

## CWD-1115
- Status: `keep`
- Positive/negative recipe: {'positives': '13 CWD-1115 vulnerable samples (WeaknessCase + selected sample_selection snippets)', 'negatives': '96 sibling vulnerable samples + 28 paired benign samples', 'notes': 'Sibling pool is capped by the batch; 1093 has no usable sample pool.'}
- Best prompt: `p1`
- Dev metric: 55/55 = 100.00%
- Holdout metric: 81/82 = 98.78%
- Main error buckets: {"false_negative_target": 1}
