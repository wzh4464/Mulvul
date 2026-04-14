# Batch B Pointer Node Evolution

Model: openai/gpt-5.4
Recipe: positive = target node vulnerable samples; negative = same-major sibling vulnerable samples plus paired benign from the target node.
No major-stage FP pool was available in the source data, so paired benign samples were used as the hard-benign slice.
Dataset policy: exact positive/negative code collisions were filtered out before evaluation.

## Node Outcomes
- CWD-1029: needs_more_iteration
  - recipe: Positive: 32 target CWD-1029 vulnerable samples. Negative: 32 total, with 16 sibling vulnerable samples from other batch-B pointer nodes and 16 paired benign samples from the target node. Dev/Holdout split: 16/48. Noise filter: 20 exact label collisions removed.
  - dev acc: 0.750
  - holdout acc: 0.667
  - errors: {'false_negatives': 12, 'fp_sibling_vuln': 1, 'fp_paired_benign': 3, 'fp_other': 0}
  - noise: [{'node': 'CWD-1029', 'sample_idx': 7, 'kind': 'same_sample_identical_vuln_benign'}, {'node': 'CWD-1029', 'sample_idx': 33, 'kind': 'same_sample_identical_vuln_benign'}, {'node': 'CWD-1029', 'sample_idx': 35, 'kind': 'same_sample_identical_vuln_benign'}] ...
- CWD-1030: needs_more_iteration
  - recipe: Positive: 8 target CWD-1030 vulnerable samples. Negative: 8 total, with 4 sibling vulnerable samples from other batch-B pointer nodes and 4 paired benign samples from the target node. Dev/Holdout split: 4/12. Noise filter: 2 exact label collisions removed.
  - dev acc: 0.750
  - holdout acc: 0.583
  - errors: {'false_negatives': 5, 'fp_sibling_vuln': 0, 'fp_paired_benign': 0, 'fp_other': 0}
  - noise: [{'node': 'CWD-1030', 'kind': 'cross_label_collision', 'code_sha1': 'd263957c2b88976690bd7fd6d9b367f412972d95'}, {'node': 'CWD-1030', 'kind': 'cross_label_collision', 'code_sha1': 'd74d16e898ebbcccd9ecebe5fa7e30ce87446262'}]
- CWD-1031: needs_more_iteration
  - recipe: Positive: 48 target CWD-1031 vulnerable samples. Negative: 48 total, with 24 sibling vulnerable samples from other batch-B pointer nodes and 24 paired benign samples from the target node. Dev/Holdout split: 24/72. Noise filter: 6 exact label collisions removed.
  - dev acc: 0.833
  - holdout acc: 0.875
  - errors: {'false_negatives': 6, 'fp_sibling_vuln': 2, 'fp_paired_benign': 1, 'fp_other': 0}
  - noise: [{'node': 'CWD-1031', 'sample_idx': 70, 'kind': 'same_sample_identical_vuln_benign'}, {'node': 'CWD-1031', 'sample_idx': 208, 'kind': 'same_sample_identical_vuln_benign'}, {'node': 'CWD-1031', 'kind': 'cross_label_collision', 'code_sha1': '09f198b464353e11d394d09391787421f6c79c4d'}] ...
- CWD-1034: blocked_by_samples
  - recipe: Positive: 1 target CWD-1034 vulnerable samples. Negative: 201 total, with 200 sibling vulnerable samples from other batch-B pointer nodes and 1 paired benign samples from the target node. Dev/Holdout split: 0/0. Noise filter: 0 exact label collisions removed.
  - metrics: n/a
  - errors: {'false_negatives': [], 'fp_sibling_vuln': [], 'fp_paired_benign': [], 'fp_other': []}
- CWD-1038: needs_more_iteration
  - recipe: Positive: 13 target CWD-1038 vulnerable samples. Negative: 13 total, with 7 sibling vulnerable samples from other batch-B pointer nodes and 6 paired benign samples from the target node. Dev/Holdout split: 7/19. Noise filter: 2 exact label collisions removed.
  - dev acc: 0.857
  - holdout acc: 0.526
  - errors: {'false_negatives': 8, 'fp_sibling_vuln': 0, 'fp_paired_benign': 1, 'fp_other': 0}
  - noise: [{'node': 'CWD-1038', 'sample_idx': 2, 'kind': 'same_sample_identical_vuln_benign'}, {'node': 'CWD-1038', 'kind': 'cross_label_collision', 'code_sha1': '4e5062d85f2e3a5f30313ff9da5dc75b9f9343be'}]
- CWD-1039: blocked_by_samples
  - recipe: Positive: 0 target CWD-1039 vulnerable samples. Negative: 200 total, with 200 sibling vulnerable samples from other batch-B pointer nodes and 0 paired benign samples from the target node. Dev/Holdout split: 0/0. Noise filter: 2 exact label collisions removed.
  - metrics: n/a
  - errors: {'false_negatives': [], 'fp_sibling_vuln': [], 'fp_paired_benign': [], 'fp_other': []}
  - noise: [{'node': 'CWD-1039', 'sample_idx': 0, 'kind': 'same_sample_identical_vuln_benign'}, {'node': 'CWD-1039', 'kind': 'cross_label_collision', 'code_sha1': '4c4ee417f6ab53825b63f14df4b0d66ed5d76857'}]
