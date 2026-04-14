# Batch A Buffer Summary

All four nodes were evaluated with the same manual binary-node workflow: same-major sibling vulnerable samples as the main negative source, plus major-stage false positives as hard benign when available.

Best prompt version across all four nodes was `v1`; the stricter `v2` variant did not win on dev.

## Results

| Node | Dev | Holdout | Status |
|---|---:|---:|---|
| CWD-1015 | 37.50% | 50.00% | needs_more_iteration |
| CWD-1016 | 37.50% | 43.75% | needs_more_iteration |
| CWD-1028 | 43.75% | 56.25% | needs_more_iteration |
| CWD-1043 | 62.50% | 70.00% | needs_more_iteration |

## Interpretation

- `CWD-1043` is the closest node, but it still stops at 70% holdout.
- `CWD-1015`, `CWD-1016`, and `CWD-1028` are dominated by sibling confusion and target false negatives.
- The hard benign pool is small and the prompt still under-recovers canonical target patterns, so no node is ready to keep.
- This batch is not blocked by a complete lack of samples; it is blocked by boundary quality and recall on the target leaf definitions.

## Next Step

The next iteration should add one or two explicit contrastive examples per node and tighten the positive trigger conditions for the canonical patterns that were missed here.
