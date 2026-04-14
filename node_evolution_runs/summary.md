# CWD Binary Node Evolution Summary

Run mode:
- Parallel subagents
- Skill: `/Users/zihanwu/.codex/skills/evolve-binary-node`
- Scope: all currently available CWD binary nodes with local benchmark data
- Status: includes first-pass results plus all redo batches for nodes that did not meet the keep standard

## Global Counts After Redo + Buffer Parent-FP + Pointer Cleaned Reruns

- Total nodes processed: `36`
- `keep`: `19`
- `needs_more_iteration`: `12`
- `blocked_by_samples`: `5`

## Redo Impact

Nodes upgraded to `keep` during redo:
- `CWD-1028`
- `CWD-1006`
- `CWD-1043`
- `CWD-1016`
- `CWD-1029`

Nodes upgraded from `blocked_by_samples` to `needs_more_iteration` after sample recovery:
- `CWD-1003`
- `CWD-1009`
- `CWD-1017`
- `CWD-1034`
- `CWD-1042`

Nodes still `blocked_by_samples` after redo:
- `CWD-1005`
- `CWD-1007`
- `CWD-1008`
- `CWD-1039`
- `CWD-1093`

## Current Status By Family

### Buffer / Bounds

Files:
- `node_evolution_runs/batch_a_buffer/summary.md`
- `node_evolution_runs/redo_a_buffer_pointer/summary.md`
- `node_evolution_runs/rerun_buffer_parentfp/summary.md`
- `node_evolution_runs/rerun_cwd1016_parentfp_expanded/summary.md`

Status:
- `CWD-1015`: `needs_more_iteration`
- `CWD-1016`: `keep`
- `CWD-1028`: `keep`
- `CWD-1043`: `keep`

Notes:
- `CWD-1028` crossed the line on redo with `100%` holdout.
- `CWD-1043` reached `100%` holdout on the parent-FP rerun after adding explicit rules for `map::at(...)`, iterator invalidation after container mutation, and algorithm/iterator-offset overreach such as `begin()+n`.
- `CWD-1016` reached `92.86%` holdout on the expanded parent-FP rerun after two changes: growing the Memory-major false-positive pool to `45` unique samples and removing `4` clearly off-node/noisy positives (`cwd_000069`, `cwd_000097`, `cwd_000132`, `cwd_000144`) from the positive pool.
- `CWD-1016` therefore now qualifies as `keep`, but this should be read as a cleaned-node result rather than an unqualified raw-dataset win.

### Pointer / Access

Files:
- `node_evolution_runs/batch_b_pointer/summary.md`
- `node_evolution_runs/redo_a_buffer_pointer/summary.md`
- `node_evolution_runs/redo_c_lowsample_logic/summary.md`
- `node_evolution_runs/rerun_cwd1029_cleaned_parallel/summary.md`

Status:
- `CWD-1029`: `keep`
- `CWD-1030`: `needs_more_iteration`
- `CWD-1031`: `needs_more_iteration`
- `CWD-1034`: `needs_more_iteration`
- `CWD-1038`: `needs_more_iteration`
- `CWD-1039`: `blocked_by_samples`

Notes:
- `CWD-1029` reached `91.30%` holdout on a cleaned-node rerun after two data fixes: removing `cwd_000824::vuln` from the positive pool as an off-node / visibly guarded sample, and filtering known mislabeled Memory-major false positives `14/34/72/75/97` out of the hard-benign pool.
- `CWD-1029` therefore now qualifies as `keep`, but this should be read as a cleaned-node result rather than an unqualified raw-dataset win.
- `CWD-1031` showed high recipe instability: earlier run hit `87.5%`, redo dropped to `68.75%`.

### Memory Management

Files:
- `node_evolution_runs/batch_c_memory_mgmt/summary.md`
- `node_evolution_runs/redo_b_memory_alloc/summary.md`

Status:
- `CWD-1002`: `keep`
- `CWD-1003`: `needs_more_iteration`
- `CWD-1009`: `needs_more_iteration`
- `CWD-1017`: `needs_more_iteration`
- `CWD-1019`: `keep`
- `CWD-1021`: `keep`
- `CWD-1022`: `needs_more_iteration`
- `CWD-1023`: `needs_more_iteration`
- `CWD-1025`: `keep`
- `CWD-1026`: `keep`
- `CWD-1027`: `keep`
- `CWD-1040`: `keep`

Notes:
- This remains the strongest family overall.
- `CWD-1021`, `CWD-1025`, and `CWD-1040` achieved `100%` holdout in the first pass.
- Recovered-sample redo showed that `CWD-1003`, `CWD-1009`, and `CWD-1017` are not strictly sample-blocked anymore, but the recovered pools introduce heavy sibling confusion.
- `CWD-1022` and `CWD-1023` remain well below standard even after adding WeaknessCase samples.

### Low-Sample Logic / Layout

Files:
- `node_evolution_runs/batch_d_low_sample/summary.md`
- `node_evolution_runs/redo_c_lowsample_logic/summary.md`

Status:
- `CWD-1005`: `blocked_by_samples`
- `CWD-1006`: `keep`
- `CWD-1007`: `blocked_by_samples`
- `CWD-1008`: `blocked_by_samples`

Notes:
- `CWD-1006` became viable after recovery and contrastive prompting, reaching `100%` holdout.
- `CWD-1005`, `CWD-1007`, and `CWD-1008` still do not have enough usable local positives for a stable binary node.

### Java / Injection

Files:
- `node_evolution_runs/batch_e_java/summary.md`
- `node_evolution_runs/redo_d_injection_java/summary.md`

Status:
- `CWD-1042`: `needs_more_iteration`
- `CWD-1068`: `keep`
- `CWD-1070`: `keep`
- `CWD-1071`: `needs_more_iteration`
- `CWD-1081`: `keep`
- `CWD-1084`: `keep`
- `CWD-1093`: `blocked_by_samples`
- `CWD-1096`: `keep`
- `CWD-1101`: `keep`
- `CWD-1115`: `keep`

Notes:
- Java remains the second-strongest family.
- `CWD-1071` did not improve enough on redo and is still only `68.09%` holdout.
- `CWD-1042` moved from blocked to iteratable after recovery, but current boundary quality is still weak.
- `CWD-1093` remains structurally underpowered with only `2` vulnerable + `2` benign local target snippets, and no WeaknessCase/codehub code pool to expand it further.

## Current Priorities

If continuing from here, the highest-value nodes are:

1. `CWD-1015`
2. `CWD-1071`
3. `CWD-1031`
4. `CWD-1042`
5. `CWD-1030`

Nodes currently best treated as data-blocked rather than prompt-limited:

- `CWD-1005`
- `CWD-1007`
- `CWD-1008`
- `CWD-1039`
- `CWD-1093`
