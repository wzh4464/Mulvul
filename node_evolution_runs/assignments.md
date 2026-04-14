# CWD Node Evolution Assignments

Skill path: `/Users/zihanwu/.codex/skills/evolve-binary-node`

## Batch A

Output directory: `node_evolution_runs/batch_a_buffer`

Nodes:
- `CWD-1015`
- `CWD-1016`
- `CWD-1028`
- `CWD-1043`

## Batch B

Output directory: `node_evolution_runs/batch_b_pointer`

Nodes:
- `CWD-1029`
- `CWD-1030`
- `CWD-1031`
- `CWD-1034`
- `CWD-1038`
- `CWD-1039`

## Batch C

Output directory: `node_evolution_runs/batch_c_memory_mgmt`

Nodes:
- `CWD-1002`
- `CWD-1009`
- `CWD-1019`
- `CWD-1021`
- `CWD-1025`
- `CWD-1026`
- `CWD-1027`
- `CWD-1040`

## Batch D

Output directory: `node_evolution_runs/batch_d_low_sample`

Nodes:
- `CWD-1003`
- `CWD-1005`
- `CWD-1006`
- `CWD-1007`
- `CWD-1008`
- `CWD-1017`
- `CWD-1022`
- `CWD-1023`
- `CWD-1042`

## Batch E

Output directory: `node_evolution_runs/batch_e_java`

Nodes:
- `CWD-1068`
- `CWD-1070`
- `CWD-1071`
- `CWD-1081`
- `CWD-1084`
- `CWD-1093`
- `CWD-1096`
- `CWD-1101`
- `CWD-1115`

## Required Output Per Batch

- `summary.md`: one consolidated write-up for the batch
- `results.json`: per-node structured results

Each node entry should include:
- positive/negative recipe
- best prompt
- dev metric
- holdout metric
- main error buckets
- status: `keep`, `blocked_by_noise`, `blocked_by_samples`, or `needs_more_iteration`
