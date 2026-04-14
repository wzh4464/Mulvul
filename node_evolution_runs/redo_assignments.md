# CWD Node Redo Assignments

Skill path: `/Users/zihanwu/.codex/skills/evolve-binary-node`

Shared upgrade for this round:
- Read `references/contrastive-prompts.md`
- Absorb the strongest `CWD-1016` lessons:
  - explicit sibling boundaries
  - explicit BENIGN guard patterns
  - target-side vs source-side separation
  - allow nearby caller/context only to recover true size, allocation size, or missing guard provenance
  - use 1-3 short contrastive examples when sibling confusion dominates

Required behavior for every node in this redo:

1. If the node was previously `needs_more_iteration`, rebuild the prompt with stronger contrastive boundaries and re-evaluate.
2. If the node was previously `blocked_by_samples`, first try to expand the sample pool from local sources before keeping the blocked verdict.
3. Search these local sources when sample recovery is needed:
   - `data/enter/cwd_benchmark_2.json`
   - `data/enter/checked_codehub_benchmark.json`
   - `data/enter/CWD-WeaknessCase-master`
   - `data/enter/CWD-Mate-master`
4. Do not overwrite first-round outputs. Write only under the assigned `redo_*` directory.

## Redo A

Output directory: `node_evolution_runs/redo_a_buffer_pointer`

Nodes:
- `CWD-1015`
- `CWD-1016`
- `CWD-1028`
- `CWD-1043`
- `CWD-1029`
- `CWD-1030`
- `CWD-1031`
- `CWD-1038`

## Redo B

Output directory: `node_evolution_runs/redo_b_memory_alloc`

Nodes:
- `CWD-1022`
- `CWD-1023`
- `CWD-1009`
- `CWD-1003`
- `CWD-1017`

## Redo C

Output directory: `node_evolution_runs/redo_c_lowsample_logic`

Nodes:
- `CWD-1005`
- `CWD-1006`
- `CWD-1007`
- `CWD-1008`
- `CWD-1034`
- `CWD-1039`

## Redo D

Output directory: `node_evolution_runs/redo_d_injection_java`

Nodes:
- `CWD-1042`
- `CWD-1071`
- `CWD-1093`

## Required Output

- `summary.md`
- `results.json`

Per node include:
- previous status
- revised positive/negative recipe
- whether extra local samples were recovered
- best prompt
- dev metric
- holdout metric
- main error buckets
- final status
