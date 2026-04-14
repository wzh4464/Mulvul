# Blocked Sample Recovery Audit

Scope: local sources only (`cwd_benchmark_2`, `CWD-WeaknessCase-master`).

## CWD-1005
- Unique benchmark positives: `1`
- Unique benchmark benigns: `1`
- WeaknessCase code files: `2`
- Duplicate labeled groups in benchmark snippets: `0`
- Recovery verdict: `local unique code is effectively exhausted; current redo already used the available pair-style WeaknessCase material`
- WeaknessCase files:
  - `/Users/zihanwu/Public/codes/Mulvul/data/enter/CWD-WeaknessCase-master/C/CWD-1005/CWD-1005-001/incorrect_struct_byte_order_01/incorrect_struct_byte_order_01.c`
  - `/Users/zihanwu/Public/codes/Mulvul/data/enter/CWD-WeaknessCase-master/CPP/CWD-1005/CWD-1005-001/incorrect_struct_byte_order_01/incorrect_struct_byte_order_01.cpp`

## CWD-1007
- Unique benchmark positives: `1`
- Unique benchmark benigns: `1`
- WeaknessCase code files: `1`
- Duplicate labeled groups in benchmark snippets: `0`
- Recovery verdict: `local unique code is exhausted; only one WeaknessCase file exists and it is already represented in the recovered pool`
- WeaknessCase files:
  - `/Users/zihanwu/Public/codes/Mulvul/data/enter/CWD-WeaknessCase-master/CPP/CWD-1007/CWD-1007-001/bit_by_bit_copy_classObj_with_virFunc/bit_by_bit_copy_classObj_with_virFunc.cpp`

## CWD-1008
- Unique benchmark positives: `1`
- Unique benchmark benigns: `1`
- WeaknessCase code files: `1`
- Duplicate labeled groups in benchmark snippets: `0`
- Recovery verdict: `local unique code is exhausted; only one WeaknessCase file exists and it is already represented in the recovered pool`
- WeaknessCase files:
  - `/Users/zihanwu/Public/codes/Mulvul/data/enter/CWD-WeaknessCase-master/CPP/CWD-1008/CWD-1008-001/using_std-vector-bool_type_obj_error/using_std-vector-bool_type_obj_error.cpp`

## CWD-1039
- Unique benchmark positives: `1`
- Unique benchmark benigns: `1`
- WeaknessCase code files: `2`
- Duplicate labeled groups in benchmark snippets: `0`
- Recovery verdict: `local unique code is effectively exhausted; redo already consumed the native pair plus the two WeaknessCase files`
- WeaknessCase files:
  - `/Users/zihanwu/Public/codes/Mulvul/data/enter/CWD-WeaknessCase-master/C/CWD-1039/CWD-1039-001/cast_ptr_to_int_data_truncation_01/cast_ptr_to_int_data_truncation_01.c`
  - `/Users/zihanwu/Public/codes/Mulvul/data/enter/CWD-WeaknessCase-master/CPP/CWD-1039/CWD-1039-001/cast_uintptr_t_to_struct_ptr_without_length_check_01/cast_uintptr_t_to_struct_ptr.cpp`

## CWD-1093
- Unique benchmark positives: `2`
- Unique benchmark benigns: `2`
- WeaknessCase code files: `0`
- Duplicate labeled groups in benchmark snippets: `0`
- Recovery verdict: `one extra benign is recoverable relative to the previous redo summary, but the node still only has a 2 vuln + 2 benign target pool and remains structurally underpowered`
