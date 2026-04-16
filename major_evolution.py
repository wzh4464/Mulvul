#!/usr/bin/env python3
"""
Per-major binary prompt evolution.

For each major category (Memory, Injection, Logic, Input, Crypto),
evolves a binary prompt that classifies whether code belongs to that major.

Dataset construction per major M:
  Positive (VULNERABLE): all vulnerable samples whose CWD maps to M
  Negative (BENIGN):     equal-count mix of benign + other-major vuln samples

Goal: cascade accuracy >= 80%

Usage:
    uv run python major_evolution.py                        # all majors, all rounds
    uv run python major_evolution.py --major Memory         # single major
    uv run python major_evolution.py --round 1 --major Memory  # specific round
"""
import argparse
import asyncio
import json
import os
import random
import re
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    from openai import AsyncOpenAI
    HAS_ASYNC_OPENAI = True
except ImportError:
    HAS_ASYNC_OPENAI = False

# ── Config ─────────────────────────────────────────────────────────────────────
SEED = 42
RAW_DATA = "/Users/zihanwu/Public/codes/Mulvul/data/enter/cwd_benchmark_2.json"
RESULTS_DIR = "major_evolution_results"
CODE_LIMIT = 8000       # large - do not truncate
CONCURRENCY = 10
MAX_TOKENS = 800
PER_CWD = 5            # max samples per CWD per class (positive/negative)

# ── CWD-to-Major mapping (manually corrected) ──────────────────────────────────
CWD_TO_MAJOR: Dict[str, str] = {
    # Memory: buffer/heap/pointer issues
    "CWD-1002": "Memory",   # 内存分配大小未受限
    "CWD-1003": "Memory",   # 缓冲区大小计算错误
    "CWD-1007": "Memory",   # 不正确的逐位操作 (corrupts object memory layout)
    "CWD-1009": "Memory",   # 未受认可的内存安全函数
    "CWD-1015": "Memory",   # 内存操作函数的源缓冲区访问长度不正确
    "CWD-1016": "Memory",   # 内存操作函数的目的缓冲区访问长度不正确
    "CWD-1017": "Memory",   # 内存拷贝重叠
    "CWD-1019": "Memory",   # 返回栈变量地址
    "CWD-1021": "Memory",   # 释放非堆内存
    "CWD-1022": "Memory",   # 内存申请和释放函数未配对
    "CWD-1023": "Memory",   # 释放未在缓冲区起始处的指针
    "CWD-1025": "Memory",   # 双重释放内存
    "CWD-1026": "Memory",   # 访问已释放内存
    "CWD-1027": "Memory",   # 内存泄漏
    "CWD-1028": "Memory",   # 数组索引越界
    "CWD-1029": "Memory",   # 指针偏移量超出范围
    "CWD-1030": "Memory",   # 访问未初始化的指针
    "CWD-1031": "Memory",   # 空指针解引用
    "CWD-1034": "Memory",   # 不受信任的指针解引用
    "CWD-1043": "Memory",   # 容器访问越界
    # Logic: platform/behavioral/format issues
    "CWD-1005": "Logic",    # 不正确的字节序
    "CWD-1006": "Logic",    # 依赖带位域的结构体内存布局
    "CWD-1008": "Logic",    # std::vector<bool> 内存布局不兼容
    # Input: type confusion and input validation
    "CWD-1038": "Input",    # 不同类型的对象指针之间转换错误
    "CWD-1039": "Input",    # 指针与非指针类型之间转换错误
    "CWD-1040": "Input",    # 不正确的null结束符
    # Injection: all injection types
    "CWD-1042": "Injection", # 未受控的格式化字符串
    "CWD-1068": "Injection", # OS命令注入
    "CWD-1070": "Injection", # 正则表达式注入
    "CWD-1071": "Injection", # 表达式语言注入
    "CWD-1081": "Injection", # XML注入
    "CWD-1082": "Injection", # XPath注入 (0 samples)
    "CWD-1084": "Injection", # XSLT注入
    "CWD-1093": "Injection", # JNDI注入
    "CWD-1096": "Injection", # 模板注入
    "CWD-1101": "Injection", # SQL注入
    "CWD-1113": "Injection", # CSV注入 (0 samples)
    "CWD-1114": "Injection", # XML外部实体攻击（XXE）(0 samples)
    "CWD-1115": "Injection", # XML内部实体扩展（XEE）
}

MAJORS = ["Memory", "Injection", "Logic", "Input", "Crypto"]

# ── Initial prompts per major ───────────────────────────────────────────────────
PROMPTS: Dict[str, Dict[int, str]] = {

"Memory": {
1: """\
You are a memory-safety vulnerability detector specialized in C/C++.

Determine whether the TARGET (TGT) function contains a MEMORY SAFETY vulnerability.

Memory safety vulnerabilities include:
- Buffer overflow / out-of-bounds read or write
- Use-after-free: accessing heap memory after free()
- Double-free: calling free() twice on the same pointer
- Memory leak: heap allocation not freed on ALL non-failure return paths
- Null-pointer or uninitialized-pointer dereference
- Dangling pointer: returning or storing address of a local variable
- Invalid free: calling free() on non-heap or non-start-of-buffer pointer
- Overlapping memcpy/memmove source and destination
- Integer overflow/underflow in size calculation leading to wrong allocation

Rules:
1. Ignore test-harness naming: TGT function name, even if it contains "Bad", "Unsafe",
   "without", "withoutCheck" — these are BENCHMARK LABELS, not evidence.
2. If the TGT function always frees/releases every allocation it makes (using free, delete,
   Free*, Release*, Delete* patterns), or always returns the pointer to the caller — BENIGN.
3. A return immediately after a malloc/new NULL check (allocation failure path) is OK.

CODE:
```c
{code}
```

Respond with JSON only:
{{"prediction": "VULNERABLE", "confidence": 0.9}}
or
{{"prediction": "BENIGN", "confidence": 0.8}}""",

2: """\
You are a memory-safety vulnerability detector specialized in C/C++ and Java.

Determine whether the TARGET (TGT) function contains a MEMORY SAFETY vulnerability.

Memory safety vulnerabilities include:
- Buffer overflow / out-of-bounds read or write (using index or offset beyond buffer size)
- Use-after-free: accessing heap memory AFTER free()/delete — look for free() before a
  later use of the same pointer in a non-error flow
- Double-free: free() called twice on the same pointer
- Memory leak: malloc/new allocation that has NO corresponding free/delete/Free*/Release*
  on at least one return path that is NOT a malloc-failure NULL-check guard
- Null-pointer dereference: pointer used without a NULL check where NULL is possible
- Uninitialized-pointer: pointer declared but never assigned before use (e.g., declared as
  `char *p;` then used as `p[0]` without going through a valid assignment first)
- Dangling pointer: return of local variable's address; pointer to stack/temp object stored
- Invalid free: free() on local array, global array, mid-buffer pointer, or already-freed ptr
- securec function misuse: memcpy_s(dest, SIZE, src, COUNT) where SIZE does not reflect the
  actual destination buffer capacity — e.g., passing COUNT again instead of true dest size
- Overlapping regions in memcpy (not memmove)
- Container/array access with unvalidated index

Rules:
1. TGT function name — "Bad", "Unsafe", "without*" — is a benchmark label, NOT evidence.
2. free/delete/Free*/Release*/Delete* variants ALL count as valid deallocation.
3. Immediate return AFTER a malloc NULL check (failure guard) is OK, not a memory leak.
4. Bitfield layout / byte order / vector<bool> → NOT this detector (those are Logic).
5. Pointer type casts / null terminator → NOT this detector (those are Input).
6. Standard allocation helpers (malloc_wrapper, calloc, new[]) count the same as malloc/new.

Analyze systematically: (a) trace each allocation to its deallocation, (b) check if any
pointer is used after free or before initialization, (c) verify size arguments.

CODE:
```c
{code}
```

Respond with JSON only:
{{"prediction": "VULNERABLE", "confidence": 0.9}}
or
{{"prediction": "BENIGN", "confidence": 0.8}}""",

3: """\
You are a memory-safety vulnerability detector specialized in C/C++ and Java.

Determine whether the TARGET (TGT) function contains a MEMORY SAFETY vulnerability.

Analyze in 3 steps, then give your answer:

STEP 1 — IDENTIFY ALLOCATIONS
List every heap allocation (malloc, calloc, new, Create*) in TGT.
For each, note: variable name, allocation site line/pattern.

STEP 2 — TRACE FREES
For each allocation, trace ALL return paths. Note where free/delete/Free*/Release* occurs.
Flag: any path that reaches a return without freeing (excluding malloc-failure NULL returns).
Also flag: any use of the pointer AFTER a free on any path.

STEP 3 — CHECK OTHER PATTERNS
- Double-free: same pointer freed twice?
- Dangling: local address returned or stored?
- Uninit: pointer used before first assignment?
- securec misuse: memcpy_s/strcpy_s SIZE arg ≠ dest buffer capacity?
- Bounds: array index provably out of range?
- Container: vector/deque index unchecked?

RULES:
- TGT function name is a benchmark label, NOT vulnerability evidence.
- free/delete/Free*/Release*/Delete* all count as valid deallocation.
- Immediate return after NULL check on just-allocated pointer = OK (malloc failure guard).

After your analysis, respond with JSON on the LAST line:
{{"prediction": "VULNERABLE", "confidence": 0.9}}
or
{{"prediction": "BENIGN", "confidence": 0.8}}

CODE:
```c
{code}
```""",

4: """\
You are a memory-safety vulnerability detector specialized in C/C++ and Java.

Determine whether the TARGET (TGT) function contains a MEMORY SAFETY vulnerability.

Memory safety vulnerabilities include:
- Buffer overflow / out-of-bounds read or write
- Use-after-free: accessing heap memory after free()
- Double-free: calling free() twice on the same pointer
- Memory leak: heap allocation not freed on ALL non-failure return paths
- Null-pointer or uninitialized-pointer dereference
- Dangling pointer: returning or storing address of a local variable
- Invalid free: calling free() on non-heap or non-start-of-buffer pointer
- Overlapping memcpy/memmove source and destination
- Integer overflow/underflow in size calculation leading to wrong allocation
- securec/safe-function wrapper misuse: custom macro or wrapper that calls memcpy_s/
  strcpy_s/memmove_s with incorrect destination size parameter

Rules:
1. TGT function name — "Bad", "Unsafe", "without*" — is a BENCHMARK LABEL, not evidence.
2. ALL context function names (BadCase, GoodCase, BadCaseFunc, GoodCaseFunc, BadCaseX,
   GoodCaseX, etc.) are test-harness labels. IGNORE them entirely.
3. free/delete/Free*/Release*/Delete* all count as valid deallocation.
4. Immediate return after NULL check on just-allocated pointer = OK (malloc failure guard).
5. If all allocations in TGT are freed or returned to caller on every reachable path → BENIGN.
6. Analyze the TGT function ONLY. Do not attribute BadCase/GoodCase behavior to TGT.

CODE:
```c
{code}
```

Respond with JSON only:
{{"prediction": "VULNERABLE", "confidence": 0.9}}
or
{{"prediction": "BENIGN", "confidence": 0.8}}""",

5: """\
You are a memory-safety vulnerability detector specialized in C/C++.

Determine whether the TARGET (TGT) function contains a MEMORY SAFETY vulnerability.

Memory safety vulnerabilities — look for ALL of these:
A. BUFFER OVERFLOW: writing/reading beyond array/buffer boundaries; index ≥ array_size.
B. USE-AFTER-FREE: a pointer is passed to free() or delete[], then accessed again on
   any return path — including through intermediate variables or function calls that
   receive the same pointer.
C. DOUBLE-FREE: free() or delete called twice on the same pointer on any path.
D. MEMORY LEAK: malloc/calloc/new returns a valid pointer, but there is a return path
   from TGT where that pointer is never freed/deleted/Released — EXCEPT paths that
   return immediately after a NULL-check failure on the just-allocated pointer.
E. UNINIT POINTER: a pointer variable is declared (e.g. `T *p;`) and dereferenced or
   returned without being assigned to a valid address on all paths.
F. DANGLING POINTER: TGT returns the address of a local/stack variable.
G. INVALID FREE: free() applied to non-heap memory (stack array, global, or an interior
   pointer not at the start of the allocation).
H. SECUREC WRAPPER MISUSE: a #define macro or inline wrapper calls memcpy_s/strcpy_s
   with the SAME value for both destination-capacity and copy-count, ignoring the
   actual destination buffer size. Pattern: `memcpy_s(dst, count, src, count)` instead
   of `memcpy_s(dst, dst_capacity, src, count)`.
I. OVERLAPPING MEMCPY: source and destination overlap in a memcpy call (not memmove).
J. INTEGER OVERFLOW → WRONG ALLOC SIZE: arithmetic on allocation size that can overflow.

Exclusions (do NOT flag):
- Bitfield layout, byte order, vector<bool> issues → not Memory
- Pointer type casts, null terminator issues → not Memory
- TGT function name / context function names (BadCase, GoodCase) → IGNORE

Rules:
1. free/delete/Free*/Release*/Delete* all count as valid deallocation.
2. malloc-failure guard: a return right after `if (ptr == NULL) return ...` is NOT a leak.
3. Functions that merely USE an external pointer (don't allocate it) cannot leak it.

CODE:
```c
{code}
```

Respond with JSON only:
{{"prediction": "VULNERABLE", "confidence": 0.9}}
or
{{"prediction": "BENIGN", "confidence": 0.8}}""",

6: """\
You are a memory-safety vulnerability detector specialized in C/C++.

Determine whether the TARGET (TGT) function contains a MEMORY SAFETY vulnerability.

Memory safety vulnerabilities include:
- Buffer overflow / out-of-bounds read or write
- Use-after-free: accessing heap memory after free()
- Double-free: calling free() twice on the same pointer
- Memory leak: heap allocation not freed on ALL non-failure return paths
- Null-pointer or uninitialized-pointer dereference
- Dangling pointer: returning or storing address of a local variable;
  OR a global/class-level pointer that is deleted/freed but NOT immediately set
  to nullptr/NULL within the same function (dangling global pointer)
- Invalid free: calling free() on non-heap or non-start-of-buffer pointer
- Overlapping memcpy/memmove source and destination
- Integer overflow/underflow in size calculation leading to wrong allocation
- securec wrapper misuse: a macro or wrapper that expands to
  memcpy_s(dst, N, src, N) where N is the copy-count — passing the SAME value
  for both destination-capacity and copy-count means the real dest buffer size
  is ignored; flag if the macro/wrapper uses a single size parameter for both

Rules:
1. BENCHMARK LABEL RULE: The TGT function name is a benchmark label, NOT evidence.
   This applies regardless of what the name says — even if it contains "doublefree",
   "uaf", "leak", "nullptr", "Bad", "Unsafe", "without" — IGNORE it entirely.
   The SAME applies to all context-level function names (BadCase, GoodCase, etc.).
2. DOUBLE-FREE PATH RULE: Double-free means the SAME pointer is freed TWICE on a
   SINGLE execution path. Two free() calls on MUTUALLY EXCLUSIVE control-flow paths
   (e.g., error-return path frees once; normal-return path frees once) is NOT
   double-free — that is correct resource cleanup.
3. free/delete/Free*/Release*/Delete* variants ALL count as valid deallocation.
4. Immediate return after a malloc NULL check (allocation failure guard) is OK — not a leak.
5. Bitfield layout, byte order, vector<bool> → NOT Memory (those are Logic).
6. Pointer type casts, null terminator issues → NOT Memory (those are Input).

CODE:
```c
{code}
```

Respond with JSON only:
{{"prediction": "VULNERABLE", "confidence": 0.9}}
or
{{"prediction": "BENIGN", "confidence": 0.8}}""",

7: """\
You are a memory-safety vulnerability detector specialized in C/C++.

Determine whether the TARGET (TGT) function contains a MEMORY SAFETY vulnerability.

Memory safety vulnerabilities include:
- Buffer overflow / out-of-bounds read or write
- Use-after-free: accessing heap memory after free()
- Double-free: calling free() twice on the same pointer on any single execution path
- Memory leak: heap allocation not freed on ALL non-failure return paths
- Null-pointer or uninitialized-pointer dereference
- Dangling pointer: returning or storing address of a local variable;
  also a global or class-member pointer that is deleted/freed without being set
  to nullptr/NULL afterward — callers may still access it
- Invalid free: calling free() on non-heap or non-start-of-buffer pointer
- Overlapping memcpy/memmove source and destination
- Integer overflow/underflow in size calculation leading to wrong allocation

Rules:
1. Ignore test-harness naming: TGT function name, even if it contains "Bad", "Unsafe",
   "without", "withoutCheck", "doublefree", "uaf", "leak", "nullptr" — these are
   BENCHMARK LABELS, not evidence. Same for context names (BadCase, GoodCase, etc.).
2. DOUBLE-FREE REQUIRES SAME PATH: Two free() calls on MUTUALLY EXCLUSIVE paths
   (error-path frees once AND success-path frees once) is correct cleanup, NOT double-free.
   Double-free only occurs when the SAME pointer is freed twice on ONE execution path.
3. If the TGT function always frees/releases every allocation it makes (using free, delete,
   Free*, Release*, Delete* patterns), or always returns the pointer to the caller — BENIGN.
4. A return immediately after a malloc/new NULL check (allocation failure path) is OK.

CODE:
```c
{code}
```

Respond with JSON only:
{{"prediction": "VULNERABLE", "confidence": 0.9}}
or
{{"prediction": "BENIGN", "confidence": 0.8}}""",

8: """\
You are a memory-safety vulnerability detector specialized in C/C++.

Determine whether the TARGET (TGT) function contains a MEMORY SAFETY vulnerability.

Memory safety vulnerabilities include:
- Buffer overflow / out-of-bounds read or write
- Use-after-free: accessing heap memory after free()
- Double-free: calling free() twice on the same pointer
- Memory leak: heap allocation not freed on ALL non-failure return paths
- Null-pointer or uninitialized-pointer dereference
- Dangling pointer: returning or storing address of a local variable;
  also a global/class-member pointer deleted/freed without being set to nullptr
- Invalid free: calling free() on non-heap or non-start-of-buffer pointer
- Overlapping memcpy source and destination
- Integer overflow in allocation size
- securec wrapper misuse: macro/wrapper that calls memcpy_s with the SAME value
  for both destination-capacity (arg 2) and copy-count (arg 4)

Rules:
1. TGT function name — even "doublefree", "uaf", "leak", "Bad", "Unsafe", "without" —
   is a BENCHMARK LABEL. IGNORE IT. Same for BadCase/GoodCase context names.
2. Double-free requires the SAME pointer freed TWICE on ONE execution path.
   Two free() calls on mutually exclusive paths (error vs success) is NOT double-free.
3. free/delete/Free*/Release*/Delete* all count as valid deallocation.
4. Immediate return after malloc NULL check = OK (not a leak).

{few_shot}
CODE:
```c
{code}
```

Respond with JSON only:
{{"prediction": "VULNERABLE", "confidence": 0.9}}
or
{{"prediction": "BENIGN", "confidence": 0.8}}""",

9: """\
You are a memory-safety vulnerability detector specialized in C/C++.

Determine whether the TARGET (TGT) function contains a MEMORY SAFETY vulnerability.

Memory safety vulnerabilities include:
- Buffer overflow / out-of-bounds read or write
- Use-after-free: accessing heap memory after free()
- Double-free: calling free() twice on the same pointer
- Memory leak: heap allocation not freed on ALL non-failure return paths
- Null-pointer or uninitialized-pointer dereference
- Dangling pointer: returning or storing address of a local variable
- Invalid free: calling free() on non-heap or non-start-of-buffer pointer
- Overlapping memcpy/memmove source and destination
- Integer overflow/underflow in size calculation leading to wrong allocation
- Uncontrolled allocation size: malloc/new/vector::resize/container::reserve
  called with a user-controlled parameter that has no upper-bound check — even
  if a zero-check exists.  A check like `if (n == 0) return` does NOT guarantee
  safety; the parameter could still be arbitrarily large.
- Missing container size limit: the context defines a maximum-size constant
  (e.g. MAX_COUNT, MAX_SIZE, MAX_CONTAINER_SIZE) but the TGT function inserts
  into the container (push_back, insert, emplace_back, operator[]) without
  checking that the container has not exceeded that limit.

Rules:
1. Ignore test-harness naming: TGT function name, even if it contains "Bad", "Unsafe",
   "without", "withoutCheck" — these are BENCHMARK LABELS, not evidence.
2. If the TGT function always frees/releases every allocation it makes (using free, delete,
   Free*, Release*, Delete* patterns), or always returns the pointer to the caller — BENIGN.
3. A return immediately after a malloc/new NULL check (allocation failure path) is OK.

CODE:
```c
{code}
```

Respond with JSON only:
{{"prediction": "VULNERABLE", "confidence": 0.9}}
or
{{"prediction": "BENIGN", "confidence": 0.8}}""",

10: """\
You are a memory-safety vulnerability detector specialized in C/C++.

Determine whether the TARGET (TGT) function contains a MEMORY SAFETY vulnerability.

Memory safety vulnerabilities include:
- Buffer overflow / out-of-bounds read or write
- Use-after-free: accessing heap memory after free()
- Double-free: calling free() twice on the same pointer
- Memory leak: heap allocation not freed on ALL non-failure return paths
- Null-pointer or uninitialized-pointer dereference
- Dangling pointer: returning or storing address of a local variable
- Invalid free: calling free() on non-heap or non-start-of-buffer pointer
- Overlapping memcpy/memmove source and destination
- Integer overflow/underflow in size calculation leading to wrong allocation
- Uncontrolled allocation size: malloc/new/vector::resize/container::reserve
  is called with a SIZE that comes from an EXTERNAL source (function parameter,
  deserialized field, network/socket read, user request count) AND the only guard
  before that call is a zero/null check — no upper-bound check like
  `if (n > MAX_SIZE) return/error`.  Do NOT flag if the size is computed internally
  from a bounded expression or a constant.
- Missing container size limit: ALL THREE conditions must hold simultaneously:
  (a) the context defines a named capacity constant that is clearly the MAXIMUM
      ELEMENT COUNT for a specific container (e.g. `MAX_ITEMS`, `MAX_CONTAINER_SIZE`);
  (b) the TGT function appends to that specific container (push_back, insert,
      emplace_back, emplace) without first checking `container.size() < MAX_*`;
  (c) the constant is NEVER used anywhere in TGT (proving it is intentionally ignored).
  Do NOT flag if the constant relates to string length, buffer bytes, or is used
  elsewhere in TGT (even in a different context).

Rules:
1. Ignore test-harness naming: TGT function name, even if it contains "Bad", "Unsafe",
   "without", "withoutCheck" — these are BENCHMARK LABELS, not evidence.
2. If the TGT function always frees/releases every allocation it makes (using free, delete,
   Free*, Release*, Delete* patterns), or always returns the pointer to the caller — BENIGN.
3. A return immediately after a malloc/new NULL check (allocation failure path) is OK.

CODE:
```c
{code}
```

Respond with JSON only:
{{"prediction": "VULNERABLE", "confidence": 0.9}}
or
{{"prediction": "BENIGN", "confidence": 0.8}}""",

11: """\
You are a memory-safety vulnerability detector specialized in C/C++.

Determine whether the TARGET (TGT) function contains a MEMORY SAFETY vulnerability.

Memory safety vulnerabilities include:
- Buffer overflow / out-of-bounds read or write
- Use-after-free: accessing heap memory after free()
- Double-free: calling free() twice on the same pointer
- Memory leak: heap allocation not freed on ALL non-failure return paths
- Null-pointer or uninitialized-pointer dereference
- Dangling pointer: returning or storing address of a local variable
- Invalid free: calling free() on non-heap or non-start-of-buffer pointer
- Overlapping memcpy/memmove source and destination
- Integer overflow/underflow in size calculation leading to wrong allocation
- securec wrapper misuse: a #define macro or inline wrapper calls memcpy_s/strcpy_s
  with the SAME value for both destination-capacity (arg 2) and copy-count (arg 4),
  ignoring the actual destination buffer size.
  Pattern: `memcpy_s(dst, count, src, count)` or `SAFE_MEMCPY_S(dst, src, count)`
  expanding to `memcpy_s(dst, count, src, count)` — flag this, it is a bug.
  Correct form: `memcpy_s(dst, sizeof(dst_buf), src, count)` where arg 2 ≠ arg 4.
- Uncontrolled allocation size: malloc/new/vector::resize/container::reserve
  is called with a SIZE that comes from an EXTERNAL source (function parameter,
  deserialized field, network/socket read, user request count) AND the only guard
  before that call is a zero/null check — no upper-bound check like
  `if (n > MAX_SIZE) return/error`.  Do NOT flag if the size is computed internally
  from a bounded expression or a constant.
- Missing container size limit: ALL THREE conditions must hold simultaneously:
  (a) the context defines a named capacity constant that is clearly the MAXIMUM
      ELEMENT COUNT for a specific container (e.g. `MAX_ITEMS`, `MAX_CONTAINER_SIZE`);
  (b) the TGT function appends to that specific container (push_back, insert,
      emplace_back, emplace) without first checking `container.size() < MAX_*`;
  (c) the constant is NEVER used anywhere in TGT (proving it is intentionally ignored).
  Do NOT flag if the constant relates to string length, buffer bytes, or is used
  elsewhere in TGT (even in a different context).

Rules:
1. Ignore test-harness naming: TGT function name, even if it contains "Bad", "Unsafe",
   "without", "withoutCheck" — these are BENCHMARK LABELS, not evidence.
   The surrounding context may also contain functions named *Bad*, *Good*, *withoutCheck*,
   *WithCheck*, *Validate*Bad*, *Validate*Good* — these are comparison variants in the
   same test file, NOT the function under analysis. Evaluate ONLY the TGT function's
   logic, regardless of what the context functions are named.
2. If the TGT function always frees/releases every allocation it makes (using free, delete,
   Free*, Release*, Delete* patterns), or always returns the pointer to the caller — BENIGN.
3. A return immediately after a malloc/new NULL check (allocation failure path) is OK.
4. securec memset_s correct usage: `memset_s(dst, sizeof(T), 0, sizeof(T))` where both
   size args equal sizeof(target) is the CORRECT way to zero a struct — NOT a vulnerability.
   The arg2==arg4 misuse rule applies ONLY to memcpy_s and strcpy_s, not to memset_s.

CODE:
```c
{code}
```

Respond with JSON only:
{{"prediction": "VULNERABLE", "confidence": 0.9}}
or
{{"prediction": "BENIGN", "confidence": 0.8}}""",

12: """\
You are a memory-safety vulnerability detector specialized in C/C++.

Determine whether the TARGET (TGT) function contains a MEMORY SAFETY vulnerability.

Memory safety vulnerabilities include:
- Buffer overflow / out-of-bounds read or write
- Use-after-free: accessing heap memory after free()
- Double-free: calling free() twice on the same pointer
- Memory leak: heap allocation not freed on ALL non-failure return paths
- Null-pointer or uninitialized-pointer dereference
- Dangling pointer: returning or storing address of a local variable
- Invalid free: calling free() on non-heap or non-start-of-buffer pointer
- Overlapping memcpy/memmove source and destination
- Integer overflow/underflow in size calculation leading to wrong allocation
- securec wrapper misuse: a #define macro or inline wrapper calls memcpy_s/strcpy_s
  with the SAME value for both destination-capacity (arg 2) and copy-count (arg 4),
  ignoring the actual destination buffer size.
  Pattern: `memcpy_s(dst, count, src, count)` or `SAFE_MEMCPY_S(dst, src, count)`
  expanding to `memcpy_s(dst, count, src, count)` — flag this, it is a bug.
  Correct form: `memcpy_s(dst, sizeof(dst_buf), src, count)` where arg 2 ≠ arg 4.
- Uncontrolled allocation size: malloc/new/vector::resize/container::reserve
  is called with a SIZE that comes from an EXTERNAL source (function parameter,
  deserialized field, network/socket read, user request count) AND the only guard
  before that call is a zero/null check — no upper-bound check like
  `if (n > MAX_SIZE) return/error`.  Do NOT flag if the size is computed internally
  from a bounded expression or a constant.
- Missing container size limit: ALL THREE conditions must hold simultaneously:
  (a) the context defines a named capacity constant that is clearly the MAXIMUM
      ELEMENT COUNT for a specific container (e.g. `MAX_ITEMS`, `MAX_CONTAINER_SIZE`);
  (b) the TGT function appends to that specific container (push_back, insert,
      emplace_back, emplace) without first checking `container.size() < MAX_*`;
  (c) the constant is NEVER used anywhere in TGT (proving it is intentionally ignored).
  Do NOT flag if the constant relates to string length, buffer bytes, or is used
  elsewhere in TGT (even in a different context).

Rules:
1. Ignore test-harness naming: TGT function name, even if it contains "Bad", "Unsafe",
   "without", "withoutCheck" — these are BENCHMARK LABELS, not evidence.
   The surrounding context may also contain functions named *Bad*, *Good*, *withoutCheck*,
   *WithCheck*, *Validate*Bad*, *Validate*Good* — these are comparison variants in the
   same test file, NOT the function under analysis. Evaluate ONLY the TGT function's
   logic, regardless of what the context functions are named.
2. If the TGT function always frees/releases every allocation it makes (using free, delete,
   Free*, Release*, Delete* patterns), or always returns the pointer to the caller — BENIGN.
3. A return immediately after a malloc/new NULL check (allocation failure path) is OK.
4. securec memset_s correct usage: `memset_s(dst, sizeof(T), 0, sizeof(T))` where both
   size args equal sizeof(target) is the CORRECT way to zero a struct — NOT a vulnerability.
   The arg2==arg4 misuse rule applies ONLY to memcpy_s and strcpy_s, not to memset_s.

CODE:
```c
{code}
```

Respond with JSON only:
{{"prediction": "VULNERABLE", "confidence": 0.9}}
or
{{"prediction": "BENIGN", "confidence": 0.8}}""",
},

"Injection": {
1: """\
You are an injection vulnerability detector for C/C++ and Java code.

Determine whether the TARGET (TGT) function contains an INJECTION vulnerability.

Injection vulnerabilities include:
- OS command injection: user-controlled data passed to exec(), system(), Runtime.exec(),
  ProcessBuilder, popen() without sanitization
- SQL injection: user input concatenated into SQL query string
- XPath injection: user input embedded in XPath expression
- XML/XSLT injection: user-controlled XML structure or stylesheet
- Expression Language injection (Spring EL, OGNL, Unified EL): user input in EL evaluation
- Template injection (Velocity, Thymeleaf, FreeMarker): user input in template rendering
- Format string injection: user-controlled format string in printf/sprintf/fprintf family
- JNDI injection: user input in InitialContext.lookup() or similar
- XML External Entity (XXE/XEE): user-controlled XML with entity expansion

Rules:
1. TGT function name (even "Bad", "Unsafe", "without*") is a benchmark label, not evidence.
2. If user input is properly sanitized, validated, or escaped before reaching the sink — BENIGN.
3. If the injection sink is reached only from a hardcoded literal — BENIGN.
4. If the sink receives data from a server-side index (integer field, not user string) — BENIGN.

CODE:
```
{code}
```

Respond with JSON only:
{{"prediction": "VULNERABLE", "confidence": 0.9}}
or
{{"prediction": "BENIGN", "confidence": 0.8}}""",

2: """\
You are an injection vulnerability detector for C/C++ and Java code.

Determine whether the TARGET (TGT) function contains an INJECTION vulnerability.

Injection vulnerabilities include:
- OS command injection: user-controlled data passed to exec(), system(), Runtime.exec(),
  ProcessBuilder, popen() without sanitization
- SQL injection: user input concatenated into SQL query string
- XPath injection: user input embedded in XPath expression
- XML/XSLT injection: user-controlled XML structure or stylesheet
- Expression Language injection (Spring EL, OGNL, Unified EL): user input in EL evaluation
- Template injection (Velocity, Thymeleaf, FreeMarker): user input in template rendering
- Format string injection: user-controlled format string in printf/sprintf/fprintf family
- JNDI injection: user input in InitialContext.lookup(), ldap lookup, or similar
- XML External Entity (XXE/XEE): user-controlled XML with entity expansion
- Regex injection / ReDoS: user-controlled string concatenated into a regex pattern that is
  then compiled/matched (String.matches(), Pattern.compile(), regexp.exec()) — allows
  catastrophic backtracking even if the final match result is discarded

Rules:
1. TGT function name (even "Bad", "Unsafe", "without*") is a benchmark label, not evidence.
2. If user input is properly sanitized, validated, or escaped before reaching the sink — BENIGN.
3. If the injection sink is reached only from a hardcoded literal — BENIGN.
4. If the sink receives data from a server-side integer index (not a user string) — BENIGN.
5. For ReDoS: even if the match result is used for validation (block on fail), the regex
   engine itself can be made to hang — flag as VULNERABLE if user controls the regex pattern.

CODE:
```
{code}
```

Respond with JSON only:
{{"prediction": "VULNERABLE", "confidence": 0.9}}
or
{{"prediction": "BENIGN", "confidence": 0.8}}""",
},

"Logic": {
1: """\
You are a logic error and platform-behavior vulnerability detector.

Determine whether the TARGET (TGT) function contains a LOGIC VULNERABILITY.

Logic vulnerabilities include:
- Incorrect byte order (endianness): reading/writing multi-byte values without byte-swap
  conversion when communicating between big-endian and little-endian systems
- Bit-field struct memory layout dependency: assuming specific in-memory layout of bitfields
  across compilers/platforms; copying bitfield structs with memcpy or bitwise operations
- std::vector<bool> incompatibility: treating vector<bool> as a normal bool array,
  performing invalid pointer/reference operations on its elements
- Incorrect bitwise operations on non-trivially-copyable C++ objects

Rules:
1. TGT function name is a benchmark label, not evidence.
2. Standard arithmetic, type casting, and control-flow errors NOT involving the above
   specific categories should be classified BENIGN for this detector.

CODE:
```c
{code}
```

Respond with JSON only:
{{"prediction": "VULNERABLE", "confidence": 0.9}}
or
{{"prediction": "BENIGN", "confidence": 0.8}}""",

2: """\
You are a logic error and platform-behavior vulnerability detector.

Determine whether the TARGET (TGT) function contains a LOGIC VULNERABILITY.

Logic vulnerabilities include:
- Incorrect byte order (endianness): reading/writing multi-byte values without byte-swap
  conversion when communicating between big-endian and little-endian systems
- Bit-field struct memory layout dependency: assuming specific in-memory layout of bitfields
  across compilers/platforms; copying bitfield structs with memcpy or bitwise operations
- std::vector<bool> incompatibility: treating vector<bool> as a normal bool array,
  performing invalid pointer/reference operations on its elements
- Incorrect bitwise operations on non-trivially-copyable C++ objects

Rules:
1. TGT function name is a benchmark label, not evidence.
2. Standard arithmetic, type casting, and control-flow errors NOT involving the above
   specific categories should be classified BENIGN for this detector.

{few_shot}
CODE:
```c
{code}
```

Respond with JSON only:
{{"prediction": "VULNERABLE", "confidence": 0.9}}
or
{{"prediction": "BENIGN", "confidence": 0.8}}""",
},

"Input": {
1: """\
You are an input validation and type-safety vulnerability detector.

Determine whether the TARGET (TGT) function contains an INPUT VALIDATION vulnerability.

Input validation vulnerabilities include:
- Pointer type confusion: casting between incompatible pointer types (e.g., object pointer
  to unrelated object type) causing misinterpretation of memory
- Integer-to-pointer or pointer-to-integer casts with incorrect semantics
- Missing or incorrect null terminator: string operations where null terminator is not
  guaranteed, leading to over-read or buffer overflow downstream
- Improper input validation: trusting user-supplied size/length that is used without
  bounds checking

Rules:
1. TGT function name is a benchmark label, not evidence.
2. Safe casts with explicit checks, or casts between compatible types — BENIGN.
3. Null-terminator issues only count if a string function later reads past the buffer.
4. Memory allocation size errors, buffer overflows, use-after-free → NOT this detector (those are Memory).

CODE:
```c
{code}
```

Respond with JSON only:
{{"prediction": "VULNERABLE", "confidence": 0.9}}
or
{{"prediction": "BENIGN", "confidence": 0.8}}""",

2: """\
You are a type-safety and input-validation vulnerability detector for C/C++.

Determine whether the TARGET (TGT) function contains a TYPE CONFUSION or INPUT VALIDATION
vulnerability — NOT a memory overflow or injection.

This detector covers:
1. Pointer type confusion: casting an object pointer to an INCOMPATIBLE object type
   (e.g., Base* → DerivedB* when the object is actually DerivedA*), causing the code to
   misinterpret the object's memory layout. Sign: reinterpret_cast, C-style cast between
   unrelated class pointers, or void* cast without runtime type check.
2. Integer↔pointer casts: casting an integer value to a pointer and dereferencing it, or
   storing a pointer in a too-small integer type, losing address bits.
3. Missing null terminator: writing bytes into a char buffer without guaranteeing the
   terminating '\\0', then passing to strlen/strcmp/strcpy/etc. downstream.

This detector does NOT cover:
- Buffer overflows or out-of-bounds writes (those are Memory)
- Injection (SQL, command, format string etc.)
- Bounds check failures (those are Memory / bounds)

Rules:
1. TGT function name is a benchmark label, not evidence.
2. reinterpret_cast or C-style cast between RELATED types (base↔derived in correct hierarchy)
   with proper virtual dispatch — BENIGN.
3. Code that only does arithmetic on integers without pointer cast — BENIGN.

CODE:
```c
{code}
```

Respond with JSON only:
{{"prediction": "VULNERABLE", "confidence": 0.9}}
or
{{"prediction": "BENIGN", "confidence": 0.8}}""",
},

"Crypto": {
1: """\
You are a cryptographic vulnerability detector.

Determine whether the TARGET (TGT) function contains a CRYPTOGRAPHIC vulnerability.

Cryptographic vulnerabilities include:
- Weak cipher (DES, RC4, MD5/SHA1 for security, ECB mode)
- Missing encryption for sensitive data
- Hardcoded credentials or keys
- Insufficient randomness (rand() instead of CSPRNG)
- Broken hash or MAC usage
- Certificate validation disabled

CODE:
```
{code}
```

Respond with JSON only:
{{"prediction": "VULNERABLE", "confidence": 0.9}}
or
{{"prediction": "BENIGN", "confidence": 0.8}}""",
},

}  # end PROMPTS


# ── Dataset construction ────────────────────────────────────────────────────────

def combine_code(context: str, func: str, language: str) -> str:
    ctx = (context or "").strip()
    fn  = (func   or "").strip()
    if not ctx and not fn:
        return ""
    if not ctx:
        return fn
    if not fn:
        return ctx
    if language == "java":
        last = ctx.rfind("}")
        if last == -1:
            return ctx + "\n\n" + fn
        return ctx[:last] + "    " + fn + "\n}"
    return ctx + "\n\n" + fn


def extract_code(code_obj: dict, language: str) -> str:
    if not code_obj:
        return ""
    ctx  = code_obj.get("context") or ""
    func = code_obj.get("func")    or ""
    cls  = code_obj.get("class")   or ""
    if func:
        return combine_code(ctx or cls, func, language)
    return ctx or cls


def build_major_dataset(
    major: str,
    raw_data: dict,
    per_cwd: int = PER_CWD,
    seed: int = SEED,
) -> List[dict]:
    """Build binary dataset for a given major.

    Positive (VULNERABLE): vulnerable code from CWDs that map to this major.
    Negative (BENIGN):     benign code + vulnerable code from OTHER majors,
                           balanced to match positive count.
    """
    rng = random.Random(seed)

    positive: List[dict] = []
    negative_benign: List[dict] = []
    negative_vuln_other: List[dict] = []

    for lang, cwd_dict in raw_data.items():
        for cwd_id, entries in cwd_dict.items():
            cwd_major = CWD_TO_MAJOR.get(cwd_id, "Unknown")
            is_target = (cwd_major == major)

            pos_for_cwd: List[dict] = []
            neg_vuln_for_cwd: List[dict] = []
            neg_benign_for_cwd: List[dict] = []

            for entry in entries:
                vc = entry.get("vulnerable_code") or {}
                v_code = extract_code(vc, lang)
                if v_code.strip():
                    if is_target:
                        pos_for_cwd.append({"label": "VULNERABLE", "cwd": cwd_id,
                                            "major": cwd_major, "lang": lang, "code": v_code})
                    else:
                        # Other-major vuln is BENIGN for this major's classifier
                        neg_vuln_for_cwd.append({"label": "BENIGN", "cwd": cwd_id,
                                                 "major": cwd_major, "lang": lang, "code": v_code})

                bc = entry.get("benign_code") or {}
                b_code = extract_code(bc, lang)
                if b_code.strip():
                    sample = {"label": "BENIGN", "cwd": None,
                              "major": None, "lang": lang, "code": b_code}
                    neg_benign_for_cwd.append(sample)

            rng.shuffle(pos_for_cwd)
            rng.shuffle(neg_vuln_for_cwd)
            rng.shuffle(neg_benign_for_cwd)

            positive.extend(pos_for_cwd[:per_cwd])
            negative_vuln_other.extend(neg_vuln_for_cwd[:per_cwd])
            negative_benign.extend(neg_benign_for_cwd[:per_cwd])

    # Balance: negative = equal count to positive, prefer benign then other-vuln
    n_pos = len(positive)
    rng.shuffle(negative_benign)
    rng.shuffle(negative_vuln_other)

    # For negatives: take from benign first, then fill with other-major vuln
    negative_pool = negative_benign + negative_vuln_other
    rng.shuffle(negative_pool)
    negative = negative_pool[:n_pos]

    # If still short, just take what we have
    dataset = positive + negative
    rng.shuffle(dataset)
    return dataset


# ── Code preprocessing ─────────────────────────────────────────────────────────

def anonymize_benchmark_names(code: str) -> str:
    """Replace misleading benchmark function/variable names with neutral names.

    This removes "naming trap" signals so the model focuses on code logic:
    - TGT functions: rename to remove 'TGT' + surrounding benchmark labels
    - Context functions with Bad/Good/Vuln/Safe/Unsafe/Freestack prefixes → neutral
    - Chinese comments describing the vulnerability → removed
    """
    import re as _re

    # 1. Replace BadCase*/GoodCase* function names (also in call sites)
    code = _re.sub(r'\bBadCase\w*', 'TestFunc', code)
    code = _re.sub(r'\bGoodCase\w*', 'TestFunc2', code)

    # 2. Replace function names that start with FreeStack/freestack (benchmark trap)
    code = _re.sub(r'\bFreeStackmemory\w*', 'ProcessBuffer', code)
    code = _re.sub(r'\bfreestackmemory\w*', 'process_buffer', code)

    # 3. Strip the "TGTcase\d*" suffix from TGT functions (leave the core name)
    code = _re.sub(r'TGTcase\d*', 'TGT', code)

    # 4. Remove single-line Chinese comments that describe vulnerability behavior
    # (These are like: // 析构函数再次释放，导致内存双重释放)
    code = _re.sub(r'//[^\n]*[\u4e00-\u9fff][^\n]*', '', code)

    return code


# ── RAG few-shot bank ──────────────────────────────────────────────────────────

# Embedding model for RAG.  Preferred: qwen/qwen3-embedding-0.6b (not yet on OpenRouter).
# Fallback: openai/text-embedding-3-small (available on OpenRouter).
# Override with env var EMBED_MODEL if you have a Qwen-compatible endpoint.
EMBED_MODEL = os.environ.get("EMBED_MODEL", "openai/text-embedding-3-small")
EMBED_LIMIT = 1024   # chars to embed (keeps cost low, captures key patterns)
FEWSHOT_DISPLAY = 500  # chars of code to show in few-shot block

# Majors where RAG few-shot is worth adding (poor prompt-only ceiling)
RAG_MAJORS = {"Memory", "Logic"}

# Canonical hard-case examples always prepended before dynamic RAG hits.
# Curated specifically for the patterns that trip the model most.
STATIC_EXAMPLES: Dict[str, List[dict]] = {
    "Memory": [
        # ── Hard FP: securec benign code (correct memcpy_s usage)
        {
            "label": "BENIGN",
            "note": "securec correct usage — memcpy_s capacity ≠ count",
            "code": """\
void copy_record(char *dst, size_t dst_cap, const char *src, size_t src_len) {
    if (src_len >= dst_cap) return;           // guard
    memcpy_s(dst, dst_cap, src, src_len);     // dst_cap != src_len → correct
}""",
        },
        # ── Hard FN: securec macro misuse (same value for both args)
        {
            "label": "VULNERABLE",
            "note": "securec macro passes count as both capacity and copy-count",
            "code": """\
#define SAFE_COPY(dst, src, n) memcpy_s((dst), (n), (src), (n))
// Above: both capacity and count = n — destination capacity is IGNORED.
void copy_ip(uint8_t *dst, const uint8_t *src) {
    SAFE_COPY(dst, src, IPV6_ADDR_LEN);  // dst may be smaller than IPV6_ADDR_LEN
}""",
        },
        # ── Hard FP: double-free naming trap — two separate paths, each frees once
        {
            "label": "BENIGN",
            "note": "two free() on mutually exclusive paths is NOT double-free",
            "code": """\
int process(Resource *r) {
    if (r->err) {
        free(r->buf);   // error path: free once
        return -1;
    }
    use(r->buf);
    free(r->buf);       // success path: free once — different path, not double-free
    return 0;
}""",
        },
        # ── Hard FN: dangling global pointer (delete without null)
        {
            "label": "VULNERABLE",
            "note": "global pointer freed but not set to nullptr — dangling",
            "code": """\
static Manager *g_mgr = nullptr;
void shutdown() {
    delete g_mgr;       // g_mgr still holds old address after delete
    // missing: g_mgr = nullptr;
}
// Any subsequent access to g_mgr dereferences dangling pointer""",
        },
    ],
}

def _cosine_sim(a: List[float], b: List[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na  = sum(x * x for x in a) ** 0.5
    nb  = sum(x * x for x in b) ** 0.5
    return dot / (na * nb + 1e-9)


class RAGBank:
    """Embedding-based few-shot retrieval bank.

    Embeds all dataset samples once (cached to disk).  At query time returns
    the top-1 VULNERABLE + top-1 BENIGN example most similar to the query,
    combined with the static canonical examples defined in STATIC_EXAMPLES.
    """

    def __init__(
        self,
        dataset: List[dict],
        major: str,
        api_key: str,
        api_base: str,
    ) -> None:
        self.dataset  = dataset
        self.major    = major
        self.api_key  = api_key
        self.api_base = api_base
        self.embeddings: List[Optional[List[float]]] = [None] * len(dataset)
        cache_dir = Path(RESULTS_DIR) / major
        cache_dir.mkdir(parents=True, exist_ok=True)
        self._cache_path = cache_dir / "_rag_embeddings.json"

    # ── Embedding helpers ───────────────────────────────────────────────────

    async def _embed_batch(
        self,
        texts: List[str],
        aclient: "AsyncOpenAI",
        sem: asyncio.Semaphore,
    ) -> List[List[float]]:
        """Embed a batch of texts via OpenRouter embedding endpoint."""
        async def _one(text: str) -> List[float]:
            async with sem:
                resp = await aclient.embeddings.create(
                    model=EMBED_MODEL,
                    input=text,
                )
                return resp.data[0].embedding
        return await asyncio.gather(*[_one(t) for t in texts])

    async def _build_async(self) -> None:
        aclient = AsyncOpenAI(
            base_url=self.api_base,
            api_key=self.api_key,
            timeout=60.0,
            max_retries=1,
        )
        sem = asyncio.Semaphore(20)  # embedding is cheaper, use higher concurrency
        texts = [s["code"][:EMBED_LIMIT] for s in self.dataset]
        print(f"  [RAG] embedding {len(texts)} samples with {EMBED_MODEL}...")
        embs = await self._embed_batch(texts, aclient, sem)
        await aclient.close()
        self.embeddings = embs  # type: ignore[assignment]

    def build(self) -> None:
        """Build (or load cached) embeddings for the dataset."""
        if self._cache_path.exists():
            with open(self._cache_path) as f:
                cached = json.load(f)
            if len(cached) == len(self.dataset):
                self.embeddings = cached
                print(f"  [RAG] loaded {len(cached)} cached embeddings "
                      f"from {self._cache_path}")
                return
        asyncio.run(self._build_async())
        with open(self._cache_path, "w") as f:
            json.dump(self.embeddings, f)
        print(f"  [RAG] saved embeddings → {self._cache_path}")

    # ── Retrieval ───────────────────────────────────────────────────────────

    def retrieve(self, query_idx: int, k_per_class: int = 1) -> Dict[str, List[dict]]:
        """Return up to k_per_class VULNERABLE + k_per_class BENIGN examples
        most similar to dataset[query_idx], excluding the query itself."""
        q_emb = self.embeddings[query_idx]
        if q_emb is None:
            return {"VULNERABLE": [], "BENIGN": []}

        sims: List[Tuple[float, int]] = []
        for j, emb in enumerate(self.embeddings):
            if j == query_idx or emb is None:
                continue
            sims.append((_cosine_sim(q_emb, emb), j))
        sims.sort(reverse=True)

        results: Dict[str, List[dict]] = {"VULNERABLE": [], "BENIGN": []}
        for _, j in sims:
            lbl = self.dataset[j]["label"]
            if len(results[lbl]) < k_per_class:
                results[lbl].append(self.dataset[j])
            if all(len(v) >= k_per_class for v in results.values()):
                break
        return results

    # ── Formatting ──────────────────────────────────────────────────────────

    def format_few_shot(self, query_idx: int) -> str:
        """Return a formatted few-shot block to inject into the prompt."""
        lines: List[str] = [
            "## Reference Examples (calibrate your analysis against these):\n"
        ]
        # 1. Static canonical examples
        for ex in STATIC_EXAMPLES.get(self.major, []):
            snippet = ex["code"][:FEWSHOT_DISPLAY]
            lines.append(
                f"### {ex['label']} — {ex['note']}\n"
                f"```c\n{snippet}\n```\n"
                f"→ **{ex['label']}**\n"
            )
        # 2. Dynamic RAG examples (1 VULNERABLE + 1 BENIGN)
        retrieved = self.retrieve(query_idx)
        for lbl, samples in retrieved.items():
            for s in samples:
                snippet = s["code"][:FEWSHOT_DISPLAY]
                cwd_hint = s.get("cwd") or "benign"
                lines.append(
                    f"### {lbl} — similar code ({cwd_hint})\n"
                    f"```c\n{snippet}\n```\n"
                    f"→ **{lbl}**\n"
                )
        lines.append("## Now analyze the target code below:\n")
        return "\n".join(lines)


# ── Prediction parsing ─────────────────────────────────────────────────────────

def parse_prediction(text: str) -> Tuple[str, float]:
    text_lower = text.lower()
    # Try JSON first
    m = re.search(r'\{[^{}]*"prediction"\s*:\s*"(\w+)"[^{}]*\}', text, re.IGNORECASE)
    if m:
        pred = m.group(1).upper()
        conf_m = re.search(r'"confidence"\s*:\s*([\d.]+)', text, re.IGNORECASE)
        conf = float(conf_m.group(1)) if conf_m else 0.5
        if pred in ("VULNERABLE", "BENIGN"):
            return pred, conf
    # Fallback
    if "vulnerable" in text_lower:
        return "VULNERABLE", 0.5
    if "benign" in text_lower:
        return "BENIGN", 0.5
    return "UNKNOWN", 0.0


# ── Async evaluation ───────────────────────────────────────────────────────────

def evaluate(
    dataset: List[dict],
    prompt_template: str,
    major: str,
    verbose: bool = True,
    max_tokens: int = MAX_TOKENS,
    concurrency: int = CONCURRENCY,
    code_limit: int = CODE_LIMIT,
    preprocess: bool = False,
    llm_preprocess: bool = False,
    rag_bank: Optional["RAGBank"] = None,
) -> dict:
    """Evaluate prompt on dataset. Returns metrics dict."""
    api_base = os.environ.get("OPENROUTER_API_BASE", "https://openrouter.ai/api/v1")
    api_key  = os.environ.get("OPENROUTER_API_KEY", "")
    model    = (os.environ.get("OPENROUTER_MODEL")
                or os.environ.get("MODEL_NAME")
                or "openai/gpt-5.4")

    errors: List[str] = []

    async def _run_all():
        aclient = AsyncOpenAI(base_url=api_base, api_key=api_key,
                              timeout=120.0, max_retries=1)
        sem = asyncio.Semaphore(concurrency)
        results_map: dict = {}
        done_count = 0

        async def _anon_llm(code: str) -> str:
            """LLM subagent: 语义识别并替换所有 benchmark 命名陷阱。"""
            import re as _re
            anon_prompt = (
                "You are a code preprocessor. Identify ALL function and variable names that are "
                "BENCHMARK LABELS (not real-world names). These include names like:\n"
                "- BadCase*, GoodCase*, IsBad*, IsGood*, IsVulnerable*, IsSecure*\n"
                "- FreeStackmemory*, FreeStack*, freestackmemory*\n"
                "- TGTcase*, *withoutCheck*, *WithCheck*, *Unsafe*, *NoBound*, *NoBounds*\n"
                "- Any PascalCase/camelCase that mixes 'Bad', 'Good', 'Vuln', 'Safe', 'Insecure', 'Secure'\n\n"
                "Return ONLY a JSON object mapping each misleading name to a short neutral replacement:\n"
                "{\"BadCaseMemcpy\": \"CopyData\", \"FreeStackmemory_TGT\": \"FreeBuffer\"}\n"
                "Use neutral names like: CopyData, ProcessBuffer, HandleRecord, TransferBytes, "
                "AllocBuffer, WriteData, ReadInput, ParseItem, StoreValue.\n"
                "If no misleading names found, return {}.\n\n"
                f"CODE:\n```c\n{code[:2000]}\n```"
            )
            try:
                async with sem:
                    resp = await aclient.chat.completions.create(
                        model=model,
                        messages=[{"role": "user", "content": anon_prompt}],
                        temperature=0.0,
                        max_tokens=300,
                    )
                text = resp.choices[0].message.content or ""
                m = _re.search(r'\{[^}]*\}', text, _re.DOTALL)
                if not m:
                    return code
                mapping = json.loads(m.group())
                result = code
                for orig, neutral in sorted(mapping.items(), key=lambda x: -len(x[0])):
                    if orig and neutral and orig in result:
                        result = _re.sub(r'\b' + _re.escape(orig) + r'\b', neutral, result)
                return result
            except Exception:
                return code  # fallback: return original on any error

        async def _one(i: int, sample: dict):
            nonlocal done_count
            code = sample["code"][:code_limit]
            if preprocess:
                code = anonymize_benchmark_names(code)
            if llm_preprocess:
                code = await _anon_llm(code)
            # Inject RAG few-shot block if available
            if rag_bank is not None and "{few_shot}" in prompt_template:
                few_shot = rag_bank.format_few_shot(i)
                prompt = prompt_template.replace("{few_shot}", few_shot).replace("{code}", code)
            else:
                prompt = prompt_template.replace("{few_shot}", "").replace("{code}", code)
            try:
                async with sem:
                    resp = await aclient.chat.completions.create(
                        model=model,
                        messages=[{"role": "user", "content": prompt}],
                        temperature=0.1,
                        max_tokens=max_tokens,
                    )
                text = resp.choices[0].message.content or ""
            except Exception as exc:
                text = ""
                errors.append(f"[{i}] {exc}")
            pred, conf = parse_prediction(text)
            label = sample["label"].upper()
            ok = (pred == label)
            results_map[i] = {
                "idx": i, "cwd": sample.get("cwd"), "major": sample.get("major"),
                "lang": sample.get("lang"), "label": label,
                "pred": pred, "conf": conf, "correct": ok,
                "code_snippet": code[:120],
            }
            done_count += 1
            if verbose:
                mark = "✓" if ok else "✗"
                cwd_str = sample.get("cwd") or "(benign)"
                print(f"  [{done_count:3d}/{len(dataset)}] {mark} "
                      f"pred={pred:<12} actual={label:<12} {cwd_str}")

        await asyncio.gather(*[_one(i, s) for i, s in enumerate(dataset)])
        await aclient.close()
        return results_map

    results_map = asyncio.run(_run_all())
    results = [results_map[i] for i in range(len(dataset))]

    correct = sum(r["correct"] for r in results)
    total   = len(results)
    accuracy = correct / total if total else 0.0

    wrong = [r for r in results if not r["correct"]]
    fp = [r for r in wrong if r["label"] == "BENIGN"]
    fn = [r for r in wrong if r["label"] == "VULNERABLE"]

    return {
        "major": major,
        "accuracy": accuracy,
        "correct": correct,
        "total": total,
        "wrong_count": len(wrong),
        "fp_count": len(fp),
        "fn_count": len(fn),
        "fp_samples": fp,
        "fn_samples": fn,
        "errors": errors,
    }


# ── Analysis helpers ────────────────────────────────────────────────────────────

def print_analysis(metrics: dict, round_num: int, major: str):
    print(f"\n{'='*65}")
    print(f"[Major={major}] Round {round_num}  accuracy={metrics['accuracy']:.1%}  "
          f"({metrics['correct']}/{metrics['total']})  "
          f"wrong={metrics['wrong_count']} (FP={metrics['fp_count']} FN={metrics['fn_count']})")
    print(f"{'='*65}")
    if metrics["errors"]:
        print(f"API errors: {len(metrics['errors'])}")
        for e in metrics["errors"][:3]:
            print(f"  {e}")
    if metrics["fn_samples"]:
        print(f"\nFalse Negatives (missed vulnerabilities)  [{len(metrics['fn_samples'])}]:")
        for r in metrics["fn_samples"][:10]:
            print(f"  [{r['idx']:3d}] cwd={r['cwd']:<14} lang={r['lang']:<5} "
                  f"conf={r['conf']:.2f}  {r['code_snippet'][:60]}...")
    if metrics["fp_samples"]:
        print(f"\nFalse Positives (incorrect alarm)  [{metrics['fp_count']}]:")
        for r in metrics["fp_samples"][:10]:
            print(f"  [{r['idx']:3d}] cwd={(r['cwd'] or 'benign'):<14} lang={r['lang']:<5} "
                  f"conf={r['conf']:.2f}  {r['code_snippet'][:60]}...")


# ── Main evolution loop ────────────────────────────────────────────────────────

def run_major(major: str, rounds: Optional[List[int]] = None, verbose: bool = True,
              preprocess: bool = False, llm_preprocess: bool = False,
              use_rag: bool = False):
    out_dir = Path(RESULTS_DIR) / major
    out_dir.mkdir(parents=True, exist_ok=True)

    # Load raw data
    with open(RAW_DATA) as f:
        raw_data = json.load(f)

    # Build dataset
    dataset = build_major_dataset(major, raw_data)
    n_pos = sum(1 for s in dataset if s["label"] == "VULNERABLE")
    n_neg = sum(1 for s in dataset if s["label"] == "BENIGN")
    print(f"\n[{major}] Dataset: {len(dataset)} total  "
          f"(VULNERABLE={n_pos}, BENIGN={n_neg})")

    # Save dataset for reference
    dataset_path = out_dir / "dataset.json"
    if not dataset_path.exists():
        with open(dataset_path, "w") as f:
            json.dump(dataset, f, ensure_ascii=False, indent=2)

    # Determine which rounds to run
    prompts = PROMPTS.get(major, {})
    if not prompts:
        print(f"[{major}] No prompts defined. Skipping.")
        return

    run_rounds = rounds if rounds else sorted(prompts.keys())

    # Build RAG bank if needed (only for majors where it helps, or when forced)
    rag_bank: Optional[RAGBank] = None
    needs_rag = use_rag and (
        major in RAG_MAJORS
        or any("{few_shot}" in (prompts.get(r) or "") for r in run_rounds)
    )
    if needs_rag:
        api_base = os.environ.get("OPENROUTER_API_BASE", "https://openrouter.ai/api/v1")
        api_key  = os.environ.get("OPENROUTER_API_KEY", "")
        rag_bank = RAGBank(dataset, major, api_key, api_base)
        rag_bank.build()

    best_accuracy = 0.0
    best_round = 0

    for rnd in run_rounds:
        if rnd not in prompts:
            print(f"[{major}] Round {rnd} not defined. Skipping.")
            continue

        prompt = prompts[rnd]
        has_fewshot = "{few_shot}" in prompt
        # Build result file suffix to avoid overwriting previous results
        if llm_preprocess:
            suffix = "_llmpp"
        elif has_fewshot and rag_bank is not None:
            suffix = "_rag"
        else:
            suffix = ""
        result_path = out_dir / f"round{rnd}{suffix}.json"
        if result_path.exists():
            with open(result_path) as f:
                saved = json.load(f)
            acc = saved.get("accuracy", 0)
            print(f"[{major}] Round {rnd}{suffix}: already done, accuracy={acc:.1%}")
            if acc > best_accuracy:
                best_accuracy = acc
                best_round = rnd
            continue

        active_rag = rag_bank if has_fewshot else None
        print(f"\n[{major}] Round {rnd}{suffix} — evaluating {len(dataset)} samples "
              f"(concurrency={CONCURRENCY}, code_limit={CODE_LIMIT}, "
              f"preprocess={preprocess}, llm_preprocess={llm_preprocess}, "
              f"rag={active_rag is not None})...")
        t0 = time.time()
        metrics = evaluate(dataset, prompt, major=major, verbose=verbose,
                           preprocess=preprocess, llm_preprocess=llm_preprocess,
                           rag_bank=active_rag)
        elapsed = time.time() - t0

        # Save
        save_data = {
            "round": rnd,
            "major": major,
            "accuracy": metrics["accuracy"],
            "correct": metrics["correct"],
            "total": metrics["total"],
            "wrong_count": metrics["wrong_count"],
            "fp_count": metrics["fp_count"],
            "fn_count": metrics["fn_count"],
            "elapsed_s": round(elapsed, 1),
            "prompt": prompt,
            "fp_samples": metrics["fp_samples"],
            "fn_samples": metrics["fn_samples"],
            "errors": metrics["errors"],
        }
        with open(result_path, "w") as f:
            json.dump(save_data, f, ensure_ascii=False, indent=2)

        print_analysis(metrics, rnd, major)
        print(f"  → saved to {result_path}  elapsed={elapsed:.0f}s")

        if metrics["accuracy"] > best_accuracy:
            best_accuracy = metrics["accuracy"]
            best_round = rnd

    print(f"\n[{major}] Best: round={best_round} accuracy={best_accuracy:.1%}")
    return best_accuracy


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--major", choices=MAJORS, default=None,
                        help="Run only this major (default: all)")
    parser.add_argument("--round", type=int, default=None,
                        help="Run only this round number")
    parser.add_argument("--quiet", action="store_true",
                        help="Suppress per-sample output")
    parser.add_argument("--preprocess", action="store_true",
                        help="Anonymize benchmark naming traps before sending to LLM")
    parser.add_argument("--llm-preprocess", action="store_true",
                        help="Use LLM subagent to semantically identify and replace "
                             "ALL misleading benchmark names (more thorough than --preprocess)")
    parser.add_argument("--rag", action="store_true",
                        help="Enable RAG few-shot injection for rounds that have {few_shot} placeholder")
    args = parser.parse_args()

    if not HAS_ASYNC_OPENAI:
        print("ERROR: openai package not installed. Run: uv add openai")
        sys.exit(1)

    api_key = os.environ.get("OPENROUTER_API_KEY", "")
    if not api_key:
        # Try loading from .env
        env_path = Path(__file__).parent / ".env"
        if env_path.exists():
            for line in env_path.read_text().splitlines():
                if "=" in line and not line.startswith("#"):
                    k, _, v = line.partition("=")
                    os.environ.setdefault(k.strip(), v.strip())
        if not os.environ.get("OPENROUTER_API_KEY"):
            print("ERROR: OPENROUTER_API_KEY not set")
            sys.exit(1)

    target_majors = [args.major] if args.major else MAJORS
    rounds = [args.round] if args.round else None
    verbose = not args.quiet
    preprocess = args.preprocess
    llm_preprocess = args.llm_preprocess
    use_rag = args.rag

    results_summary: Dict[str, float] = {}
    for major in target_majors:
        acc = run_major(major, rounds=rounds, verbose=verbose,
                        preprocess=preprocess, llm_preprocess=llm_preprocess,
                        use_rag=use_rag)
        if acc is not None:
            results_summary[major] = acc

    if len(results_summary) > 1:
        print(f"\n{'='*65}")
        print("Summary (best round per major):")
        for m, a in results_summary.items():
            print(f"  {m:<12}: {a:.1%}")


if __name__ == "__main__":
    main()
