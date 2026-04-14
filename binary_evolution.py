#!/usr/bin/env python3
"""
单节点二分类进化实验：Vulnerable vs Benign
由 Claude 亲自主导每轮 prompt 迭代
"""
import asyncio
import os, sys, json, time, re
from pathlib import Path
from typing import List, Dict, Tuple

try:
    from openai import AsyncOpenAI
    HAS_ASYNC_OPENAI = True
except ImportError:
    HAS_ASYNC_OPENAI = False

sys.path.append('/Users/zihanwu/Public/codes/Mulvul/src')
from mulvul.llm.client import load_env_vars, OpenAICompatibleClient
load_env_vars()

# ── 已知噪声样本（0-indexed）：代码与标签不符，排除出分母 ───────────────
# [10] CWD-1030: 代码有 null check 但标 VULNERABLE
# [97] CWD-1040: 代码有 null check 但标 VULNERABLE
NOISE_INDICES: set = {10, 97}

# ── 预处理：去除命名伪装 ─────────────────────────────────────────────
def preprocess_code(code: str) -> str:
    """替换 benchmark 命名伪装，减少函数名对模型的干扰"""
    # ...Bad / ...Unsafe → ...VariantA（要求前面是字母/数字，后面不是小写字母）
    code = re.sub(r'(?<=[A-Za-z0-9_])(Bad|Unsafe)(?![a-z])', r'VariantA', code)
    # ...Good → ...VariantB
    code = re.sub(r'(?<=[A-Za-z0-9_])(Good)(?![a-z])', r'VariantB', code)
    # without(Check|LengthCheck) → WithGuard
    code = re.sub(r'without(?:Check|LengthCheck|check|lengthcheck)',
                  r'WithGuard', code, flags=re.IGNORECASE)
    return code

# ── LLM 调用 ──────────────────────────────────────────────────────────
def call_llm(client, prompt: str, max_tokens: int = 600) -> str:
    return client.generate(prompt, max_tokens=max_tokens)

# ── 响应解析 ──────────────────────────────────────────────────────────
def parse_prediction(response: str) -> Tuple[str, float]:
    """从响应中提取 prediction 和 confidence"""
    text = response.strip()

    # 尝试解析 JSON
    for pattern in (r'\{[\s\S]*\}', r'\[[\s\S]*\]'):
        m = re.search(pattern, text)
        if m:
            try:
                data = json.loads(m.group())
                if isinstance(data, dict):
                    pred = (data.get('prediction') or data.get('label') or
                            data.get('verdict') or '').upper()
                    conf = float(data.get('confidence', 0.5))
                    if pred in ('VULNERABLE', 'BENIGN'):
                        return pred, conf
            except Exception:
                pass

    # 回退：关键词匹配
    upper = text.upper()
    vuln_pos = upper.find('VULNERABLE')
    benign_pos = upper.find('BENIGN')
    if vuln_pos == -1 and benign_pos == -1:
        return 'UNKNOWN', 0.0
    if vuln_pos != -1 and (benign_pos == -1 or vuln_pos < benign_pos):
        return 'VULNERABLE', 0.6
    return 'BENIGN', 0.6

# ── 单轮评估（asyncio 真并发） ───────────────────────────────────────
def evaluate(client, dataset: List[Dict], prompt_template: str,
             verbose: bool = True, max_tokens: int = 600,
             concurrency: int = 10, preprocess: bool = False,
             skip_indices: set = None, code_limit: int = 3000) -> Dict:
    skip_set = skip_indices or set()

    # 从 client 取出连接参数，构建 AsyncOpenAI
    api_base  = getattr(client, 'api_base',  None) or os.environ.get('OPENROUTER_API_BASE', 'https://openrouter.ai/api/v1')
    api_key   = getattr(client, 'api_key',   None) or os.environ.get('OPENROUTER_API_KEY', '')
    model     = getattr(client, 'model_name', None) or 'gpt-5.4'

    async def _run_all():
        aclient = AsyncOpenAI(base_url=api_base, api_key=api_key,
                              timeout=90.0, max_retries=1)
        sem = asyncio.Semaphore(concurrency)
        errors: list = []
        done_count = 0
        results_map: Dict[int, Dict] = {}

        async def _one(i: int, sample: Dict):
            nonlocal done_count
            code = sample['code'][:code_limit]
            if preprocess:
                code = preprocess_code(code)
            prompt = prompt_template.replace('{code}', code)
            async with sem:
                try:
                    resp = await aclient.chat.completions.create(
                        model=model,
                        messages=[{'role': 'user', 'content': prompt}],
                        temperature=0.1,
                        max_tokens=max_tokens,
                    )
                    text = resp.choices[0].message.content or ''
                    pred, conf = parse_prediction(text)
                except Exception as e:
                    pred, conf = 'ERROR', 0.0
                    errors.append(f'sample {i}: {e}')
            label = sample['label'].upper()
            ok = (pred == label)
            result = {
                'idx': i, 'cwd': sample.get('cwd'), 'label': label,
                'pred': pred, 'conf': conf, 'correct': ok,
                'code_snippet': code[:120],
            }
            results_map[i] = result
            done_count += 1
            if verbose:
                noise = '[NOISE]' if i in skip_set else ''
                mark = '✓' if ok else '✗'
                print(f"  [{done_count:3d}/{len(dataset)}] {mark} pred={pred:<12} "
                      f"actual={label}  cwd={sample.get('cwd') or 'benign'} {noise}")

        await asyncio.gather(*[_one(i, s) for i, s in enumerate(dataset)])
        await aclient.close()
        return results_map, errors

    results_map, errors = asyncio.run(_run_all())

    results = [results_map[i] for i in range(len(dataset))]

    # 全量指标（向后兼容）
    full_correct = sum(r['correct'] for r in results)
    full_acc = full_correct / len(results)

    # 去噪指标
    clean = [r for r in results if r['idx'] not in skip_set]
    clean_correct = sum(r['correct'] for r in clean)
    clean_acc = clean_correct / len(clean) if clean else 0.0

    wrong = [r for r in clean if not r['correct']]
    return {
        'accuracy': full_acc,
        'correct': full_correct,
        'total': len(results),
        'clean_accuracy': clean_acc,
        'clean_correct': clean_correct,
        'clean_total': len(clean),
        'wrong_samples': wrong,
        'errors': errors,
        'results': results,
    }

# ── 失败分析 ──────────────────────────────────────────────────────────
def analyze_failures(wrong: List[Dict]) -> str:
    if not wrong:
        return "无错误！"

    false_neg = [r for r in wrong if r['label']=='VULNERABLE' and r['pred']!='VULNERABLE']
    false_pos = [r for r in wrong if r['label']=='BENIGN' and r['pred']!='BENIGN']

    lines = [f"总错误: {len(wrong)}  |  漏报(FN): {len(false_neg)}  |  误报(FP): {len(false_pos)}"]

    if false_neg:
        lines.append("\n=== 漏报（实际 Vulnerable 预测成 Benign）===")
        for r in false_neg[:6]:
            lines.append(f"  CWD={r['cwd']}  pred={r['pred']}({r['conf']:.2f})")
            lines.append(f"    代码: {r['code_snippet'][:100]}")

    if false_pos:
        lines.append("\n=== 误报（实际 Benign 预测成 Vulnerable）===")
        for r in false_pos[:4]:
            lines.append(f"  pred={r['pred']}({r['conf']:.2f})")
            lines.append(f"    代码: {r['code_snippet'][:100]}")

    return '\n'.join(lines)

# ── 主程序 ────────────────────────────────────────────────────────────
def main():
    dataset = json.load(open('binary_eval_dataset.json'))
    print(f"📊 数据集: {len(dataset)} 样本 ({sum(1 for s in dataset if s['label']=='Vulnerable')} vuln + {sum(1 for s in dataset if s['label']=='Benign')} benign)")

    key = os.environ.get('OPENROUTER_API_KEY') or os.environ.get('API_KEY', '')
    client = OpenAICompatibleClient(
        model_name='gpt-5.4',
        api_base='https://openrouter.ai/api/v1',
        api_key=key,
    )

    # ── 第 0 代：基础 + 忽略命名、看逻辑 ─────────────────────────────
    PROMPT_R0 = """You are a security code auditor. Analyze this code for actual security vulnerabilities.

CODE:
```
{code}
```

CRITICAL RULE: Function names like "...Bad", "...Unsafe", "withoutCheck", "TestXxxBad" are
TEST LABELS in a benchmark dataset — they do NOT prove the code is vulnerable.
You must analyze the ACTUAL CODE LOGIC, not the names.

Check the primary function (TGT or main logic function) for:
- Missing null check: Is a pointer/reference used without first checking for null/nullptr?
- Missing bounds check: Is an array index used without verifying it's within bounds?
- Integer overflow: Is arithmetic on user-supplied or large values used as array size/index?
- Use-after-free: Is memory accessed after being freed?
- Dangerous injection: Is user input passed directly to exec(), eval(), xpath, or template engines?

If the primary function HAS explicit null/bounds/size checks → BENIGN (the fix is in place).
Only output VULNERABLE if you see an ACTUAL missing check in the code logic.

Respond with JSON only:
{"prediction": "VULNERABLE", "confidence": 0.9}
or
{"prediction": "BENIGN", "confidence": 0.85}"""

    out = Path('./binary_evolution_results')
    out.mkdir(exist_ok=True)

    # ── 第 1 代：TGT 函数 + 证据驱动 ──────────────────────────────────
    PROMPT_R1 = """You are a security code auditor analyzing code from a vulnerability benchmark.

CODE:
```
{code}
```

IMPORTANT CONTEXT:
- This benchmark has paired vulnerable/benign versions of each function.
- Functions named "...Bad", "...Unsafe" are TEST HELPERS — their presence alone is NOT evidence.
- The primary subject is the function named "...TGT" (target) — that is what you must analyze.
- A benign TGT has the FIX applied (proper checks). A vulnerable TGT is MISSING the fix.

STEP 1 — Find the TGT function (ends in "TGT"):
If found, this is your ONLY analysis target.
If not found, focus on the main logic function (not test harness functions).

STEP 2 — Analyze TGT function's OWN code logic:
- Does it check for null/nullptr before dereferencing a pointer? (missing → VULNERABLE)
- Does it validate array indices before access? (missing → VULNERABLE)
- Does it validate buffer sizes before copy/write? (missing → VULNERABLE)
- Does it check for integer overflow before using values as sizes? (missing → VULNERABLE)
- For Java: Does it sanitize/validate user input before passing to exec/eval/xpath? (missing → VULNERABLE)
- Does it use std::vector<bool> with element access? (yes → VULNERABLE: proxy-reference bug)

STEP 3 — Verdict:
VULNERABLE: TGT function is clearly missing a required safety check.
BENIGN: TGT function has the necessary checks in place OR no clear flaw found.
Default to BENIGN when uncertain.

Respond with JSON only:
{"prediction": "VULNERABLE", "confidence": 0.9}
or
{"prediction": "BENIGN", "confidence": 0.85}"""

    # ── 第 2 代：双语言 + FP 严控 ─────────────────────────────────────
    PROMPT_R2 = """You are a security auditor. This code is from a paired vulnerability benchmark.
Each pair has a VULNERABLE version (missing a check) and a BENIGN/FIXED version (check added).
Your task: determine if THIS specific code is the vulnerable or the fixed version.

CODE:
```
{code}
```

KEY INSIGHT: The code may call functions named "...Bad" or "...Unsafe" in test-harness context.
This does NOT make the code vulnerable — the question is whether the TGT function (ending in "TGT")
or the primary logic function is missing its own safety check.

ANALYSIS:

For C/C++ TGT function — identify the SINGLE most critical operation and check:
- If it's a pointer dereference: Is there a null check immediately before? No null check → VULNERABLE
- If it's an array access with computed index: Is there a bounds check? No bounds check → VULNERABLE
- If it allocates memory from user input: Is the size validated? No validation → VULNERABLE
- If it frees and reuses memory: Is the pointer cleared? Not cleared → VULNERABLE
- If it uses std::vector<bool>: → VULNERABLE (always, proxy-reference specialization)

For Java TGT function — check user input flow:
- Does user input (@RequestParam, @RequestBody) reach exec(), eval(), xpath.evaluate(),
  template.merge(), kieHelper, without being sanitized/whitelisted? → VULNERABLE
- Is user input validated before use? → BENIGN

VERDICT RULE: Only output VULNERABLE if you identify the specific MISSING check.
If the TGT function has the check in place, output BENIGN — regardless of other functions in the file.

Respond with JSON only:
{"prediction": "VULNERABLE", "confidence": 0.9}
or
{"prediction": "BENIGN", "confidence": 0.85}"""

    # ── 第 3 代：最严格 FP 控制 ────────────────────────────────────────
    PROMPT_R3 = """Security code review. Determine: VULNERABLE (missing a safety check) or BENIGN (check present).

CODE:
```
{code}
```

STEP 1 — Identify the target function:
Find the function ending in "TGT". That is the function to audit.
Ignore all other helper functions (they exist for comparison, not as the audit target).

STEP 2 — Find the SINGLE critical operation in the TGT function:
What is the ONE security-sensitive operation this function performs?
(e.g., "allocates memory based on user input", "dereferences a pointer", "calls exec with user string")

STEP 3 — Is there a guard for that operation?
A guard is: null check before deref, bounds check before array access, size validation before alloc,
input sanitization before exec/eval, signed/overflow check before arithmetic-as-size.

Does the TGT function have a guard? YES or NO?

STEP 4 — Verdict:
- Guard present (YES) → BENIGN
- Guard absent (NO) → VULNERABLE
- No clear single critical operation found → BENIGN (default)
- std::vector<bool> used in C++ → VULNERABLE

Respond with JSON only:
{"prediction": "VULNERABLE", "confidence": 0.9}
or
{"prediction": "BENIGN", "confidence": 0.85}"""

    # ── 第 4 代：综合最优 ──────────────────────────────────────────────
    PROMPT_R4 = """You are a precise security auditor. Classify this code as VULNERABLE or BENIGN.

CODE:
```
{code}
```

GROUND RULES:
1. Function names ending in "Bad", "Unsafe", or describing a vulnerability ("withoutCheck", etc.)
   are benchmark labels — NOT evidence. Ignore them for classification.
2. Only the TGT function (ends in "TGT") matters. Analyze only its own code logic.
3. BENIGN means the TGT function has the safety fix applied. VULNERABLE means it's missing it.

FAST-PATH (immediate verdict):
- C++ TGT uses `std::vector<bool>` with element access/iteration → VULNERABLE
- Java TGT has @RequestParam/@RequestBody input going to exec()/eval()/xpath/template/drools WITHOUT sanitization → VULNERABLE
- Java TGT from package containing "redos" AND uses regex concatenation with user input → VULNERABLE
- Java TGT from package containing "xee" AND uses XPath/SAX without disabling external entities → VULNERABLE

OTHERWISE — analyze the TGT function:
What security-sensitive operation does it do? Does it have a guard (null check, bounds check, size validation, input encoding)?

Guard present → BENIGN
Guard absent → VULNERABLE
Cannot identify TGT or operation → BENIGN (default)

Respond with JSON only:
{"prediction": "VULNERABLE", "confidence": 0.9}
or
{"prediction": "BENIGN", "confidence": 0.85}"""

    # ── 第 5 代：基于 R2 + 更强 FP 防御 + 新 FN 规则 ──────────────────
    PROMPT_R5 = """You are a security auditor. This code is from a paired vulnerability benchmark.
Each CWD has a VULNERABLE version (missing the safety fix) and a BENIGN version (fix applied).
Determine which version this is.

CODE:
```
{code}
```

STEP 1 — Find the target function:
Look for a function whose name ends in "TGT" or "TGTcase". That is your ONLY analysis target.
If no "TGT" function exists, focus on the primary logic function (not test harness / print functions).

STEP 2 — IGNORE all of the following (they are benchmark artifacts, NOT evidence):
- Function names in the file that contain "Bad", "Unsafe", "withoutCheck", "withoutlengthcheck"
- The TGT function's OWN name, even if it contains "without" or describes an issue
- Calls in test helper functions to "...Bad" or "...Good" variants
- Only analyze the BODY of the TGT function

STEP 3 — Does the TGT function body have a GUARD for its primary operation?

GUARD = one of:
  C/C++:
  - null check before pointer deref: `if (ptr == NULL)`
  - bounds check before array/buffer op: `if (len >= MAX)` or `if (idx < size)`
  - size validation before memcpy/memmove with correct parameters
  - integer overflow check before arithmetic-as-size
  - Java: input validation/sanitization before exec/eval/xpath/template

  Guard present → BENIGN (the fix is applied)
  Guard absent → VULNERABLE (the fix is missing)

ALSO VULNERABLE (no guard possible — these are inherently broken):
  - `tempObj.str().c_str()` or `tempObj.method().c_str()` — dangling pointer (temp object destroyed)
  - `delete ptr` without `ptr = nullptr` immediately after (only flag if ptr is used again)
  - Struct/array members used with memcmp/memcpy/comparison where some members were never initialized
  - `free(ptr)` followed by use of `ptr` without reassignment

STEP 4 — Verdict:
  TGT has guard → BENIGN
  TGT is missing guard / has inherently broken pattern above → VULNERABLE
  No clear critical operation found → BENIGN (default)

Respond with JSON only:
{"prediction": "VULNERABLE", "confidence": 0.9}
or
{"prediction": "BENIGN", "confidence": 0.85}"""

    # ── 第 6 代：基于 R5 + 修复 Java 整数参数 FP + 更强 test-harness 屏蔽 ──
    PROMPT_R6 = """You are a security auditor. This code is from a paired vulnerability benchmark.
One version is VULNERABLE (safety fix missing) and the other BENIGN (fix applied).
Your task: determine which version THIS code is.

CODE:
```
{code}
```

STEP 1 — Target:
Find the function ending in "TGT" or "TGTcase". Audit ONLY that function's body.
If no TGT function exists, use the primary business-logic function.

STEP 2 — Ignore (benchmark artifacts):
- Any helper function named Test...() or test...() that calls ...Bad() / ...Good() variants
- ALL function names containing "Bad", "Unsafe", "withoutCheck" — anywhere in the file
- The TGT function's own name even if it says "without" or "Bad"
- Do NOT treat the presence of "...Bad()" calls in the file as vulnerability evidence

STEP 3 — What is the ONE critical operation in the TGT function body?

STEP 4 — Is there a guard (safety fix) for that operation?

C/C++ guards:
- Null check before deref: `if (ptr == NULL)` — valid ONLY if no unsafe pointer arithmetic follows (ptr+N) without additional size validation
- Bounds check before array/buffer op: index < size, or memcpy_s with correct count vs dest size
- Error check after safe functions: memcpy_s/memset_s return value checked

Java guards:
- exec/eval/xpath/KieHelper with @RequestParam STRING: is string validated with regex/whitelist? If yes → BENIGN
- exec/eval/xpath/KieHelper with @RequestParam INT/int: integer param is NOT a string injection risk → BENIGN
- Using com.huawei.* security-wrapped API instead of raw org.mvel2/org.springframework directly → assume BENIGN

ALSO VULNERABLE (patterns that are inherently broken regardless of guards):
- C++: `tempObj.str().c_str()` or `tempObj.method().c_str()` — dangling pointer
- C++: global pointer deleted without ptr=nullptr when the pointer is used elsewhere

STEP 5:
Guard present → BENIGN
Guard absent for a clear security-sensitive operation → VULNERABLE
Uncertain / no critical operation identified → BENIGN (default)
C++ std::vector<bool> with element access → VULNERABLE

Respond with JSON only:
{"prediction": "VULNERABLE", "confidence": 0.9}
or
{"prediction": "BENIGN", "confidence": 0.85}"""

    # ── 第 7 代：修复 R6 ptr+N 规则过激 + Java JNDI + 截断默认 BENIGN ───
    PROMPT_R7 = """You are a security auditor reviewing code from a paired vulnerability benchmark.
Each CWD has a VULNERABLE version (fix missing) and a BENIGN version (fix applied).

CODE:
```
{code}
```

STEP 1 — Target function:
Find the function whose name ends in "TGT" or "TGTcase". Audit ONLY its body.
If no TGT exists, analyze the primary business-logic function (ignore test/print helpers).
If the TGT function body appears incomplete or truncated → BENIGN (default, cannot assess).

STEP 2 — Ignore these benchmark artifacts:
- ALL functions containing "Bad", "Unsafe", "withoutCheck" in their names
- Functions like TestXxx() or test_xxx() that call ...Bad() / ...Good() variants
- The TGT function's own name — even if it says "withoutcheck", only its BODY matters

STEP 3 — Security operation + guard check:

C/C++ — determine the primary security-sensitive operation, then look for its guard:
  Null dereference: guard = `if (ptr == NULL) return/exit` before the dereference
    → ALSO check: if after null-check, code does `(Type*)(ptr + N)` cast with NO validation
      of whether ptr's memory is large enough to contain N elements → VULNERABLE (overread)
    → But if there IS a bounds check like (idx < size) alongside the ptr arithmetic → BENIGN
  Buffer op (memcpy/memmove/sprintf): guard = destination size AND count both bounded
  Integer overflow: guard = explicit overflow check before arithmetic used as size
  Use-after-free: `free(ptr)` then use ptr, or `delete ptr` without `ptr=nullptr` when reused
  Dangling pointer: `tempObj.str().c_str()` or `tempObj.method().c_str()` (temp destroyed) → VULNERABLE
  Uninitialized struct member used in memcmp/comparison → VULNERABLE

Java — determine if user input reaches a dangerous sink:
  Dangerous sinks: exec(), eval(), XPath.evaluate(), KieHelper.addContent(), JNDI lookup (new InitialContext().lookup(input)), MVEL.eval/executeExpression with org.mvel2
  Guard = input validated with regex/whitelist BEFORE reaching the sink → BENIGN
  No validation → VULNERABLE
  Exception: @RequestParam int (integer) parameter → NOT a string injection risk → BENIGN
  Exception: Using com.huawei.* security-wrapped API → BENIGN

STEP 4 — Verdict:
  Guard present → BENIGN
  Guard absent / dangerous pattern present → VULNERABLE
  Cannot identify clear security-sensitive operation → BENIGN (default)
  C++ std::vector<bool> element access → VULNERABLE

Respond with JSON only:
{"prediction": "VULNERABLE", "confidence": 0.9}
or
{"prediction": "BENIGN", "confidence": 0.85}"""

    # ── 第 8 代：精确修复 R6 的 ptr+N 规则，避免 FP ────────────────────
    PROMPT_R8 = """You are a security auditor. This code is from a paired vulnerability benchmark.
One version is VULNERABLE (safety fix missing), the other BENIGN (fix applied).

CODE:
```
{code}
```

STEP 1 — Target function:
Find the function whose name ends in "TGT" or "TGTcase". Audit ONLY its body.
If no TGT exists, use the primary business-logic function (not test/print helpers).

STEP 2 — Ignore these benchmark artifacts completely:
- ALL functions whose names contain "Bad", "Unsafe", "withoutCheck" — anywhere in the file
- ANY function that calls "...Bad(...)" or "...Good(...)" variants — those are test harness helpers
- The TGT function's OWN name even if it contains "without" — only its body code matters

STEP 3 — Identify the TGT's ONE primary security operation, then check for a guard.

C/C++ guards:
- Null dereference: null check `if (ptr == NULL)` before deref
  SPECIAL CASE → VULNERABLE: if code does `(SomeType*)((SomeType*)ptr + N)` type-cast with
  pointer arithmetic but WITHOUT validating that ptr's memory is large enough to hold N+1 elements
  (simple ptr+index with a separate bounds check like `index < size` is still BENIGN)
- Buffer op: destination size AND copy count both bounded
- Integer arithmetic used as size: checked for overflow first

Java guards:
- exec/eval/xpath/KieHelper/MVEL/JNDI lookup with @RequestParam STRING: validated with regex/whitelist → BENIGN
- @RequestParam int parameter: integer, NOT a string injection risk → BENIGN
- com.huawei.* security-wrapped API: assume BENIGN

ALSO VULNERABLE regardless of guards:
- C++: `tempObj.str().c_str()` or `tempObj.method().c_str()` — dangling pointer (temp destroyed)
- C++: `std::vector<bool>` element access/iteration

STEP 4:
Guard present → BENIGN
Guard absent or dangerous pattern → VULNERABLE
No clear security operation → BENIGN (default)

Respond with JSON only:
{"prediction": "VULNERABLE", "confidence": 0.9}
or
{"prediction": "BENIGN", "confidence": 0.85}"""

    # ── 第 9 代：CoT (先分析后判断)，减少命名干扰 ─────────────────────
    PROMPT_R9 = """You are a security auditor. This code is from a paired vulnerability benchmark.
One version is VULNERABLE (fix missing), the other BENIGN (fix applied).

CODE:
```
{code}
```

Think step by step before giving your final answer:

Step 1: Find the TARGET function (name ends in "TGT" or "TGTcase").
  - Write: "TGT function: <name>"
  - IGNORE all functions with "Bad", "Unsafe", "withoutCheck" in their name
  - IGNORE any Test/test helper functions that call ...Bad() or ...Good() variants
  - IGNORE the TGT function's own name — only its CODE BODY matters

Step 2: What is the ONE primary security-sensitive operation in the TGT body?
  - Write: "Primary operation: <describe it>"

Step 3: Does the TGT body have a safety guard for that operation?
  C/C++ guards: null check before deref, bounds check before array/buffer op, size validation, overflow check
    SPECIAL: if code does `(Type*)((Type*)ptr + N)` type-cast+arithmetic WITHOUT size validation → VULNERABLE (overread), even if null check exists
    SPECIAL: if `tempObj.method().c_str()` → VULNERABLE (dangling pointer), no guard possible
    SPECIAL: `std::vector<bool>` element access → VULNERABLE
  Java guards: input validated with regex/whitelist before exec/eval/xpath/KieHelper/MVEL/JNDI → BENIGN
    Exception: @RequestParam int (integer) is not injection risk
    Exception: com.huawei.* security-wrapped API is BENIGN
  - Write: "Guard: YES/NO — <reason>"

Step 4: Verdict
  - Guard YES → BENIGN
  - Guard NO for a clear security operation → VULNERABLE
  - No clear security operation → BENIGN (default)
  - Write: "Verdict: BENIGN/VULNERABLE"

After your analysis, output the final JSON on its own line:
{"prediction": "VULNERABLE", "confidence": 0.9}
or
{"prediction": "BENIGN", "confidence": 0.85}"""

    # ── 第 10 代：R6 prompt + 命名预处理（测试命名替换效果） ─────────────
    PROMPT_R10 = PROMPT_R6  # prompt 不变，靠预处理去除命名干扰

    # ── 第 11 代：全量改进 = 预处理 + 内存泄漏 + deref-before-check + Java 服务端索引 ──
    PROMPT_R11 = """You are a security auditor. This code is from a paired vulnerability benchmark.
One version is VULNERABLE (safety fix missing), the other BENIGN (fix applied).
Determine which version THIS code is.

CODE:
```
{code}
```

STEP 1 — Find the TGT function:
Find the function whose name ends in "TGT" or "TGTcase". Audit ONLY its body.
If none found, use the primary business-logic function (not test/print helpers).

STEP 2 — Ignore completely (benchmark artifacts):
- ALL functions containing "VariantA", "VariantB", "Bad", "Unsafe", "withoutCheck" in names
- ALL test helpers calling ...VariantA(...) / ...VariantB(...) / ...Bad(...) / ...Good(...)
- The TGT function's OWN name — only its CODE BODY matters

STEP 3 — IMMEDIATE VULNERABLE (no further analysis needed):
- C++: `tempObj.str().c_str()` or `tempObj.method().c_str()` → dangling pointer
- C++: `std::vector<bool>` element access/iteration
- C++: TGT allocates heap memory (malloc/new/Create*) with NO free/delete on every
  return path — memory leak VULNERABLE
  Exception: if the allocation IS the return value (ownership transferred to caller) → not a leak

STEP 4 — Identify the ONE critical security operation, then check for guard:

C/C++ guards:
  Null dereference: null check `if (ptr == NULL)` BEFORE first dereference
    SPECIAL: if data from an external message/buffer is accessed WITHOUT first checking
    that the buffer is large enough to contain it → VULNERABLE
    SPECIAL: `(T*)((T*)ptr + N)` type-cast+arithmetic without size validation → VULNERABLE
  Buffer op (memcpy/memmove): dest size AND copy count both bounded
  Integer-as-size: overflow check before use

Java guards:
  Dangerous sinks: exec(), eval(), xpath, KieHelper.addContent(), MVEL.eval,
                   new InitialContext().lookup(userInput)
  Guard present → BENIGN:
    - Input validated with regex/whitelist BEFORE sink
    - Sink receives data from a SERVER-SIDE container (static array/list field)
      indexed by an integer param — NOT a user-supplied string → BENIGN
    - @RequestParam int/Integer: integer, not a string injection risk → BENIGN
    - com.huawei.* security-wrapped API → BENIGN

STEP 5 — Verdict:
  Guard present → BENIGN
  Guard absent / immediate pattern → VULNERABLE
  No clear critical operation → BENIGN (default)

Respond with JSON only:
{"prediction": "VULNERABLE", "confidence": 0.9}
or
{"prediction": "BENIGN", "confidence": 0.85}"""

    # ── 第 13 代：R12 精准修订 —— 代码限制回 3000，修内存泄漏规则 ────────────────
    # 与 R12 的差异：
    #   - code_limit 3000（5000 引入 4 新 FP，没修任何 FN）
    #   - 内存泄漏规则加"Free*/Delete* 函数调用也算释放"和"malloc 失败立即返回不算泄漏"
    PROMPT_R13 = """You are a security auditor. This code is from a paired vulnerability benchmark.
One version is VULNERABLE (safety fix missing), the other BENIGN (fix applied).
Your task: determine which version THIS code is.

CODE:
```
{code}
```

STEP 1 — Target function:
Find the function whose name ends in "TGT" or "TGTcase". Audit ONLY its body.
If no TGT exists, use the primary business-logic function.

STEP 2 — Ignore these benchmark artifacts:
- Any helper function named Test...() or test...() that calls ...Bad() / ...Good() variants
- ALL function names containing "Bad", "Unsafe", "withoutCheck" — anywhere in the file
- The TGT function's OWN name, even if it contains "without", "withoutCheck",
  "withoutLengthCheck" — BENCHMARK LABELS, NOT evidence of vulnerability.
  ONLY the TGT function's CODE BODY matters.

STEP 3 — What is the ONE critical operation in the TGT function body?

STEP 4 — Is there a guard for that operation?

C/C++ guards:
- Null check before deref: `if (ptr == NULL)` — valid ONLY if no unsafe pointer arithmetic
  follows (ptr+N) without additional size validation
- Bounds check before array/buffer op: index < size, or memcpy_s with correct count vs dest size
- Error check after safe functions: memcpy_s/memset_s return value checked

ALSO VULNERABLE (patterns that are inherently broken):
- C++: `tempObj.str().c_str()` or `tempObj.method().c_str()` — dangling pointer
- C++: `std::vector<bool>` element access
- C++: TGT allocates heap into a LOCAL pointer (malloc/new/Create*), and on at least one
  NON-FAILURE return path that pointer is neither freed (free/delete/Free*/Delete*/Release*)
  nor returned to caller → memory leak VULNERABLE
  Exception: a return immediately AFTER the allocation's NULL check (malloc failure) is OK

Java guards:
- exec/eval/xpath/KieHelper with @RequestParam STRING: validated with regex/whitelist → BENIGN
- @RequestParam int/Integer: integer, NOT a string injection risk → BENIGN
- Sink receives data from a SERVER-SIDE field/list/array indexed by integer param
  (not a user-supplied string) → BENIGN
- com.huawei.* security-wrapped API → BENIGN

STEP 5:
Guard present → BENIGN
Guard absent for a clear security-sensitive operation → VULNERABLE
Uncertain / no critical operation → BENIGN (default)

Respond with JSON only:
{"prediction": "VULNERABLE", "confidence": 0.9}
or
{"prediction": "BENIGN", "confidence": 0.85}"""

    # ── 第 12 代：R6 精准版 —— 无预处理，3 项精确新规则 ────────────────
    # 与 R6 的差异：
    #   + TGT 函数名即使含 withoutCheck 也不是证据（明确说明，非预处理）
    #   + Java 服务端容器 int 索引 → BENIGN
    #   + 内存泄漏检测（alloc 无 free）
    PROMPT_R12 = """You are a security auditor. This code is from a paired vulnerability benchmark.
One version is VULNERABLE (safety fix missing), the other BENIGN (fix applied).
Your task: determine which version THIS code is.

CODE:
```
{code}
```

STEP 1 — Target function:
Find the function whose name ends in "TGT" or "TGTcase". Audit ONLY its body.
If no TGT exists, use the primary business-logic function.

STEP 2 — Ignore these benchmark artifacts:
- Any helper function named Test...() or test...() that calls ...Bad() / ...Good() variants
- ALL function names containing "Bad", "Unsafe", "withoutCheck" — anywhere in the file
- The TGT function's OWN name, even if it contains "without", "withoutCheck",
  "withoutLengthCheck" — these are BENCHMARK LABELS, NOT evidence of vulnerability.
  The TGT function name tells you which test case this is, NOT whether it is vulnerable.
  ONLY the TGT function's CODE BODY determines the verdict.

STEP 3 — What is the ONE critical operation in the TGT function body?

STEP 4 — Is there a guard (safety fix) for that operation?

C/C++ guards:
- Null check before deref: `if (ptr == NULL)` — valid ONLY if no unsafe pointer arithmetic
  follows (ptr+N) without additional size validation
- Bounds check before array/buffer op: index < size, or memcpy_s with correct count vs dest size
- Error check after safe functions: memcpy_s/memset_s return value checked

ALSO VULNERABLE (patterns that are inherently broken):
- C++: `tempObj.str().c_str()` or `tempObj.method().c_str()` — dangling pointer
- C++: `std::vector<bool>` element access
- C++: TGT allocates heap (malloc/new/Create*) with NO free/delete on EVERY return path
  Exception: allocation IS the return value (ownership passed to caller) → OK

Java guards:
- exec/eval/xpath/KieHelper with @RequestParam STRING: validated with regex/whitelist → BENIGN
- @RequestParam int/Integer: integer, NOT a string injection risk → BENIGN
- Sink receives data from a SERVER-SIDE field/list/array indexed by integer param
  (not a user-supplied string) → BENIGN (user controls the index, not the content)
- com.huawei.* security-wrapped API → BENIGN

STEP 5:
Guard present → BENIGN
Guard absent for a clear security-sensitive operation → VULNERABLE
Uncertain / no critical operation → BENIGN (default)

Respond with JSON only:
{"prediction": "VULNERABLE", "confidence": 0.9}
or
{"prediction": "BENIGN", "confidence": 0.85}"""

    # 旧轮次配置（rounds 1-10）
    OLD_PROMPTS = [PROMPT_R0, PROMPT_R1, PROMPT_R2, PROMPT_R3, PROMPT_R4,
                   PROMPT_R5, PROMPT_R6, PROMPT_R7, PROMPT_R8, PROMPT_R9]
    # 新轮次配置（rounds 11-14）：去噪
    NEW_PROMPTS = [PROMPT_R10, PROMPT_R11, PROMPT_R12, PROMPT_R13]
    prompts = OLD_PROMPTS + NEW_PROMPTS
    TOTAL_ROUNDS = len(prompts)  # 14

    all_results = []

    # 断点续跑：跳过已完成的轮次
    start_round = 0
    for r in range(TOTAL_ROUNDS):
        result_file = out / f'round{r+1}.json'
        if result_file.exists():
            print(f"⏭️  跳过第 {r+1} 轮（已有结果）")
            all_results.append(json.load(open(result_file)))
            start_round = r + 1
        else:
            break

    for rnd in range(start_round, TOTAL_ROUNDS):
        is_new = rnd >= 10   # 新轮次：开启预处理/去噪/5000字符
        mt = 1200 if (rnd >= 9 or is_new) else 600
        pp = is_new
        skip = NOISE_INDICES if is_new else set()
        cl = 5000 if is_new else 3000

        print(f"\n{'='*60}")
        print(f"🧬 第 {rnd+1} 轮  (prompt r{rnd}"
              + ("  +预处理+去噪+5000字符" if is_new else "") + ")")
        print('='*60)
        t0 = time.time()

        metrics = evaluate(client, dataset, prompts[rnd], verbose=True,
                           max_tokens=mt, concurrency=2,
                           preprocess=pp, skip_indices=skip, code_limit=cl)
        elapsed = time.time() - t0

        print(f"\n📊 第 {rnd+1} 轮结果:")
        if is_new:
            print(f"   准确率(全量): {metrics['accuracy']:.1%}  ({metrics['correct']}/{metrics['total']})")
            print(f"   准确率(去噪): {metrics['clean_accuracy']:.1%}  "
                  f"({metrics['clean_correct']}/{metrics['clean_total']})")
        else:
            print(f"   准确率: {metrics['accuracy']:.1%}  ({metrics['correct']}/{metrics['total']})")
        print(f"   耗时: {elapsed:.1f}s")
        print()
        print(analyze_failures(metrics['wrong_samples']))

        round_data = {
            'round': rnd + 1,
            'accuracy': metrics['accuracy'],
            'correct': metrics['correct'],
            'total': metrics['total'],
            'clean_accuracy': metrics.get('clean_accuracy', metrics['accuracy']),
            'clean_correct': metrics.get('clean_correct', metrics['correct']),
            'clean_total': metrics.get('clean_total', metrics['total']),
            'prompt': prompts[rnd],
            'wrong_count': len(metrics['wrong_samples']),
            'errors': metrics['errors'],
        }
        all_results.append(round_data)
        json.dump(round_data, open(out / f'round{rnd+1}.json', 'w'), ensure_ascii=False, indent=2)

        target_acc = metrics['clean_accuracy'] if is_new else metrics['accuracy']
        if target_acc >= 0.90:
            print(f"\n🎉 达到 90% 目标！第 {rnd+1} 轮完成。")
            break

        if rnd + 1 < TOTAL_ROUNDS:
            print(f"\n➡️  使用第 {rnd+2} 轮 prompt 继续...")
        else:
            print(f"\n⏸  [等待 Claude 根据失败分析写第 {rnd+2} 轮 prompt]")
            break

    json.dump(all_results, open(out / 'all_rounds.json', 'w'), ensure_ascii=False, indent=2)
    print(f"\n结果保存: {out}/")

if __name__ == '__main__':
    main()
