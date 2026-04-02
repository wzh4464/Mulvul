# Experiment Todos

## Stage 1 — Baseline audit
- [x] Inspect current Layer-1 pipeline, metrics, prompts, sampler, and prior results
- [x] Save research request
- [x] Draft experiment plan and success signals

## Stage 2 — Minimal high-value fixes
- [ ] Change fitness from accuracy to macro-F1
- [ ] Fix/extend CLI and config for layer1 balancing and evaluation options
- [ ] Improve sampling so training can retain Benign and evaluation can be more trustworthy
- [ ] Add prompt sanitization and few-shot support for minority classes

## Stage 3 — Validation
- [ ] Run a smoke test on reduced generations
- [ ] Run a stronger experiment if smoke test is stable
- [ ] Compare against baseline on macro-F1 and per-class F1

## Success signals
- Smoke test completes without malformed prompt failures
- Full experiment improves macro-F1 over 0.17 baseline
- Stretch target: macro-F1 > 0.30 on 11-class task
