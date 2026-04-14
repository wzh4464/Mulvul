# Full-Sample Hybrid CWD Cascade Run

## Summary
- Timestamp: 20260415_021603
- Backend: openrouter_hybrid_leaf_binary
- Model: openai/gpt-5.4
- Eval variants: 1341
- Dev variants for threshold calibration: 48
- Support variants for prototype calibration/tie-break: 1293
- Evolved leaf prompts loaded: 33 / 35
- Fallback leaf prompts: 2
- Sample workers: 4

## Calibration
- Thresholds: major=0.16, middle=0.14, cwe=0.12
- Dev exact match: 0.167
- Dev path coverage: 0.750

## Final Metrics
| Metric | Value |
|---|---:|
| Final exact match | 0.296 |
| Major accuracy | 0.505 |
| Middle accuracy | 0.523 |
| CWD accuracy | 0.336 |
| Vulnerable vs Benign F1 | 0.725 |
| Macro F1 | 0.158 |
| Path coverage | 0.544 |
| Major route recall@1 | 0.391 |
| Middle route recall@1 | 0.286 |
| Avg nodes scored/sample | 14.90 |

## Stage Activity
- Major accept rate: 1.000
- Middle trigger rate: 0.688
- CWD trigger rate: 0.657
- Non-benign prediction rate: 0.846

## Notes
- Major and middle nodes use the current `ranking_v2` cascade prompts.
- CWD leaf nodes use the best concrete binary prompts recovered from `node_evolution_runs` when available.
- Prototype similarity is used only for threshold calibration and leaf tie-breaking, not as the final classifier.
