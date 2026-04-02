# Research Request

Goal: Improve PrimeVul Layer-1 CWE Classification (11-class) in /home/jie/Evoprompt.

Current best result (layer1_20251030_172442): accuracy 0.6683 on 828 samples, macro-F1 0.17, with severe failure on minority classes.

Requested focus:
1. Sampling strategy to address class imbalance and ensure adequate category representation in evaluation
2. Prompt engineering to improve multi-class discrimination
3. Evolution algorithm tuning (batch_size, generations, mutation strategy)
4. Evaluation metric: consider macro-F1 instead of accuracy as fitness
5. Few-shot examples for minority classes in prompts

Constraints:
- Use the codebase at /home/jie/Evoprompt
- Use the LLM API from .env
- All Python commands must use: uv run python
- Validate improvements with experiments
- Target: macro-F1 > 0.30 on the full 11-class task
