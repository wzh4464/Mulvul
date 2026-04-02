# Evolutor 组件逻辑整理

## Mutator（变异器）
- 触发条件：基类在演化循环中为每个个体抛硬币，命中 `mutation_rate` 后才调用具体算法的 `mutate`，否则跳过。核心逻辑如下：

```python
# src/evoprompt/algorithms/base.py
for individual in population:
    if np.random.random() < self.mutation_rate:
        mutated = self.mutate(individual, llm_client)
        offspring.append(mutated)
```

- 遗传算法的 `mutate` 对 prompt 进行“小幅改写”。只有当 LLM 返回的文本非空且长度大于 10 时才视作成功，失败或异常则返回原始个体：

```python
# src/evoprompt/algorithms/genetic.py
response = llm_client.generate(mutation_prompt, temperature=0.8)
new_prompt = response.strip()
if new_prompt and len(new_prompt) > 10:
    return Individual(new_prompt)
return Individual(individual.prompt)
```

- 差分进化的 prompt 更新主要发生在 `crossover`：基于三条样本 prompt 引导 LLM 组合，若未生成有效文本则退回基准 prompt。额外的 `mutate` 只是微调，同样带有长度校验与回退：

```python
# src/evoprompt/algorithms/differential.py
mutant_prompt = llm_client.generate(de_prompt, temperature=0.6).strip()
if mutant_prompt and len(mutant_prompt) > 10:
    return [Individual(mutant_prompt)]
return [Individual(x_r1.prompt)]

new_prompt = llm_client.generate(mutation_prompt, temperature=0.5).strip()
if new_prompt and len(new_prompt) > 10:
    return Individual(new_prompt)
return Individual(individual.prompt)
```

## Selector（选择器）
- 遗传算法支持三种父代选择策略，通过配置项 `selection_method` 切换：  
  - `tournament`：随机抽取至多 `tournament_size` 个体，比较适应度选出胜者，重复两次得到双亲（`src/evoprompt/algorithms/genetic.py:48` 起）。  
  - `roulette`：根据适应度比例抽样，若存在负值会整体平移，适应度全为零时退化为随机选择（`src/evoprompt/algorithms/genetic.py:60` 起）。  
  - `random`：无偏随机挑选两个体（`src/evoprompt/algorithms/genetic.py:87` 起）。
- 精英保留：基类 `_select_survivors` 会按适应度降序排序，只保留前 `population_size` 个体进入下一代：

```python
# src/evoprompt/algorithms/base.py
population.sort_by_fitness()
survivors = population.individuals[:self.population_size]
return Population(survivors)
```

- 差分进化的成对选择：对每个目标个体构造试验个体后，逐位比较，只有试验的适应度更高时才替换目标，从而决定 prompt 是否更新：

```python
# src/evoprompt/algorithms/differential.py
if trial.fitness and target.fitness and trial.fitness > target.fitness:
    final_individuals.append(trial)
else:
    final_individuals.append(target)
```

## 统计反馈（高级 LLM 总结）
- 批次（generation）级别的统计最容易插入在基类主循环中：每轮完成 `evaluate_population`、生成 `offspring` 并合并后，已经掌握了当前批次的所有适应度信息，此时可以调用高阶模型生成总结，再决定是否记录或回传。
- 建议在 `_select_survivors` 之前插入，如下伪代码所示；这样既能访问当代的全部个体，也不会影响后续的精英筛选：

```python
# src/evoprompt/algorithms/base.py（示意位置）
all_individuals = population.individuals + offspring
all_population = Population(all_individuals)
all_population = self.evaluate_population(all_population, evaluator)

# 在这里汇总 batch 统计信息
summary_prompt = build_summary_prompt(all_population)
summary_text = analytics_llm.generate(summary_prompt, temperature=0.0)
logger.info("Generation %s summary:\n%s", generation, summary_text)

population = self._select_survivors(all_population)
```

- `build_summary_prompt` 可以收集指标（平均/最高/最低适应度、典型改写片段等），并通过高阶模型输出“做得好/做得不好”的要点。若需跨多轮统计，可在 `EvolutionAlgorithm` 中维护累积结构，再在迭代末或 `evolve` 结束时统一总结。建议把额外依赖（如新的 LLM client 或日志器）通过配置字典传入，保持现有 API 向下兼容。
