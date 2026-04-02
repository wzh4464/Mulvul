#!/usr/bin/env python
import argparse
from src.evoprompt.workflows.cwe_research_concepts import run_cwe_rc_workflow


def main():
    p = argparse.ArgumentParser(description="Run CWE Research Concepts evolution")
    p.add_argument("--dev_file", required=True)
    p.add_argument("--test_file", required=False)
    p.add_argument("--dataset", default="primevul")
    p.add_argument("--algorithm", default="de", choices=["de", "ga"])
    p.add_argument("--population_size", type=int, default=10)
    p.add_argument("--generations", type=int, default=5)
    p.add_argument("--mutation_rate", type=float, default=0.1)
    p.add_argument("--llm_type", default="gpt-3.5-turbo")
    p.add_argument("--sample_size", type=int, default=50)
    p.add_argument("--test_sample_size", type=int, default=100)
    p.add_argument("--output_dir", default="/workspace/outputs/cwe_results")
    p.add_argument("--initial_prompts_file", default=None)
    args = p.parse_args()

    res = run_cwe_rc_workflow(
        dataset=args.dataset,
        algorithm=args.algorithm,
        population_size=args.population_size,
        max_generations=args.generations,
        mutation_rate=args.mutation_rate,
        llm_type=args.llm_type,
        sample_size=args.sample_size,
        test_sample_size=args.test_sample_size,
        output_dir=args.output_dir,
        dev_file=args.dev_file,
        test_file=args.test_file or args.dev_file,
        initial_prompts_file=args.initial_prompts_file,
    )

    print("Best fitness:", res.get("best_fitness"))


if __name__ == "__main__":
    main()