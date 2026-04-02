#!/usr/bin/env python3
"""完整的三层检测训练脚本

支持:
- RAG增强 (可选)
- Scale增强 (可选)
- Multi-agent协同进化
- 层级训练策略
"""

import asyncio
import os
import sys
import json
import argparse
import time
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from mulvul.prompts.hierarchical_three_layer import (
    ThreeLayerPromptFactory,
    ThreeLayerPromptSet,
)
from mulvul.detectors.three_layer_detector import ThreeLayerDetector, ThreeLayerEvaluator
from mulvul.detectors.rag_three_layer_detector import RAGThreeLayerDetector
from mulvul.detectors.parallel_hierarchical_detector import (
    ParallelHierarchicalDetector,
    create_parallel_detector,
)
from mulvul.rag.knowledge_base import KnowledgeBase, KnowledgeBaseBuilder
from mulvul.data.dataset import PrimevulDataset
from mulvul.llm.client import load_env_vars, create_llm_client
from mulvul.llm.async_client import AsyncLLMClient
from mulvul.multiagent.agents import create_detection_agent, create_meta_agent
from mulvul.multiagent.coordinator import MultiAgentCoordinator, CoordinatorConfig
from mulvul.algorithms.coevolution import CoevolutionaryAlgorithm
from mulvul.utils.trace import TraceManager, TraceConfig, trace_enabled_from_env
from mulvul.core.prompt_change_logger import PromptChangeLogger


# ---------------------------------------------------------------------------
# Baseline prompt constants
# ---------------------------------------------------------------------------

GPT4O_RAG_PROMPT = """You are a security code auditor. Follow the output format exactly.

Given the following C/C++ code and retrieved vulnerability knowledge evidence, decide whether the code contains a vulnerability and identify the most likely CWE type.

Instructions:
- Analyze the code carefully for common vulnerability patterns (buffer overflows, null dereferences, integer overflows, use-after-free, injection, etc.).
- Use the retrieved evidence as additional context to support or inform your analysis.
- If evidence examples show similar vulnerable patterns, cite their IDs.
- If no vulnerability is found after thorough analysis, output "NONE".
- Output must be JSON with keys: "cwe" (string "CWE-XXX" or "NONE"), "rationale" (1-3 sentences), "evidence_ids" (list of IDs used)

[CODE]
{code_snippet}

[EVIDENCE]
{packed_evidence_with_ids}"""

AGENT_TOOL_PROMPT = """You are a security code auditor with access to a retrieval tool.

Task: Identify the most likely CWE type for the given code (or "NONE" if no vulnerability).

You may call the tool:
- SEARCH(query, top_k) - searches vulnerability knowledge base, returns similar code examples

Rules:
- At most {max_tool_calls} tool calls.
- Use evidence to justify your answer.
- Final answer must be JSON with keys: "cwe", "rationale", "evidence_ids"

Code to analyze:
{code_snippet}

If you want to search, respond with: SEARCH("your query", top_k)
When ready to give final answer, respond with JSON."""


def setup_environment():
    """配置环境"""
    load_env_vars()

    api_key = os.getenv("API_KEY")
    if not api_key:
        print("❌ API_KEY not found in .env")
        return False

    print("✅ Environment configured:")
    print(f"   Detection Model: {os.getenv('MODEL_NAME', 'gpt-4')}")
    print(f"   Meta Model: {os.getenv('META_MODEL_NAME', 'claude-4.5')}")

    return True


def load_or_build_knowledge_base(args):
    """加载或构建知识库

    Args:
        args: 命令行参数

    Returns:
        KnowledgeBase or None
    """
    if not args.use_rag:
        print("\n⏭️  RAG disabled, skipping knowledge base")
        return None

    print("\n📚 Knowledge Base Setup")
    print("=" * 70)

    # 检查是否有已存在的知识库
    if args.kb_path and Path(args.kb_path).exists():
        print(f"   📖 Loading existing KB: {args.kb_path}")
        kb = KnowledgeBase.load(args.kb_path)
        stats = kb.statistics()
        print(f"   ✅ Loaded {stats['total_examples']} examples")

        # Build clean pool if missing and needed for contrastive retrieval
        needs_clean = getattr(args, 'method', 'mulvul') in (
            'gpt4o_rag_singlepass', 'single_agent_tool_rag', 'clean_pool_sensitivity',
        )
        if needs_clean and len(kb.clean_examples) == 0:
            print("   🧹 Building clean pool for contrastive retrieval...")
            from mulvul.rag.knowledge_base import build_clean_pool_from_dataset
            train_dataset = PrimevulDataset(args.train_file, "train")
            build_clean_pool_from_dataset(kb, train_dataset, max_samples=500, seed=42)
            print(f"   ✅ Added {len(kb.clean_examples)} clean examples")

        return kb

    # 构建新知识库
    print("   🔨 Building new knowledge base...")

    if args.kb_from_dataset:
        # 从数据集构建
        print(f"   📂 Source: Dataset ({args.kb_samples_per_category} samples/category)")
        dataset = PrimevulDataset(args.train_file, "train")

        from mulvul.rag.knowledge_base import create_knowledge_base_from_dataset
        import tempfile

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_path = f.name

        try:
            kb = create_knowledge_base_from_dataset(
                dataset,
                temp_path,
                samples_per_category=args.kb_samples_per_category
            )
            kb = KnowledgeBase.load(temp_path)
        finally:
            if Path(temp_path).exists():
                Path(temp_path).unlink()
    else:
        # 使用默认示例
        print("   📦 Source: Default examples")
        kb = KnowledgeBaseBuilder.create_default_kb()

    stats = kb.statistics()
    print(f"   ✅ Built KB with {stats['total_examples']} examples")

    # 保存知识库
    if args.kb_path:
        Path(args.kb_path).parent.mkdir(parents=True, exist_ok=True)
        kb.save(args.kb_path)
        print(f"   💾 Saved to: {args.kb_path}")

    return kb


def create_detector(prompt_set, llm_client, kb, args):
    """创建检测器

    Args:
        prompt_set: Prompt集合
        llm_client: LLM客户端
        kb: 知识库 (可为None)
        args: 命令行参数

    Returns:
        检测器实例
    """
    print("\n🔧 Creating Detector")
    print("=" * 70)

    if args.detector == "parallel":
        print("   🎯 Type: Parallel Hierarchical Detector")
        print(f"   ⚡ Scale enhancement: {args.use_scale}")
        print(f"   📊 Layer1 top-k: {args.layer1_top_k}")
        print(f"   📊 Layer2 top-k: {args.layer2_top_k}")
        print(f"   📊 Layer3 top-k: {args.layer3_top_k}")
        print(f"   🚦 Max concurrency: {args.parallel_max_concurrency}")
        if args.use_rag:
            print(f"   🔍 RAG: enabled (top_k={args.rag_top_k}, retriever={args.rag_retriever_type})")

        async_client = AsyncLLMClient(
            api_base=os.getenv("API_BASE_URL"),
            api_key=os.getenv("API_KEY"),
            model_name=os.getenv("MODEL_NAME", "gpt-4"),
            max_concurrency=args.parallel_max_concurrency,
        )

        detector = create_parallel_detector(
            llm_client=async_client,
            prompt_set=prompt_set,
            enable_enhancement=args.use_scale,
            layer1_top_k=args.layer1_top_k,
            layer2_top_k=args.layer2_top_k,
            layer3_top_k=args.layer3_top_k,
            max_concurrent_requests=args.parallel_max_concurrency,
            knowledge_base=kb,
            enable_rag=args.use_rag,
            rag_top_k=args.rag_top_k,
            rag_retriever_type=args.rag_retriever_type,
        )
    elif args.use_rag and kb is not None:
        print(f"   🎯 Type: RAG-Enhanced Three-Layer")
        print(f"   📊 RAG top-k: {args.rag_top_k}")
        print(f"   🔍 Retriever: {args.rag_retriever_type}")
        print(f"   ⚡ Scale enhancement: {args.use_scale}")

        detector = RAGThreeLayerDetector(
            prompt_set=prompt_set,
            llm_client=llm_client,
            knowledge_base=kb,
            use_scale_enhancement=args.use_scale,
            retriever_type=args.rag_retriever_type,
            top_k=args.rag_top_k
        )
    else:
        print(f"   🎯 Type: Basic Three-Layer")
        print(f"   ⚡ Scale enhancement: {args.use_scale}")

        detector = ThreeLayerDetector(
            prompt_set=prompt_set,
            llm_client=llm_client,
            use_scale_enhancement=args.use_scale
        )

    return detector


def run_evaluation(detector, dataset, args, trace_manager: TraceManager = None):
    """运行评估

    Args:
        detector: 检测器
        dataset: 数据集
        args: 命令行参数

    Returns:
        评估指标字典
    """
    print("\n📊 Running Evaluation")
    print("=" * 70)

    eval_count = args.eval_samples if args.eval_samples is not None else "all"
    print(f"   🔍 Evaluating on {eval_count} samples...")
    start = time.time()

    if isinstance(detector, ParallelHierarchicalDetector):
        metrics = run_parallel_evaluation(detector, dataset, args)
    else:
        evaluator = ThreeLayerEvaluator(detector, dataset)
        # 使用verbose=True打印详细的Macro/Weighted/Micro F1
        metrics = evaluator.evaluate(sample_size=args.eval_samples, verbose=True)

    elapsed = time.time() - start

    print(f"\n   ✅ Evaluation completed in {elapsed:.1f}s")

    if trace_manager and trace_manager.enabled:
        trace_manager.log_event(
            "evaluation",
            {
                "mode": "baseline" if not args.train else "evaluation",
                "metrics": metrics,
                "eval_samples": args.eval_samples,
            },
        )

    return metrics


def run_parallel_evaluation(detector, dataset, args):
    """并行检测器评估。

    复用三层评估口径，便于和串行检测器对齐对比。
    """
    from mulvul.prompts.hierarchical_three_layer import get_full_path
    from mulvul.evaluators.multiclass_metrics import MultiClassMetrics

    all_samples = dataset.get_samples()

    # Filter to samples with valid CWE + resolvable full path
    valid_samples = []
    for s in all_samples:
        cwes = s.metadata.get("cwe", []) if hasattr(s, "metadata") else []
        if not cwes:
            continue
        major, middle, _ = get_full_path(cwes[0])
        if major and middle:
            valid_samples.append(s)

    if args.eval_samples is not None:
        samples = valid_samples[: args.eval_samples]
    else:
        samples = valid_samples

    print(f"   📋 CWE-labeled samples: {len(valid_samples)} / {len(all_samples)}, evaluating {len(samples)}")

    # Batch detect using a single event loop to avoid aiohttp session issues
    codes = [s.input_text for s in samples]
    all_paths = asyncio.run(detector.detect_batch_async(codes, show_progress=True))

    layer1_metrics = MultiClassMetrics()
    layer2_metrics = MultiClassMetrics()
    layer3_metrics = MultiClassMetrics()

    stats = {
        "total": 0,
        "full_path_correct": 0,
    }
    results = []

    for sample, paths in zip(samples, all_paths):
        cwes = sample.metadata.get("cwe", [])
        actual_cwe = cwes[0]
        actual_major, actual_middle, _ = get_full_path(actual_cwe)

        top_path = paths[0] if paths else None

        predicted_major = top_path.layer1_category if top_path else "Unknown"
        predicted_middle = top_path.layer2_category if (top_path and top_path.layer2_category) else "Unknown"
        predicted_cwe = top_path.layer3_cwe if (top_path and top_path.layer3_cwe) else "Unknown"

        stats["total"] += 1

        layer1_metrics.add_prediction(predicted_major, actual_major.value)
        layer2_metrics.add_prediction(predicted_middle, actual_middle.value)
        layer3_metrics.add_prediction(predicted_cwe, actual_cwe)

        if (
            predicted_major == actual_major.value
            and predicted_middle == actual_middle.value
            and predicted_cwe == actual_cwe
        ):
            stats["full_path_correct"] += 1

        results.append(
            {
                "actual_major": actual_major.value,
                "actual_middle": actual_middle.value,
                "actual_cwe": actual_cwe,
                "predicted_major": predicted_major,
                "predicted_middle": predicted_middle,
                "predicted_cwe": predicted_cwe,
            }
        )

    metrics = {
        "total_samples": stats["total"],
        "layer1": {
            "accuracy": round(layer1_metrics.accuracy, 4),
            "macro_f1": round(layer1_metrics.compute_macro_f1(), 4),
            "weighted_f1": round(layer1_metrics.compute_weighted_f1(), 4),
            "micro_f1": round(layer1_metrics.compute_micro_f1(), 4),
            "macro_precision": round(layer1_metrics.compute_macro_precision(), 4),
            "macro_recall": round(layer1_metrics.compute_macro_recall(), 4),
        },
        "layer2": {
            "accuracy": round(layer2_metrics.accuracy, 4),
            "macro_f1": round(layer2_metrics.compute_macro_f1(), 4),
            "weighted_f1": round(layer2_metrics.compute_weighted_f1(), 4),
            "micro_f1": round(layer2_metrics.compute_micro_f1(), 4),
            "macro_precision": round(layer2_metrics.compute_macro_precision(), 4),
            "macro_recall": round(layer2_metrics.compute_macro_recall(), 4),
        },
        "layer3": {
            "accuracy": round(layer3_metrics.accuracy, 4),
            "macro_f1": round(layer3_metrics.compute_macro_f1(), 4),
            "weighted_f1": round(layer3_metrics.compute_weighted_f1(), 4),
            "micro_f1": round(layer3_metrics.compute_micro_f1(), 4),
            "macro_precision": round(layer3_metrics.compute_macro_precision(), 4),
            "macro_recall": round(layer3_metrics.compute_macro_recall(), 4),
        },
        "full_path_accuracy": round(
            stats["full_path_correct"] / stats["total"] if stats["total"] > 0 else 0,
            4,
        ),
        "sample_results": results[:10],
        "detector_mode": "parallel",
    }

    print("\n" + "=" * 70)
    print("PARALLEL DETECTOR EVALUATION RESULTS")
    print("=" * 70)
    print(f"\nTotal Samples: {metrics['total_samples']}")
    print(f"Full Path Accuracy: {metrics['full_path_accuracy']:.4f}")
    print(f"Layer1 Accuracy: {metrics['layer1']['accuracy']:.4f}")
    print(f"Layer2 Accuracy: {metrics['layer2']['accuracy']:.4f}")
    print(f"Layer3 Accuracy: {metrics['layer3']['accuracy']:.4f}")

    return metrics


def run_training(initial_prompt_set, detector, dataset, kb, args, trace_manager: TraceManager = None, prompt_change_logger: PromptChangeLogger = None):
    """运行训练

    Args:
        initial_prompt_set: 初始prompt集合
        detector: 检测器
        dataset: 数据集
        kb: 知识库
        args: 命令行参数
        prompt_change_logger: Always-on prompt change logger

    Returns:
        优化后的prompt集合
    """
    print("\n🚀 Starting Training")
    print("=" * 70)

    # 创建agents
    print("   🤖 Creating agents...")
    from mulvul.llm.client import OpenAICompatibleClient
    detection_llm = OpenAICompatibleClient(
        api_base=os.getenv("API_BASE_URL"),
        api_key=os.getenv("API_KEY"),
        model_name=os.getenv("MODEL_NAME", "gpt-4"),
    )
    detection_agent = create_detection_agent(
        model_name=os.getenv("MODEL_NAME", "gpt-4"),
        llm_client=detection_llm,
    )
    meta_agent = create_meta_agent(
        model_name=os.getenv("META_MODEL_NAME", "claude-4.5")
    )

    # 创建协调器
    print("   🎯 Creating coordinator...")
    coordinator_config = CoordinatorConfig(
        batch_size=args.batch_size,
        enable_batch_feedback=True,
        statistics_window=5
    )
    coordinator = MultiAgentCoordinator(
        detection_agent=detection_agent,
        meta_agent=meta_agent,
        config=coordinator_config,
        trace_manager=trace_manager,
        prompt_change_logger=prompt_change_logger,
    )

    # 创建进化算法配置
    print("   🧬 Creating evolution algorithm...")
    config = {
        "population_size": args.population_size,
        "max_generations": args.max_generations,
        "elite_size": args.elite_size,
        "mutation_rate": args.mutation_rate,
        "meta_improve_interval": args.meta_improve_interval,
        "meta_improve_count": args.meta_improve_count,
        "top_k": args.elite_size,
        "enable_elitism": True,
        "meta_improvement_rate": 0.3,
        "eval_sample_size": args.batch_size,
    }

    algorithm = CoevolutionaryAlgorithm(
        config=config,
        coordinator=coordinator,
        dataset=dataset
    )

    print()
    print(f"   📋 Configuration:")
    print(f"      Population: {args.population_size}")
    print(f"      Generations: {args.max_generations}")
    print(f"      Elite size: {args.elite_size}")
    print(f"      Mutation rate: {args.mutation_rate}")
    print(f"      Batch size: {args.batch_size}")
    print(f"      Meta improve interval: {args.meta_improve_interval}")
    print(f"      Meta improve count: {args.meta_improve_count}")

    # 运行进化
    print()
    print("   🎬 Starting evolution...")
    print("=" * 70)

    # 提取初始prompts - 使用layer1 prompt作为初始种群
    # TODO: 未来应该支持完整的三层prompt集合优化
    initial_prompts = [initial_prompt_set.layer1_prompt]

    if trace_manager and trace_manager.enabled:
        trace_manager.save_prompt_snapshot(
            "initial_layer1_prompt",
            initial_prompt_set.layer1_prompt,
            metadata={"stage": "initialization"},
        )

    evolution_result = algorithm.evolve(initial_prompts=initial_prompts)

    print()
    print("   ✅ Training completed!")
    print(f"      Best fitness: {evolution_result['best_fitness']:.4f}")

    # TODO: 将best_individual.prompt转换回ThreeLayerPromptSet
    # 目前返回初始prompt集合
    if trace_manager and trace_manager.enabled:
        trace_manager.log_event(
            "training_complete",
            {
                "best_fitness": evolution_result.get("best_fitness"),
            },
        )

    return initial_prompt_set


def save_results(output_dir, metrics, prompt_set, args):
    """保存结果

    Args:
        output_dir: 输出目录
        metrics: 评估指标
        prompt_set: Prompt集合
        args: 命令行参数
    """
    print(f"\n💾 Saving Results to: {output_dir}")
    print("=" * 70)

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # 保存配置
    config = {
        "detector": args.detector,
        "use_rag": args.use_rag,
        "use_scale": args.use_scale,
        "rag_top_k": args.rag_top_k if args.use_rag else None,
        "rag_retriever_type": args.rag_retriever_type if args.use_rag else None,
        "layer1_top_k": args.layer1_top_k if args.detector == "parallel" else None,
        "layer2_top_k": args.layer2_top_k if args.detector == "parallel" else None,
        "layer3_top_k": args.layer3_top_k if args.detector == "parallel" else None,
        "parallel_max_concurrency": args.parallel_max_concurrency if args.detector == "parallel" else None,
        "train": args.train,
        "population_size": args.population_size if args.train else None,
        "max_generations": args.max_generations if args.train else None,
        "timestamp": datetime.now().isoformat(),
    }

    with open(output_dir / "config.json", "w") as f:
        json.dump(config, f, indent=2)
    print("   ✅ config.json")

    # 保存评估结果
    with open(output_dir / "metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)
    print("   ✅ metrics.json")

    # 保存prompt集合
    with open(output_dir / "prompts.json", "w") as f:
        json.dump(prompt_set.to_dict(), f, indent=2, ensure_ascii=False)
    print("   ✅ prompts.json")

    # 保存可读的prompt文本
    with open(output_dir / "prompts.txt", "w", encoding="utf-8") as f:
        f.write("="*70 + "\n")
        f.write("Three-Layer Prompts\n")
        f.write("="*70 + "\n\n")

        f.write("LAYER 1 PROMPT\n")
        f.write("-"*70 + "\n")
        f.write(prompt_set.layer1_prompt + "\n\n")

        f.write("LAYER 2 PROMPTS\n")
        f.write("-"*70 + "\n")
        for cat, prompt in prompt_set.layer2_prompts.items():
            f.write(f"\n[{cat.value}]\n")
            f.write(prompt + "\n")

        f.write("\nLAYER 3 PROMPTS\n")
        f.write("-"*70 + "\n")
        for cat, prompt in prompt_set.layer3_prompts.items():
            f.write(f"\n[{cat.value}]\n")
            f.write(prompt + "\n")
    print("   ✅ prompts.txt")

    print(f"\n📁 All results saved to: {output_dir}")


# ---------------------------------------------------------------------------
# Baseline helpers
# ---------------------------------------------------------------------------


def parse_baseline_response(response: str) -> dict:
    """Parse JSON response from baseline models."""
    import re as _re

    # Try to extract JSON from response
    try:
        json_match = _re.search(r'\{[^{}]*\}', response, _re.DOTALL)
        if json_match:
            data = json.loads(json_match.group())
            return {
                'cwe': data.get('cwe', 'NONE'),
                'rationale': data.get('rationale', ''),
                'evidence_ids': data.get('evidence_ids', []),
                'raw_response': response,
            }
    except json.JSONDecodeError:
        pass

    # Fallback: extract CWE pattern
    cwe_match = _re.search(r'CWE-\d+', response)
    if cwe_match:
        return {
            'cwe': cwe_match.group(),
            'rationale': response[:200],
            'evidence_ids': [],
            'raw_response': response,
        }

    return {
        'cwe': 'NONE',
        'rationale': response[:200],
        'evidence_ids': [],
        'raw_response': response,
    }


def filter_cwe_labeled_samples(dataset, max_samples=None):
    """Filter dataset to samples with valid CWE labels (matching MulVul eval).

    Returns list of samples that have CWE metadata and can be resolved
    to a full path in the three-layer hierarchy.
    """
    from mulvul.prompts.hierarchical_three_layer import get_full_path

    all_samples = dataset.get_samples()
    valid = []
    for s in all_samples:
        cwes = s.metadata.get("cwe", []) if hasattr(s, "metadata") else []
        if not cwes:
            continue
        major, middle, _ = get_full_path(cwes[0])
        if major and middle:
            valid.append(s)

    if max_samples is not None:
        valid = valid[:max_samples]

    print(f"   CWE-labeled samples: {len(valid)} / {len(all_samples)}, using {len(valid)}")
    return valid


def compute_baseline_metrics(results: list) -> dict:
    """Compute multi-class Macro-F1 (by CWE) + binary metrics.

    Matches the MulVul evaluation pipeline so numbers are directly comparable.
    """
    from mulvul.evaluators.multiclass_metrics import MultiClassMetrics

    # Multi-class CWE metrics
    cwe_metrics = MultiClassMetrics()
    # Binary vuln/benign metrics
    tp = fp = fn = tn = 0

    for r in results:
        predicted_cwe = r.get('cwe', 'NONE')
        actual_vuln = str(r.get('ground_truth', '0')) == '1'

        # For multi-class CWE: benign samples have actual_cwe = "NONE"
        # (even if they carry CWE metadata from the patched-pair labeling)
        gt_cwes = r.get('ground_truth_cwe', [])
        actual_cwe = gt_cwes[0] if (gt_cwes and actual_vuln) else 'NONE'

        # Multi-class: predicted CWE vs actual CWE
        cwe_metrics.add_prediction(predicted_cwe, actual_cwe)

        # Binary
        predicted_vuln = predicted_cwe != 'NONE'
        if predicted_vuln and actual_vuln:
            tp += 1
        elif predicted_vuln and not actual_vuln:
            fp += 1
        elif not predicted_vuln and actual_vuln:
            fn += 1
        else:
            tn += 1

    total = tp + fp + fn + tn
    accuracy = (tp + tn) / total if total > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    macro_f1 = cwe_metrics.compute_macro_f1()

    metrics = {
        'macro_f1': round(macro_f1, 4),
        'macro_precision': round(cwe_metrics.compute_macro_precision(), 4),
        'macro_recall': round(cwe_metrics.compute_macro_recall(), 4),
        'cwe_accuracy': round(cwe_metrics.accuracy, 4),
        'binary_accuracy': round(accuracy, 4),
        'binary_precision': round(precision, 4),
        'binary_recall': round(recall, 4),
        'binary_f1': round(f1, 4),
        'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn,
        'total': total,
    }
    print(f"\n   Baseline Metrics:")
    print(f"   Macro-F1 (CWE):  {metrics['macro_f1']:.4f}")
    print(f"   CWE Accuracy:    {metrics['cwe_accuracy']:.4f}")
    print(f"   Binary F1:       {metrics['binary_f1']:.4f}")
    print(f"   Binary Precision:{metrics['binary_precision']:.4f}")
    print(f"   Binary Recall:   {metrics['binary_recall']:.4f}")
    print(f"   (TP={tp} FP={fp} FN={fn} TN={tn})")
    return metrics


def save_baseline_results(output_dir: str, method: str, results: list, metrics: dict):
    """Save baseline results and metrics to output directory."""
    out = Path(output_dir)
    metrics_dir = out / "metrics"
    metrics_dir.mkdir(parents=True, exist_ok=True)

    with open(metrics_dir / f"{method}_metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)

    results_dir = out / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    with open(results_dir / f"{method}_results.jsonl", "w") as f:
        for r in results:
            f.write(json.dumps(r, default=str) + "\n")

    print(f"\n   Saved metrics to: {metrics_dir / f'{method}_metrics.json'}")
    print(f"   Saved results to: {results_dir / f'{method}_results.jsonl'}")


async def run_gpt4o_rag_singlepass(samples, retriever, llm_client, cost_tracker, args) -> list:
    """Run GPT-4o + RAG single-pass baseline.

    Args:
        samples: Pre-filtered list of samples to evaluate.
    """
    results = []

    print(f"   Running GPT-4o + RAG single-pass on {len(samples)} samples...")

    for i, sample in enumerate(samples):
        sample_id = sample.metadata.get('idx', i)
        cost_tracker.start_sample(sample_id, 'gpt4o_rag_singlepass')

        # Retrieve contrastive evidence
        retrieval_start = time.perf_counter()
        evidence = retriever.retrieve_contrastive(
            sample.input_text,
            vulnerable_top_k=args.top_k,
            clean_top_k=args.clean_top_k,
        )
        retrieval_time = (time.perf_counter() - retrieval_start) * 1000
        cost_tracker.log_retrieval_call(args.top_k + args.clean_top_k, retrieval_time)

        # Single LLM call
        prompt = GPT4O_RAG_PROMPT.format(
            code_snippet=sample.input_text[:4000],
            packed_evidence_with_ids=evidence.formatted_text,
        )

        response = await llm_client.generate_async(prompt)

        # Parse response
        prediction = parse_baseline_response(response)
        prediction['ground_truth'] = sample.target
        prediction['ground_truth_cwe'] = sample.metadata.get('cwe', [])
        results.append(prediction)

        cost_tracker.end_sample()

        if (i + 1) % 100 == 0:
            print(f"   Processed {i + 1}/{len(samples)} samples")

    return results


async def run_single_agent_tool_rag(samples, retriever, llm_client, cost_tracker, args) -> list:
    """Run Single-Agent + Tool + RAG baseline.

    Args:
        samples: Pre-filtered list of samples to evaluate.
    """
    import re as _re

    results = []

    print(f"   Running Single-Agent + Tool + RAG on {len(samples)} samples...")

    for i, sample in enumerate(samples):
        sample_id = sample.metadata.get('idx', i)
        cost_tracker.start_sample(sample_id, 'single_agent_tool_rag')

        # Initial prompt
        prompt = AGENT_TOOL_PROMPT.format(
            max_tool_calls=args.max_tool_calls,
            code_snippet=sample.input_text[:4000],
        )

        tool_calls_used = 0
        conversation = prompt
        response = ""

        while tool_calls_used < args.max_tool_calls:
            response = await llm_client.generate_async(conversation)

            # Check for SEARCH tool call
            search_match = _re.search(
                r'SEARCH\s*\(\s*["\']([^"\']+)["\'],?\s*(\d+)?\s*\)', response,
            )

            if search_match:
                query = search_match.group(1)
                top_k = int(search_match.group(2)) if search_match.group(2) else 3

                # Execute retrieval
                retrieval_start = time.perf_counter()
                evidence = retriever.retrieve_contrastive(query, top_k, 1)
                retrieval_time = (time.perf_counter() - retrieval_start) * 1000
                cost_tracker.log_retrieval_call(top_k + 1, retrieval_time)

                # Continue conversation
                conversation = (
                    f"{conversation}\n\nAssistant: {response}\n\n"
                    f"[TOOL RESULT]\n{evidence.formatted_text}\n\n"
                    f"Now provide your final JSON answer:"
                )
                tool_calls_used += 1
            else:
                # Final answer (no SEARCH call)
                break

        # Parse final response
        prediction = parse_baseline_response(response)
        prediction['ground_truth'] = sample.target
        prediction['ground_truth_cwe'] = sample.metadata.get('cwe', [])
        prediction['tool_calls_used'] = tool_calls_used
        results.append(prediction)

        cost_tracker.end_sample()

        if (i + 1) % 100 == 0:
            print(f"   Processed {i + 1}/{len(samples)} samples")

    return results


async def run_clean_pool_sensitivity(samples, kb, llm_client, args) -> dict:
    """Run clean pool sensitivity experiment across multiple fractions.

    Args:
        samples: Pre-filtered list of CWE-labeled samples to evaluate.
    """
    from mulvul.utils.cost_tracker import CostTracker
    from mulvul.rag.retriever import CodeSimilarityRetriever

    fractions = [0.1, 0.25, 0.5, 1.0]
    all_results = {}

    print("\n" + "=" * 60)
    print("CLEAN POOL SENSITIVITY EXPERIMENT")
    print("=" * 60)

    for frac in fractions:
        print(f"\n   Running with clean_pool_frac={frac}")

        cost_dir = Path(args.output_dir) / "cost"
        cost_dir.mkdir(parents=True, exist_ok=True)
        cost_tracker = CostTracker(cost_dir / f"mulvul_frac_{frac}.jsonl")

        retriever = CodeSimilarityRetriever(
            kb, contrastive=True, clean_pool_frac=frac, clean_pool_seed=42,
        )

        pool_stats = {
            "total_clean": len(kb.clean_examples),
            "subsampled": len(retriever._get_clean_pool()),
            "fraction": frac,
        }
        print(f"   Clean pool: {pool_stats['subsampled']}/{pool_stats['total_clean']}")

        # Run GPT-4o single-pass with this retriever as a proxy evaluation
        results = await run_gpt4o_rag_singlepass(
            samples, retriever, llm_client, cost_tracker, args,
        )

        metrics = compute_baseline_metrics(results)
        save_baseline_results(
            args.output_dir, f'clean_pool_frac_{frac}', results, metrics,
        )

        all_results[str(frac)] = {
            "clean_pool_size": pool_stats['subsampled'],
            "fraction": frac,
            "macro_f1": metrics['macro_f1'],
            "binary_accuracy": metrics['binary_accuracy'],
            "binary_precision": metrics['binary_precision'],
            "binary_recall": metrics['binary_recall'],
            "binary_f1": metrics['binary_f1'],
        }

    # Print summary table
    print("\n" + "=" * 60)
    print("CLEAN POOL SENSITIVITY RESULTS")
    print("=" * 60)
    print(f"{'Fraction':>10} | {'Pool Size':>10} | {'Macro-F1':>8} | {'B-Prec':>10} | {'B-Recall':>8}")
    print("-" * 60)
    for frac_str, data in sorted(all_results.items(), key=lambda x: float(x[0])):
        print(
            f"{data['fraction']:10.2f} | {data['clean_pool_size']:10d} | "
            f"{data['macro_f1']:8.4f} | {data['binary_precision']:10.4f} | {data['binary_recall']:8.4f}"
        )

    return all_results


def _patch_detection_agent_for_category_prompts(detection_agent):
    """Patch DetectionAgent.detect() to handle category-output prompts.

    The default DetectionAgent normalizes responses as 'vulnerable' only if the
    response literally contains that word.  Layer-1 prompts output category
    names (Memory, Injection, …, Benign).  This patch counts any non-Benign
    category as 'vulnerable' so binary F1 fitness is meaningful.
    """
    VULN_CATEGORIES = ["memory", "injection", "logic", "input", "crypto"]

    _original_detect = detection_agent.detect

    def _patched_detect(prompt, code_samples, **kwargs):
        formatted_prompts = [prompt.replace("{input}", code) for code in code_samples]
        raw_responses = detection_agent.llm_client.batch_generate(
            formatted_prompts,
            temperature=detection_agent.config.temperature,
            max_tokens=detection_agent.config.max_tokens,
            batch_size=detection_agent.config.batch_size,
            use_async=True,
        )

        normalized = []
        vuln_count = 0
        for pred in raw_responses:
            pred_lower = pred.lower().strip()
            if any(cat in pred_lower for cat in VULN_CATEGORIES):
                normalized.append("vulnerable")
                vuln_count += 1
            elif "vulnerable" in pred_lower:
                normalized.append("vulnerable")
                vuln_count += 1
            elif "benign" in pred_lower:
                normalized.append("benign")
            else:
                normalized.append("benign")

        return normalized

    detection_agent.detect = _patched_detect


def run_pairing_evolution(
    generator_model: str,
    executor_model: str,
    train_dataset,
    eval_samples: list,
    kb,
    args,
    output_dir: Path,
) -> dict:
    """Run one evolution with a specific generator→executor model pairing.

    Returns dict with best_fitness, generation stats, and eval Macro-F1.
    """
    from mulvul.llm.client import OpenAICompatibleClient

    pairing = f"{generator_model}_to_{executor_model}"
    print(f"\n{'='*60}")
    print(f"   PAIRING: {pairing}")
    print(f"   Generator (meta): {generator_model}")
    print(f"   Executor (detection): {executor_model}")
    print(f"{'='*60}")

    # Resolve model names to API model IDs
    model_map = {
        'claude': 'claude-sonnet-4-5-20250929-thinking',
        'gpt4o': 'gpt-4o',
    }
    gen_model_id = model_map.get(generator_model, generator_model)
    exec_model_id = model_map.get(executor_model, executor_model)

    # Create executor (detection) agent
    detection_llm = OpenAICompatibleClient(
        api_base=os.getenv("API_BASE_URL"),
        api_key=os.getenv("API_KEY"),
        model_name=exec_model_id,
    )
    detection_agent = create_detection_agent(
        model_name=exec_model_id,
        llm_client=detection_llm,
    )

    # Patch detection agent to handle category-output prompts
    # (layer1 prompt outputs "Memory"/"Injection"/... not "vulnerable"/"benign")
    _patch_detection_agent_for_category_prompts(detection_agent)

    # Create generator (meta) agent
    meta_agent = create_meta_agent(model_name=gen_model_id)

    # Create coordinator (no trace for ablation)
    coordinator_config = CoordinatorConfig(
        batch_size=args.batch_size,
        enable_batch_feedback=True,
        statistics_window=5,
    )
    coordinator = MultiAgentCoordinator(
        detection_agent=detection_agent,
        meta_agent=meta_agent,
        config=coordinator_config,
    )

    # Evolution config — compact for ablation
    # Use at least 20 samples for meaningful fitness (avoid all-benign batches)
    evo_eval_samples = max(20, args.batch_size)
    evo_config = {
        "population_size": args.population_size,
        "max_generations": args.max_generations,
        "elite_size": args.elite_size,
        "mutation_rate": args.mutation_rate,
        "meta_improve_interval": args.meta_improve_interval,
        "meta_improve_count": args.meta_improve_count,
        "top_k": args.elite_size,
        "enable_elitism": True,
        "meta_improvement_rate": 0.3,
        "eval_sample_size": evo_eval_samples,
    }

    algorithm = CoevolutionaryAlgorithm(
        config=evo_config,
        coordinator=coordinator,
        dataset=train_dataset,
    )

    print(f"   Pop={args.population_size}, Gen={args.max_generations}, EvoSamples={evo_eval_samples}")

    # Run evolution with default initial prompts
    initial_prompt_set = ThreeLayerPromptFactory.create_default_prompt_set()
    initial_prompts = [initial_prompt_set.layer1_prompt]

    evolution_result = algorithm.evolve(initial_prompts=initial_prompts)

    best_fitness = evolution_result.get("best_fitness", 0)
    best_prompt = evolution_result.get("best_prompt", "")
    fitness_history = evolution_result.get("fitness_history", [])

    print(f"\n   Evolution complete: best_fitness={best_fitness:.4f}")

    # Now evaluate the evolved prompt on eval samples using the executor model
    # Use the same parallel detector setup as MulVul
    evolved_prompt_set = ThreeLayerPromptFactory.create_default_prompt_set()
    if best_prompt:
        evolved_prompt_set = ThreeLayerPromptSet(
            layer1_prompt=best_prompt,
            layer2_prompts=evolved_prompt_set.layer2_prompts,
            layer3_prompts=evolved_prompt_set.layer3_prompts,
        )

    eval_llm = AsyncLLMClient(
        api_base=os.getenv("API_BASE_URL"),
        api_key=os.getenv("API_KEY"),
        model_name=exec_model_id,
    )
    eval_detector = create_parallel_detector(
        llm_client=eval_llm,
        prompt_set=evolved_prompt_set,
        knowledge_base=kb if args.use_rag else None,
        enable_rag=args.use_rag,
    )

    # Run evaluation in a SINGLE async event loop (avoids stale sessions)
    from collections import defaultdict

    print(f"   Evaluating evolved prompt on {len(eval_samples)} samples...")

    async def _eval_all_async():
        gt_cwes = set()
        per_cwe_tp = defaultdict(int)
        per_cwe_fp = defaultdict(int)
        per_cwe_fn = defaultdict(int)
        total_correct = 0

        for i, sample in enumerate(eval_samples):
            actual_vuln = str(sample.target) == '1'
            gt_cwe_list = sample.metadata.get('cwe', [])
            actual_cwe = gt_cwe_list[0] if (gt_cwe_list and actual_vuln) else 'NONE'
            if actual_cwe != 'NONE':
                gt_cwes.add(actual_cwe)

            try:
                paths = await eval_detector.detect_async(sample.input_text)
                if paths and len(paths) > 0:
                    predicted_cwe = paths[0].layer3_cwe or 'NONE'
                else:
                    predicted_cwe = 'NONE'
            except Exception as e:
                print(f"   [WARN] Sample {i} detection failed: {e}")
                predicted_cwe = 'NONE'

            if actual_cwe != 'NONE':
                if predicted_cwe == actual_cwe:
                    per_cwe_tp[actual_cwe] += 1
                    total_correct += 1
                else:
                    per_cwe_fn[actual_cwe] += 1
            if predicted_cwe != 'NONE' and predicted_cwe in gt_cwes and predicted_cwe != actual_cwe:
                per_cwe_fp[predicted_cwe] += 1

            if (i + 1) % 10 == 0:
                print(f"   Evaluated {i+1}/{len(eval_samples)}")

        return gt_cwes, per_cwe_tp, per_cwe_fp, per_cwe_fn, total_correct

    gt_cwes, per_cwe_tp, per_cwe_fp, per_cwe_fn, total_correct = asyncio.run(
        _eval_all_async()
    )

    print(f"   Evaluated {len(eval_samples)}/{len(eval_samples)}")

    # Compute Macro-F1 (GT-classes only, no NONE)
    f1_scores = []
    for cwe in gt_cwes:
        tp = per_cwe_tp[cwe]
        fp = per_cwe_fp[cwe]
        fn = per_cwe_fn[cwe]
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0
        f1_scores.append(f1)

    macro_f1 = sum(f1_scores) / len(f1_scores) if f1_scores else 0

    result = {
        "pairing": pairing,
        "generator_model": generator_model,
        "executor_model": executor_model,
        "best_evolution_fitness": round(best_fitness, 4),
        "eval_macro_f1": round(macro_f1 * 100, 2),
        "eval_accuracy": round(total_correct / max(1, sum(1 for s in eval_samples if str(s.target) == '1')) * 100, 2),
        "fitness_history": [round(f, 4) for f in fitness_history],
        "num_gt_classes": len(gt_cwes),
    }

    # Save per-pairing results
    pairing_dir = output_dir / pairing
    pairing_dir.mkdir(parents=True, exist_ok=True)
    with open(pairing_dir / "result.json", "w") as f:
        json.dump(result, f, indent=2)

    print(f"   Eval Macro-F1: {result['eval_macro_f1']}%")
    return result


def _make_balanced_dataset(dataset, max_total=200):
    """Create a balanced dataset with interleaved vuln/benign samples.

    The default PrimevulDataset has all benign samples first, so
    get_samples(N) returns only benign.  This creates a shuffled dataset
    where vulnerable and benign samples are interleaved.
    """
    import random as _rng
    from mulvul.data.dataset import Dataset, Sample

    all_samples = dataset.get_samples()
    vuln = [s for s in all_samples if str(s.target) == '1']
    benign = [s for s in all_samples if str(s.target) != '1']

    _rng.shuffle(vuln)
    _rng.shuffle(benign)

    # Take equal amounts, up to max_total / 2 each
    half = max_total // 2
    selected_vuln = vuln[:min(half, len(vuln))]
    selected_benign = benign[:min(half, len(benign))]

    # Interleave
    balanced = []
    for v, b in zip(selected_vuln, selected_benign):
        balanced.append(v)
        balanced.append(b)
    # Append any remaining
    i = min(len(selected_vuln), len(selected_benign))
    balanced.extend(selected_vuln[i:])
    balanced.extend(selected_benign[i:])

    class _BalancedDataset(Dataset):
        def load_data(self, data_path):
            return balanced

    ds = _BalancedDataset("balanced_train")
    ds._samples = balanced
    n_vuln = sum(1 for s in balanced if str(s.target) == '1')
    print(f"   Balanced train dataset: {len(balanced)} samples ({n_vuln} vuln, {len(balanced) - n_vuln} benign)")
    return ds


def run_pairing_ablation(samples, kb, args) -> dict:
    """Run cross-model prompt evolution pairing ablation (synchronous)."""

    # Load training dataset and create balanced version for evolution
    raw_train_dataset = PrimevulDataset(args.train_file, "train")
    train_dataset = _make_balanced_dataset(raw_train_dataset, max_total=200)

    output_dir = Path(args.output_dir) / "pairing_ablation"
    output_dir.mkdir(parents=True, exist_ok=True)

    # Define pairings to test
    pairings = [
        (args.evo_generator_model, args.evo_executor_model),
    ]
    # Add same-model pairing if not already the same
    if args.evo_generator_model != args.evo_executor_model:
        pairings.append((args.evo_executor_model, args.evo_executor_model))

    print("\n" + "=" * 60)
    print("CROSS-MODEL PAIRING ABLATION")
    print("=" * 60)
    print(f"   Pairings to test: {len(pairings)}")
    for gen, exe in pairings:
        print(f"   - {gen} → {exe}")

    all_results = {}
    for gen_model, exec_model in pairings:
        result = run_pairing_evolution(
            generator_model=gen_model,
            executor_model=exec_model,
            train_dataset=train_dataset,
            eval_samples=samples,
            kb=kb,
            args=args,
            output_dir=output_dir,
        )
        all_results[result["pairing"]] = result

    # Summary table
    print("\n" + "=" * 60)
    print("PAIRING ABLATION RESULTS")
    print("=" * 60)
    print(f"{'Pairing':>25} | {'Evo Fitness':>12} | {'Eval Macro-F1':>14}")
    print("-" * 60)
    for pairing, data in all_results.items():
        print(
            f"{pairing:>25} | {data['best_evolution_fitness']:12.4f} | "
            f"{data['eval_macro_f1']:13.2f}%"
        )

    # Save summary
    with open(output_dir / "summary.json", "w") as f:
        json.dump(all_results, f, indent=2)

    return all_results


def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description="三层检测训练脚本 - 支持RAG和Scale增强"
    )

    # 数据集参数
    parser.add_argument(
        "--train-file",
        default="./data/primevul/primevul/dev.jsonl",
        help="训练数据文件"
    )
    parser.add_argument(
        "--eval-file",
        default="./data/primevul/primevul/primevul_test.jsonl",
        help="评估数据文件"
    )
    parser.add_argument(
        "--eval-samples",
        type=int,
        default=None,
        help="评估样本数量 (默认全量)"
    )
    parser.add_argument(
        "--detector",
        choices=["serial", "parallel"],
        default="parallel",
        help="检测器模式: serial=原三层串行, parallel=并行层级检测器",
    )
    parser.add_argument(
        "--layer1-top-k",
        type=int,
        default=2,
        help="并行检测器 Layer1 top-k",
    )
    parser.add_argument(
        "--layer2-top-k",
        type=int,
        default=2,
        help="并行检测器 Layer2 top-k",
    )
    parser.add_argument(
        "--layer3-top-k",
        type=int,
        default=1,
        help="并行检测器 Layer3 top-k",
    )
    parser.add_argument(
        "--parallel-max-concurrency",
        type=int,
        default=20,
        help="并行检测器最大并发请求数",
    )

    # RAG参数
    parser.add_argument(
        "--use-rag",
        action="store_true",
        help="启用RAG增强"
    )
    parser.add_argument(
        "--kb-path",
        default="./outputs/knowledge_base.json",
        help="知识库路径"
    )
    parser.add_argument(
        "--kb-from-dataset",
        action="store_true",
        help="从数据集构建知识库"
    )
    parser.add_argument(
        "--kb-samples-per-category",
        type=int,
        default=3,
        help="每个类别采样数量"
    )
    parser.add_argument(
        "--rag-top-k",
        type=int,
        default=2,
        help="RAG检索top-k"
    )
    parser.add_argument(
        "--rag-retriever-type",
        choices=["lexical", "embedding"],
        default="lexical",
        help="RAG检索器类型"
    )

    # Scale增强参数
    parser.add_argument(
        "--use-scale",
        action="store_true",
        help="启用Scale增强"
    )

    # 训练参数
    parser.add_argument(
        "--train",
        action="store_true",
        help="运行训练 (否则仅评估)"
    )
    parser.add_argument(
        "--population-size",
        type=int,
        default=5,
        help="种群大小"
    )
    parser.add_argument(
        "--max-generations",
        type=int,
        default=10,
        help="最大代数"
    )
    parser.add_argument(
        "--elite-size",
        type=int,
        default=1,
        help="精英个体数量"
    )
    parser.add_argument(
        "--mutation-rate",
        type=float,
        default=0.3,
        help="变异率"
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=10,
        help="批处理大小"
    )
    parser.add_argument(
        "--meta-improve-interval",
        type=int,
        default=3,
        help="Meta优化间隔"
    )
    parser.add_argument(
        "--meta-improve-count",
        type=int,
        default=2,
        help="每次Meta优化个体数"
    )
    parser.add_argument(
        "--release",
        action="store_true",
        help="关闭详细追踪输出 (默认开启)",
    )

    # Supplementary experiment arguments
    parser.add_argument(
        '--method', type=str, default='mulvul',
        choices=['mulvul', 'gpt4o_rag_singlepass', 'single_agent_tool_rag',
                 'gpt4o_no_rag', 'clean_pool_sensitivity', 'pairing_ablation'],
        help='Evaluation method to run (default: mulvul)',
    )
    parser.add_argument(
        '--baseline-model', type=str, default='gpt-4o',
        help='Model name for baseline methods (default: gpt-4o)',
    )
    parser.add_argument(
        '--top-k', type=int, default=3,
        help='Number of retrieved examples for baseline methods',
    )
    parser.add_argument(
        '--clean-top-k', type=int, default=1,
        help='Number of clean examples for contrastive retrieval',
    )
    parser.add_argument(
        '--max-tool-calls', type=int, default=2,
        help='Maximum tool calls for agent baseline',
    )
    parser.add_argument(
        '--clean-pool-frac', type=float, default=1.0,
        help='Fraction of clean pool to use (for sensitivity experiment)',
    )
    parser.add_argument(
        '--evo-generator-model', type=str, default='claude',
        choices=['claude', 'gpt4o'],
        help='Model for generating prompt mutations',
    )
    parser.add_argument(
        '--evo-executor-model', type=str, default='gpt4o',
        choices=['claude', 'gpt4o'],
        help='Model for executing/evaluating prompts',
    )
    parser.add_argument(
        '--evo-cwe-subset', type=str, default=None,
        help='Path to JSON file with CWE subset for ablation',
    )

    # 输出参数
    parser.add_argument(
        "--output-dir",
        help="输出目录 (默认自动生成)"
    )

    args = parser.parse_args()

    if args.release:
        os.environ["EVOPROMPT_RELEASE"] = "1"

    # 设置输出目录
    if not args.output_dir:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        mode = "train" if args.train else "eval"
        rag_suffix = "_rag" if args.use_rag else ""
        scale_suffix = "_scale" if args.use_scale else ""
        args.output_dir = f"./outputs/three_layer_{mode}{rag_suffix}{scale_suffix}_{timestamp}"

    trace_enabled = not args.release if args.release else trace_enabled_from_env()
    trace_manager = TraceManager(
        TraceConfig(
            enabled=trace_enabled,
            base_dir=Path(args.output_dir),
            experiment_id=Path(args.output_dir).name,
        )
    )

    # Always-on prompt change logger (independent of release mode)
    prompt_change_logger = PromptChangeLogger(output_dir=Path(args.output_dir))

    # 开始
    print("🏗️  Three-Layer Detection Training System")
    print("=" * 70)
    print()
    print("📋 Configuration:")
    print(f"   Mode: {'Training' if args.train else 'Evaluation Only'}")
    print(f"   Detector: {'Parallel' if args.detector == 'parallel' else 'Serial'}")
    print(f"   RAG: {'✅ Enabled' if args.use_rag else '❌ Disabled'}")
    print(f"   Scale: {'✅ Enabled' if args.use_scale else '❌ Disabled'}")
    print(f"   Output: {args.output_dir}")
    if args.detector == "parallel" and args.use_rag:
        print(f"   🔍 RAG-enhanced parallel detection enabled")

    # 环境设置
    if not setup_environment():
        return 1

    # 加载知识库
    kb = load_or_build_knowledge_base(args)

    # ── Supplementary experiment dispatch ──────────────────────────────
    if args.method != 'mulvul':
        # Load eval dataset for supplementary methods
        eval_dataset = PrimevulDataset(args.eval_file, "dev")
        print(f"\n   Eval dataset: {len(eval_dataset)} samples")

        # Filter to CWE-labeled samples (matching MulVul evaluation pipeline)
        eval_samples = filter_cwe_labeled_samples(eval_dataset, args.eval_samples)

        # Create baseline LLM client with the specified model
        baseline_model = args.baseline_model
        print(f"   Baseline model: {baseline_model}")

        if args.method == 'gpt4o_rag_singlepass':
            from mulvul.utils.cost_tracker import CostTracker
            from mulvul.rag.retriever import CodeSimilarityRetriever

            cost_dir = Path(args.output_dir) / "cost"
            cost_dir.mkdir(parents=True, exist_ok=True)
            cost_tracker = CostTracker(cost_dir / "gpt4o_rag_singlepass.jsonl")

            retriever = CodeSimilarityRetriever(kb, contrastive=True)

            async_client = AsyncLLMClient(
                api_base=os.getenv("API_BASE_URL"),
                api_key=os.getenv("API_KEY"),
                model_name=baseline_model,
            )

            results = asyncio.run(run_gpt4o_rag_singlepass(
                eval_samples, retriever, async_client, cost_tracker, args,
            ))

            metrics = compute_baseline_metrics(results)
            save_baseline_results(args.output_dir, 'gpt4o_rag_singlepass', results, metrics)
            return 0

        elif args.method == 'single_agent_tool_rag':
            from mulvul.utils.cost_tracker import CostTracker
            from mulvul.rag.retriever import CodeSimilarityRetriever

            cost_dir = Path(args.output_dir) / "cost"
            cost_dir.mkdir(parents=True, exist_ok=True)
            cost_tracker = CostTracker(cost_dir / "single_agent_tool_rag.jsonl")

            retriever = CodeSimilarityRetriever(kb, contrastive=True)

            async_client = AsyncLLMClient(
                api_base=os.getenv("API_BASE_URL"),
                api_key=os.getenv("API_KEY"),
                model_name=baseline_model,
            )

            results = asyncio.run(run_single_agent_tool_rag(
                eval_samples, retriever, async_client, cost_tracker, args,
            ))

            metrics = compute_baseline_metrics(results)
            save_baseline_results(args.output_dir, 'single_agent_tool_rag', results, metrics)
            return 0

        elif args.method == 'clean_pool_sensitivity':
            async_client = AsyncLLMClient(
                api_base=os.getenv("API_BASE_URL"),
                api_key=os.getenv("API_KEY"),
                model_name=baseline_model,
            )

            results = asyncio.run(run_clean_pool_sensitivity(
                eval_samples, kb, async_client, args,
            ))

            metrics_dir = Path(args.output_dir) / "metrics"
            metrics_dir.mkdir(parents=True, exist_ok=True)
            with open(metrics_dir / "clean_pool_sensitivity.json", "w") as f:
                json.dump(results, f, indent=2)
            return 0

        elif args.method == 'pairing_ablation':
            results = run_pairing_ablation(eval_samples, kb, args)
            return 0

        print(f"\n   Unknown method: {args.method}")
        return 1
    # ── End supplementary experiment dispatch ──────────────────────────

    # 加载数据集
    print("\n📂 Loading Dataset")
    print("=" * 70)
    print(f"   Training: {args.train_file}")
    print(f"   Evaluation: {args.eval_file}")

    train_dataset = PrimevulDataset(args.train_file, "train")
    eval_dataset = PrimevulDataset(args.eval_file, "dev")

    print(f"   ✅ Train: {len(train_dataset)} samples")
    print(f"   ✅ Eval: {len(eval_dataset)} samples")

    # 创建初始prompt集合
    print("\n📝 Creating Initial Prompts")
    print("=" * 70)
    prompt_set = ThreeLayerPromptFactory.create_default_prompt_set()
    counts = prompt_set.count_prompts()
    print(f"   ✅ Created {counts['total']} prompts")
    print(f"      Layer 1: {counts['layer1']}")
    print(f"      Layer 2: {counts['layer2']}")
    print(f"      Layer 3: {counts['layer3']}")

    # 创建LLM客户端
    llm_client = create_llm_client(llm_type=os.getenv("MODEL_NAME", "gpt-4"))

    # 创建检测器
    detector = create_detector(prompt_set, llm_client, kb, args)

    # 评估基线
    print("\n📊 Baseline Evaluation")
    print("=" * 70)
    baseline_metrics = run_evaluation(detector, eval_dataset, args, trace_manager=trace_manager)

    # 训练
    if args.train:
        prompt_set = run_training(prompt_set, detector, train_dataset, kb, args, trace_manager=trace_manager, prompt_change_logger=prompt_change_logger)

        # 重新创建检测器并评估
        print("\n📊 Final Evaluation")
        print("=" * 70)
        detector = create_detector(prompt_set, llm_client, kb, args)
        final_metrics = run_evaluation(detector, eval_dataset, args, trace_manager=trace_manager)

        # 保存最终结果
        save_results(args.output_dir, final_metrics, prompt_set, args)
    else:
        # 仅评估，保存基线结果
        save_results(args.output_dir, baseline_metrics, prompt_set, args)

    # Print prompt change summary
    change_summary = prompt_change_logger.get_summary()
    if change_summary["total_changes"] > 0:
        print(f"\n   Prompt changes logged: {change_summary['total_changes']}")
        print(f"   Log file: {prompt_change_logger.log_file}")

    print("\n" + "=" * 70)
    print("✨ Completed!")
    print()
    print("📁 Results:")
    print(f"   {args.output_dir}/")
    print(f"   ├── config.json      # 配置")
    print(f"   ├── metrics.json     # 评估指标")
    print(f"   ├── prompts.json     # Prompt集合")
    print(f"   └── prompts.txt      # 可读Prompt")

    if kb and args.kb_path:
        print()
        print(f"📚 Knowledge Base: {args.kb_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
