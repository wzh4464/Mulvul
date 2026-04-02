"""多分类评估指标 - 专为三层漏洞检测设计

支持三种F1计算方式:
1. Macro-F1: 所有类别同等重要 (推荐用于不平衡数据)
2. Weighted-F1: 按样本数量加权
3. Micro-F1: 全局计算 (等同于accuracy)

适用场景: 漏洞检测中的类别不平衡问题
"""

from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional
from collections import defaultdict
import json


@dataclass
class ClassMetrics:
    """单个类别的评估指标"""

    class_name: str
    tp: int = 0  # True Positives
    fp: int = 0  # False Positives
    tn: int = 0  # True Negatives
    fn: int = 0  # False Negatives
    support: int = 0  # 该类别的实际样本数

    @property
    def precision(self) -> float:
        """精确率 = TP / (TP + FP)"""
        if self.tp + self.fp == 0:
            return 0.0
        return self.tp / (self.tp + self.fp)

    @property
    def recall(self) -> float:
        """召回率 = TP / (TP + FN)"""
        if self.tp + self.fn == 0:
            return 0.0
        return self.tp / (self.tp + self.fn)

    @property
    def f1_score(self) -> float:
        """F1分数 = 2 * (precision * recall) / (precision + recall)"""
        if self.precision + self.recall == 0:
            return 0.0
        return 2 * (self.precision * self.recall) / (self.precision + self.recall)

    @property
    def accuracy(self) -> float:
        """准确率 = (TP + TN) / (TP + TN + FP + FN)"""
        total = self.tp + self.tn + self.fp + self.fn
        if total == 0:
            return 0.0
        return (self.tp + self.tn) / total

    def to_dict(self) -> Dict:
        """转换为字典"""
        return {
            "class": self.class_name,
            "support": self.support,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1_score": round(self.f1_score, 4),
            "accuracy": round(self.accuracy, 4),
            "tp": self.tp,
            "fp": self.fp,
            "tn": self.tn,
            "fn": self.fn,
        }


@dataclass
class MultiClassMetrics:
    """多分类评估指标

    支持三种F1计算方式:
    - Macro-F1: 所有类别平等对待 (推荐用于漏洞检测)
    - Weighted-F1: 按样本数加权
    - Micro-F1: 全局计算
    """

    # 每个类别的指标
    class_metrics: Dict[str, ClassMetrics] = field(default_factory=dict)

    # 混淆矩阵: predicted -> actual -> count
    confusion_matrix: Dict[str, Dict[str, int]] = field(
        default_factory=lambda: defaultdict(lambda: defaultdict(int))
    )

    # 总样本数
    total_samples: int = 0

    # 正确预测数
    correct_predictions: int = 0

    def add_prediction(self, predicted: str, actual: str):
        """添加一个预测结果

        Args:
            predicted: 预测的类别
            actual: 实际的类别
        """
        self.total_samples += 1

        # 更新混淆矩阵
        self.confusion_matrix[predicted][actual] += 1

        # 统计正确预测
        if predicted == actual:
            self.correct_predictions += 1

        # 初始化类别指标（如果需要）
        if predicted not in self.class_metrics:
            self.class_metrics[predicted] = ClassMetrics(class_name=predicted)
        if actual not in self.class_metrics:
            self.class_metrics[actual] = ClassMetrics(class_name=actual)

        # 更新每个类别的TP/FP/TN/FN
        # 注意: 在多分类中，我们采用One-vs-Rest策略
        for class_name in set(list(self.class_metrics.keys())):
            metrics = self.class_metrics[class_name]

            # 实际是该类 + 预测也是该类 = TP
            if actual == class_name and predicted == class_name:
                metrics.tp += 1
            # 实际不是该类 + 预测是该类 = FP
            elif actual != class_name and predicted == class_name:
                metrics.fp += 1
            # 实际是该类 + 预测不是该类 = FN
            elif actual == class_name and predicted != class_name:
                metrics.fn += 1
            # 实际不是该类 + 预测也不是该类 = TN
            else:  # actual != class_name and predicted != class_name
                metrics.tn += 1

            # 更新support (该类的实际样本数)
            if actual == class_name:
                metrics.support += 1

    def compute_macro_f1(self) -> float:
        """计算Macro-F1 (宏平均)

        所有类别同等重要，不考虑样本数量
        推荐用于不平衡数据集 (如漏洞检测)

        Formula: mean(F1_i for all classes i)
        """
        if not self.class_metrics:
            return 0.0

        f1_scores = [m.f1_score for m in self.class_metrics.values()]
        return sum(f1_scores) / len(f1_scores)

    def compute_weighted_f1(self) -> float:
        """计算Weighted-F1 (加权平均)

        按样本数量加权，样本多的类别权重大

        Formula: sum(F1_i * support_i) / total_samples
        """
        if self.total_samples == 0:
            return 0.0

        weighted_sum = sum(
            m.f1_score * m.support
            for m in self.class_metrics.values()
        )
        return weighted_sum / self.total_samples

    def compute_micro_f1(self) -> float:
        """计算Micro-F1 (微平均)

        全局计算TP/FP/FN，在多分类中等同于accuracy

        Formula: 2 * (P_micro * R_micro) / (P_micro + R_micro)
        """
        # 全局TP = 正确预测数
        global_tp = self.correct_predictions

        # 全局FP + FN = 错误预测数
        global_fp_fn = self.total_samples - self.correct_predictions

        if global_tp + global_fp_fn == 0:
            return 0.0

        # Micro-F1 = accuracy (在多分类中)
        return global_tp / self.total_samples

    def compute_macro_precision(self) -> float:
        """计算Macro-Precision (宏平均精确率)"""
        if not self.class_metrics:
            return 0.0

        precisions = [m.precision for m in self.class_metrics.values()]
        return sum(precisions) / len(precisions)

    def compute_macro_recall(self) -> float:
        """计算Macro-Recall (宏平均召回率)"""
        if not self.class_metrics:
            return 0.0

        recalls = [m.recall for m in self.class_metrics.values()]
        return sum(recalls) / len(recalls)

    def compute_weighted_precision(self) -> float:
        """计算Weighted-Precision (加权精确率)"""
        if self.total_samples == 0:
            return 0.0

        weighted_sum = sum(
            m.precision * m.support
            for m in self.class_metrics.values()
        )
        return weighted_sum / self.total_samples

    def compute_weighted_recall(self) -> float:
        """计算Weighted-Recall (加权召回率)"""
        if self.total_samples == 0:
            return 0.0

        weighted_sum = sum(
            m.recall * m.support
            for m in self.class_metrics.values()
        )
        return weighted_sum / self.total_samples

    @property
    def accuracy(self) -> float:
        """总体准确率"""
        if self.total_samples == 0:
            return 0.0
        return self.correct_predictions / self.total_samples

    def get_per_class_metrics(self) -> Dict[str, Dict]:
        """获取每个类别的详细指标"""
        return {
            class_name: metrics.to_dict()
            for class_name, metrics in self.class_metrics.items()
        }

    def get_classification_report(self) -> Dict:
        """生成分类报告 (类似sklearn.metrics.classification_report)

        Returns:
            包含所有指标的字典
        """
        report = {
            "per_class_metrics": self.get_per_class_metrics(),
            "macro_avg": {
                "precision": round(self.compute_macro_precision(), 4),
                "recall": round(self.compute_macro_recall(), 4),
                "f1_score": round(self.compute_macro_f1(), 4),
                "support": self.total_samples,
            },
            "weighted_avg": {
                "precision": round(self.compute_weighted_precision(), 4),
                "recall": round(self.compute_weighted_recall(), 4),
                "f1_score": round(self.compute_weighted_f1(), 4),
                "support": self.total_samples,
            },
            "micro_avg": {
                "precision": round(self.accuracy, 4),  # Micro = Accuracy
                "recall": round(self.accuracy, 4),
                "f1_score": round(self.compute_micro_f1(), 4),
                "support": self.total_samples,
            },
            "overall": {
                "accuracy": round(self.accuracy, 4),
                "total_samples": self.total_samples,
                "correct_predictions": self.correct_predictions,
            }
        }

        return report

    def print_report(self, layer_name: str = ""):
        """打印格式化的分类报告

        Args:
            layer_name: 层级名称 (如 "Layer 1", "Layer 2")
        """
        report = self.get_classification_report()

        header = f"Classification Report"
        if layer_name:
            header += f" - {layer_name}"

        print("\n" + "=" * 70)
        print(header)
        print("=" * 70)

        # 打印每个类别的指标
        print(f"\n{'Class':<20} {'Precision':>10} {'Recall':>10} {'F1-Score':>10} {'Support':>10}")
        print("-" * 70)

        for class_name, metrics in sorted(report["per_class_metrics"].items()):
            print(
                f"{class_name:<20} "
                f"{metrics['precision']:>10.4f} "
                f"{metrics['recall']:>10.4f} "
                f"{metrics['f1_score']:>10.4f} "
                f"{metrics['support']:>10}"
            )

        print("-" * 70)

        # 打印汇总指标
        print(f"\n{'Metric':<20} {'Precision':>10} {'Recall':>10} {'F1-Score':>10} {'Support':>10}")
        print("-" * 70)

        for avg_type in ["macro_avg", "weighted_avg", "micro_avg"]:
            avg_name = avg_type.replace("_", " ").title()
            avg = report[avg_type]
            print(
                f"{avg_name:<20} "
                f"{avg['precision']:>10.4f} "
                f"{avg['recall']:>10.4f} "
                f"{avg['f1_score']:>10.4f} "
                f"{avg['support']:>10}"
            )

        print("-" * 70)
        print(f"\nAccuracy: {report['overall']['accuracy']:.4f}")
        print(f"Total Samples: {report['overall']['total_samples']}")
        print()

    def get_confusion_matrix_dict(self) -> Dict:
        """获取混淆矩阵 (可序列化格式)"""
        return {
            pred: dict(actual_counts)
            for pred, actual_counts in self.confusion_matrix.items()
        }

    def print_confusion_matrix(self):
        """打印混淆矩阵"""
        if not self.confusion_matrix:
            print("No predictions recorded.")
            return

        # 获取所有类别
        all_classes = sorted(set(
            list(self.confusion_matrix.keys()) +
            [actual for counts in self.confusion_matrix.values() for actual in counts.keys()]
        ))

        print("\n" + "=" * 70)
        print("Confusion Matrix")
        print("=" * 70)
        print("\nRows: Predicted, Columns: Actual\n")

        # 打印表头
        header = f"{'Predicted':<15}"
        for cls in all_classes:
            header += f"{cls:>12}"
        print(header)
        print("-" * len(header))

        # 打印每一行
        for pred_class in all_classes:
            row = f"{pred_class:<15}"
            for actual_class in all_classes:
                count = self.confusion_matrix.get(pred_class, {}).get(actual_class, 0)
                row += f"{count:>12}"
            print(row)

        print()


def compute_layered_metrics(
    predictions: List[Tuple[str, str]],
    layer_name: str = ""
) -> MultiClassMetrics:
    """计算层级化的多分类指标

    Args:
        predictions: List of (predicted, actual) tuples
        layer_name: 层级名称 (用于打印)

    Returns:
        MultiClassMetrics对象
    """
    metrics = MultiClassMetrics()

    for predicted, actual in predictions:
        metrics.add_prediction(predicted, actual)

    return metrics


def compare_averaging_methods(metrics: MultiClassMetrics) -> Dict:
    """对比三种F1计算方法

    Args:
        metrics: MultiClassMetrics对象

    Returns:
        包含三种方法的对比结果
    """
    comparison = {
        "macro_f1": {
            "value": round(metrics.compute_macro_f1(), 4),
            "description": "所有类别同等重要 (推荐用于不平衡数据)",
            "formula": "mean(F1_i for all classes)",
        },
        "weighted_f1": {
            "value": round(metrics.compute_weighted_f1(), 4),
            "description": "按样本数量加权 (样本多的类别权重大)",
            "formula": "sum(F1_i * support_i) / total_samples",
        },
        "micro_f1": {
            "value": round(metrics.compute_micro_f1(), 4),
            "description": "全局计算 (等同于accuracy)",
            "formula": "global_TP / total_samples",
        },
        "accuracy": {
            "value": round(metrics.accuracy, 4),
            "description": "总体准确率",
        }
    }

    return comparison


def print_averaging_comparison(metrics: MultiClassMetrics):
    """打印三种F1方法的对比"""
    comparison = compare_averaging_methods(metrics)

    print("\n" + "=" * 70)
    print("F1 Averaging Methods Comparison")
    print("=" * 70)

    for method, info in comparison.items():
        print(f"\n{method.upper().replace('_', '-')}:")
        print(f"  Value: {info['value']:.4f}")
        print(f"  Description: {info['description']}")
        if 'formula' in info:
            print(f"  Formula: {info['formula']}")

    print("\n" + "=" * 70)
    print("💡 推荐用于漏洞检测: Macro-F1")
    print("   原因: 强制模型在所有类别(包括少数类)上都表现好")
    print("=" * 70)


def recall_at_k(
    predictions: List[List[str]],
    ground_truth: List[str],
    k: int = 3
) -> float:
    """计算 Recall@k - Router Agent 的优化目标

    检查 top-k 预测中是否包含正确类别。

    Args:
        predictions: List of top-k predictions for each sample [[pred1, pred2, ...], ...]
        ground_truth: List of actual labels
        k: Number of top predictions to consider

    Returns:
        Recall@k score in [0, 1]

    Example:
        >>> predictions = [["Memory", "Injection", "Logic"], ["Benign", "Memory"]]
        >>> ground_truth = ["Memory", "Benign"]
        >>> recall_at_k(predictions, ground_truth, k=3)
        1.0  # Both correct labels are in top-3
    """
    if len(predictions) != len(ground_truth):
        raise ValueError("predictions and ground_truth must have same length")

    if not predictions:
        return 0.0

    correct = 0
    for preds, gt in zip(predictions, ground_truth):
        top_k_preds = preds[:k] if isinstance(preds, list) else [preds]
        if gt in top_k_preds:
            correct += 1

    return correct / len(ground_truth)


def recall_at_k_with_confidence(
    predictions: List[List[tuple]],
    ground_truth: List[str],
    k: int = 3
) -> Dict:
    """计算 Recall@k 并返回详细统计

    Args:
        predictions: List of [(category, confidence), ...] for each sample
        ground_truth: List of actual labels
        k: Number of top predictions to consider

    Returns:
        Dict with recall@k and detailed statistics
    """
    if len(predictions) != len(ground_truth):
        raise ValueError("predictions and ground_truth must have same length")

    if not predictions:
        return {"recall_at_k": 0.0, "k": k, "total": 0, "correct": 0}

    correct = 0
    correct_positions = []  # Position where correct label was found

    for preds, gt in zip(predictions, ground_truth):
        top_k = preds[:k]
        categories = [p[0] if isinstance(p, tuple) else p for p in top_k]

        if gt in categories:
            correct += 1
            pos = categories.index(gt) + 1  # 1-indexed position
            correct_positions.append(pos)

    recall = correct / len(ground_truth)

    # Calculate mean reciprocal rank (MRR)
    mrr = sum(1.0 / pos for pos in correct_positions) / len(ground_truth) if correct_positions else 0.0

    return {
        "recall_at_k": round(recall, 4),
        "k": k,
        "total": len(ground_truth),
        "correct": correct,
        "mrr": round(mrr, 4),  # Mean Reciprocal Rank
        "position_distribution": {
            f"top_{i}": sum(1 for p in correct_positions if p == i)
            for i in range(1, k + 1)
        }
    }


class RouterMetrics:
    """Router Agent 专用评估指标

    优化目标: Recall@k (确保正确类别在 top-k 预测中)
    """

    def __init__(self, k: int = 3):
        self.k = k
        self.predictions: List[List[tuple]] = []  # [(category, confidence), ...]
        self.ground_truth: List[str] = []

    def add_prediction(self, top_k_preds: List[tuple], actual: str):
        """添加一个路由预测

        Args:
            top_k_preds: [(category, confidence), ...] 按置信度排序
            actual: 实际类别
        """
        self.predictions.append(top_k_preds)
        self.ground_truth.append(actual)

    def compute_recall_at_k(self, k: int = None) -> float:
        """计算 Recall@k"""
        k = k or self.k
        categories_only = [
            [p[0] if isinstance(p, tuple) else p for p in preds]
            for preds in self.predictions
        ]
        return recall_at_k(categories_only, self.ground_truth, k)

    def get_report(self) -> Dict:
        """获取完整评估报告"""
        return recall_at_k_with_confidence(
            self.predictions, self.ground_truth, self.k
        )

    def print_report(self):
        """打印评估报告"""
        report = self.get_report()

        print("\n" + "=" * 50)
        print("Router Agent Evaluation Report")
        print("=" * 50)
        print(f"Recall@{self.k}: {report['recall_at_k']:.2%}")
        print(f"MRR (Mean Reciprocal Rank): {report['mrr']:.4f}")
        print(f"Total samples: {report['total']}")
        print(f"Correct (in top-{self.k}): {report['correct']}")

        print("\nPosition Distribution:")
        for pos, count in report['position_distribution'].items():
            print(f"  {pos}: {count}")
        print("=" * 50)
