"""Base metric implementations for EvoPrompt."""

from abc import ABC, abstractmethod
from typing import List, Any, Dict
import numpy as np


class Metric(ABC):
    """Abstract base class for evaluation metrics."""
    
    @abstractmethod
    def compute(self, predictions: List[Any], targets: List[Any]) -> float:
        """Compute metric score."""
        pass
        
    def __call__(self, predictions: List[Any], targets: List[Any]) -> float:
        """Allow calling metric as function."""
        return self.compute(predictions, targets)


class AccuracyMetric(Metric):
    """Accuracy metric for classification tasks."""
    
    def compute(self, predictions: List[Any], targets: List[Any]) -> float:
        """Compute accuracy score."""
        if not predictions or not targets or len(predictions) != len(targets):
            return 0.0
            
        correct = sum(1 for p, t in zip(predictions, targets) if str(p) == str(t))
        return correct / len(targets)


class F1Metric(Metric):
    """F1 score metric for binary classification."""
    
    def __init__(self, positive_label: str = "1"):
        self.positive_label = positive_label
        
    def compute(self, predictions: List[Any], targets: List[Any]) -> float:
        """Compute F1 score."""
        if not predictions or not targets or len(predictions) != len(targets):
            return 0.0
            
        # Convert to strings for comparison
        pred_str = [str(p) for p in predictions]
        target_str = [str(t) for t in targets]
        
        # Calculate TP, FP, FN
        tp = sum(1 for p, t in zip(pred_str, target_str) 
                if p == self.positive_label and t == self.positive_label)
        fp = sum(1 for p, t in zip(pred_str, target_str) 
                if p == self.positive_label and t != self.positive_label)
        fn = sum(1 for p, t in zip(pred_str, target_str) 
                if p != self.positive_label and t == self.positive_label)
        
        # Calculate precision and recall
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        
        # Calculate F1
        if precision + recall == 0:
            return 0.0
        return 2 * (precision * recall) / (precision + recall)


class PrecisionMetric(Metric):
    """Precision metric for binary classification."""
    
    def __init__(self, positive_label: str = "1"):
        self.positive_label = positive_label
        
    def compute(self, predictions: List[Any], targets: List[Any]) -> float:
        """Compute precision score."""
        if not predictions or not targets or len(predictions) != len(targets):
            return 0.0
            
        pred_str = [str(p) for p in predictions]
        target_str = [str(t) for t in targets]
        
        tp = sum(1 for p, t in zip(pred_str, target_str) 
                if p == self.positive_label and t == self.positive_label)
        fp = sum(1 for p, t in zip(pred_str, target_str) 
                if p == self.positive_label and t != self.positive_label)
        
        return tp / (tp + fp) if (tp + fp) > 0 else 0.0


class RecallMetric(Metric):
    """Recall metric for binary classification."""
    
    def __init__(self, positive_label: str = "1"):
        self.positive_label = positive_label
        
    def compute(self, predictions: List[Any], targets: List[Any]) -> float:
        """Compute recall score."""
        if not predictions or not targets or len(predictions) != len(targets):
            return 0.0
            
        pred_str = [str(p) for p in predictions]
        target_str = [str(t) for t in targets]
        
        tp = sum(1 for p, t in zip(pred_str, target_str) 
                if p == self.positive_label and t == self.positive_label)
        fn = sum(1 for p, t in zip(pred_str, target_str) 
                if p != self.positive_label and t == self.positive_label)
        
        return tp / (tp + fn) if (tp + fn) > 0 else 0.0


class ROUGEMetric(Metric):
    """ROUGE metric for text generation tasks."""
    
    def __init__(self, rouge_type: str = "rouge-l"):
        self.rouge_type = rouge_type
        
    def compute(self, predictions: List[str], targets: List[str]) -> float:
        """Compute ROUGE score."""
        try:
            from rouge import Rouge
            rouge = Rouge()
            
            # Filter out empty predictions/targets
            valid_pairs = [(p, t) for p, t in zip(predictions, targets) 
                          if p.strip() and t.strip()]
            
            if not valid_pairs:
                return 0.0
                
            pred_filtered, target_filtered = zip(*valid_pairs)
            
            scores = rouge.get_scores(list(pred_filtered), list(target_filtered), avg=True)
            return scores[self.rouge_type]['f']
            
        except ImportError:
            # Fallback to simple overlap metric
            return self._simple_overlap(predictions, targets)
    
    def _simple_overlap(self, predictions: List[str], targets: List[str]) -> float:
        """Simple word overlap as fallback."""
        if not predictions or not targets:
            return 0.0
            
        total_score = 0.0
        valid_pairs = 0
        
        for pred, target in zip(predictions, targets):
            if not pred.strip() or not target.strip():
                continue
                
            pred_words = set(pred.lower().split())
            target_words = set(target.lower().split())
            
            if not target_words:
                continue
                
            overlap = len(pred_words & target_words)
            score = overlap / len(target_words)
            total_score += score
            valid_pairs += 1
            
        return total_score / valid_pairs if valid_pairs > 0 else 0.0


class BLEUMetric(Metric):
    """BLEU metric for text generation tasks."""
    
    def compute(self, predictions: List[str], targets: List[str]) -> float:
        """Compute BLEU score."""
        try:
            from sacrebleu import corpus_bleu
            
            # Filter out empty predictions/targets
            valid_pairs = [(p, t) for p, t in zip(predictions, targets) 
                          if p.strip() and t.strip()]
            
            if not valid_pairs:
                return 0.0
                
            pred_filtered, target_filtered = zip(*valid_pairs)
            
            # SacreBLEU expects targets as list of lists
            targets_formatted = [[t] for t in target_filtered]
            
            bleu = corpus_bleu(list(pred_filtered), targets_formatted)
            return bleu.score / 100.0  # Convert to 0-1 range
            
        except ImportError:
            # Fallback to simple n-gram overlap
            return self._simple_ngram_overlap(predictions, targets)
    
    def _simple_ngram_overlap(self, predictions: List[str], targets: List[str], n: int = 4) -> float:
        """Simple n-gram overlap as fallback."""
        if not predictions or not targets:
            return 0.0
            
        def get_ngrams(text: str, n: int):
            words = text.lower().split()
            return set(tuple(words[i:i+n]) for i in range(len(words) - n + 1))
        
        total_score = 0.0
        valid_pairs = 0
        
        for pred, target in zip(predictions, targets):
            if not pred.strip() or not target.strip():
                continue
                
            scores = []
            for ngram_size in range(1, min(n + 1, len(target.split()) + 1)):
                pred_ngrams = get_ngrams(pred, ngram_size)
                target_ngrams = get_ngrams(target, ngram_size)
                
                if not target_ngrams:
                    continue
                    
                overlap = len(pred_ngrams & target_ngrams)
                score = overlap / len(target_ngrams)
                scores.append(score)
            
            if scores:
                # Geometric mean of n-gram scores
                avg_score = np.exp(np.mean(np.log(np.array(scores) + 1e-8)))
                total_score += avg_score
                valid_pairs += 1
                
        return total_score / valid_pairs if valid_pairs > 0 else 0.0