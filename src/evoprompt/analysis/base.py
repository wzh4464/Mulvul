"""Abstract base class for static analyzers."""

from abc import ABC, abstractmethod
from typing import Optional


class StaticAnalyzer(ABC):
    """静态分析器抽象基类"""

    @classmethod
    @abstractmethod
    def is_available(cls) -> bool:
        """检查分析器依赖是否可用"""
        pass

    @abstractmethod
    def analyze(self, code: str, lang: str) -> "AnalysisResult":
        """分析代码并返回结果

        Args:
            code: 源代码文本
            lang: 语言标识 (c/cpp/java/python)

        Returns:
            AnalysisResult: 分析结果,失败时返回空结果而非抛异常
        """
        pass

    def analyze_with_cache(
        self, code: str, lang: str, cache: Optional["AnalysisCache"] = None
    ) -> "AnalysisResult":
        """带缓存的分析

        Args:
            code: 源代码文本
            lang: 语言标识
            cache: 可选的缓存对象

        Returns:
            AnalysisResult: 分析结果
        """
        if cache:
            cached = cache.get(code, lang)
            if cached:
                return cached

        result = self.analyze(code, lang)

        if cache:
            cache.set(code, lang, result)

        return result
