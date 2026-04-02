"""Caching mechanism for static analysis results."""

import hashlib
import json
from pathlib import Path
from typing import Optional
import logging

logger = logging.getLogger(__name__)


class AnalysisCache:
    """基于磁盘的分析结果缓存"""

    def __init__(self, cache_dir: str = ".cache/analysis"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _get_cache_key(self, code: str, lang: str) -> str:
        """使用SHA256生成缓存键

        Args:
            code: 源代码
            lang: 语言标识

        Returns:
            str: 十六进制格式的缓存键
        """
        content = f"{lang}:{code}"
        return hashlib.sha256(content.encode()).hexdigest()

    def get(self, code: str, lang: str) -> Optional["AnalysisResult"]:
        """获取缓存的分析结果

        Args:
            code: 源代码
            lang: 语言标识

        Returns:
            Optional[AnalysisResult]: 缓存的结果,不存在返回None
        """
        from .result import AnalysisResult

        cache_file = self.cache_dir / f"{self._get_cache_key(code, lang)}.json"
        if cache_file.exists():
            try:
                with open(cache_file, encoding="utf-8") as f:
                    return AnalysisResult.from_dict(json.load(f))
            except Exception as e:
                # 缓存损坏,删除并返回None
                logger.warning(f"Corrupted cache file {cache_file}: {e}")
                cache_file.unlink()
        return None

    def set(self, code: str, lang: str, result: "AnalysisResult") -> None:
        """保存分析结果到缓存

        Args:
            code: 源代码
            lang: 语言标识
            result: 分析结果
        """
        cache_file = self.cache_dir / f"{self._get_cache_key(code, lang)}.json"
        try:
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(result.to_dict(), f)
        except Exception as e:
            logger.warning(f"Failed to write cache file {cache_file}: {e}")

    def clear(self) -> int:
        """清空缓存

        Returns:
            int: 删除的缓存文件数量
        """
        count = 0
        for cache_file in self.cache_dir.glob("*.json"):
            try:
                cache_file.unlink()
                count += 1
            except Exception as e:
                logger.warning(f"Failed to delete cache file {cache_file}: {e}")
        return count

    def get_stats(self) -> dict:
        """获取缓存统计信息

        Returns:
            dict: 包含缓存文件数量和总大小的字典
        """
        files = list(self.cache_dir.glob("*.json"))
        total_size = sum(f.stat().st_size for f in files)
        return {"count": len(files), "total_size_bytes": total_size}
