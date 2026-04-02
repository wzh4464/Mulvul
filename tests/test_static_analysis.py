"""Tests for static analysis module."""

import pytest
import tempfile
import shutil
from pathlib import Path

from evoprompt.analysis import (
    BanditAnalyzer,
    AnalysisCache,
    AnalysisResult,
    Vulnerability,
)


class TestBanditAnalyzer:
    """Tests for BanditAnalyzer"""

    def test_is_available(self):
        """Test availability check"""
        # This test will pass or fail depending on whether bandit is installed
        result = BanditAnalyzer.is_available()
        assert isinstance(result, bool)

    @pytest.mark.skipif(
        not BanditAnalyzer.is_available(), reason="Bandit not installed"
    )
    def test_analyze_basic(self):
        """Test basic Bandit analysis"""
        code = """
import pickle
data = pickle.loads(user_input)  # CWE-502
"""
        analyzer = BanditAnalyzer()
        result = analyzer.analyze(code, "python")

        assert isinstance(result, AnalysisResult)
        assert result.language == "python"
        assert result.tool == "bandit"
        assert not result.is_empty()
        assert len(result.vulnerabilities) > 0

    @pytest.mark.skipif(
        not BanditAnalyzer.is_available(), reason="Bandit not installed"
    )
    def test_cwe_mapping(self):
        """Test CWE mapping"""
        code = "import pickle; pickle.loads(data)"
        analyzer = BanditAnalyzer()
        result = analyzer.analyze(code, "python")

        cwe_codes = result.get_cwe_codes()
        # Should find CWE-502 for pickle usage
        assert any("CWE" in str(code) for code in cwe_codes if code)

    def test_analyzer_graceful_degradation_tool_unavailable(self):
        """Test graceful degradation when tool is unavailable"""
        # Even if bandit is not installed, should return empty result
        analyzer = BanditAnalyzer()
        result = analyzer.analyze("print('hello')", "python")

        assert isinstance(result, AnalysisResult)
        assert result.language == "python"
        assert result.tool == "bandit"

    def test_analyzer_wrong_language(self):
        """Test analyzer with wrong language"""
        analyzer = BanditAnalyzer()
        result = analyzer.analyze("int main() {}", "c")

        assert result.is_empty()
        assert result.language == "c"

    @pytest.mark.skipif(
        not BanditAnalyzer.is_available(), reason="Bandit not installed"
    )
    def test_severity_levels(self):
        """Test severity level parsing"""
        code = """
import pickle
import hashlib
pickle.loads(data)  # HIGH severity
hashlib.md5(data)  # MEDIUM severity
"""
        analyzer = BanditAnalyzer()
        result = analyzer.analyze(code, "python")

        severities = [v.severity for v in result.vulnerabilities]
        assert "high" in severities or "medium" in severities


class TestAnalysisCache:
    """Tests for AnalysisCache"""

    def test_cache_basic(self):
        """Test basic cache operations"""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = AnalysisCache(tmpdir)

            # Create a test result
            result = AnalysisResult(
                vulnerabilities=[
                    Vulnerability(
                        type="test",
                        severity="high",
                        line_number=1,
                        cwe_id="CWE-123",
                        description="Test vuln",
                    )
                ],
                language="python",
                tool="test",
            )

            # Save to cache
            code = "test code"
            cache.set(code, "python", result)

            # Retrieve from cache
            cached = cache.get(code, "python")
            assert cached is not None
            assert len(cached.vulnerabilities) == 1
            assert cached.vulnerabilities[0].cwe_id == "CWE-123"

    def test_cache_miss(self):
        """Test cache miss"""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = AnalysisCache(tmpdir)
            result = cache.get("nonexistent code", "python")
            assert result is None

    def test_cache_clear(self):
        """Test cache clearing"""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = AnalysisCache(tmpdir)

            # Add some entries
            result = AnalysisResult(language="python", tool="test")
            cache.set("code1", "python", result)
            cache.set("code2", "python", result)

            # Check stats
            stats = cache.get_stats()
            assert stats["count"] == 2

            # Clear cache
            cleared = cache.clear()
            assert cleared == 2

            # Verify empty
            stats = cache.get_stats()
            assert stats["count"] == 0

    def test_cache_key_uniqueness(self):
        """Test cache key uniqueness"""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = AnalysisCache(tmpdir)

            result1 = AnalysisResult(language="python", tool="test1")
            result2 = AnalysisResult(language="c", tool="test2")

            # Same code, different languages should have different keys
            cache.set("code", "python", result1)
            cache.set("code", "c", result2)

            cached_py = cache.get("code", "python")
            cached_c = cache.get("code", "c")

            assert cached_py.tool == "test1"
            assert cached_c.tool == "test2"


class TestAnalysisResult:
    """Tests for AnalysisResult"""

    def test_result_empty(self):
        """Test empty result detection"""
        result = AnalysisResult()
        assert result.is_empty()

        result.vulnerabilities.append(
            Vulnerability("test", "high", 1, "CWE-1", "desc")
        )
        assert not result.is_empty()

    def test_result_summary(self):
        """Test summary generation"""
        result = AnalysisResult(
            vulnerabilities=[
                Vulnerability("test1", "high", 1, "CWE-78", "Cmd injection"),
                Vulnerability("test2", "medium", 2, "CWE-89", "SQL injection"),
            ],
            language="python",
            tool="bandit",
        )

        summary = result.get_summary()
        assert "2 potential issues" in summary
        assert "1 high severity" in summary

    def test_result_serialization(self):
        """Test result serialization/deserialization"""
        original = AnalysisResult(
            vulnerabilities=[
                Vulnerability("test", "high", 10, "CWE-502", "Pickle usage")
            ],
            language="python",
            tool="bandit",
        )

        # Serialize
        data = original.to_dict()

        # Deserialize
        restored = AnalysisResult.from_dict(data)

        assert len(restored.vulnerabilities) == 1
        assert restored.vulnerabilities[0].cwe_id == "CWE-502"
        assert restored.language == "python"
        assert restored.tool == "bandit"
