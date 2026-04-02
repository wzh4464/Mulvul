"""Data structures for static analysis results."""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


@dataclass
class Vulnerability:
    """单个漏洞发现"""

    type: str  # 漏洞类型
    severity: str  # 严重程度: high/medium/low
    line_number: Optional[int]  # 行号
    cwe_id: Optional[str]  # CWE编号 (如 "CWE-502")
    description: str  # 描述
    confidence: str = "medium"  # 置信度


@dataclass
class AnalysisResult:
    """统一的分析结果"""

    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    language: str = "unknown"
    tool: str = "unknown"
    raw_output: Dict[str, Any] = field(default_factory=dict)

    def is_empty(self) -> bool:
        """检查是否为空结果"""
        return len(self.vulnerabilities) == 0

    def get_cwe_codes(self) -> List[str]:
        """提取所有CWE编号"""
        return [v.cwe_id for v in self.vulnerabilities if v.cwe_id]

    def get_summary(self, max_length: int = 300) -> str:
        """生成简短摘要用于prompt增强"""
        if self.is_empty():
            return "No issues found"

        high = [v for v in self.vulnerabilities if v.severity == "high"]
        medium = [v for v in self.vulnerabilities if v.severity == "medium"]

        summary = f"Found {len(self.vulnerabilities)} potential issues"
        details = []

        if high:
            high_cwes = list(set(v.cwe_id or v.type for v in high[:3]))
            details.append(f"{len(high)} high severity ({', '.join(high_cwes)})")

        if medium:
            details.append(f"{len(medium)} medium severity")

        if details:
            summary += ": " + ", ".join(details)

        return summary[:max_length]

    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典用于缓存"""
        return {
            "vulnerabilities": [
                {
                    "type": v.type,
                    "severity": v.severity,
                    "line_number": v.line_number,
                    "cwe_id": v.cwe_id,
                    "description": v.description,
                    "confidence": v.confidence,
                }
                for v in self.vulnerabilities
            ],
            "language": self.language,
            "tool": self.tool,
            "raw_output": self.raw_output,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AnalysisResult":
        """从字典反序列化"""
        vulnerabilities = [
            Vulnerability(**v) for v in data.get("vulnerabilities", [])
        ]
        return cls(
            vulnerabilities=vulnerabilities,
            language=data.get("language", "unknown"),
            tool=data.get("tool", "unknown"),
            raw_output=data.get("raw_output", {}),
        )
