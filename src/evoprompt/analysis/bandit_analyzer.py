"""Bandit static analyzer for Python code."""

import subprocess
import json
import tempfile
import shutil
from pathlib import Path
from typing import Optional
import logging

from .base import StaticAnalyzer
from .result import AnalysisResult, Vulnerability

logger = logging.getLogger(__name__)


class BanditAnalyzer(StaticAnalyzer):
    """Bandit 静态分析器(Python)"""

    # Bandit测试ID到CWE的映射
    CWE_MAPPING = {
        "B102": "CWE-78",  # exec用法
        "B103": "CWE-78",  # set_bad_file_permissions
        "B104": "CWE-200",  # hardcoded_bind_all_interfaces
        "B105": "CWE-259",  # hardcoded_password_string
        "B106": "CWE-259",  # hardcoded_password_funcarg
        "B107": "CWE-259",  # hardcoded_password_default
        "B108": "CWE-377",  # hardcoded_tmp_directory
        "B110": "CWE-703",  # try_except_pass
        "B112": "CWE-703",  # try_except_continue
        "B201": "CWE-327",  # flask_debug_true
        "B301": "CWE-502",  # pickle
        "B302": "CWE-22",  # marshal
        "B303": "CWE-327",  # md5
        "B304": "CWE-327",  # ciphers
        "B305": "CWE-327",  # cipher_modes
        "B306": "CWE-377",  # mktemp_q
        "B307": "CWE-502",  # eval
        "B308": "CWE-20",  # mark_safe
        "B310": "CWE-22",  # urllib_urlopen
        "B311": "CWE-330",  # random
        "B312": "CWE-759",  # telnetlib
        "B313": "CWE-327",  # xml_bad_cElementTree
        "B314": "CWE-327",  # xml_bad_ElementTree
        "B315": "CWE-327",  # xml_bad_expatreader
        "B316": "CWE-327",  # xml_bad_expatbuilder
        "B317": "CWE-327",  # xml_bad_sax
        "B318": "CWE-327",  # xml_bad_minidom
        "B319": "CWE-327",  # xml_bad_pulldom
        "B320": "CWE-327",  # xml_bad_etree
        "B321": "CWE-22",  # ftplib
        "B323": "CWE-327",  # unverified_context
        "B324": "CWE-327",  # hashlib
        "B325": "CWE-377",  # tempnam
        "B401": "CWE-94",  # import_telnetlib
        "B402": "CWE-22",  # import_ftplib
        "B403": "CWE-502",  # import_pickle
        "B404": "CWE-78",  # import_subprocess
        "B405": "CWE-327",  # import_xml_etree
        "B406": "CWE-327",  # import_xml_sax
        "B407": "CWE-327",  # import_xml_expat
        "B408": "CWE-327",  # import_xml_minidom
        "B409": "CWE-327",  # import_xml_pulldom
        "B410": "CWE-327",  # import_lxml
        "B411": "CWE-327",  # import_xmlrpclib
        "B412": "CWE-327",  # import_httpoxy
        "B413": "CWE-327",  # import_pycrypto
        "B501": "CWE-295",  # request_with_no_cert_validation
        "B502": "CWE-295",  # ssl_with_bad_version
        "B503": "CWE-327",  # ssl_with_bad_defaults
        "B504": "CWE-295",  # ssl_with_no_version
        "B505": "CWE-327",  # weak_cryptographic_key
        "B506": "CWE-522",  # yaml_load
        "B507": "CWE-295",  # ssh_no_host_key_verification
        "B601": "CWE-78",  # paramiko_calls
        "B602": "CWE-78",  # subprocess_popen_with_shell_equals_true
        "B603": "CWE-78",  # subprocess_without_shell_equals_true
        "B604": "CWE-78",  # any_other_function_with_shell_equals_true
        "B605": "CWE-78",  # start_process_with_a_shell
        "B606": "CWE-78",  # start_process_with_no_shell
        "B607": "CWE-78",  # start_process_with_partial_path
        "B608": "CWE-89",  # hardcoded_sql_expressions
        "B609": "CWE-78",  # linux_commands_wildcard_injection
        "B610": "CWE-89",  # django_extra_used
        "B611": "CWE-89",  # django_rawsql_used
        "B701": "CWE-502",  # jinja2_autoescape_false
        "B702": "CWE-295",  # use_of_mako_templates
        "B703": "CWE-295",  # django_mark_safe
    }

    @classmethod
    def is_available(cls) -> bool:
        """检查 bandit 是否安装"""
        return shutil.which("bandit") is not None

    def analyze(self, code: str, lang: str) -> AnalysisResult:
        """使用 Bandit 分析 Python 代码

        Args:
            code: 源代码文本
            lang: 语言标识

        Returns:
            AnalysisResult: 分析结果,失败时返回空结果
        """
        # 检查工具是否可用
        if not self.is_available():
            logger.debug("Bandit is not available")
            return AnalysisResult(language=lang, tool="bandit")

        # 只分析Python代码
        if lang not in ["python", "py"]:
            return AnalysisResult(language=lang, tool="bandit")

        # 写入临时文件
        temp_file = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".py", delete=False, encoding="utf-8"
            ) as f:
                f.write(code)
                temp_file = f.name

            # 运行 bandit
            result = subprocess.run(
                ["bandit", "-f", "json", temp_file],
                capture_output=True,
                text=True,
                timeout=30,  # 30秒超时
            )

            # 解析输出
            try:
                output = json.loads(result.stdout)
            except json.JSONDecodeError:
                logger.warning("Failed to parse bandit output")
                return AnalysisResult(language=lang, tool="bandit")

            vulnerabilities = []
            for issue in output.get("results", []):
                vuln = Vulnerability(
                    type=issue.get("test_id", "unknown"),
                    severity=issue.get("issue_severity", "MEDIUM").lower(),
                    line_number=issue.get("line_number"),
                    cwe_id=self.CWE_MAPPING.get(issue.get("test_id")),
                    description=issue.get("issue_text", ""),
                    confidence=issue.get("issue_confidence", "MEDIUM").lower(),
                )
                vulnerabilities.append(vuln)

            return AnalysisResult(
                vulnerabilities=vulnerabilities,
                language=lang,
                tool="bandit",
                raw_output=output,
            )

        except subprocess.TimeoutExpired:
            logger.warning("Bandit analysis timed out")
            return AnalysisResult(language=lang, tool="bandit")
        except Exception as e:
            logger.warning(f"Bandit analysis failed: {e}")
            return AnalysisResult(language=lang, tool="bandit")
        finally:
            # 清理临时文件
            if temp_file:
                Path(temp_file).unlink(missing_ok=True)
