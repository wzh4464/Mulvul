import os
import pytest

from evoprompt.utils.response_parsing import (
    extract_cwe_major,
    extract_vulnerability_label,
)


pytestmark = pytest.mark.skipif(
    os.getenv("RUN_RESPONSE_PARSING_TESTS") != "1",
    reason="响应解析测试默认关闭，设置 RUN_RESPONSE_PARSING_TESTS=1 后再运行",
)


@pytest.mark.parametrize(
    "response,expected",
    [
        ("The code is vulnerable.\nRecommend patching.", "1"),
        ("BENIGN sample with no issues detected", "0"),
        ("Yes, clearly a vulnerability", "1"),
        ("", "0"),
        (None, "0"),
    ],
)
def test_extract_vulnerability_label(response, expected):
    assert extract_vulnerability_label(response) == expected


@pytest.mark.parametrize(
    "response,expected",
    [
        ("Benign", "Benign"),
        ("CWE-120 classic overflow", "Buffer Errors"),
        ("SQL injection detected", "Injection"),
        ("Unknown text", "Other"),
    ],
)
def test_extract_cwe_major(response, expected):
    assert extract_cwe_major(response) == expected

