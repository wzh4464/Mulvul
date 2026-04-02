import pytest

from mulvul.strategies import create_strategy
from mulvul.utils.legacy import ensure_legacy_three_layer_enabled


def test_create_strategy_rejects_legacy_mulvul_by_default():
    with pytest.raises(ValueError, match="Legacy mode 'mulvul' is disabled"):
        create_strategy("mulvul", object(), {})


def test_create_strategy_allows_legacy_mulvul_with_explicit_flag():
    strategy = create_strategy(
        "mulvul",
        object(),
        {"allow_legacy_mulvul": True},
    )
    assert strategy.__class__.__name__ == "MulVulStrategy"


def test_legacy_three_layer_guard_rejects_mulvul_default():
    with pytest.raises(ValueError, match="--method mulvul"):
        ensure_legacy_three_layer_enabled("mulvul", allow_legacy_script=False)


def test_legacy_three_layer_guard_allows_explicit_or_non_mulvul():
    ensure_legacy_three_layer_enabled("mulvul", allow_legacy_script=True)
    ensure_legacy_three_layer_enabled("gpt4o_rag_singlepass", allow_legacy_script=False)
