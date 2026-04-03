from mulvul.data.cwe_hierarchy import (
    BENIGN_LABEL,
    CWE_TO_MIDDLE,
    MAJOR_TO_MIDDLE,
    MIDDLE_TO_CWE,
    MIDDLE_TO_MAJOR,
    validate_taxonomy,
)


def test_canonical_taxonomy_has_no_internal_invariant_errors():
    assert validate_taxonomy() == []


def test_each_middle_belongs_to_exactly_one_major():
    owners = {}
    for major, middles in MAJOR_TO_MIDDLE.items():
        for middle in middles:
            assert middle not in owners
            owners[middle] = major

    assert BENIGN_LABEL not in owners
    assert owners == MIDDLE_TO_MAJOR


def test_each_cwe_belongs_to_exactly_one_middle():
    owners = {}
    for middle, cwes in MIDDLE_TO_CWE.items():
        for cwe in cwes:
            assert cwe not in owners
            owners[cwe] = middle

    assert owners == CWE_TO_MIDDLE


def test_every_defined_middle_has_a_parent_major():
    all_forward_middles = {middle for middles in MAJOR_TO_MIDDLE.values() for middle in middles}

    assert set(MIDDLE_TO_CWE) == all_forward_middles
    assert BENIGN_LABEL not in MIDDLE_TO_CWE
