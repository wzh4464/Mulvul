from mulvul.data.cwe_hierarchy import (
    BENIGN_LABEL,
    CWE_GROUPS,
    CWE_TO_GROUP,
    CWE_TO_MIDDLE,
    MAJOR_TO_MIDDLE,
    MIDDLE_TO_CWE,
    MIDDLE_TO_MAJOR,
    compressed_candidates,
    cwe_node_id,
    major_node_id,
    middle_node_id,
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
    all_forward_middles = {
        middle for middles in MAJOR_TO_MIDDLE.values() for middle in middles
    }

    assert set(MIDDLE_TO_CWE) == all_forward_middles
    assert BENIGN_LABEL not in MIDDLE_TO_CWE


def test_stable_v2_node_ids_are_machine_friendly_and_unique():
    major_ids = [major_node_id(major) for major in MAJOR_TO_MIDDLE]
    middle_ids = [middle_node_id(middle) for middle in MIDDLE_TO_CWE]
    cwe_ids = [cwe_node_id(cwe) for cwes in MIDDLE_TO_CWE.values() for cwe in cwes]

    assert major_node_id("Memory") == "major_memory"
    assert middle_node_id("Buffer Errors") == "middle_buffer_errors"
    assert cwe_node_id("CWE-120") == "cwe_120"
    assert len(major_ids) == len(set(major_ids))
    assert len(middle_ids) == len(set(middle_ids))
    assert len(cwe_ids) == len(set(cwe_ids))


# ------------------------------------------------------------------
# CWE group compression tests
# ------------------------------------------------------------------


def test_compressed_candidates_reduces_buffer_errors():
    raw = MIDDLE_TO_CWE["Buffer Errors"]
    compressed = compressed_candidates("Buffer Errors")
    assert len(compressed) < len(raw)
    # CWE-119 group should collapse 6 CWEs into 1
    assert "CWE-119" in compressed
    assert "CWE-120" not in compressed  # collapsed into CWE-119
    assert "CWE-121" not in compressed


def test_compressed_candidates_preserves_ungrouped():
    # Pointer Dereference has CWE-476, CWE-617 - neither grouped
    compressed = compressed_candidates("Pointer Dereference")
    assert "CWE-476" in compressed
    assert "CWE-617" in compressed


def test_compressed_candidates_unknown_middle_returns_empty():
    assert compressed_candidates("Nonexistent Category") == []


def test_cwe_to_group_maps_members():
    assert CWE_TO_GROUP["CWE-120"] == "CWE-119"
    assert CWE_TO_GROUP["CWE-121"] == "CWE-119"
    assert CWE_TO_GROUP["CWE-122"] == "CWE-119"
    assert CWE_TO_GROUP["CWE-787"] == "CWE-119"
    assert CWE_TO_GROUP["CWE-805"] == "CWE-119"
    assert CWE_TO_GROUP["CWE-119"] == "CWE-119"  # representative maps to itself
    assert CWE_TO_GROUP.get("CWE-476") is None  # not grouped


def test_cwe_groups_members_exist_in_taxonomy():
    """Every CWE listed in CWE_GROUPS must exist in the canonical taxonomy."""
    all_cwes = {cwe for cwes in MIDDLE_TO_CWE.values() for cwe in cwes}
    for rep, members in CWE_GROUPS.items():
        for member in members:
            assert member in all_cwes, f"{member} from group {rep} not in taxonomy"


def test_compressed_candidates_order_preserves_first_seen():
    """The compressed list should keep the order of first appearance."""
    compressed = compressed_candidates("Buffer Errors")
    # CWE-119 appears first in the raw list and is the representative
    assert compressed[0] == "CWE-119"
    # CWE-125 is ungrouped and should appear after CWE-119
    assert "CWE-125" in compressed
    assert compressed.index("CWE-119") < compressed.index("CWE-125")
