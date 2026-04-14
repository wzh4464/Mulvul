from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_module():
    project_root = Path(__file__).resolve().parents[1]
    script_path = project_root / "scripts" / "build_cf_p_dataset.py"
    spec = importlib.util.spec_from_file_location("build_cf_p_dataset", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_build_primevul_inventory_uses_primary_cwe_and_caps_sampling():
    module = _load_module()
    records = [
        {"idx": 1, "target": 1, "cwe": ["CWE-79", "CWE-89"], "func": "a"},
        {"idx": 2, "target": 1, "cwe": ["CWE-79"], "func": "b"},
        {"idx": 3, "target": 0, "cwe": [], "func": "benign"},
    ]
    records.extend(
        {
            "idx": 100 + i,
            "target": 1,
            "cwe": ["CWE-22"],
            "func": f"func_{i}",
        }
        for i in range(60)
    )

    inventory = module.build_primevul_inventory(records, per_cwe_cap=50, seed=7)

    assert inventory.primary_cwe_counts == {"CWE-22": 60, "CWE-79": 2}
    assert inventory.prime_cwe_set == {"CWE-22", "CWE-79"}
    assert len(inventory.sampled_vulnerable_by_cwe["CWE-79"]) == 2
    assert len(inventory.sampled_vulnerable_by_cwe["CWE-22"]) == 50
    assert inventory.benign_pool == [
        {
            "idx": 3,
            "target": 0,
            "cwe": [],
            "func": "benign",
            "source": "primevul",
            "primary_cwe": None,
        }
    ]


def test_parse_insert_values_and_decode_sql_value_handle_replace_and_quotes():
    module = _load_module()
    line = (
        "INSERT INTO method_change VALUES("
        "'217096824924488','41461181100456','_dl_dst_count',"
        "'_dl_dst_count(const char * name)','[''name'']','150','176',"
        "replace('_dl_dst_count()\\n{\\n  return ''ok'';\\n}','\\n',char(10)),"
        "'22','13','199','0','True');"
    )

    values = module.parse_insert_values(line)

    assert values[0] == "'217096824924488'"
    assert module.decode_sql_value(values[2]) == "_dl_dst_count"
    assert module.decode_sql_value(values[7]) == "_dl_dst_count()\n{\n  return 'ok';\n}"
    assert module.parse_bool_token(values[12]) is True


def test_extract_cf_p_records_from_lines_filters_language_before_change_and_cwe():
    module = _load_module()
    prime_cwe_set = {"CWE-79", "CWE-22"}
    cwe_lines = [
        "INSERT INTO cwe_classification VALUES('CVE-1','CWE-79');",
        "INSERT INTO cwe_classification VALUES('CVE-2','CWE-89');",
    ]
    cve_to_prime_cwes = module.load_relevant_cwe_map_from_lines(cwe_lines, prime_cwe_set)

    sql_lines = [
        "INSERT INTO fixes VALUES('CVE-1','hash-1','https://github.com/acme/app');",
        "INSERT INTO fixes VALUES('CVE-2','hash-2','https://github.com/acme/other');",
        "INSERT INTO file_change VALUES('10','hash-1','app.py','app.py','app.py',ModificationType.MODIFY,NULL,NULL,NULL,NULL,'print(user_input)','print(old_input)','10','1','20','Python');",
        "INSERT INTO file_change VALUES('11','hash-2','other.java','other.java','other.java',ModificationType.MODIFY,NULL,NULL,NULL,NULL,'System.out.println(x);','System.out.println(old);','9','1','18','Java');",
        "INSERT INTO method_change VALUES('100','10','foo','foo()','[]','1','3','print(user_input)','3','1','10','0','True');",
        "INSERT INTO method_change VALUES('101','10','foo_fixed','foo_fixed()','[]','1','3','print(safe_input)','3','1','10','0','False');",
        "INSERT INTO method_change VALUES('102','11','bar','bar()','[]','1','3','System.out.println(x);','3','1','10','0','True');",
    ]

    records = module.extract_cf_p_records_from_lines(
        sql_lines,
        cve_to_prime_cwes=cve_to_prime_cwes,
        allowed_cwe_set=prime_cwe_set,
        preferred_cwe_set=prime_cwe_set,
    )

    assert len(records) == 1
    assert records[0]["idx"] == 100
    assert records[0]["lang"] == "python"
    assert records[0]["cwe"] == ["CWE-79"]
    assert records[0]["commit_id"] == "hash-1"
    assert records[0]["project"] == "app"


def test_build_topup_dataset_prefers_primevul_then_cvefixes_and_adds_benign():
    module = _load_module()

    primevul_records = [
        {"idx": i, "target": 1, "cwe": ["CWE-79"], "func": f"pv79_{i}"}
        for i in range(40)
    ]
    primevul_records.extend(
        {"idx": 100 + i, "target": 1, "cwe": ["CWE-22"], "func": f"pv22_{i}"}
        for i in range(49)
    )
    primevul_records.extend(
        {"idx": 1000 + i, "target": 0, "cwe": [], "func": f"benign_{i}"}
        for i in range(80)
    )

    inventory = module.build_primevul_inventory(primevul_records, per_cwe_cap=50, seed=13)

    cf_p_records = [
        {
            "idx": 2000 + i,
            "target": 1,
            "cwe": ["CWE-79"],
            "func": f"cf79_{i}",
            "source": "cvefixes",
            "lang": "python",
        }
        for i in range(12)
    ]

    result = module.build_topup_dataset(
        inventory,
        cf_p_records,
        target_per_cwe=50,
        seed=13,
    )

    assert result.kept_cwes == ["CWE-79"]
    assert result.dropped_cwes == ["CWE-22"]
    assert result.per_cwe_stats["CWE-79"]["prime_selected"] == 40
    assert result.per_cwe_stats["CWE-79"]["cf_selected"] == 10
    assert result.per_cwe_stats["CWE-22"]["kept"] is False

    vuln_records = [record for record in result.records if int(record["target"]) == 1]
    benign_records = [record for record in result.records if int(record["target"]) == 0]
    prime_anchor_records = [
        record
        for record in vuln_records
        if record["anchor_cwe"] == "CWE-79"
        and record["supplement_strategy"] == "primevul_anchor"
    ]
    same_cwe_records = [
        record
        for record in vuln_records
        if record["anchor_cwe"] == "CWE-79"
        and record["supplement_strategy"] == "same_cwe_direct"
    ]

    assert len(prime_anchor_records) == 40
    assert len(same_cwe_records) == 10
    assert {record["anchor_major"] for record in prime_anchor_records + same_cwe_records} == {"Injection"}
    assert {record["primary_cwe"] for record in same_cwe_records} == {"CWE-79"}
    assert all(record["supplement_strategy"] == "benign" for record in benign_records)
    assert all(record["anchor_cwe"] is None for record in benign_records)
    assert all(record["anchor_major"] is None for record in benign_records)

    vuln_count = len(vuln_records)
    benign_count = len(benign_records)
    assert vuln_count == 50
    assert benign_count == 50


def test_build_topup_dataset_can_use_same_major_replacements_without_reuse():
    module = _load_module()

    primevul_records = [
        {"idx": i, "target": 1, "cwe": ["CWE-77"], "func": f"pv77_{i}"}
        for i in range(10)
    ]
    primevul_records.extend(
        {"idx": 100 + i, "target": 1, "cwe": ["CWE-78"], "func": f"pv78_{i}"}
        for i in range(10)
    )
    primevul_records.extend(
        {"idx": 1000 + i, "target": 0, "cwe": [], "func": f"benign_{i}"}
        for i in range(60)
    )

    inventory = module.build_primevul_inventory(primevul_records, per_cwe_cap=50, seed=21)

    cf_p_records = [
        {
            "idx": 2000 + i,
            "target": 1,
            "cwe": ["CWE-79"],
            "func": f"cf79_{i}",
            "source": "cvefixes",
            "lang": "python",
            "primary_cwe": "CWE-79",
        }
        for i in range(60)
    ]

    result = module.build_topup_dataset(
        inventory,
        cf_p_records,
        target_per_cwe=50,
        seed=21,
    )

    assert result.kept_cwes == ["CWE-77"]
    assert result.dropped_cwes == ["CWE-78"]
    assert result.per_cwe_stats["CWE-77"]["cf_same_cwe_selected"] == 0
    assert result.per_cwe_stats["CWE-77"]["cf_same_major_selected"] == 40
    assert result.per_cwe_stats["CWE-77"]["same_major_replacement_cwe_counts"] == {"CWE-79": 40}
    assert result.per_cwe_stats["CWE-78"]["kept"] is False

    vuln_records = [record for record in result.records if int(record["target"]) == 1]
    same_major_records = [
        record
        for record in vuln_records
        if record["supplement_strategy"] == "same_major_replacement"
    ]
    assert len(vuln_records) == 50
    assert sum(1 for record in vuln_records if record["cwe"] == ["CWE-79"]) == 40
    assert len(same_major_records) == 40
    assert {record["anchor_cwe"] for record in same_major_records} == {"CWE-77"}
    assert {record["anchor_major"] for record in same_major_records} == {"Injection"}
    assert {record["primary_cwe"] for record in same_major_records} == {"CWE-79"}
    assert len({record["idx"] for record in vuln_records}) == 50


def test_build_stats_tracks_same_cwe_and_same_major_composition():
    module = _load_module()

    primevul_records = [
        {"idx": i, "target": 1, "cwe": ["CWE-77"], "func": f"pv77_{i}"}
        for i in range(40)
    ]
    primevul_records.extend(
        {"idx": 100 + i, "target": 1, "cwe": ["CWE-78"], "func": f"pv78_{i}"}
        for i in range(10)
    )
    primevul_records.extend(
        {"idx": 200 + i, "target": 1, "cwe": ["CWE-79"], "func": f"pv79_{i}"}
        for i in range(10)
    )
    primevul_records.extend(
        {"idx": 1000 + i, "target": 0, "cwe": [], "func": f"benign_{i}"}
        for i in range(120)
    )
    inventory = module.build_primevul_inventory(primevul_records, per_cwe_cap=50, seed=9)

    direct_cf_p_records = [
        {
            "idx": 2000 + i,
            "target": 1,
            "cwe": ["CWE-77"],
            "func": f"cf77_{i}",
            "source": "cvefixes",
            "lang": "python",
            "primary_cwe": "CWE-77",
        }
        for i in range(10)
    ]
    same_major_only_records = [
        {
            "idx": 3000 + i,
            "target": 1,
            "cwe": ["CWE-89"],
            "func": f"cf89_{i}",
            "source": "cvefixes",
            "lang": "python",
            "primary_cwe": "CWE-89",
        }
        for i in range(40)
    ]
    topup_candidate_records = direct_cf_p_records + same_major_only_records

    topup_result = module.build_topup_dataset(
        inventory,
        topup_candidate_records,
        target_per_cwe=50,
        seed=9,
    )
    stats = module.build_stats(
        inventory,
        direct_cf_p_records,
        topup_result,
        topup_candidate_records=topup_candidate_records,
    )

    assert stats["topup_50"]["same_cwe_direct_count"] == 10
    assert stats["topup_50"]["same_major_replacement_count"] == 40
    assert stats["topup_50"]["per_anchor_replacement_cwe_distribution"] == {
        "CWE-78": {"CWE-89": 40}
    }
    assert stats["topup_50"]["anchors_dropped_after_same_major_search"] == ["CWE-79"]
