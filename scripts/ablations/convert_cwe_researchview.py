from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parents[1]
SOURCE_PATH = ROOT_DIR / "data" / "primevul" / "cwe_researchview.txt"
OUTPUT_PATH = ROOT_DIR / "cwe_researchview.json"
PRIMEVUL_SUFFIX = "[PrimeVul]"


def parse_cwe_tree(text: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    stack: list[tuple[int, str]] = []

    for raw_line in text.splitlines():
        stripped_line = raw_line.lstrip()
        if not stripped_line.startswith("- "):
            continue

        indent_width = len(raw_line) - len(stripped_line)
        level = indent_width // 2

        while stack and stack[-1][0] >= level:
            stack.pop()

        content = stripped_line[2:].strip()
        is_primevul = False

        if content.endswith(PRIMEVUL_SUFFIX):
            is_primevul = True
            content = content[: -len(PRIMEVUL_SUFFIX)].rstrip()

        if " " not in content:
            continue

        cwe_id, name = content.split(" ", 1)
        parent_id = stack[-1][1] if stack else None

        records.append(
            {
                "id": cwe_id,
                "name": name,
                "parent_id": parent_id,
                "is_primevul": is_primevul,
                "level": level,
            }
        )

        stack.append((level, cwe_id))

    return records


def main() -> None:
    text = SOURCE_PATH.read_text(encoding="utf-8")
    records = parse_cwe_tree(text)
    OUTPUT_PATH.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
