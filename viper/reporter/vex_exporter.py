import json
from pathlib import Path


def export_vex_json(vex_document: dict, output_path: str) -> str:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as f:
        json.dump(vex_document, f, indent=2, ensure_ascii=False)

    return str(path)