"""Script to export the BitGuard OpenAPI schema to docs/openapi.json."""

import json
import sys
from pathlib import Path

# Remove script directory if Python added it to sys.path to avoid shadowing stdlib logging
script_dir = str(Path(__file__).resolve().parent)
if sys.path and sys.path[0] == script_dir:
    sys.path.pop(0)

# Ensure repository root is on sys.path
repo_root = Path(__file__).resolve().parent.parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from services.bitguard.main import app  # noqa: E402


def export_openapi_schema(target_path: Path | None = None) -> Path:
    """Extract app OpenAPI schema and write to disk."""
    if target_path is None:
        target_path = Path(__file__).resolve().parent.parent.parent / "docs" / "openapi.json"

    target_path.parent.mkdir(parents=True, exist_ok=True)
    schema = app.openapi()
    target_path.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target_path


if __name__ == "__main__":
    out = export_openapi_schema()
    print(f"Exported OpenAPI schema to {out}")
