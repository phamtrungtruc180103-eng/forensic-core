from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

from backend.couch_store import store

ROOT = Path(__file__).resolve().parent.parent
STORAGE = ROOT / "storage"
BACKUP = STORAGE / f"json-backup-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
COLLECTIONS = {
    "projects": ("projects.json", "projectID"),
    "investigators": ("investigators.json", "investigatorID"),
    "reports": ("reports.json", "reportID"),
    "relations": ("relations.json", "relationID"),
    "ledger": ("ledger.json", "txID"),
}


def load(path: Path, default):
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> None:
    store.ensure_database()
    BACKUP.mkdir(parents=True, exist_ok=True)
    metadata = load(STORAGE / "metadata.json", {})
    metadata_items = list(metadata.values()) if isinstance(metadata, dict) else metadata
    collections = {**COLLECTIONS, "metadata": ("metadata.json", "evidenceID")}
    for collection, (filename, id_field) in collections.items():
        path = STORAGE / filename
        if path.exists():
            shutil.copy2(path, BACKUP / filename)
        values = metadata_items if collection == "metadata" else load(path, [])
        if not isinstance(values, list):
            raise ValueError(f"{filename} must contain a JSON array or object map")
        store.replace_collection(collection, values, id_field)
        print(f"migrated {collection}: {len(values)} documents")
    print(f"JSON backup: {BACKUP}")
    print(f"CouchDB database: {store.database}")


if __name__ == "__main__":
    main()
