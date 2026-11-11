from __future__ import annotations

import sys

from backend.couch_store import store
from backend.fabric_adapter import check_fabric_connection


def main() -> int:
    try:
        store.ensure_database()
        status = check_fabric_connection()
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"Fabric preflight failed: {exc}", file=sys.stderr)
        return 1
    print(
        "Fabric preflight passed: "
        f"channel={status['channel']} "
        f"chaincode={status['chaincode']} "
        f"evidence={status['evidenceCount']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
