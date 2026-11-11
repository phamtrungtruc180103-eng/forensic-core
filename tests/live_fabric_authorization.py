from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.fabric_adapter import invoke_event
from backend.fabric_ca import wallet_msp_path


def main() -> int:
    evidence_id = os.environ["TEST_EVIDENCE_ID"]
    actor_id = os.environ["TEST_ACTOR_ID"]
    enrollment_id = os.environ["TEST_ENROLLMENT_ID"]
    expected_rejection = os.getenv("TEST_EXPECTED_REJECTION", "not allowed")
    action = os.getenv("TEST_ACTION", "ANALYZE")
    event = {
        "evidenceID": evidence_id,
        "action": action,
        "investigator": actor_id,
        "fromHolder": os.getenv("TEST_FROM_HOLDER", ""),
        "toHolder": os.getenv("TEST_TO_HOLDER", ""),
        "reason": "Authorization rejection acceptance test",
        "result": "This transaction must not commit",
        "timestamp": "2026-10-15T00:00:00Z",
    }
    try:
        invoke_event(event, str(wallet_msp_path(enrollment_id)))
    except RuntimeError as exc:
        if expected_rejection not in str(exc):
            print(f"Unexpected Fabric rejection: {exc}", file=sys.stderr)
            return 1
        print(f"PASS: Fabric chaincode rejected transaction ({expected_rejection})")
        return 0
    print("FAIL: unauthorized Fabric transaction was committed", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
