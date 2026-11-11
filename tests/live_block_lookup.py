from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.fabric_adapter import query_transaction_block


if __name__ == "__main__":
    result = query_transaction_block(os.environ["TEST_TX_ID"])
    print(json.dumps(result, indent=2))
