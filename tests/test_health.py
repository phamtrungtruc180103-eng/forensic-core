from __future__ import annotations

import unittest
from unittest.mock import patch

from fastapi.responses import Response

import backend.main as main


class HealthTest(unittest.TestCase):
    def tearDown(self) -> None:
        main.HEALTH_CACHE = None

    @patch("backend.main.check_fabric_connection", side_effect=RuntimeError("peer unavailable"))
    def test_fabric_failure_is_not_reported_as_connected(self, _check) -> None:
        response = Response()
        with patch.dict("os.environ", {"FABRIC_PEER_CLI": "1"}):
            result = main.health(response)

        self.assertEqual(response.status_code, 503)
        self.assertEqual(result["status"], "disconnected")
        self.assertEqual(result["detail"], "Fabric connection check failed")

    def test_local_mode_is_explicit(self) -> None:
        response = Response()
        with patch.dict("os.environ", {"FABRIC_PEER_CLI": "0"}):
            result = main.health(response)

        self.assertEqual(result["status"], "connected")
        self.assertEqual(result["ledger"], "local-adapter")


if __name__ == "__main__":
    unittest.main()
