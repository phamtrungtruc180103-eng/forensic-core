from __future__ import annotations

import unittest
from unittest.mock import Mock, patch

from backend.fabric_adapter import check_fabric_connection, invoke_event, invoke_transaction


class FabricConnectionTest(unittest.TestCase):
    @patch("backend.fabric_adapter.query_transaction", return_value=[])
    def test_connection_check_reports_chaincode_details(self, query) -> None:
        result = check_fabric_connection()

        query.assert_called_once_with("QueryAllEvidence", [])
        self.assertEqual(result["channel"], "evidence-channel")
        self.assertEqual(result["chaincode"], "evidence")
        self.assertEqual(result["evidenceCount"], 0)

    @patch("backend.fabric_adapter.query_transaction", return_value={"unexpected": True})
    def test_connection_check_rejects_unexpected_response(self, _query) -> None:
        with self.assertRaisesRegex(RuntimeError, "unexpected response"):
            check_fabric_connection()

    @patch("backend.fabric_adapter.invoke_transaction", return_value={"txID": "abc", "transactionStatus": "VALID"})
    def test_verify_event_uses_generic_custody_transaction(self, invoke) -> None:
        event = {
            "evidenceID": "E1", "action": "VERIFY", "investigator": "INV1",
            "reason": "Integrity check", "result": "MATCH", "referenceHash": "aaa",
            "currentHash": "aaa", "timestamp": "2026-01-01T00:00:00Z",
        }

        result = invoke_event(event, "/wallet/msp")

        self.assertEqual(result["transactionStatus"], "VALID")
        function, args, msp_path, record_id = invoke.call_args.args
        self.assertEqual(function, "RecordCustodyEvent")
        self.assertEqual(args[1], "VERIFY")
        self.assertEqual(args[6], "MATCH")
        self.assertEqual(msp_path, "/wallet/msp")
        self.assertEqual(record_id, "E1")

    @patch("backend.fabric_adapter.query_transaction_block", return_value={"blockNumber": 10, "blockHash": "current", "previousBlockHash": "previous", "transactionStatus": "VALID"})
    @patch("backend.fabric_adapter.subprocess.run")
    def test_invoke_receipt_contains_fabric_commit_data(self, run, _channel_info) -> None:
        run.return_value = Mock(returncode=0, stdout="", stderr="txid [" + "a" * 64 + "] committed with status (VALID)")

        receipt = invoke_transaction("DeleteEvidence", ["E1"])

        self.assertEqual(receipt["txID"], "a" * 64)
        self.assertEqual(receipt["transactionStatus"], "VALID")
        self.assertEqual(receipt["blockNumber"], 10)
        self.assertEqual(receipt["blockHash"], "current")
        self.assertEqual(receipt["previousBlockHash"], "previous")


if __name__ == "__main__":
    unittest.main()
