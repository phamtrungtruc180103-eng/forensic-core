from __future__ import annotations

import json
import os
import re
import subprocess
import base64
from pathlib import Path
from typing import Any


def _clean_fabric_output(output: str) -> str:
    return re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", output).strip()


def invoke_event(event: dict[str, Any], msp_path: str | None = None) -> dict[str, Any]:
    """Invoke one custody transaction using a peer CLI configured by the Fabric shell."""
    action = event.get("action", "CREATE")
    if action in {"CREATE", "COLLECT"}:
        function = "RecordEvidence"
        args = [
            event["evidenceID"], event["caseID"], event["fileName"], event["sha256Hash"],
            event["merkleRoot"], event["investigator"], event["timestamp"],
            event.get("evidenceType", "FILE"), event.get("source", ""),
            event.get("acquisitionMethod", ""), event.get("collectedAt", event["timestamp"]),
        ]
    elif action in {"ACCESS", "TRANSFER", "RECEIVE", "ANALYZE", "VERIFY"}:
        function = "RecordCustodyEvent"
        args = [
            event["evidenceID"], action, event["investigator"], event.get("fromHolder", ""),
            event.get("toHolder", ""), event.get("reason", ""), event.get("result", ""),
            event.get("referenceHash", ""), event.get("currentHash", ""), event["timestamp"],
        ]
    elif action == "DELETE":
        function = "DeleteEvidence"
        args = [event["evidenceID"]]
    else:
        raise ValueError(f"Unsupported Fabric action: {action}")

    return invoke_transaction(function, args, msp_path, event["evidenceID"])


def invoke_staff(function: str, args: list[str], msp_path: str | None = None) -> dict[str, Any]:
    if function not in {"RegisterStaff", "UpdateStaffRole", "DeactivateStaff"}:
        raise ValueError(f"Unsupported staff transaction: {function}")
    return invoke_transaction(function, args, msp_path, args[0], "QueryStaff")


def invoke_transaction(
    function: str,
    args: list[str],
    msp_path: str | None = None,
    record_id: str | None = None,
    query_function: str = "QueryEvidence",
) -> dict[str, Any]:
    peer_binary = os.getenv("FABRIC_PEER_BIN", "peer")
    channel = os.getenv("FABRIC_CHANNEL", "evidence-channel")
    chaincode = os.getenv("FABRIC_CHAINCODE", "evidence")
    orderer = os.getenv("FABRIC_ORDERER_ADDRESS", "localhost:7050")
    orderer_ca = os.getenv("FABRIC_ORDERER_CA")
    peer_addresses = [value for value in os.getenv("FABRIC_PEER_ADDRESSES", "").split(",") if value]
    peer_certs = [value for value in os.getenv("FABRIC_PEER_TLS_ROOT_CERTS", "").split(",") if value]
    payload = json.dumps({"function": function, "Args": args}, separators=(",", ":"))
    command = [peer_binary, "chaincode", "invoke", "-o", orderer, "-C", channel, "-n", chaincode, "-c", payload, "--waitForEvent"]
    if orderer_ca:
        command.extend(["--tls", "--cafile", orderer_ca])
    for index, address in enumerate(peer_addresses):
        command.extend(["--peerAddresses", address])
        if index < len(peer_certs):
            command.extend(["--tlsRootCertFiles", peer_certs[index]])
    env = os.environ.copy()
    if msp_path:
        env["CORE_PEER_MSPCONFIGPATH"] = msp_path
    try:
        result = subprocess.run(command, env=env, check=False, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Fabric invoke timed out after 60 seconds") from exc
    output = _clean_fabric_output("\n".join(part for part in (result.stdout, result.stderr) if part))
    if "MVCC_READ_CONFLICT" in output:
        raise RuntimeError(
            "Giao dịch bị trùng thời điểm cập nhật. Dữ liệu chứng cứ vừa được thay đổi; "
            "hãy tải lại chứng cứ rồi thử lại."
        )
    if result.returncode != 0:
        raise RuntimeError(output or "Fabric peer invoke failed")
    tx_id = None
    if record_id:
        record = query_transaction(query_function, [record_id], msp_path)
        tx_id = record.get("lastTxID") if isinstance(record, dict) else None
    if not tx_id:
        match = re.search(r"txid\s*[\[:=]\s*([a-fA-F0-9]{64})", output, re.IGNORECASE)
        tx_id = match.group(1) if match else None
    block = query_transaction_block(tx_id, msp_path) if tx_id else {}
    return {
        "txID": tx_id,
        "transactionStatus": block.get("transactionStatus", "VALID"),
        "blockNumber": block.get("blockNumber"),
        "blockHash": block.get("blockHash", ""),
        "previousBlockHash": block.get("previousBlockHash", ""),
        "blockLookup": "QSCC_BY_TX_ID" if block else "UNAVAILABLE",
        "peerOutput": output,
    }


def query_transaction(function: str, args: list[str], msp_path: str | None = None) -> Any:
    peer_binary = os.getenv("FABRIC_PEER_BIN", "peer")
    channel = os.getenv("FABRIC_CHANNEL", "evidence-channel")
    chaincode = os.getenv("FABRIC_CHAINCODE", "evidence")
    payload = json.dumps({"function": function, "Args": args}, separators=(",", ":"))
    try:
        env = os.environ.copy()
        if msp_path:
            env["CORE_PEER_MSPCONFIGPATH"] = msp_path
        result = subprocess.run(
            [peer_binary, "chaincode", "query", "-C", channel, "-n", chaincode, "-c", payload],
            env=env, check=False, capture_output=True, text=True, timeout=30,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Fabric query timed out after 30 seconds") from exc
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "Fabric peer query failed")
    return json.loads(result.stdout)


def query_channel_info(msp_path: str | None = None) -> dict[str, Any]:
    peer_binary = os.getenv("FABRIC_PEER_BIN", "peer")
    channel = os.getenv("FABRIC_CHANNEL", "evidence-channel")
    env = os.environ.copy()
    if msp_path:
        env["CORE_PEER_MSPCONFIGPATH"] = msp_path
    try:
        result = subprocess.run(
            [peer_binary, "channel", "getinfo", "-c", channel],
            env=env, check=False, capture_output=True, text=True, timeout=30,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Fabric channel info timed out after 30 seconds") from exc
    output = _clean_fabric_output("\n".join(part for part in (result.stdout, result.stderr) if part))
    if result.returncode != 0:
        raise RuntimeError(output or "Fabric channel info failed")
    match = re.search(r"Blockchain info:\s*(\{.*\})", output)
    if not match:
        raise RuntimeError("Unable to parse Fabric blockchain info")
    return json.loads(match.group(1))


def _query_qscc_block(function: str, value: str, msp_path: str | None = None) -> dict[str, Any]:
    peer_binary = os.getenv("FABRIC_PEER_BIN", "peer")
    configtxlator_binary = os.getenv("CONFIGTXLATOR_BIN", str(Path(peer_binary).with_name("configtxlator")))
    channel = os.getenv("FABRIC_CHANNEL", "evidence-channel")
    payload = json.dumps({"function": function, "Args": [channel, value]}, separators=(",", ":"))
    env = os.environ.copy()
    if msp_path:
        env["CORE_PEER_MSPCONFIGPATH"] = msp_path
    try:
        query = subprocess.run(
            [peer_binary, "chaincode", "query", "-C", channel, "-n", "qscc", "-c", payload, "--raw"],
            env=env, check=False, capture_output=True, timeout=30,
        )
        if query.returncode != 0:
            raise RuntimeError(query.stderr.decode(errors="replace").strip() or "QSCC block query failed")
        raw_output = query.stdout.strip()
        if raw_output.startswith(b"[") and raw_output.endswith(b"]"):
            try:
                raw_block = bytes(int(value) for value in raw_output[1:-1].split())
            except ValueError as exc:
                raise RuntimeError("Unable to parse QSCC raw byte array") from exc
        else:
            raw_block = raw_output
        decoded = subprocess.run(
            [configtxlator_binary, "proto_decode", "--input", "/dev/stdin", "--type", "common.Block", "--output", "/dev/stdout"],
            input=raw_block, check=False, capture_output=True, timeout=30,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Fabric block lookup timed out after 30 seconds") from exc
    if decoded.returncode != 0:
        raise RuntimeError(decoded.stderr.decode(errors="replace").strip() or "Fabric block decode failed")
    return json.loads(decoded.stdout)


def query_transaction_block(tx_id: str, msp_path: str | None = None) -> dict[str, Any]:
    block = _query_qscc_block("GetBlockByTxID", tx_id, msp_path)
    envelopes = block.get("data", {}).get("data", [])
    tx_index = next(
        (
            index for index, envelope in enumerate(envelopes)
            if envelope.get("payload", {}).get("header", {}).get("channel_header", {}).get("tx_id") == tx_id
        ),
        None,
    )
    if tx_index is None:
        raise RuntimeError(f"Transaction {tx_id} was not found in the block returned by QSCC")
    header = block.get("header", {})
    block_number = int(header.get("number", 0))
    metadata = block.get("metadata", {}).get("metadata", [])
    validation_code = None
    if len(metadata) > 2:
        validation_filter = base64.b64decode(metadata[2])
        if tx_index < len(validation_filter):
            validation_code = validation_filter[tx_index]
    channel_info = query_channel_info(msp_path)
    latest_block_number = max(int(channel_info.get("height", 0)) - 1, 0)
    if block_number == latest_block_number:
        block_hash = channel_info.get("currentBlockHash", "")
    else:
        next_block = _query_qscc_block("GetBlockByNumber", str(block_number + 1), msp_path)
        block_hash = next_block.get("header", {}).get("previous_hash", "")
    return {
        "txID": tx_id,
        "blockNumber": block_number,
        "blockHash": block_hash,
        "previousBlockHash": header.get("previous_hash", ""),
        "dataHash": header.get("data_hash", ""),
        "validationCode": validation_code,
        "transactionStatus": "VALID" if validation_code in (None, 0) else f"INVALID_{validation_code}",
    }


def check_fabric_connection() -> dict[str, Any]:
    """Verify that the configured peer, channel, and chaincode are usable."""
    evidence = query_transaction("QueryAllEvidence", [])
    if not isinstance(evidence, list):
        raise RuntimeError("Fabric health query returned an unexpected response")
    return {
        "channel": os.getenv("FABRIC_CHANNEL", "evidence-channel"),
        "chaincode": os.getenv("FABRIC_CHAINCODE", "evidence"),
        "evidenceCount": len(evidence),
    }
