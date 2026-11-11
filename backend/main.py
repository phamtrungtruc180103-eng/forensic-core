from __future__ import annotations

import hashlib
import json
import os
import time
import threading
import uuid
from urllib.parse import quote
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, Field
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles

from backend.fabric_adapter import check_fabric_connection, invoke_event, invoke_staff, query_transaction, query_transaction_block
from backend.fabric_ca import ensure_org_crl_current, enroll_staff, publish_org_crl, revoke_staff, wallet_msp_path
from backend.pdf_signing import certificate_common_name, sign_pdf_pades
from backend.couch_store import store
from backend.auth import authenticate, change_password, create_access_token, create_user, current_user, require_admin

ROOT = Path(__file__).resolve().parent.parent
STORAGE_DIR = Path(os.getenv("EVIDENCE_STORAGE", ROOT / "storage"))
STORAGE_DIR.mkdir(parents=True, exist_ok=True)
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", str(2 * 1024 * 1024 * 1024)))
EVIDENCE_TYPES = {
    "PHYSICAL_DEVICE", "DISK_IMAGE", "MEMORY_DUMP", "FILE",
    "NETWORK_CAPTURE", "LOG", "OTHER",
}
HEALTH_CACHE: tuple[float, dict[str, Any], int] | None = None
CRL_REFRESH_STOP = threading.Event()


class ProjectInput(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    description: str = Field(default="", max_length=500)
    status: str = Field(default="ACTIVE", pattern="^(ACTIVE|PAUSED|CLOSED)$")
    progress: int = Field(default=0, ge=0, le=100)


class InvestigatorInput(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    email: str = Field(min_length=3, max_length=160)
    role: str = Field(pattern="^(INVESTIGATOR|ANALYST|SUPERVISOR|OBSERVER)$")
    enrollmentID: str = Field(min_length=1, max_length=160)
    organization: str = Field(default="Org1MSP", min_length=1, max_length=160)


class EvidenceUpdateInput(BaseModel):
    case_id: str = Field(min_length=1, max_length=128)
    investigator_id: str = Field(min_length=1, max_length=128)
    evidence_type: str = Field(default="FILE", pattern="^(PHYSICAL_DEVICE|DISK_IMAGE|MEMORY_DUMP|FILE|NETWORK_CAPTURE|LOG|OTHER)$")


class InvestigatorCreateInput(InvestigatorInput):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=12, max_length=256)


class ReportInput(BaseModel):
    name: str = Field(min_length=1, max_length=180)
    project_id: str = Field(min_length=1, max_length=80)
    description: str = Field(default="", max_length=500)


class RelationInput(BaseModel):
    from_evidence: str = Field(min_length=1, max_length=128)
    to_evidence: str = Field(min_length=1, max_length=128)
    relation: str = Field(min_length=1, max_length=100)
    relation_type: str = Field(default="RELATED", max_length=80)
    discovery_note: str = Field(default="", max_length=500)


class CaseMemberInput(BaseModel):
    investigator_id: str = Field(min_length=1, max_length=128)
    role: str = Field(pattern="^(INVESTIGATOR|ANALYST|SUPERVISOR|OBSERVER)$")


class CredentialsInput(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=256)
    position: str = Field(default="INVESTIGATOR", pattern="^(ADMIN|INVESTIGATOR|ANALYST|SUPERVISOR|OBSERVER)$")


class UserInput(CredentialsInput):
    password: str = Field(min_length=12, max_length=256)
    role: str = Field(default="user", pattern="^user$")


class InvestigatorStatusInput(BaseModel):
    account_status: str = Field(pattern="^(ACTIVE|LOCKED)$")
    revoke_fabric_identity: bool = False


class PasswordChangeInput(BaseModel):
    current_password: str = Field(min_length=8, max_length=256)
    new_password: str = Field(min_length=12, max_length=256)

app = FastAPI(title="Forensic Core API", version="1.0.0")
allowed_origins = [
    origin.strip()
    for origin in os.getenv("CORS_ALLOWED_ORIGINS", "http://localhost:8000,http://127.0.0.1:8000").split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


def crl_refresh_worker() -> None:
    while not CRL_REFRESH_STOP.is_set():
        try:
            ensure_org_crl_current()
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"CRL refresh warning: {exc}")
        CRL_REFRESH_STOP.wait(60 * 60)


@app.on_event("startup")
def start_crl_refresh_worker() -> None:
    if os.getenv("FABRIC_PEER_CLI", "0") == "1":
        CRL_REFRESH_STOP.clear()
        threading.Thread(target=crl_refresh_worker, name="fabric-crl-refresh", daemon=True).start()


@app.on_event("shutdown")
def stop_crl_refresh_worker() -> None:
    CRL_REFRESH_STOP.set()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def resource_list(collection: str) -> list[dict[str, Any]]:
    return store.documents(collection)


def ensure_couch() -> None:
    store.ensure_database()


def merkle_root(leaves: list[str]) -> str:
    if not leaves:
        return ""
    level = leaves[:]
    while len(level) > 1:
        next_level: list[str] = []
        for index in range(0, len(level), 2):
            right = level[index + 1] if index + 1 < len(level) else level[index]
            next_level.append(hashlib.sha256((level[index] + right).encode("ascii")).hexdigest())
        level = next_level
    return level[0]


def merkle_proof(leaves: list[str], index: int) -> list[dict[str, str]]:
    proof: list[dict[str, str]] = []
    level = leaves[:]
    current = index
    while len(level) > 1:
        sibling = current - 1 if current % 2 else current + 1
        if sibling >= len(level):
            sibling = current
        proof.append({"position": "left" if current % 2 else "right", "hash": level[sibling]})
        level = [
            hashlib.sha256((level[offset] + (level[offset + 1] if offset + 1 < len(level) else level[offset])).encode("ascii")).hexdigest()
            for offset in range(0, len(level), 2)
        ]
        current //= 2
    return proof


def hash_file(path: Path) -> tuple[str, str]:
    digest = hashlib.sha256()
    leaves: list[str] = []
    with path.open("rb") as evidence_file:
        while chunk := evidence_file.read(1024 * 1024):
            digest.update(chunk)
            leaves.append(hashlib.sha256(chunk).hexdigest())
    return digest.hexdigest(), merkle_root(leaves)


def ensure_unique_evidence_hash(sha256_hash: str) -> None:
    if os.getenv("FABRIC_PEER_CLI", "0") == "1":
        try:
            existing = query_transaction("QueryAllEvidence", [])
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=502, detail=f"Fabric duplicate check failed: {exc}") from exc
    else:
        existing = resource_list("metadata")
    duplicate = next(
        (item for item in existing if str(item.get("sha256Hash", "")).lower() == sha256_hash.lower()),
        None,
    )
    if duplicate:
        raise HTTPException(
            status_code=409,
            detail=f"Tệp có cùng mã băm với chứng cứ đã tồn tại: {duplicate.get('evidenceID', '-')}",
        )


def investigator_for_user(user: dict[str, Any]) -> dict[str, Any] | None:
    return next((item for item in resource_list("investigators") if item.get("userID") == user.get("userID")), None)


def transaction_identity(user: dict[str, Any], actor_id: str) -> str | None:
    if user.get("role") == "admin":
        return None
    investigator = investigator_for_user(user)
    if not investigator:
        raise HTTPException(status_code=403, detail="Tài khoản chưa liên kết với hồ sơ nhân viên")
    if investigator.get("accountStatus", investigator.get("status")) != "ACTIVE":
        raise HTTPException(status_code=403, detail="Tài khoản nhân viên đã bị khóa")
    if investigator.get("fabricIdentityStatus", investigator.get("status")) != "ACTIVE":
        raise HTTPException(status_code=403, detail="Danh tính Fabric của nhân viên không hoạt động")
    if investigator.get("investigatorID") != actor_id:
        raise HTTPException(status_code=403, detail="Người thực hiện phải khớp với tài khoản đang đăng nhập")
    msp_path = wallet_msp_path(str(investigator.get("enrollmentID", "")))
    if not msp_path.is_dir():
        raise HTTPException(status_code=503, detail="Không tìm thấy Fabric Wallet của nhân viên")
    return str(msp_path)


def signing_msp_for_user(user: dict[str, Any]) -> Path:
    if user.get("role") == "admin":
        path = Path(os.getenv("CORE_PEER_MSPCONFIGPATH", ""))
        if not path.is_dir():
            raise HTTPException(status_code=503, detail="Fabric Admin MSP is unavailable for PDF signing")
        return path
    investigator = investigator_for_user(user)
    if not investigator:
        raise HTTPException(status_code=403, detail="Tài khoản chưa liên kết với Fabric identity")
    if investigator.get("fabricIdentityStatus", investigator.get("status")) != "ACTIVE":
        raise HTTPException(status_code=403, detail="Fabric identity is not active")
    path = wallet_msp_path(str(investigator.get("enrollmentID", "")))
    if not path.is_dir():
        raise HTTPException(status_code=503, detail="Fabric Wallet is unavailable for PDF signing")
    return path


def ensure_active_investigator(investigator_id: str) -> dict[str, Any]:
    investigator = store.get("investigators", investigator_id)
    if not investigator:
        raise HTTPException(status_code=404, detail="Investigator not found")
    if investigator.get("accountStatus", investigator.get("status")) != "ACTIVE":
        raise HTTPException(status_code=409, detail="Investigator account is locked")
    if os.getenv("FABRIC_PEER_CLI", "0") == "1" and investigator.get("fabricIdentityStatus", investigator.get("status")) != "ACTIVE":
        raise HTTPException(status_code=409, detail="Investigator Fabric identity is not active")
    return investigator


def next_investigator_id() -> str:
    existing_ids = {
        str(item.get("investigatorID", ""))
        for item in resource_list("investigators")
    }
    number = 1
    while True:
        candidate = f"INV{number:03d}"
        if candidate not in existing_ids:
            if os.getenv("FABRIC_PEER_CLI", "0") != "1":
                return candidate
            try:
                query_transaction("QueryStaff", [candidate])
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                raise HTTPException(status_code=502, detail=f"Fabric staff ID check failed: {exc}") from exc
            except RuntimeError as exc:
                if "staff not found" in str(exc).lower():
                    return candidate
                raise HTTPException(status_code=502, detail=f"Fabric staff ID check failed: {exc}") from exc
        number += 1


def authenticated_actor(
    user: dict[str, Any],
    requested_actor: str | None,
    fallback: str,
    allowed_roles: set[str] | None = None,
) -> str:
    if user.get("role") == "admin":
        actor_id = (requested_actor or fallback).strip()
    else:
        investigator = investigator_for_user(user)
        if not investigator:
            raise HTTPException(status_code=403, detail="Tài khoản chưa liên kết với hồ sơ nhân viên")
        actor_id = str(investigator["investigatorID"])
        if requested_actor and requested_actor.strip() != actor_id:
            raise HTTPException(status_code=403, detail="Không thể thực hiện giao dịch thay cho nhân viên khác")
    actor = ensure_active_investigator(actor_id)
    if allowed_roles and actor.get("role") not in allowed_roles:
        raise HTTPException(status_code=403, detail=f"Vai trò {actor.get('role')} không được phép thực hiện thao tác này")
    return actor_id


def append_ledger(event: dict[str, Any], user: dict[str, Any]) -> dict[str, Any]:
    receipt: dict[str, Any] = {}
    if os.getenv("FABRIC_PEER_CLI", "0") == "1":
        try:
            receipt = invoke_event(event, transaction_identity(user, str(event.get("investigator", ""))))
        except (OSError, RuntimeError, ValueError) as exc:
            raise HTTPException(status_code=502, detail=f"Fabric invoke failed: {exc}") from exc
    ensure_couch()
    transaction_id = receipt.get("txID") or uuid.uuid4().hex
    existing = store.documents("ledger")
    previous = max(existing, key=lambda item: item.get("blockNumber", 0), default={})
    block_number = receipt.get("blockNumber", int(previous.get("blockNumber", 0)) + 1)
    record = {
        "txID": transaction_id,
        "blockNumber": block_number,
        "sender": event.get("sender") or event.get("investigator", ""),
        "organization": event.get("organization", "Forensic Core"),
        "transactionStatus": receipt.get("transactionStatus", "LOCAL_CONFIRMED"),
        **event,
    }
    record["blockHash"] = receipt.get("blockHash", "")
    record["previousBlockHash"] = receipt.get("previousBlockHash", "")
    record["ledgerSource"] = "FABRIC" if receipt else "LOCAL"
    store.put("ledger", transaction_id, record)
    return record


def get_evidence(evidence_id: str) -> dict[str, Any]:
    ensure_couch()
    evidence = store.get("metadata", evidence_id)
    if evidence is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return evidence


def authoritative_evidence(evidence_id: str) -> dict[str, Any]:
    if os.getenv("FABRIC_PEER_CLI", "0") != "1":
        return get_evidence(evidence_id)
    try:
        return query_transaction("QueryEvidence", [evidence_id])
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=502, detail=f"Fabric query failed: {exc}") from exc


def offchain_path(evidence_id: str, cached: dict[str, Any]) -> Path:
    stored_path = cached.get("storagePath")
    if stored_path:
        return (ROOT / stored_path).resolve()
    candidates = list(STORAGE_DIR.glob(f"{evidence_id}_*"))
    if len(candidates) == 1:
        return candidates[0].resolve()
    raise HTTPException(status_code=404, detail="Off-chain evidence file mapping not found")


@app.get("/health", include_in_schema=False)
@app.get("/api/health")
def health(response: Response) -> dict[str, Any]:
    global HEALTH_CACHE
    if os.getenv("FABRIC_PEER_CLI", "0") != "1":
        return {
            "status": "connected",
            "ledger": "local-adapter",
            "channel": os.getenv("FABRIC_CHANNEL", "evidence-channel"),
            "timestamp": utc_now(),
        }
    now = time.monotonic()
    if HEALTH_CACHE and now - HEALTH_CACHE[0] < 10:
        response.status_code = HEALTH_CACHE[2]
        return HEALTH_CACHE[1]
    try:
        fabric = check_fabric_connection()
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        response.status_code = 503
        result = {
            "status": "disconnected",
            "ledger": "fabric-peer",
            "channel": os.getenv("FABRIC_CHANNEL", "evidence-channel"),
            "chaincode": os.getenv("FABRIC_CHAINCODE", "evidence"),
            "detail": "Fabric connection check failed",
            "timestamp": utc_now(),
        }
        HEALTH_CACHE = (now, result, 503)
        return result
    result = {"status": "connected", "ledger": "fabric-peer", **fabric, "timestamp": utc_now()}
    HEALTH_CACHE = (now, result, 200)
    return result


@app.post("/api/auth/register", status_code=201)
def register(payload: CredentialsInput) -> dict[str, Any]:
    ensure_couch()
    if payload.position == "ADMIN":
        raise HTTPException(status_code=403, detail="Không thể đăng ký tài khoản quản trị viên")
    user = create_user(payload.username, payload.password, "user", payload.position)
    return {"access_token": create_access_token(user), "token_type": "bearer", "user": public_user(user)}


@app.post("/api/auth/login")
def login(payload: CredentialsInput) -> dict[str, Any]:
    user = authenticate(payload.username, payload.password, payload.position)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password", headers={"WWW-Authenticate": "Bearer"})
    return {"access_token": create_access_token(user), "token_type": "bearer", "user": public_user(user)}


@app.get("/api/auth/me")
def me(user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    return public_user(user)


@app.post("/api/auth/change-password")
def update_password(payload: PasswordChangeInput, user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    updated = change_password(user, payload.current_password, payload.new_password)
    initial_password_file = ROOT / ".secrets" / "admin_initial_password"
    if updated.get("role") == "admin" and initial_password_file.exists():
        initial_password_file.unlink()
    return {"changed": True, "user": public_user(updated)}


@app.get("/api/admin/users")
def list_users(_: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
    ensure_couch()
    return [public_user(user) for user in resource_list("users")]


@app.post("/api/admin/users", status_code=201)
def admin_create_user(payload: UserInput, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
    user = create_user(payload.username, payload.password, payload.role, payload.position)
    return public_user(user)


def public_user(user: dict[str, Any]) -> dict[str, Any]:
    return {
        "userID": user["userID"], "username": user["username"], "role": user["role"],
        "position": user.get("position", "INVESTIGATOR"), "status": user["status"],
        "investigatorID": user.get("investigatorID"), "mustChangePassword": user.get("mustChangePassword", False),
        "createdAt": user["createdAt"],
    }


@app.get("/api/evidence")
def list_evidence(case_id: str | None = None, _: dict[str, Any] = Depends(current_user)) -> list[dict[str, Any]]:
    ensure_couch()
    if os.getenv("FABRIC_PEER_CLI", "0") == "1":
        try:
            function = "QueryEvidenceByCase" if case_id else "QueryAllEvidence"
            values = query_transaction(function, [case_id] if case_id else [])
            cache = {item["evidenceID"]: item for item in resource_list("metadata")}
            values = [
                {**item, **cache.get(item["evidenceID"], {}), **item}
                for item in values if item.get("status", "ACTIVE") != "DELETED"
            ]
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=502, detail=f"Fabric rich query failed: {exc}") from exc
    else:
        values = resource_list("metadata")
        if case_id:
            values = [item for item in values if item["caseID"] == case_id]
    return sorted(values, key=lambda item: item["timestamp"], reverse=True)


@app.get("/api/projects")
def list_projects(_: dict[str, Any] = Depends(current_user)) -> list[dict[str, Any]]:
    ensure_couch()
    return resource_list("projects")


@app.get("/api/ledger")
def list_ledger(_: dict[str, Any] = Depends(current_user)) -> list[dict[str, Any]]:
    ensure_couch()
    return sorted(resource_list("ledger"), key=lambda item: item.get("timestamp", ""), reverse=True)


@app.get("/api/ledger/{transaction_id}")
def verify_ledger_transaction(transaction_id: str, _: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    ensure_couch()
    transaction = store.get("ledger", transaction_id)
    if not transaction:
        raise HTTPException(status_code=404, detail="Transaction not found")
    if transaction.get("ledgerSource") == "FABRIC" or os.getenv("FABRIC_PEER_CLI", "0") == "1":
        evidence_id = transaction.get("evidenceID")
        if not evidence_id:
            return {"transaction": transaction, "valid": False, "status": "NOT_VERIFIED", "detail": "Evidence ID is missing"}
        try:
            history = query_transaction("QueryHistory", [str(evidence_id)])
            fabric_block = query_transaction_block(transaction_id)
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=502, detail=f"Fabric transaction verification failed: {exc}") from exc
        matched = next((event for event in history if event.get("txID") == transaction_id), None)
        return {
            "transaction": transaction,
            "fabricEvent": matched,
            "fabricBlock": fabric_block,
            "valid": matched is not None and fabric_block.get("transactionStatus") == "VALID",
            "status": fabric_block.get("transactionStatus") if matched else "NOT_FOUND_ON_FABRIC",
        }
    return {"transaction": transaction, "valid": transaction.get("transactionStatus") == "LOCAL_CONFIRMED", "status": transaction.get("transactionStatus")}


@app.get("/api/projects/{project_id}/summary")
def project_summary(project_id: str, _: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    ensure_couch()
    project = store.get("projects", project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    project_evidence = [item for item in resource_list("metadata") if item.get("caseID") == project_id]
    members = [item for item in resource_list("case_members") if item.get("caseID") == project_id]
    member_ids = {item.get("investigatorID") for item in members}
    activities = [
        item for item in resource_list("ledger")
        if item.get("caseID") == project_id or item.get("evidenceID") in {evidence.get("evidenceID") for evidence in project_evidence}
    ]
    return {
        "project": project,
        "evidenceCount": len(project_evidence),
        "memberCount": len(members),
        "members": members,
        "activities": sorted(activities, key=lambda item: item.get("timestamp", ""), reverse=True)[:10],
        "progress": project.get("progress", 100 if project.get("status") == "CLOSED" else 0),
        "responsibleCount": len(member_ids),
    }


@app.get("/api/projects/{project_id}/merkle")
def project_merkle(project_id: str, _: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    ensure_couch()
    if not store.get("projects", project_id):
        raise HTTPException(status_code=404, detail="Project not found")
    items = sorted(
        [item for item in resource_list("metadata") if item.get("caseID") == project_id],
        key=lambda item: item.get("evidenceID", ""),
    )
    leaves = [item.get("sha256Hash", "") for item in items if item.get("sha256Hash")]
    root = merkle_root(leaves)
    return {
        "projectID": project_id,
        "merkleRoot": root,
        "leafCount": len(leaves),
        "leaves": [
            {"evidenceID": item["evidenceID"], "fileName": item.get("fileName", ""), "hash": item.get("sha256Hash", ""), "proof": merkle_proof(leaves, index)}
            for index, item in enumerate(items)
            if item.get("sha256Hash")
        ],
    }


@app.post("/api/projects", status_code=201)
def create_project(payload: ProjectInput, user: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
    ensure_couch()
    project = {"projectID": store.next_id("projects", "PRJ."), **payload.model_dump(), "createdBy": user["username"], "createdAt": utc_now()}
    store.put("projects", project["projectID"], project)
    return project


@app.put("/api/projects/{project_id}")
def update_project(project_id: str, payload: ProjectInput, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
    ensure_couch()
    project = store.get("projects", project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    updated = {**project, **payload.model_dump(), "projectID": project_id}
    store.put("projects", project_id, updated)
    return updated


@app.delete("/api/projects/{project_id}")
def delete_project(project_id: str, _: dict[str, Any] = Depends(require_admin)) -> dict[str, bool]:
    ensure_couch()
    project = store.get("projects", project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if any(item.get("caseID") == project_id for item in resource_list("metadata")):
        raise HTTPException(status_code=409, detail="Cannot delete a project that has evidence")
    if any(item.get("caseID") == project_id for item in resource_list("case_members")):
        raise HTTPException(status_code=409, detail="Cannot delete a project that has assigned members")
    revision = project.get("_rev")
    if not revision:
        raise HTTPException(status_code=500, detail="Project revision is missing")
    store.delete("projects", project_id, revision)
    return {"deleted": True}


@app.get("/api/investigators")
def list_investigators(_: dict[str, Any] = Depends(current_user)) -> list[dict[str, Any]]:
    ensure_couch()
    return resource_list("investigators")


@app.get("/api/investigators/{investigator_id}/fabric-identity")
def investigator_fabric_identity(investigator_id: str, user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    ensure_couch()
    investigator = store.get("investigators", investigator_id)
    if not investigator:
        raise HTTPException(status_code=404, detail="Investigator not found")
    if user.get("role") != "admin" and investigator.get("userID") != user.get("userID"):
        raise HTTPException(status_code=403, detail="Cannot inspect another employee identity")
    ledger_staff = None
    ledger_error = None
    if os.getenv("FABRIC_PEER_CLI", "0") == "1":
        try:
            ledger_staff = query_transaction("QueryStaff", [investigator_id])
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            ledger_error = str(exc)
    msp_path = wallet_msp_path(str(investigator.get("enrollmentID", "")))
    return {
        "investigatorID": investigator_id,
        "accountStatus": investigator.get("accountStatus", investigator.get("status")),
        "fabricIdentityStatus": investigator.get("fabricIdentityStatus", "NOT_PROVISIONED"),
        "walletPresent": msp_path.is_dir(),
        "walletReference": investigator.get("walletReference"),
        "ledgerStaff": ledger_staff,
        "ledgerError": ledger_error,
    }


@app.post("/api/investigators", status_code=201)
def create_investigator(payload: InvestigatorCreateInput, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
    ensure_couch()
    configured_msp = os.getenv("CORE_PEER_LOCALMSPID", "Org1MSP")
    if payload.organization != configured_msp:
        raise HTTPException(status_code=422, detail=f"Organization must match the active Fabric MSP: {configured_msp}")
    if any(item.get("enrollmentID") == payload.enrollmentID for item in resource_list("investigators")):
        raise HTTPException(status_code=409, detail="Enrollment ID already exists")
    account_position = payload.role
    admin = _
    investigator_id = next_investigator_id()
    wallet_path = None
    if os.getenv("FABRIC_PEER_CLI", "0") == "1":
        try:
            wallet_path = enroll_staff(payload.enrollmentID, investigator_id, payload.role)
        except (OSError, RuntimeError, ValueError) as exc:
            raise HTTPException(status_code=502, detail="Fabric CA enrollment failed") from exc
    investigator = {
        "investigatorID": investigator_id,
        "name": payload.name,
        "email": payload.email,
        "role": payload.role,
        "enrollmentID": payload.enrollmentID,
        "organization": payload.organization,
        "status": "ACTIVE",
        "accountStatus": "ACTIVE",
        "fabricIdentityStatus": "ACTIVE" if os.getenv("FABRIC_PEER_CLI", "0") == "1" else "NOT_PROVISIONED",
        "walletReference": f"wallet://{payload.enrollmentID}",
        "createdAt": utc_now(),
        "createdBy": admin.get("username", admin.get("userID", "")),
    }
    if os.getenv("FABRIC_PEER_CLI", "0") == "1":
        try:
            invoke_staff("RegisterStaff", [
                investigator["investigatorID"],
                investigator["enrollmentID"],
                investigator["organization"],
                investigator["role"],
                investigator["createdAt"],
                investigator["createdBy"],
            ])
        except (OSError, RuntimeError, ValueError) as exc:
            try:
                revoke_staff(payload.enrollmentID)
                publish_org_crl()
            except (OSError, RuntimeError, ValueError):
                pass
            raise HTTPException(status_code=502, detail="Fabric staff registration failed") from exc
    try:
        user = create_user(payload.username, payload.password, "user", account_position)
        investigator["userID"] = user["userID"]
        user["investigatorID"] = investigator["investigatorID"]
        store.put("users", user["userID"], user)
        store.put("investigators", investigator["investigatorID"], investigator)
    except (HTTPException, OSError, RuntimeError, ValueError) as exc:
        if os.getenv("FABRIC_PEER_CLI", "0") == "1" and wallet_path:
            try:
                invoke_staff("DeactivateStaff", [investigator_id, investigator["createdBy"]])
                revoke_staff(payload.enrollmentID)
                publish_org_crl()
            except (OSError, RuntimeError, ValueError) as rollback_exc:
                raise HTTPException(status_code=502, detail="Staff rollback failed after application persistence error") from rollback_exc
        raise exc
    return investigator


@app.put("/api/investigators/{investigator_id}")
def update_investigator(investigator_id: str, payload: InvestigatorInput, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
    ensure_couch()
    investigator = store.get("investigators", investigator_id)
    if not investigator:
        raise HTTPException(status_code=404, detail="Investigator not found")
    if payload.enrollmentID != investigator.get("enrollmentID") or payload.organization != investigator.get("organization"):
        raise HTTPException(status_code=422, detail="Enrollment ID and organization cannot be changed after Fabric enrollment")
    updated = {**investigator, **payload.model_dump(), "investigatorID": investigator_id}
    if os.getenv("FABRIC_PEER_CLI", "0") == "1" and payload.role != investigator.get("role"):
        try:
            invoke_staff("UpdateStaffRole", [investigator_id, payload.role, _.get("username", _.get("userID", ""))])
        except (OSError, RuntimeError, ValueError) as exc:
            raise HTTPException(status_code=502, detail=f"Fabric staff role update failed: {exc}") from exc
    store.put("investigators", investigator_id, updated)
    if investigator.get("userID"):
        linked_user = store.get("users", investigator["userID"])
        if linked_user:
            linked_user["position"] = payload.role
            store.put("users", linked_user["userID"], linked_user)
    return updated


@app.delete("/api/investigators/{investigator_id}")
def delete_investigator(investigator_id: str, _: dict[str, Any] = Depends(require_admin)) -> dict[str, bool]:
    ensure_couch()
    investigator = store.get("investigators", investigator_id)
    if not investigator:
        raise HTTPException(status_code=404, detail="Investigator not found")
    if os.getenv("FABRIC_PEER_CLI", "0") == "1":
        try:
            invoke_staff("DeactivateStaff", [investigator_id, _.get("username", _.get("userID", ""))])
        except (OSError, RuntimeError, ValueError) as exc:
            raise HTTPException(status_code=502, detail=f"Fabric staff deactivation failed: {exc}") from exc
        try:
            revoke_staff(str(investigator.get("enrollmentID", "")))
            publish_org_crl()
            fabric_status = "REVOKED"
        except (OSError, RuntimeError, ValueError) as exc:
            fabric_status = "REVOKE_PENDING"
            investigator.update({"status": "INACTIVE", "accountStatus": "LOCKED", "fabricIdentityStatus": fabric_status, "revokedAt": utc_now(), "revokedBy": _.get("username", "")})
            store.put("investigators", investigator_id, investigator)
            if investigator.get("userID"):
                linked_user = store.get("users", investigator["userID"])
                if linked_user:
                    linked_user["status"] = "LOCKED"
                    store.put("users", linked_user["userID"], linked_user)
            raise HTTPException(status_code=502, detail="Fabric CA revocation failed after ledger deactivation") from exc
    else:
        fabric_status = investigator.get("fabricIdentityStatus", "NOT_PROVISIONED")
    investigator.update({"status": "INACTIVE", "accountStatus": "LOCKED", "fabricIdentityStatus": fabric_status, "revokedAt": utc_now(), "revokedBy": _.get("username", "")})
    store.put("investigators", investigator_id, investigator)
    if investigator.get("userID"):
        linked_user = store.get("users", investigator["userID"])
        if linked_user:
            linked_user["status"] = "LOCKED"
            store.put("users", linked_user["userID"], linked_user)
    return {"deleted": False, "locked": True, "fabricRevoked": fabric_status == "REVOKED"}


@app.patch("/api/investigators/{investigator_id}/status")
def change_investigator_status(investigator_id: str, payload: InvestigatorStatusInput, user: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
    ensure_couch()
    investigator = store.get("investigators", investigator_id)
    if not investigator:
        raise HTTPException(status_code=404, detail="Investigator not found")
    if payload.revoke_fabric_identity:
        delete_investigator(investigator_id, user)
        return store.get("investigators", investigator_id) or investigator
    investigator["accountStatus"] = payload.account_status
    investigator["status"] = "ACTIVE" if payload.account_status == "ACTIVE" else "INACTIVE"
    investigator["statusChangedAt"] = utc_now()
    investigator["statusChangedBy"] = user.get("username", user.get("userID", ""))
    store.put("investigators", investigator_id, investigator)
    if investigator.get("userID"):
        linked_user = store.get("users", investigator["userID"])
        if linked_user:
            linked_user["status"] = payload.account_status
            store.put("users", linked_user["userID"], linked_user)
    return investigator


@app.get("/api/reports")
def list_reports(_: dict[str, Any] = Depends(current_user)) -> list[dict[str, Any]]:
    ensure_couch()
    return resource_list("reports")


@app.get("/api/reports/{report_id}")
def report_detail(report_id: str, _: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    ensure_couch()
    report = store.get("reports", report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    project = store.get("projects", report["project_id"])
    evidence_items = [item for item in resource_list("metadata") if item.get("caseID") == report["project_id"]]
    evidence_ids = {item.get("evidenceID") for item in evidence_items}
    transactions = [item for item in resource_list("ledger") if item.get("evidenceID") in evidence_ids]
    transaction_index = {item.get("txID"): item for item in transactions}
    if os.getenv("FABRIC_PEER_CLI", "0") == "1":
        custody = []
        try:
            for evidence_id in evidence_ids:
                custody.extend({**transaction_index.get(event.get("txID"), {}), **event} for event in query_transaction("QueryHistory", [str(evidence_id)]))
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=502, detail=f"Fabric report history query failed: {exc}") from exc
    else:
        custody = [item for item in transactions if item.get("action") in {"COLLECT", "CREATE", "ACCESS", "TRANSFER", "RECEIVE", "ANALYZE", "VERIFY"}]
    verifications = resource_list("verifications")
    hash_checks = []
    for item in evidence_items:
        latest = max(
            (check for check in verifications if check.get("evidenceID") == item.get("evidenceID")),
            key=lambda check: check.get("verifiedAt", ""), default=None,
        )
        hash_checks.append(latest or {
            "evidenceID": item.get("evidenceID"), "referenceHash": item.get("sha256Hash", ""),
            "currentHash": "", "status": "NOT_VERIFIED", "verifiedAt": None, "verifiedBy": None,
        })
    statuses = [check["status"] for check in hash_checks]
    conclusion = "MISMATCH_DETECTED" if "MISMATCH" in statuses else "ALL_MATCH" if statuses and all(status == "MATCH" for status in statuses) else "INCOMPLETE_VERIFICATION"
    return {
        "report": report, "project": project, "evidence": evidence_items, "hashChecks": hash_checks,
        "custody": sorted(custody, key=lambda item: item.get("timestamp", "")), "transactions": transactions,
        "conclusion": conclusion,
        "limitations": "Kết luận chỉ áp dụng cho các tệp off-chain còn truy cập được và đã được tính lại SHA-256.",
        "generatedAt": utc_now(), "timezone": "UTC",
    }


def pdf_escape(value: Any) -> str:
    return str(value or "-").replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)").replace("\n", " ")


def build_report_pdf(data: dict[str, Any]) -> bytes:
    lines = [
        "FORENSIC CORE - EVIDENCE REPORT",
        f"Report: {data['report'].get('reportID', '-')}",
        f"Project: {data.get('project', {}).get('projectID', '-') } - {data.get('project', {}).get('name', '-')}",
        f"Prepared by: {data['report'].get('createdBy', '-')}",
        f"Report created: {data['report'].get('createdAt', '-')} ({data['report'].get('timezone', 'UTC')})",
        f"Generated: {data.get('generatedAt', utc_now())} ({data.get('timezone', 'UTC')})",
        "",
        "EVIDENCE AND HASH VERIFICATION",
    ]
    for item, check in zip(data["evidence"], data["hashChecks"]):
        lines.extend([
            f"Evidence ID: {item.get('evidenceID', '-')}",
            f"File: {item.get('fileName', '-')}",
            f"SHA-256: {item.get('sha256Hash', '-')}",
            f"Current SHA-256: {check.get('currentHash', '-')}",
            f"Hash status: {check.get('status', 'NOT_VERIFIED')}",
            f"Verified by: {check.get('verifiedBy', '-')}",
            f"Recorded at: {item.get('timestamp', '-')}",
            "",
        ])
    lines.extend([f"CONCLUSION: {data.get('conclusion', 'INCOMPLETE_VERIFICATION')}", f"LIMITATIONS: {data.get('limitations', '-')}", "", "CHAIN OF CUSTODY AND TRANSACTIONS"])
    for item in data["custody"]:
        lines.append(
            f"{item.get('timestamp', '-')} | {item.get('action', '-')} | Actor {item.get('actorID', item.get('investigator', '-'))} "
            f"| Signer {item.get('signerID', '-')} | TX {item.get('txID', '-')} | {item.get('transactionStatus', '-')} "
            f"| Block {item.get('blockNumber', '-')}"
        )
    lines.extend(["", "INDEPENDENT VERIFICATION", "Transaction IDs and SHA-256 hashes above can be checked through the Ledger Blockchain menu."])
    content = "BT /F1 9 Tf 45 780 Td " + " ".join(f"({pdf_escape(line)}) Tj 0 -14 Td" for line in lines) + " ET"
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        f"<< /Length {len(content.encode())} >>\nstream\n{content}\nendstream".encode(),
    ]
    pdf = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for index, obj in enumerate(objects, 1):
        offsets.append(len(pdf))
        pdf.extend(f"{index} 0 obj\n".encode() + obj + b"\nendobj\n")
    xref = len(pdf)
    pdf.extend(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode())
    pdf.extend("".join(f"{offset:010d} 00000 n \n" for offset in offsets[1:]).encode())
    pdf.extend(f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF".encode())
    return bytes(pdf)


@app.get("/api/reports/{report_id}/pdf")
def export_report_pdf(report_id: str, user: dict[str, Any] = Depends(current_user)) -> Response:
    data = report_detail(report_id, user)
    msp_path = signing_msp_for_user(user)
    signer_id = certificate_common_name(msp_path)
    try:
        signed_pdf = sign_pdf_pades(
            build_report_pdf(data),
            msp_path,
            field_name=f"ForensicSignature_{report_id}",
            signer_name=signer_id,
            reason=f"Forensic evidence report {report_id}",
        )
    except (OSError, RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=500, detail=f"PAdES signing failed: {exc}") from exc
    signature_hash = hashlib.sha256(signed_pdf).hexdigest()
    signature_record = {
        "signatureID": signature_hash,
        "reportID": report_id,
        "format": "PAdES-B-B",
        "digestAlgorithm": "SHA-256",
        "documentSHA256": signature_hash,
        "signedBy": user.get("username", user.get("userID", "")),
        "fabricSigner": signer_id,
        "signerMSP": os.getenv("CORE_PEER_LOCALMSPID", "Org1MSP"),
        "signedAt": utc_now(),
    }
    store.put("report_signatures", signature_hash, signature_record)
    return Response(
        content=signed_pdf,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{quote(report_id)}-signed.pdf"',
            "X-PDF-Signature": "PAdES-B-B",
            "X-Document-SHA256": signature_hash,
            "X-Fabric-Signer": signer_id,
        },
    )


@app.post("/api/reports", status_code=201)
def create_report(payload: ReportInput, _: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    ensure_couch()
    if not store.get("projects", payload.project_id):
        raise HTTPException(status_code=404, detail="Project not found")
    report = {
        "reportID": store.next_id("reports", "BC"), **payload.model_dump(), "status": "GENERATED",
        "createdBy": _.get("username", _.get("userID", "")), "createdAt": utc_now(), "timezone": "UTC",
    }
    store.put("reports", report["reportID"], report)
    return report


@app.get("/api/relations")
def list_relations(_: dict[str, Any] = Depends(current_user)) -> list[dict[str, Any]]:
    ensure_couch()
    return resource_list("relations")


@app.get("/api/cases/{case_id}/members")
def list_case_members(case_id: str, _: dict[str, Any] = Depends(current_user)) -> list[dict[str, Any]]:
    ensure_couch()
    return [item for item in resource_list("case_members") if item.get("caseID") == case_id]


@app.post("/api/cases/{case_id}/members", status_code=201)
def assign_case_member(case_id: str, payload: CaseMemberInput, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
    ensure_couch()
    if not store.get("projects", case_id):
        raise HTTPException(status_code=404, detail="Project not found")
    if not any(item.get("investigatorID") == payload.investigator_id for item in resource_list("investigators")):
        raise HTTPException(status_code=404, detail="Investigator not found")
    member = {
        "caseMemberID": uuid.uuid4().hex,
        "caseID": case_id,
        "investigatorID": payload.investigator_id,
        "role": payload.role,
        "status": "ACTIVE",
        "assignedAt": utc_now(),
    }
    store.put("case_members", member["caseMemberID"], member)
    return member


@app.delete("/api/cases/{case_id}/members/{member_id}")
def remove_case_member(case_id: str, member_id: str, _: dict[str, Any] = Depends(require_admin)) -> dict[str, bool]:
    ensure_couch()
    member = store.get("case_members", member_id)
    if not member or member.get("caseID") != case_id:
        raise HTTPException(status_code=404, detail="Case member not found")
    if "_rev" not in member:
        raise HTTPException(status_code=500, detail="Case member revision is missing")
    store.delete("case_members", member_id, member["_rev"])
    return {"deleted": True}


@app.post("/api/relations", status_code=201)
def create_relation(payload: RelationInput, _: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    if payload.from_evidence == payload.to_evidence:
        raise HTTPException(status_code=400, detail="A relation must connect two different evidence records")
    evidence_ids = {item["evidenceID"] for item in list_evidence()}
    if payload.from_evidence not in evidence_ids or payload.to_evidence not in evidence_ids:
        raise HTTPException(status_code=404, detail="Both evidence records must exist")
    ensure_couch()
    relation = {
        "relationID": store.next_id("relations", "REL"), **payload.model_dump(),
        "createdBy": _.get("username", _.get("userID", "")), "createdAt": utc_now(),
    }
    store.put("relations", relation["relationID"], relation)
    return relation


@app.put("/api/relations/{relation_id}")
def update_relation(relation_id: str, payload: RelationInput, _: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    if payload.from_evidence == payload.to_evidence:
        raise HTTPException(status_code=400, detail="A relation must connect two different evidence records")
    evidence_ids = {item["evidenceID"] for item in list_evidence()}
    if payload.from_evidence not in evidence_ids or payload.to_evidence not in evidence_ids:
        raise HTTPException(status_code=404, detail="Both evidence records must exist")
    ensure_couch()
    relation = store.get("relations", relation_id)
    if not relation:
        raise HTTPException(status_code=404, detail="Relation not found")
    updated = {
        **relation, **payload.model_dump(), "relationID": relation_id,
        "updatedBy": _.get("username", _.get("userID", "")), "updatedAt": utc_now(),
    }
    store.put("relations", relation_id, updated)
    return updated


@app.delete("/api/relations/{relation_id}")
def delete_relation(relation_id: str, _: dict[str, Any] = Depends(require_admin)) -> dict[str, bool]:
    ensure_couch()
    relation = store.get("relations", relation_id)
    if not relation:
        raise HTTPException(status_code=404, detail="Relation not found")
    revision = relation.get("_rev")
    if not revision:
        raise HTTPException(status_code=500, detail="Relation revision is missing")
    store.delete("relations", relation_id, revision)
    return {"deleted": True}


@app.post("/api/evidence", status_code=201)
async def upload_evidence(
    file: UploadFile = File(...),
    case_id: str = Form(...),
    investigator_id: str = Form(...),
    evidence_type: str = Form("FILE"),
    source: str = Form(""),
    acquisition_method: str = Form(""),
    collected_at: str = Form(""),
    _: dict[str, Any] = Depends(current_user),
) -> dict[str, Any]:
    case_id = case_id.strip()
    investigator_id = investigator_id.strip()
    safe_name = Path(file.filename or "").name
    if not safe_name or safe_name in {".", ".."}:
        raise HTTPException(status_code=400, detail="A valid file name is required")
    if not case_id or not investigator_id:
        raise HTTPException(status_code=400, detail="case_id and investigator_id are required")
    if evidence_type not in EVIDENCE_TYPES:
        raise HTTPException(status_code=422, detail="Invalid evidence type")
    ensure_couch()
    if not store.get("projects", case_id):
        raise HTTPException(status_code=404, detail="The selected case does not exist")
    ensure_active_investigator(investigator_id)
    authenticated_actor(_, investigator_id, investigator_id, {"INVESTIGATOR", "ANALYST", "SUPERVISOR"})
    evidence_id = uuid.uuid4().hex
    destination = STORAGE_DIR / f"{evidence_id}_{safe_name}"
    written = 0
    try:
        with destination.open("xb") as output:
            while chunk := await file.read(1024 * 1024):
                written += len(chunk)
                if written > MAX_UPLOAD_BYTES:
                    raise HTTPException(status_code=413, detail="Evidence file exceeds MAX_UPLOAD_BYTES")
                output.write(chunk)
    except HTTPException:
        destination.unlink(missing_ok=True)
        raise
    except OSError as exc:
        destination.unlink(missing_ok=True)
        raise HTTPException(status_code=500, detail=f"Unable to store evidence file: {exc}") from exc
    sha256_hash, root = hash_file(destination)
    try:
        ensure_unique_evidence_hash(sha256_hash)
    except HTTPException:
        destination.unlink(missing_ok=True)
        raise
    timestamp = utc_now()
    evidence = {
        "evidenceID": evidence_id,
        "caseID": case_id,
        "fileName": safe_name,
        "storagePath": str(destination.relative_to(ROOT)),
        "sha256Hash": sha256_hash,
        "merkleRoot": root,
        "investigator": investigator_id,
        "timestamp": timestamp,
        "action": "COLLECT",
        "evidenceType": evidence_type,
        "source": source.strip(),
        "acquisitionMethod": acquisition_method.strip(),
        "collectedAt": collected_at.strip() or timestamp,
        "verificationStatus": "NOT_VERIFIED",
        "sizeBytes": written,
    }
    try:
        ledger_record = append_ledger(evidence, _)
        evidence.update({
            "action": "COLLECT", "lastTxID": ledger_record["txID"],
            "transactionStatus": ledger_record["transactionStatus"],
        })
        store.put("metadata", evidence_id, evidence)
    except HTTPException:
        destination.unlink(missing_ok=True)
        raise
    except (OSError, RuntimeError) as exc:
        destination.unlink(missing_ok=True)
        raise HTTPException(status_code=500, detail=f"Unable to persist evidence metadata: {exc}") from exc
    return evidence


@app.get("/api/evidence/{evidence_id}")
def query_evidence(evidence_id: str, _: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    return authoritative_evidence(evidence_id)


@app.put("/api/evidence/{evidence_id}")
def update_evidence(evidence_id: str, payload: EvidenceUpdateInput, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
    ensure_couch()
    evidence = get_evidence(evidence_id)
    case_id = payload.case_id.strip()
    if not store.get("projects", case_id):
        raise HTTPException(status_code=404, detail="The selected case does not exist")
    ensure_active_investigator(payload.investigator_id.strip())
    if os.getenv("FABRIC_PEER_CLI", "0") == "1":
        ledger_evidence = authoritative_evidence(evidence_id)
        changed = (
            ledger_evidence.get("caseID") != case_id
            or ledger_evidence.get("investigator") != payload.investigator_id.strip()
            or ledger_evidence.get("evidenceType", "FILE") != payload.evidence_type
        )
        if changed:
            raise HTTPException(status_code=409, detail="Core evidence metadata is immutable after being committed to Fabric")
    updated = {**evidence, "caseID": case_id, "investigator": payload.investigator_id.strip(), "evidenceType": payload.evidence_type}
    store.put("metadata", evidence_id, updated)
    return updated


@app.delete("/api/evidence/{evidence_id}")
def delete_evidence(evidence_id: str, _: dict[str, Any] = Depends(require_admin)) -> dict[str, bool]:
    ensure_couch()
    cached = store.get("metadata", evidence_id)
    evidence = authoritative_evidence(evidence_id) if os.getenv("FABRIC_PEER_CLI", "0") == "1" else get_evidence(evidence_id)
    path: Path | None = None
    if cached:
        path = offchain_path(evidence_id, cached)
        if STORAGE_DIR.resolve() not in path.parents:
            raise HTTPException(status_code=500, detail="Invalid off-chain storage path")
    append_ledger({
        "evidenceID": evidence_id,
        "caseID": evidence.get("caseID", ""),
        "fileName": evidence.get("fileName", ""),
        "sha256Hash": evidence.get("sha256Hash", ""),
        "merkleRoot": evidence.get("merkleRoot", ""),
        "investigator": evidence.get("investigator", ""),
        "timestamp": utc_now(),
        "action": "DELETE",
    }, _)
    if cached and cached.get("_rev"):
        store.delete("metadata", evidence_id, cached["_rev"])
    if path:
        path.unlink(missing_ok=True)
    return {"deleted": True}


@app.get("/api/evidence/{evidence_id}/history")
def query_history(evidence_id: str, _: dict[str, Any] = Depends(current_user)) -> list[dict[str, Any]]:
    if os.getenv("FABRIC_PEER_CLI", "0") == "1":
        try:
            return query_transaction("QueryHistory", [evidence_id])
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=502, detail=f"Fabric history query failed: {exc}") from exc
    return [item for item in store.documents("ledger") if item["evidenceID"] == evidence_id]


@app.post("/api/evidence/{evidence_id}/access")
def access_evidence(evidence_id: str, actor_id: str = Form(...), reason: str = Form("Truy cập phục vụ điều tra"), _: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    actor_id = authenticated_actor(_, actor_id, authoritative_evidence(evidence_id).get("investigator", ""), {"INVESTIGATOR", "ANALYST", "SUPERVISOR", "OBSERVER"})
    if not actor_id:
        raise HTTPException(status_code=400, detail="actor_id is required")
    evidence = authoritative_evidence(evidence_id)
    event = {**evidence, "action": "ACCESS", "investigator": actor_id, "fromHolder": "", "toHolder": "", "reason": reason.strip(), "result": "", "timestamp": utc_now()}
    receipt = append_ledger(event, _)
    committed = authoritative_evidence(evidence_id)
    return {**committed, "txID": receipt["txID"], "transactionStatus": receipt["transactionStatus"]}


@app.post("/api/evidence/{evidence_id}/transfer")
def transfer_evidence(
    evidence_id: str,
    from_holder: str = Form(...),
    to_holder: str = Form(...),
    actor_id: str = Form(...),
    reason: str = Form("Bàn giao chứng cứ"),
    _: dict[str, Any] = Depends(current_user),
) -> dict[str, Any]:
    from_holder, to_holder = from_holder.strip(), to_holder.strip()
    actor_id = authenticated_actor(_, actor_id, from_holder, {"INVESTIGATOR", "SUPERVISOR"})
    if not from_holder or not to_holder or not actor_id:
        raise HTTPException(status_code=400, detail="from_holder, to_holder and actor_id are required")
    if from_holder == to_holder:
        raise HTTPException(status_code=400, detail="from_holder and to_holder must be different")
    ensure_active_investigator(to_holder)
    evidence = authoritative_evidence(evidence_id)
    current_holder = str(evidence.get("currentHolder") or evidence.get("investigator") or "")
    if current_holder and current_holder != from_holder:
        raise HTTPException(status_code=409, detail=f"from_holder does not match current holder: {current_holder}")
    event = {**evidence, "action": "TRANSFER", "fromHolder": from_holder, "toHolder": to_holder, "investigator": actor_id, "reason": reason.strip(), "result": "", "timestamp": utc_now()}
    receipt = append_ledger(event, _)
    committed = authoritative_evidence(evidence_id)
    event = {**committed, "txID": receipt["txID"], "transactionStatus": receipt["transactionStatus"]}
    ensure_couch()
    metadata = store.get("metadata", evidence_id) or {}
    storage_path = metadata.get("storagePath")
    if storage_path:
        event["storagePath"] = storage_path
    store.put("metadata", evidence_id, {**metadata, **event})
    return event


@app.post("/api/evidence/{evidence_id}/receive")
def receive_evidence(
    evidence_id: str,
    actor_id: str = Form(...),
    from_holder: str = Form(""),
    reason: str = Form("Tiếp nhận chứng cứ"),
    _: dict[str, Any] = Depends(current_user),
) -> dict[str, Any]:
    evidence = authoritative_evidence(evidence_id)
    actor = authenticated_actor(_, actor_id, str(evidence.get("investigator", "")), {"INVESTIGATOR", "SUPERVISOR"})
    pending_recipient = str(evidence.get("toHolder") or "")
    if pending_recipient and pending_recipient != actor:
        raise HTTPException(status_code=403, detail=f"Only pending recipient {pending_recipient} may receive evidence")
    event = {
        **evidence, "action": "RECEIVE", "investigator": actor, "fromHolder": from_holder.strip(),
        "toHolder": actor, "reason": reason.strip(), "result": "RECEIVED", "timestamp": utc_now(),
    }
    receipt = append_ledger(event, _)
    committed = authoritative_evidence(evidence_id)
    event = {**committed, "txID": receipt["txID"], "transactionStatus": receipt["transactionStatus"], "currentHolder": actor}
    metadata = store.get("metadata", evidence_id) or {}
    store.put("metadata", evidence_id, {**metadata, **event})
    return event


@app.post("/api/evidence/{evidence_id}/analyze")
def analyze_evidence(
    evidence_id: str,
    actor_id: str = Form(...),
    reason: str = Form(...),
    result: str = Form(...),
    _: dict[str, Any] = Depends(current_user),
) -> dict[str, Any]:
    evidence = authoritative_evidence(evidence_id)
    actor = authenticated_actor(_, actor_id, str(evidence.get("investigator", "")), {"INVESTIGATOR", "ANALYST", "SUPERVISOR"})
    if not reason.strip() or not result.strip():
        raise HTTPException(status_code=400, detail="reason and result are required")
    event = {
        **evidence, "action": "ANALYZE", "investigator": actor,
        "reason": reason.strip(), "result": result.strip(), "timestamp": utc_now(),
    }
    receipt = append_ledger(event, _)
    committed = authoritative_evidence(evidence_id)
    return {**committed, "txID": receipt["txID"], "transactionStatus": receipt["transactionStatus"]}


@app.get("/api/evidence/{evidence_id}/verify")
@app.post("/api/evidence/{evidence_id}/verify")
def verify_integrity(evidence_id: str, actor_id: str | None = None, _: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    cached = get_evidence(evidence_id)
    evidence = authoritative_evidence(evidence_id)
    path = offchain_path(evidence_id, cached)
    if STORAGE_DIR.resolve() not in path.parents:
        raise HTTPException(status_code=500, detail="Invalid off-chain storage path")
    actor = authenticated_actor(_, actor_id, str(evidence.get("investigator", "")), {"INVESTIGATOR", "ANALYST", "SUPERVISOR"})
    if not path.exists():
        actual_hash, actual_root, status, reason = "", "", "NOT_VERIFIED", "Off-chain evidence file is missing"
    else:
        actual_hash, actual_root = hash_file(path)
        status = "MATCH" if actual_hash == evidence["sha256Hash"] and actual_root == evidence["merkleRoot"] else "MISMATCH"
        reason = "SHA-256 and Merkle Root comparison"
    event = {
        **evidence, "action": "VERIFY", "investigator": actor, "timestamp": utc_now(), "reason": reason,
        "result": status, "referenceHash": evidence.get("sha256Hash", ""), "currentHash": actual_hash,
    }
    receipt = append_ledger(event, _)
    verification = {
        "verificationID": receipt["txID"], "evidenceID": evidence_id, "status": status,
        "referenceHash": evidence.get("sha256Hash", ""), "currentHash": actual_hash,
        "expectedMerkleRoot": evidence.get("merkleRoot", ""), "actualMerkleRoot": actual_root,
        "verifiedBy": actor, "fabricSigner": query_transaction("QueryEvidence", [evidence_id]).get("signerID", "") if os.getenv("FABRIC_PEER_CLI", "0") == "1" else actor,
        "verifiedAt": utc_now(), "txID": receipt["txID"], "transactionStatus": receipt["transactionStatus"],
    }
    store.put("verifications", verification["verificationID"], verification)
    cached.update({"verificationStatus": status, "lastVerifiedAt": verification["verifiedAt"], "lastVerificationID": verification["verificationID"]})
    store.put("metadata", evidence_id, cached)
    return {
        "evidenceID": evidence_id,
        "status": status,
        "valid": status == "MATCH",
        "expectedSHA256": evidence["sha256Hash"],
        "actualSHA256": actual_hash,
        "expectedMerkleRoot": evidence["merkleRoot"],
        "actualMerkleRoot": actual_root,
        "verifiedBy": actor,
        "verifiedAt": verification["verifiedAt"],
        "txID": receipt["txID"],
        "transactionStatus": receipt["transactionStatus"],
    }


@app.get("/api/evidence/{evidence_id}/file")
def download_evidence(evidence_id: str, _: dict[str, Any] = Depends(current_user)) -> FileResponse:
    evidence = get_evidence(evidence_id)
    path = offchain_path(evidence_id, evidence)
    if STORAGE_DIR.resolve() not in path.parents or not path.is_file():
        raise HTTPException(status_code=404, detail="Off-chain evidence file not found")
    return FileResponse(path, filename=evidence["fileName"], media_type="application/octet-stream")


app.mount("/", StaticFiles(directory=ROOT / "frontend", html=True), name="frontend")
