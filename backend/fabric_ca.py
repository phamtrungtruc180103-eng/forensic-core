from __future__ import annotations

import os
import secrets
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

from cryptography import x509


ROOT = Path(__file__).resolve().parent.parent
FABRIC_HOME = Path(os.getenv("FABRIC_HOME", str(ROOT.parent / "fabric-samples")))
ORG1_HOME = FABRIC_HOME / "test-network/organizations/peerOrganizations/org1.example.com"
CA_CERT = FABRIC_HOME / "test-network/organizations/fabric-ca/org1/ca-cert.pem"
ADMIN_HOME = Path(os.getenv("FABRIC_CA_ADMIN_HOME", str(ORG1_HOME)))
WALLET_ROOT = Path(os.getenv("FABRIC_WALLET_DIR", str(ROOT / ".fabric-wallets")))
ORG_CRL = ORG1_HOME / "msp" / "crls" / "crl.pem"
CA_URL = os.getenv("FABRIC_CA_URL", "https://localhost:7054")
CA_NAME = os.getenv("FABRIC_CA_NAME", "ca-org1")
AFFILIATION = os.getenv("FABRIC_CA_AFFILIATION", "org1.department1")


def _client_binary() -> str:
    return os.getenv("FABRIC_CA_CLIENT_BIN", str(FABRIC_HOME / "bin/fabric-ca-client"))


def _run(args: list[str], home: Path, timeout: int = 60) -> str:
    env = {**os.environ, "FABRIC_CA_CLIENT_HOME": str(home)}
    try:
        result = subprocess.run(
            [_client_binary(), *args],
            env=env,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(f"fabric-ca-client not found: {_client_binary()}") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Fabric CA operation timed out") from exc
    output = "\n".join(part for part in (result.stdout, result.stderr) if part).strip()
    if result.returncode != 0:
        raise RuntimeError(output or "Fabric CA operation failed")
    return output


def wallet_msp_path(enrollment_id: str) -> Path:
    return WALLET_ROOT / enrollment_id / "msp"


def enroll_staff(enrollment_id: str, staff_id: str, role: str) -> Path:
    enrollment_id = enrollment_id.strip()
    if not enrollment_id or "/" in enrollment_id or "\\" in enrollment_id or enrollment_id in {".", ".."}:
        raise ValueError("Invalid Fabric enrollment ID")
    wallet = WALLET_ROOT / enrollment_id
    if wallet.exists():
        raise ValueError(f"Fabric identity already exists locally: {enrollment_id}")
    secret = secrets.token_urlsafe(24)
    scheme, separator, address = CA_URL.partition("://")
    if not separator or not address:
        raise ValueError("FABRIC_CA_URL must include a URL scheme")
    enrollment_url = f"{scheme}://{quote(enrollment_id, safe='')}:{quote(secret, safe='')}@{address}"
    WALLET_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    wallet.mkdir(mode=0o700)
    try:
        _run(
            [
                "register",
                "--caname",
                CA_NAME,
                "--id.name",
                enrollment_id,
                "--id.secret",
                secret,
                "--id.type",
                "client",
                "--id.affiliation",
                AFFILIATION,
                "--id.attrs",
                f"staffID={staff_id}:ecert,role={role}:ecert",
                "--tls.certfiles",
                str(CA_CERT),
            ],
            ADMIN_HOME,
        )
        _run(
            [
                "enroll",
                "-u",
                enrollment_url,
                "--caname",
                CA_NAME,
                "--tls.certfiles",
                str(CA_CERT),
            ],
            wallet,
        )
        source_msp_config = ORG1_HOME / "msp" / "config.yaml"
        target_msp_config = wallet / "msp" / "config.yaml"
        if source_msp_config.is_file():
            shutil.copyfile(source_msp_config, target_msp_config)
        for path in wallet.rglob("*"):
            if path.is_file():
                path.chmod(0o600)
            elif path.is_dir():
                path.chmod(0o700)
        return wallet
    except Exception:
        for path in sorted(wallet.rglob("*"), reverse=True):
            if path.is_file() or path.is_symlink():
                path.unlink()
            else:
                path.rmdir()
        wallet.rmdir()
        raise


def revoke_staff(enrollment_id: str) -> str:
    enrollment_id = enrollment_id.strip()
    if not enrollment_id or "/" in enrollment_id or "\\" in enrollment_id or enrollment_id in {".", ".."}:
        raise ValueError("Invalid Fabric enrollment ID")
    return _run(
        [
            "revoke",
            "--caname",
            CA_NAME,
            "--revoke.name",
            enrollment_id,
            "--gencrl",
            "--tls.certfiles",
            str(CA_CERT),
        ],
        ADMIN_HOME,
    )


def publish_org_crl(timeout: int = 180) -> str:
    script = ROOT / "scripts" / "update_org1_crl.sh"
    try:
        result = subprocess.run(
            [str(script)],
            env=os.environ.copy(),
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(f"CRL channel update script not found: {script}") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("CRL channel update timed out") from exc
    output = "\n".join(part for part in (result.stdout, result.stderr) if part).strip()
    if result.returncode != 0:
        raise RuntimeError(output or "CRL channel update failed")
    return output


def refresh_org_crl() -> str:
    return _run(
        ["gencrl", "--caname", CA_NAME, "--tls.certfiles", str(CA_CERT)],
        ADMIN_HOME,
    )


def ensure_org_crl_current(minimum_validity: timedelta = timedelta(hours=6)) -> bool:
    needs_refresh = True
    if ORG_CRL.is_file():
        crl = x509.load_pem_x509_crl(ORG_CRL.read_bytes())
        next_update = crl.next_update_utc
        needs_refresh = next_update is None or next_update - datetime.now(timezone.utc) <= minimum_validity
    if not needs_refresh:
        return False
    refresh_org_crl()
    publish_org_crl()
    return True
