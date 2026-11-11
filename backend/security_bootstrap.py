from __future__ import annotations

import os
import secrets
from pathlib import Path

from backend.auth import _find_user, _password_hash, create_user, verify_password
from backend.couch_store import store

ROOT = Path(__file__).resolve().parent.parent
SECRETS_DIR = ROOT / ".secrets"
INITIAL_ADMIN_PASSWORD = SECRETS_DIR / "admin_initial_password"


def _write_secret(path: Path, value: str) -> None:
    SECRETS_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    SECRETS_DIR.chmod(0o700)
    path.write_text(value + "\n", encoding="utf-8")
    path.chmod(0o600)


def main() -> int:
    store.ensure_database()
    admin = _find_user(os.getenv("ADMIN_USERNAME", "admin"))
    configured_password = os.getenv("ADMIN_PASSWORD")
    if admin is None:
        password = configured_password or secrets.token_urlsafe(24)
        admin = create_user(os.getenv("ADMIN_USERNAME", "admin"), password, "admin", "ADMIN")
        admin["mustChangePassword"] = configured_password is None
        store.put("users", admin["userID"], admin)
        if configured_password is None:
            _write_secret(INITIAL_ADMIN_PASSWORD, password)
        print("Security bootstrap created the admin account without a default password")
        return 0
    if verify_password("admin123", admin.get("passwordHash", "")):
        password = configured_password or secrets.token_urlsafe(24)
        admin["passwordHash"] = _password_hash(password)
        admin["mustChangePassword"] = configured_password is None
        store.put("users", admin["userID"], admin)
        if configured_password is None:
            _write_secret(INITIAL_ADMIN_PASSWORD, password)
        print("Security bootstrap rotated the insecure default admin password")
    else:
        print("Security bootstrap confirmed that the admin password is not the default")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
