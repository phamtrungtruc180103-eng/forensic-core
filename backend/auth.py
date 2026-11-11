from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from backend.couch_store import store

JWT_ALGORITHM = "HS256"
JWT_EXPIRY_MINUTES = int(os.getenv("JWT_EXPIRY_MINUTES", "60"))
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JWT_SECRET_FILE = os.path.join(ROOT, ".secrets", "jwt_secret")


def _load_jwt_secret() -> str:
    configured = os.getenv("JWT_SECRET")
    if configured:
        if len(configured) < 32:
            raise RuntimeError("JWT_SECRET must contain at least 32 characters")
        return configured
    try:
        os.makedirs(os.path.dirname(JWT_SECRET_FILE), mode=0o700, exist_ok=True)
        os.chmod(os.path.dirname(JWT_SECRET_FILE), 0o700)
        if os.path.exists(JWT_SECRET_FILE):
            with open(JWT_SECRET_FILE, encoding="utf-8") as handle:
                secret = handle.read().strip()
            if secret:
                return secret
        secret = secrets.token_urlsafe(48)
        with open(JWT_SECRET_FILE, "x", encoding="utf-8") as handle:
            handle.write(secret + "\n")
        os.chmod(JWT_SECRET_FILE, 0o600)
        return secret
    except OSError as exc:
        raise RuntimeError(f"Unable to initialize persistent JWT secret: {exc}") from exc


JWT_SECRET = _load_jwt_secret()
POSITIONS = ("ADMIN", "INVESTIGATOR", "ANALYST", "SUPERVISOR", "OBSERVER")
bearer = HTTPBearer(auto_error=False)


def _password_hash(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 240_000)
    return f"{salt}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        salt, expected = encoded.split("$", 1)
        actual = _password_hash(password, salt).split("$", 1)[1]
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def create_access_token(user: dict[str, Any]) -> str:
    now = datetime.now(timezone.utc)
    claims = {
        "sub": user["userID"],
        "username": user["username"],
        "role": user["role"],
        "position": user.get("position"),
        "iat": now,
        "exp": now + timedelta(minutes=JWT_EXPIRY_MINUTES),
    }
    return jwt.encode(claims, JWT_SECRET, algorithm=JWT_ALGORITHM)


def _find_user(username: str) -> dict[str, Any] | None:
    return next((item for item in store.documents("users") if item.get("username") == username), None)


def authenticate(username: str, password: str, position: str = "INVESTIGATOR") -> dict[str, Any] | None:
    store.ensure_database()
    user = _find_user(username)
    position_matches = user and (user.get("position", "INVESTIGATOR") == position or (user.get("role") == "admin" and position == "ADMIN"))
    if not user or user.get("status") != "ACTIVE" or not position_matches or not verify_password(password, user.get("passwordHash", "")):
        return None
    return user


def create_user(username: str, password: str, role: str = "user", position: str = "INVESTIGATOR") -> dict[str, Any]:
    username = username.strip().lower()
    if not username or len(username) > 80 or len(password) < 12:
        raise HTTPException(status_code=422, detail="Username is required and password must contain at least 12 characters")
    if position not in POSITIONS:
        raise HTTPException(status_code=422, detail=f"Position must be one of: {', '.join(POSITIONS)}")
    if position == "ADMIN" and role != "admin":
        raise HTTPException(status_code=403, detail="Only admin accounts can use the ADMIN position")
    store.ensure_database()
    if _find_user(username):
        raise HTTPException(status_code=409, detail="Username already exists")
    user = {
        "userID": secrets.token_hex(12),
        "username": username,
        "passwordHash": _password_hash(password),
        "role": role,
        "position": position,
        "status": "ACTIVE",
        "createdAt": datetime.now(timezone.utc).isoformat(),
    }
    store.put("users", user["userID"], user)
    return user


def change_password(user: dict[str, Any], current_password: str, new_password: str) -> dict[str, Any]:
    if not verify_password(current_password, user.get("passwordHash", "")):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if len(new_password) < 12:
        raise HTTPException(status_code=422, detail="New password must contain at least 12 characters")
    user["passwordHash"] = _password_hash(new_password)
    user["mustChangePassword"] = False
    user["passwordChangedAt"] = datetime.now(timezone.utc).isoformat()
    store.put("users", user["userID"], user)
    return user


def current_user(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)) -> dict[str, Any]:
    if not credentials or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bearer token is required", headers={"WWW-Authenticate": "Bearer"})
    try:
        claims = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired token", headers={"WWW-Authenticate": "Bearer"}) from exc
    user_id = claims.get("sub")
    if not isinstance(user_id, str):
        raise HTTPException(status_code=401, detail="Invalid token subject", headers={"WWW-Authenticate": "Bearer"})
    store.ensure_database()
    user = store.get("users", user_id)
    if not user or user.get("status") != "ACTIVE":
        raise HTTPException(status_code=401, detail="User is inactive or no longer exists", headers={"WWW-Authenticate": "Bearer"})
    return user


def require_admin(user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin role is required")
    return user
