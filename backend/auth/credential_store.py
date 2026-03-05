"""
Aegis AI — Credential Store

Securely stores scan credentials using Fernet symmetric encryption.
Credentials are encrypted at rest and decrypted only when needed
for login automation during authenticated scans.

Supported auth types:
- form:   HTML form-based login (username/password fields)
- jwt:    Bearer token authentication
- cookie: Direct session cookie injection
"""
from __future__ import annotations

import json
import os
import base64
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent.parent))

from utils.logger import get_logger

logger = get_logger(__name__, "AUTH")

# ── Key management ──────────────────────────────────────────────────────────

_KEY_ENV = "AEGIS_CREDENTIAL_KEY"
_KEY_FILE = Path(__file__).resolve().parent / ".credential_key"


def _get_or_create_key() -> bytes:
    """
    Return the Fernet encryption key.

    Priority:
    1. AEGIS_CREDENTIAL_KEY env var
    2. .credential_key file next to this module
    3. Generate a new key and write it to file
    """
    env_key = os.environ.get(_KEY_ENV)
    if env_key:
        return env_key.encode()

    if _KEY_FILE.exists():
        return _KEY_FILE.read_bytes().strip()

    key = Fernet.generate_key()
    _KEY_FILE.write_bytes(key)
    _KEY_FILE.chmod(0o600)
    logger.info("[AUTH] Generated new credential encryption key")
    return key


# ── Data Model ──────────────────────────────────────────────────────────────

@dataclass
class ScanCredential:
    """Credentials for authenticating to a target application."""

    # Auth type: "form" | "jwt" | "cookie"
    auth_type: str = "form"

    # Form-based login fields
    login_url: str = ""
    username_field: str = "username"
    password_field: str = "password"
    username: str = ""
    password: str = ""

    # Extra form fields (e.g. CSRF token name)
    extra_fields: Dict[str, str] = field(default_factory=dict)

    # JWT / bearer token (for auth_type="jwt")
    jwt_token: str = ""

    # Direct cookies (for auth_type="cookie")
    cookies: Dict[str, str] = field(default_factory=dict)

    # Custom headers to inject (e.g. Authorization)
    custom_headers: Dict[str, str] = field(default_factory=dict)

    # Submit selector (CSS) — if the login form has a non-standard submit button
    submit_selector: str = ""

    # Success indicator — URL fragment or text expected after successful login
    success_url_contains: str = ""
    success_body_contains: str = ""

    def has_credentials(self) -> bool:
        """Return True if enough info exists to attempt authentication."""
        if self.auth_type == "form":
            return bool(self.login_url and self.username and self.password)
        if self.auth_type == "jwt":
            return bool(self.jwt_token)
        if self.auth_type == "cookie":
            return bool(self.cookies)
        return False

    def to_safe_dict(self) -> Dict[str, Any]:
        """Return a dict with secrets masked (for logging / state storage)."""
        d = asdict(self)
        if d.get("password"):
            d["password"] = "****"
        if d.get("jwt_token"):
            d["jwt_token"] = d["jwt_token"][:12] + "..."
        for k in list(d.get("cookies", {})):
            d["cookies"][k] = "****"
        return d


# ── Credential Store ────────────────────────────────────────────────────────

class CredentialStore:
    """
    Encrypt-at-rest credential store backed by Fernet.

    Usage::

        store = CredentialStore()
        cred = ScanCredential(
            auth_type="form",
            login_url="https://example.com/login",
            username="admin",
            password="secret",
        )
        token = store.encrypt(cred)     # encrypted blob (str)
        cred2 = store.decrypt(token)    # ScanCredential
    """

    def __init__(self):
        self._fernet = Fernet(_get_or_create_key())

    # ── Encrypt / Decrypt ────────────────────────────────────────────────

    def encrypt(self, credential: ScanCredential) -> str:
        """Encrypt a ScanCredential and return a URL-safe base64 token."""
        payload = json.dumps(asdict(credential)).encode()
        return self._fernet.encrypt(payload).decode()

    def decrypt(self, token: str) -> ScanCredential:
        """Decrypt a token back into a ScanCredential."""
        try:
            payload = self._fernet.decrypt(token.encode())
            data = json.loads(payload)
            return ScanCredential(**data)
        except (InvalidToken, json.JSONDecodeError) as exc:
            logger.error("[AUTH] Failed to decrypt credential: %s", exc)
            raise ValueError("Invalid or corrupted credential token") from exc

    # ── Convenience: build from frontend dict ────────────────────────────

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> ScanCredential:
        """
        Build a ScanCredential from a raw dict (e.g. API request body).

        Accepts the frontend-facing field names and normalizes them.
        """
        auth_type = data.get("auth_type", "form")

        cred = ScanCredential(auth_type=auth_type)

        if auth_type == "form":
            cred.login_url = data.get("login_url", "")
            cred.username_field = data.get("username_field", "username")
            cred.password_field = data.get("password_field", "password")
            cred.username = data.get("username", "")
            cred.password = data.get("password", "")
            cred.submit_selector = data.get("submit_selector", "")
            cred.success_url_contains = data.get("success_url_contains", "")
            cred.success_body_contains = data.get("success_body_contains", "")

        elif auth_type == "jwt":
            cred.jwt_token = data.get("jwt_token", "")
            cred.custom_headers = data.get("custom_headers", {})
            if cred.jwt_token and not cred.custom_headers:
                cred.custom_headers["Authorization"] = f"Bearer {cred.jwt_token}"

        elif auth_type == "cookie":
            raw = data.get("cookies", data.get("session_cookie", ""))
            if isinstance(raw, str) and raw:
                # Parse "name=value; name2=value2" cookie string
                cred.cookies = {}
                for part in raw.split(";"):
                    part = part.strip()
                    if "=" in part:
                        k, v = part.split("=", 1)
                        cred.cookies[k.strip()] = v.strip()
            elif isinstance(raw, dict):
                cred.cookies = raw

        return cred
