"""
Aegis AI — Session Manager

Maintains authenticated sessions throughout a scan lifecycle:
- Stores AuthSession (cookies, headers, JWT) in scan state
- Attaches auth context to the RequestEngine
- Monitors session validity by checking for auth-failure indicators
- Refreshes sessions when expired (re-runs login automation)

Usage::

    mgr = SessionManager()
    session = await mgr.authenticate(credential)
    mgr.apply_to_engine(engine)        # patches RequestEngine
    if mgr.needs_refresh(response):
        session = await mgr.refresh()  # re-login
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent.parent))

from backend.auth.credential_store import ScanCredential
from backend.auth.login_automation import LoginAutomation, AuthSession
from utils.logger import get_logger

logger = get_logger(__name__, "AUTH")

# ── Session-expired indicators ──────────────────────────────────────────────

_SESSION_EXPIRED_STATUS_CODES = {401, 403}

_SESSION_EXPIRED_BODY_INDICATORS = [
    "session expired",
    "session has expired",
    "login required",
    "please log in",
    "please sign in",
    "access denied",
    "not authenticated",
    "authentication required",
    "token expired",
    "token is expired",
    "jwt expired",
    "invalid token",
    "unauthorized",
]

_SESSION_EXPIRED_REDIRECT_PATHS = [
    "/login", "/signin", "/auth", "/session/new", "/sso",
]

# How often we check session liveness (avoid hammering)
_MIN_REFRESH_INTERVAL_S = 60


class SessionManager:
    """
    Manages the authenticated session for a single scan.

    Lifecycle:
    1. authenticate(credential) — runs login automation → AuthSession
    2. apply_to_engine(engine)  — injects cookies / headers into RequestEngine
    3. needs_refresh(response)  — checks if a response indicates session loss
    4. refresh()                — re-runs login automation to get a fresh session
    """

    def __init__(self, on_event: Optional[Callable] = None):
        self._credential: Optional[ScanCredential] = None
        self._session: Optional[AuthSession] = None
        self._login_automation = LoginAutomation()
        self._on_event = on_event
        self._last_refresh: float = 0.0
        self._refresh_count: int = 0
        self._max_refreshes: int = 3  # guard against infinite re-login loops

    # ── Properties ──────────────────────────────────────────────────────

    @property
    def session(self) -> Optional[AuthSession]:
        return self._session

    @property
    def is_authenticated(self) -> bool:
        return self._session is not None and self._session.login_successful

    # ── Core API ────────────────────────────────────────────────────────

    async def authenticate(self, credential: ScanCredential) -> AuthSession:
        """
        Run the login flow and store the resulting session.

        Returns the AuthSession (check .login_successful).
        """
        self._credential = credential

        await self._emit("AUTH_START", f"Authenticating ({credential.auth_type})...")

        session = await self._login_automation.login(credential)
        self._session = session
        self._last_refresh = time.monotonic()

        if session.login_successful:
            await self._emit(
                "AUTH_SUCCESS",
                f"Login successful — {len(session.cookies)} cookies captured",
                session.to_dict(),
            )
        else:
            await self._emit(
                "AUTH_FAILED",
                f"Login failed: {session.error or 'unknown reason'}",
                session.to_dict(),
            )

        return session

    def apply_to_engine(self, engine: Any) -> None:
        """
        Inject the authenticated session into a RequestEngine.

        Patches:
        - engine.session_cookies — merged with login cookies
        - engine._auth_headers   — custom auth headers (Authorization, etc.)
        """
        if not self._session or not self._session.login_successful:
            return

        # Merge cookies
        engine.session_cookies.update(self._session.cookies)

        # Store auth headers on the engine (RequestEngine reads them in _request)
        if not hasattr(engine, "_auth_headers"):
            engine._auth_headers = {}
        engine._auth_headers.update(self._session.headers)

        logger.info(
            "[AUTH] Applied session to engine: cookies=%d headers=%d",
            len(self._session.cookies),
            len(self._session.headers),
        )

    def needs_refresh(self, response: Any) -> bool:
        """
        Check whether a response indicates the session has expired.

        Args:
            response: An HttpResponse from the RequestEngine
        """
        if not self._session or not self._session.login_successful:
            return False

        # Throttle refresh checks
        if time.monotonic() - self._last_refresh < _MIN_REFRESH_INTERVAL_S:
            return False

        if self._refresh_count >= self._max_refreshes:
            return False

        # Check status code
        status = getattr(response, "status_code", 0)
        if status in _SESSION_EXPIRED_STATUS_CODES:
            return True

        # Check body for session-expired language
        body = getattr(response, "body", "")
        if body:
            body_lower = body.lower()
            for indicator in _SESSION_EXPIRED_BODY_INDICATORS:
                if indicator in body_lower:
                    return True

        # Check if redirected to a login page
        redirects = getattr(response, "redirect_chain", [])
        for redir in redirects:
            for login_path in _SESSION_EXPIRED_REDIRECT_PATHS:
                if login_path in redir.lower():
                    return True

        return False

    async def refresh(self) -> AuthSession:
        """
        Re-run the login automation with the stored credential.

        Returns the new AuthSession.
        """
        if not self._credential:
            return AuthSession(
                login_successful=False,
                error="No credential stored for refresh",
            )

        self._refresh_count += 1
        logger.info("[AUTH] Refreshing session (attempt %d/%d)",
                     self._refresh_count, self._max_refreshes)

        await self._emit(
            "AUTH_REFRESH",
            f"Session expired — refreshing (attempt {self._refresh_count})",
        )

        session = await self._login_automation.login(self._credential)
        self._session = session
        self._last_refresh = time.monotonic()

        if session.login_successful:
            await self._emit("AUTH_REFRESH_OK", "Session refreshed successfully")
        else:
            await self._emit("AUTH_REFRESH_FAIL", f"Session refresh failed: {session.error}")

        return session

    # ── Event helper ────────────────────────────────────────────────────

    async def _emit(self, event_type: str, message: str, details: dict = None):
        if self._on_event:
            await self._on_event({
                "agent": "AUTH",
                "event_type": event_type,
                "message": message,
                "details": details or {},
            })
