"""
Aegis AI — Login Automation (Playwright)

Automates the login process for authenticated scans:
1. Navigate to the login page
2. Auto-detect or use provided username/password field selectors
3. Fill credentials and submit the form
4. Wait for successful navigation
5. Extract session cookies, JWT tokens, and auth headers

Returns an AuthSession containing everything the RequestEngine
needs to make authenticated requests.
"""
from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent.parent))

from backend.auth.credential_store import ScanCredential
from utils.logger import get_logger

logger = get_logger(__name__, "AUTH")

# ── Playwright (graceful degradation) ───────────────────────────────────────
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from playwright.async_api import Page, BrowserContext

try:
    from playwright.async_api import async_playwright as _async_playwright
    _PW_AVAILABLE = True
except ImportError:
    _async_playwright = None  # type: ignore[assignment]
    _PW_AVAILABLE = False


# ── Data structures ─────────────────────────────────────────────────────────

@dataclass
class AuthSession:
    """
    Result of a successful login automation.

    Carries cookies, headers, and optional JWT that the RequestEngine
    attaches to every subsequent request.
    """
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    jwt: str = ""
    login_successful: bool = False
    login_url: str = ""
    post_login_url: str = ""
    auth_type: str = "form"
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "login_successful": self.login_successful,
            "auth_type": self.auth_type,
            "cookie_count": len(self.cookies),
            "header_count": len(self.headers),
            "has_jwt": bool(self.jwt),
            "login_url": self.login_url,
            "post_login_url": self.post_login_url,
            "error": self.error,
        }


# ── Username/password field selectors (ordered by likelihood) ───────────────

_USERNAME_SELECTORS = [
    'input[name="username"]',
    'input[name="user"]',
    'input[name="email"]',
    'input[name="login"]',
    'input[name="user_login"]',
    'input[name="log"]',
    'input[id="username"]',
    'input[id="email"]',
    'input[id="user"]',
    'input[type="email"]',
    'input[type="text"][autocomplete="username"]',
    'input[type="text"]',  # fallback: first text input
]

_PASSWORD_SELECTORS = [
    'input[name="password"]',
    'input[name="pass"]',
    'input[name="passwd"]',
    'input[name="pwd"]',
    'input[name="user_pass"]',
    'input[id="password"]',
    'input[id="pass"]',
    'input[type="password"]',
]

_SUBMIT_SELECTORS = [
    'button[type="submit"]',
    'input[type="submit"]',
    'button:has-text("Log in")',
    'button:has-text("Login")',
    'button:has-text("Sign in")',
    'button:has-text("Submit")',
    'button:has-text("Enter")',
    'form button',
]

# Tokens stored in localStorage / JS that look like JWTs
_JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")

_LOGIN_TIMEOUT_MS = 15_000
_NAV_TIMEOUT_MS = 10_000


# ── Login Automation ────────────────────────────────────────────────────────

class LoginAutomation:
    """
    Playwright-powered login automation.

    Usage::

        cred = ScanCredential(auth_type="form", login_url="...", ...)
        auto = LoginAutomation()
        session = await auto.login(cred)
        print(session.cookies)
    """

    async def login(self, credential: ScanCredential) -> AuthSession:
        """
        Execute the login flow and return an AuthSession.

        Dispatches to the appropriate handler based on auth_type.
        """
        if credential.auth_type == "jwt":
            return self._build_jwt_session(credential)

        if credential.auth_type == "cookie":
            return self._build_cookie_session(credential)

        # form-based login
        if not _PW_AVAILABLE:
            logger.error("[AUTH] Playwright not installed — cannot automate form login")
            return AuthSession(
                login_successful=False,
                error="Playwright not installed. Run: pip install playwright && playwright install chromium",
            )

        return await self._form_login(credential)

    # ── Form-based login ────────────────────────────────────────────────

    async def _form_login(self, cred: ScanCredential) -> AuthSession:
        """Automate a form-based login using Playwright."""
        session = AuthSession(auth_type="form", login_url=cred.login_url)

        pw = await _async_playwright().start()  # type: ignore[misc]
        browser = None
        try:
            browser = await pw.chromium.launch(headless=True, args=["--no-sandbox"])
            context = await browser.new_context(
                ignore_https_errors=True,
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
            )
            page: Page = await context.new_page()  # type: ignore[assignment]

            # ── Navigate to login page ──────────────────────────────────
            logger.info("[AUTH] Navigating to login page: %s", cred.login_url)
            await page.goto(cred.login_url, wait_until="networkidle", timeout=_NAV_TIMEOUT_MS)

            # ── Locate username field ───────────────────────────────────
            username_el = None
            if cred.username_field and cred.username_field not in ("username", "user", "email"):
                # User provided a custom selector
                for sel in [
                    f'input[name="{cred.username_field}"]',
                    f'input[id="{cred.username_field}"]',
                    cred.username_field,
                ]:
                    username_el = await page.query_selector(sel)
                    if username_el:
                        break

            if not username_el:
                for sel in _USERNAME_SELECTORS:
                    username_el = await page.query_selector(sel)
                    if username_el:
                        break

            if not username_el:
                session.error = "Could not find username input on login page"
                logger.warning("[AUTH] %s", session.error)
                await browser.close()
                await pw.stop()
                return session

            # ── Locate password field ───────────────────────────────────
            password_el = None
            if cred.password_field and cred.password_field not in ("password", "pass"):
                for sel in [
                    f'input[name="{cred.password_field}"]',
                    f'input[id="{cred.password_field}"]',
                    cred.password_field,
                ]:
                    password_el = await page.query_selector(sel)
                    if password_el:
                        break

            if not password_el:
                for sel in _PASSWORD_SELECTORS:
                    password_el = await page.query_selector(sel)
                    if password_el:
                        break

            if not password_el:
                session.error = "Could not find password input on login page"
                logger.warning("[AUTH] %s", session.error)
                await browser.close()
                await pw.stop()
                return session

            # ── Fill credentials and submit ─────────────────────────────
            await username_el.fill(cred.username)
            await password_el.fill(cred.password)
            await asyncio.sleep(0.3)  # small delay for JS validation

            # Find submit button
            submit_el = None
            if cred.submit_selector:
                submit_el = await page.query_selector(cred.submit_selector)

            if not submit_el:
                for sel in _SUBMIT_SELECTORS:
                    submit_el = await page.query_selector(sel)
                    if submit_el:
                        break

            if submit_el:
                await submit_el.click()
            else:
                # Fallback: press Enter on password field
                await password_el.press("Enter")

            # ── Wait for navigation ─────────────────────────────────────
            try:
                await page.wait_for_load_state("networkidle", timeout=_LOGIN_TIMEOUT_MS)
            except Exception:
                await asyncio.sleep(2)  # fallback wait

            post_login_url = page.url
            session.post_login_url = post_login_url

            # ── Validate login success ──────────────────────────────────
            login_ok = await self._check_login_success(
                page, cred, post_login_url,
            )
            session.login_successful = login_ok

            if not login_ok:
                session.error = "Login may have failed — could not confirm success"
                logger.warning("[AUTH] %s (landed on %s)", session.error, post_login_url)

            # ── Extract cookies ─────────────────────────────────────────
            assert context is not None
            cookies_list = await context.cookies()
            for c in cookies_list:
                name = c.get("name", "")
                value = c.get("value", "")
                if name and value:
                    session.cookies[name] = value

            # ── Try to extract JWT from localStorage ────────────────────
            try:
                storage = await page.evaluate("""() => {
                    const items = {};
                    for (let i = 0; i < localStorage.length; i++) {
                        const key = localStorage.key(i);
                        items[key] = localStorage.getItem(key);
                    }
                    return items;
                }""")
                for key, val in (storage or {}).items():
                    if val and _JWT_PATTERN.search(str(val)):
                        session.jwt = str(val)
                        session.headers["Authorization"] = f"Bearer {val}"
                        logger.info("[AUTH] Extracted JWT from localStorage key '%s'", key)
                        break
            except Exception:
                pass  # localStorage not available in all contexts

            logger.info(
                "[AUTH] Login %s | cookies=%d jwt=%s url=%s",
                "SUCCESS" if login_ok else "UNCERTAIN",
                len(session.cookies),
                "yes" if session.jwt else "no",
                post_login_url,
            )

        except Exception as exc:
            session.error = f"Login automation error: {exc}"
            logger.error("[AUTH] %s", session.error)

        finally:
            try:
                if browser:
                    await browser.close()
            except Exception:
                pass
            try:
                await pw.stop()
            except Exception:
                pass

        return session

    # ── JWT session (no browser needed) ─────────────────────────────────

    @staticmethod
    def _build_jwt_session(cred: ScanCredential) -> AuthSession:
        """Build a session from a pre-existing JWT token."""
        headers = dict(cred.custom_headers)
        if cred.jwt_token and "Authorization" not in headers:
            headers["Authorization"] = f"Bearer {cred.jwt_token}"

        return AuthSession(
            jwt=cred.jwt_token,
            headers=headers,
            login_successful=True,
            auth_type="jwt",
        )

    # ── Cookie session (no browser needed) ──────────────────────────────

    @staticmethod
    def _build_cookie_session(cred: ScanCredential) -> AuthSession:
        """Build a session from pre-existing cookies."""
        return AuthSession(
            cookies=dict(cred.cookies),
            headers=dict(cred.custom_headers),
            login_successful=True,
            auth_type="cookie",
        )

    # ── Login success heuristics ────────────────────────────────────────

    @staticmethod
    async def _check_login_success(
        page: "Page",  # type: ignore[name-defined]
        cred: ScanCredential,
        post_login_url: str,
    ) -> bool:
        """
        Determine if the login was successful using several heuristics.
        """
        # 1. URL changed away from login page
        login_path = urlparse(cred.login_url).path
        current_path = urlparse(post_login_url).path
        url_changed = current_path != login_path

        # 2. User-provided success indicator
        if cred.success_url_contains and cred.success_url_contains in post_login_url:
            return True

        if cred.success_body_contains:
            body = await page.content()
            if cred.success_body_contains in body:
                return True

        # 3. No error messages visible
        body_text = await page.inner_text("body")
        body_lower = body_text.lower()
        error_indicators = [
            "invalid password", "incorrect password", "wrong password",
            "login failed", "authentication failed", "invalid credentials",
            "incorrect username", "account not found", "access denied",
        ]
        has_error = any(ind in body_lower for ind in error_indicators)

        # 4. Dashboard/home indicators
        success_indicators = [
            "dashboard", "welcome", "my account", "profile",
            "logout", "sign out", "log out",
        ]
        has_success = any(ind in body_lower for ind in success_indicators)

        if has_error:
            return False
        if url_changed and has_success:
            return True
        if url_changed:
            return True  # URL changed, assume success

        return False
