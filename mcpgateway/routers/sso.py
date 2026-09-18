# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/routers/sso.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Single Sign-On (SSO) authentication routes for OAuth2/OIDC providers.
Handles SSO login flows, provider configuration, and callback handling.
"""

# Standard
import secrets
import urllib.parse
from typing import Dict, List, Optional
from urllib.parse import unquote, urlparse

# Third-Party
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
import jwt
from pydantic import BaseModel, model_validator
from sqlalchemy.orm import Session

# First-Party
from mcpgateway.common.query_params import QueryErrorCodeSso
from mcpgateway.common.validators import SafeIdentifier, SafeName
from mcpgateway.config import settings
from mcpgateway.db import get_db
from mcpgateway.middleware.rbac import get_current_user_with_permissions, require_permission
from mcpgateway.services.logging_service import LoggingService
from mcpgateway.services.sso_service import invalidate_trusted_provider_cache, SSOService
from mcpgateway.services.team_management_service import TeamManagementService
from mcpgateway.utils.log_sanitizer import sanitize_for_log
from mcpgateway.utils.paths import resolve_root_path
from mcpgateway.utils.verify_credentials import invalidate_external_identity_cache

# Initialize logging
logging_service = LoggingService()
logger = logging_service.get_logger("mcpgateway.routers.sso")


class SSOProviderCreateRequest(BaseModel):
    """Request to create SSO provider."""

    id: SafeIdentifier
    name: SafeName
    display_name: SafeName
    provider_type: str  # oauth2, oidc
    client_id: str
    client_secret: str
    authorization_url: str
    token_url: str
    userinfo_url: str
    issuer: Optional[str] = None
    jwks_uri: Optional[str] = None
    scope: str = "openid profile email"
    trusted_domains: List[str] = []
    auto_create_users: bool = True
    team_mapping: Dict = {}
    provider_metadata: Dict = {}  # Role mappings, groups_claim config, etc.
    trusted_for_api_auth: bool = False
    api_audience: Optional[str] = None

    @model_validator(mode="after")
    def _require_audience_when_api_trusted(self):
        """Ensure api_audience is set when trusted_for_api_auth is enabled.

        Returns:
            SSOProviderCreateRequest: The validated model instance.

        Raises:
            ValueError: If trusted_for_api_auth is True but api_audience is empty.
        """
        if self.trusted_for_api_auth and not (self.api_audience or "").strip():
            raise ValueError("api_audience is required when trusted_for_api_auth is enabled (prevents confused-deputy token acceptance)")
        return self


class SSOProviderUpdateRequest(BaseModel):
    """Request to update SSO provider."""

    name: Optional[SafeName] = None
    display_name: Optional[SafeName] = None
    provider_type: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    authorization_url: Optional[str] = None
    token_url: Optional[str] = None
    userinfo_url: Optional[str] = None
    issuer: Optional[str] = None
    jwks_uri: Optional[str] = None
    scope: Optional[str] = None
    trusted_domains: Optional[List[str]] = None
    auto_create_users: Optional[bool] = None
    team_mapping: Optional[Dict] = None
    provider_metadata: Optional[Dict] = None  # Role mappings, groups_claim config, etc.
    is_enabled: Optional[bool] = None
    trusted_for_api_auth: Optional[bool] = None
    api_audience: Optional[str] = None

    @model_validator(mode="after")
    def _require_audience_when_api_trusted(self):
        """Ensure api_audience is provided when enabling trusted_for_api_auth in this update.

        Returns:
            SSOProviderUpdateRequest: The validated model instance.

        Raises:
            ValueError: If trusted_for_api_auth is being set to True but api_audience is empty.
        """
        if self.trusted_for_api_auth is True and not (self.api_audience or "").strip():
            raise ValueError("api_audience is required when trusted_for_api_auth is enabled (prevents confused-deputy token acceptance)")
        return self


# Create router
sso_router = APIRouter(prefix="/auth/sso", tags=["SSO Authentication"])


class SSOProviderResponse(BaseModel):
    """SSO provider information for client."""

    id: str
    name: str
    display_name: str
    authorization_url: Optional[str] = None  # Only provided when initiating login


class SSOLoginResponse(BaseModel):
    """SSO login initiation response."""

    authorization_url: str
    state: str


class SSOCallbackResponse(BaseModel):
    """SSO authentication callback response."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: Dict


@sso_router.get("/providers", response_model=List[SSOProviderResponse])
async def list_sso_providers(
    db: Session = Depends(get_db),
) -> List[SSOProviderResponse]:
    """List available SSO providers for login.

    Args:
        db: Database session

    Returns:
        List of enabled SSO providers with basic information.

    Raises:
        HTTPException: If SSO authentication is disabled

    Examples:
        >>> import asyncio
        >>> asyncio.iscoroutinefunction(list_sso_providers)
        True
    """
    if not settings.sso_enabled:
        raise HTTPException(status_code=404, detail="SSO authentication is disabled")

    sso_service = SSOService(db)
    providers = sso_service.list_enabled_providers()

    return [SSOProviderResponse(id=provider.id, name=provider.name, display_name=provider.display_name) for provider in providers]


def _normalize_origin(scheme: str, host: str, port: int | None) -> str:
    """Normalize an origin to scheme://host:port format.

    Args:
        scheme: URL scheme (http/https)
        host: Hostname
        port: Port number (None uses default for scheme)

    Returns:
        Normalized origin string
    """
    # Use default ports for scheme if not specified
    default_ports = {"http": 80, "https": 443}
    if port is None or port == default_ports.get(scheme):
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


def _validate_redirect_uri(redirect_uri: str, request: Request | None = None) -> bool:
    """Validate redirect_uri to prevent open redirect attacks.

    Validates against a server-side allowlist (settings.allowed_origins and settings.app_domain).
    Does NOT trust the Host header to prevent spoofing attacks.

    Allows:
    - Relative URIs (no scheme/host)
    - URIs matching configured allowed_origins (full origin including scheme and port)
    - URIs matching app_domain (if configured)

    Args:
        redirect_uri: The redirect URI to validate
        request: The FastAPI request object (unused, kept for API compatibility)

    Returns:
        True if the redirect_uri is safe, False otherwise
    """
    parsed = urlparse(redirect_uri)

    # Allow relative URIs (no scheme and no netloc)
    if not parsed.scheme and not parsed.netloc:
        return True

    # For absolute URIs, validate against server-side allowlist only
    # Extract full origin components from redirect_uri
    redirect_scheme = parsed.scheme.lower()
    redirect_host = parsed.hostname.lower() if parsed.hostname else ""
    redirect_port = parsed.port

    # Normalize the redirect origin
    redirect_origin = _normalize_origin(redirect_scheme, redirect_host, redirect_port)

    # Check against app_domain (if configured)
    if hasattr(settings, "app_domain") and settings.app_domain:
        # app_domain is an HttpUrl - extract the hostname for comparison
        app_domain_host = urlparse(str(settings.app_domain)).hostname or ""
        app_domain_host = app_domain_host.lower()
        if redirect_host == app_domain_host:
            # Only allow HTTPS in production, or HTTP for localhost
            if redirect_scheme == "https" or (redirect_scheme == "http" and app_domain_host in ("localhost", "127.0.0.1")):
                return True

    # Check against allowed_origins (full origin match including scheme and port)
    if hasattr(settings, "allowed_origins") and settings.allowed_origins:
        for origin in settings.allowed_origins:
            origin = origin.strip()
            if not origin:
                continue

            # Parse the allowed origin
            origin_parsed = urlparse(origin if "://" in origin else f"https://{origin}")
            origin_scheme = origin_parsed.scheme.lower() if origin_parsed.scheme else "https"
            origin_host = origin_parsed.hostname.lower() if origin_parsed.hostname else origin.lower()
            origin_port = origin_parsed.port

            # Normalize and compare full origins
            allowed_origin = _normalize_origin(origin_scheme, origin_host, origin_port)
            if redirect_origin == allowed_origin:
                return True

    return False


@sso_router.get("/login/zen")
async def initiate_zen_sso_login(
    request: Request,
    response: Response,
):
    """Initiate Zen/CPD SSO login flow.

    Generates CSRF state, stores it in a short-lived signed/HTTP-only cookie,
    and redirects the browser to the CPD callback path where CPD nginx intercepts
    unauthenticated requests and redirects to the CPD login page.

    Args:
        request: FastAPI request object
        response: FastAPI response object

    Returns:
        RedirectResponse to CPD callback path
    """
    if not settings.sso_zen_enabled or not settings.sso_zen_cpd_host:
        raise HTTPException(status_code=404, detail="Zen SSO authentication is disabled or CPD host is not configured")

    state = secrets.token_urlsafe(32)
    cpd_host = settings.sso_zen_cpd_host.strip()

    # Determine CF callback base — explicit setting wins, then request.base_url
    if hasattr(settings, "sso_zen_cf_callback_base") and settings.sso_zen_cf_callback_base:
        cf_host = str(settings.sso_zen_cf_callback_base).rstrip("/")
    elif hasattr(settings, "app_domain") and settings.app_domain:
        cf_host = str(settings.app_domain).rstrip("/")
    else:
        # request.base_url is scheme://host[:port]/ — strip trailing slash
        cf_host = str(request.base_url).rstrip("/")

    # Build CPD callback redirect URL
    cb_params = urllib.parse.urlencode({"state": state, "cf_host": cf_host})
    cpd_redirect_url = f"https://{cpd_host}/zen/auth/sso/callback/zen?{cb_params}"

    # Third-Party
    from fastapi.responses import RedirectResponse

    redirect_resp = RedirectResponse(url=cpd_redirect_url, status_code=302)

    # The Zen SSO flow is intentionally cross-site: the browser visits the CPD
    # domain and is redirected back to CF.  SameSite=Lax (the default) causes
    # some browsers to suppress the cookie on that cross-site redirect, breaking
    # CSRF validation.  SameSite=None is required here; it mandates Secure=True.
    redirect_resp.set_cookie(
        key="zen_sso_state",
        value=state,
        max_age=300,  # 5 minutes
        httponly=True,
        secure=True,  # SameSite=None requires Secure
        samesite="none",
        path=settings.app_root_path or "/",
    )

    return redirect_resp


@sso_router.get("/login/zen/token", include_in_schema=False)
async def zen_token_paste_page(request: Request):
    """Render a token-paste page for local dev testing of Zen SSO (dev environment only).

    In production the nginx extension proxies the CPD callback to the normal
    /auth/sso/callback/zen endpoint with the JWT in a header.  Locally that
    extension isn't active, so this page lets you paste the Zen JWT obtained
    from the CPD UI and exchange it for a CF session directly.

    Only available when ``environment=development``.
    """
    if settings.environment != "development":
        raise HTTPException(status_code=404, detail="Not found")

    root_path = request.scope.get("root_path", "")
    cpd_host = getattr(settings, "sso_zen_cpd_host", "") or ""
    display_name = getattr(settings, "sso_zen_display_name", None) or "IBM Cloud Pak for Automation"
    cpd_url = f"https://{cpd_host}" if cpd_host else "#"
    password_key = "password"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Login with {display_name}</title>
  <style>
    body {{ font-family: system-ui, sans-serif; max-width: 560px; margin: 80px auto; padding: 0 20px; color: #1f2328; }}
    h2 {{ font-size: 1.25rem; margin-bottom: 4px; }}
    p {{ color: #57606a; font-size: .9rem; margin-bottom: 20px; }}
    ol {{ color: #57606a; font-size: .9rem; padding-left: 20px; line-height: 1.8; }}
    a {{ color: #3b82d4; }}
    textarea {{ width: 100%; height: 100px; font-family: monospace; font-size: .8rem;
               border: 1px solid #e5e7eb; border-radius: 6px; padding: 8px;
               box-sizing: border-box; resize: vertical; }}
    button {{ margin-top: 12px; padding: 10px 24px; background: #1d4ed8; color: #fff;
              border: none; border-radius: 6px; cursor: pointer; font-size: .95rem; }}
    button:hover {{ background: #1e40af; }}
    .note {{ margin-top: 16px; font-size: .8rem; color: #9ca3af; }}
  </style>
</head>
<body>
  <h2>Login with {display_name}</h2>
  <p>Dev-mode token exchange — not shown in production.</p>
  <ol>
    <li>Open <a href="{cpd_url}/auth/login" target="_blank">{cpd_url}/auth/login</a></li>
    <li>Log in with your CPD credentials</li>
    <li>Open browser DevTools → Application → Cookies → find <code>ibm-private-cloud-session</code>, or run in the console:<br>
        <code>document.cookie</code> / check Network tab for <code>Authorization</code> header</li>
    <li>Alternatively run:<br>
        <code>curl -sk -X POST {cpd_url}/icp4d-api/v1/authorize \\<br>
        &nbsp;&nbsp;-H 'Content-Type: application/json' \\<br>
        &nbsp;&nbsp;-d '{{"username":"admin","{password_key}":"&lt;YOUR_CPD_PASSWORD&gt;"}}' | python3 -m json.tool</code></li>
    <li>Paste the <code>token</code> value below and click Login</li>
  </ol>
  <form method="POST" action="{root_path}/auth/sso/login/zen/token">
    <textarea name="zen_token" placeholder="eyJhbGciOiJS..." required></textarea>
    <br>
    <button type="submit">Login with {display_name}</button>
  </form>
  <p class="note">This page is only available in development mode.</p>
</body>
</html>"""
    # Standard
    from fastapi.responses import HTMLResponse

    return HTMLResponse(html)


@sso_router.post("/login/zen/token", include_in_schema=False)
async def zen_token_exchange(
    request: Request,
    db: Session = Depends(get_db),
):
    """Accept a Zen JWT posted from the token-paste page and create a CF session.

    Dev environment only — skips the CSRF state cookie check because the
    browser flow never went through ``/auth/sso/login/zen``.
    """
    # Third-Party
    from fastapi.responses import HTMLResponse, RedirectResponse

    # First-Party
    from mcpgateway.utils.security_cookies import CookieTooLargeError, set_auth_cookie

    if settings.environment != "development":
        raise HTTPException(status_code=404, detail="Not found")

    if not settings.sso_zen_enabled:
        raise HTTPException(status_code=404, detail="Zen SSO is disabled")

    root_path = request.scope.get("root_path", "")

    form = await request.form()
    zen_token = (form.get("zen_token") or "").strip()
    if not zen_token:
        return HTMLResponse("<p>Missing token. <a href='javascript:history.back()'>Go back</a>.</p>", status_code=400)

    sso_service = SSOService(db)
    try:
        user_info = sso_service.handle_zen_callback(zen_token)
    except Exception as exc:
        logger.warning("Zen token exchange failed: %s", exc)
        return HTMLResponse(f"<p>Token verification failed: {type(exc).__name__}. <a href='javascript:history.back()'>Go back</a>.</p>", status_code=400)

    access_token = await sso_service.authenticate_or_create_user(user_info)
    if not access_token:
        return RedirectResponse(url=f"{root_path}/admin/login?error=user_creation_failed", status_code=302)

    redirect_response = RedirectResponse(url=f"{root_path}/admin", status_code=302)
    try:
        set_auth_cookie(redirect_response, access_token, remember_me=False)
    except CookieTooLargeError:
        return RedirectResponse(url=f"{root_path}/admin/login?error=token_too_large", status_code=302)

    return redirect_response


@sso_router.get("/callback/zen")
async def handle_zen_sso_callback(
    request: Request,
    state: str = Query(..., description="CSRF state parameter"),
    token: Optional[str] = Query(None, description="Zen JWT token from browser redirect"),
    db: Session = Depends(get_db),
):
    """Handle Zen/CPD SSO authentication callback.

    Receives Zen JWT via query param (browser redirect flow) or Authorization / X-Zen-Token header,
    verifies signature against the Zen public key, authenticates or creates the user,
    and redirects to /admin with an auth cookie.

    Args:
        request: FastAPI request object
        state: CSRF state parameter for validation
        db: Database session

    Returns:
        RedirectResponse to /admin on success, or /admin/login?error=... on failure
    """
    # Third-Party
    from fastapi.responses import RedirectResponse

    # First-Party
    from mcpgateway.utils.security_cookies import CookieTooLargeError, set_auth_cookie

    root_path = request.scope.get("root_path", "") if request else ""

    if not settings.sso_zen_enabled:
        raise HTTPException(status_code=404, detail="Zen SSO authentication is disabled")

    # The Zen callback is proxied by CPD nginx — the browser's origin is the CPD
    # domain, so relative redirects would land on CPD, not CF.  Use the configured
    # CF base URL for all redirects so the browser ends up on the right domain.
    cf_base = str(settings.sso_zen_cf_callback_base).rstrip("/") if settings.sso_zen_cf_callback_base else ""

    def _cf_redirect(path: str) -> RedirectResponse:
        url = f"{cf_base}{root_path}{path}" if cf_base else f"{root_path}{path}"
        return RedirectResponse(url=url, status_code=302)

    # CSRF state validation: the browser carries zen_sso_state (SameSite=None)
    # set when /auth/sso/login/zen was first called.
    state_decoded = unquote(state)
    state_cookie = request.cookies.get("zen_sso_state") if request else None
    if not state_cookie or not secrets.compare_digest(state_cookie, state_decoded):
        logger.warning("Zen SSO state validation failed")
        return _cf_redirect("/admin/login?error=sso_failed")

    # Extract Zen JWT from query param (token=...), Authorization header, or X-Zen-Token header
    zen_token = (token or "").strip() or None
    if not zen_token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            zen_token = auth_header[7:].strip()
    if not zen_token:
        zen_token = request.headers.get("X-Zen-Token", "").strip() or None

    if not zen_token:
        logger.warning("Zen SSO callback missing JWT token in query param, Authorization, or X-Zen-Token header")
        return _cf_redirect("/admin/login?error=sso_failed")

    sso_service = SSOService(db)
    try:
        user_info = sso_service.handle_zen_callback(zen_token)
    except Exception as exc:
        logger.warning("Zen SSO callback failed to verify token: %s", exc)
        return _cf_redirect("/admin/login?error=sso_failed")

    try:
        access_token = await sso_service.authenticate_or_create_user(user_info)
    except Exception as exc:
        logger.warning("Zen SSO callback failed to authenticate user: %s", exc, exc_info=True)
        return _cf_redirect("/admin/login?error=sso_failed")
    if not access_token:
        return _cf_redirect("/admin/login?error=user_creation_failed")

    redirect_response = _cf_redirect("/admin")

    # Clear state cookie
    redirect_response.delete_cookie(
        key="zen_sso_state",
        path=settings.app_root_path or "/",
    )

    try:
        set_auth_cookie(redirect_response, access_token, remember_me=False)
    except CookieTooLargeError:
        return _cf_redirect("/admin/login?error=token_too_large")

    return redirect_response


@sso_router.get("/login/{provider_id}", response_model=SSOLoginResponse)
async def initiate_sso_login(
    provider_id: str,
    request: Request,
    response: Response,
    redirect_uri: str = Query(..., max_length=2048, description="Callback URI after authentication"),
    # scopes is space-separated per RFC 6749 Section 3.3 and its character set is
    # provider-specific (Google scopes are URLs, Microsoft Graph allows many special
    # chars). Server-side resolution in _resolve_login_scopes enforces the provider
    # allowlist; the Query layer only bounds length.
    scopes: Optional[str] = Query(None, max_length=500, description="Space-separated OAuth scopes"),
    db: Session = Depends(get_db),
) -> SSOLoginResponse:
    """Initiate SSO authentication flow.

    Validates the redirect_uri against a server-side allowlist to prevent open redirect attacks.
    Only allows relative URIs, URIs matching app_domain, or URIs from configured allowed_origins.
    Does NOT trust the Host header for validation.

    Args:
        provider_id: SSO provider identifier (e.g., 'github', 'google')
        request: FastAPI request object
        response: FastAPI response object used to set session-binding cookie
        redirect_uri: Callback URI after successful authentication
        scopes: Optional custom OAuth scopes (space-separated)
        db: Database session

    Returns:
        Authorization URL and state parameter for redirect.

    Raises:
        HTTPException: If SSO is disabled, provider not found, or redirect_uri is invalid

    Examples:
        >>> import asyncio
        >>> asyncio.iscoroutinefunction(initiate_sso_login)
        True
    """
    if not settings.sso_enabled:
        raise HTTPException(status_code=404, detail="SSO authentication is disabled")

    # Validate redirect_uri to prevent open redirect attacks
    # Uses server-side allowlist (allowed_origins, app_domain) - does NOT trust Host header
    if not _validate_redirect_uri(redirect_uri, request):
        # Sanitize untrusted redirect_uri before logging to prevent log injection
        logger.warning(f"SSO login rejected - invalid redirect_uri: {sanitize_for_log(redirect_uri)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid redirect_uri. Must be a relative path or URL matching allowed origins.",
        )

    sso_service = SSOService(db)
    scope_list = scopes.split() if scopes else None
    browser_session_binding = secrets.token_urlsafe(32)

    try:
        auth_url = sso_service.get_authorization_url(provider_id, redirect_uri, scope_list, session_binding=browser_session_binding)
    except ValueError as exc:
        logger.warning(f"OAuth authorization request error: {exc}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid OAuth authorization request") from exc

    if not auth_url:
        raise HTTPException(status_code=404, detail=f"SSO provider '{provider_id}' not found or disabled")

    # Extract state from URL for client reference
    # Standard
    import urllib.parse

    parsed = urllib.parse.urlparse(auth_url)
    params = urllib.parse.parse_qs(parsed.query)
    state = params.get("state", [""])[0]

    use_secure = (settings.environment == "production") or settings.secure_cookies
    response.set_cookie(
        key="sso_session_id",
        value=browser_session_binding,
        httponly=True,
        secure=use_secure,
        samesite=settings.cookie_samesite,
        path=settings.app_root_path or "/",
    )

    return SSOLoginResponse(authorization_url=auth_url, state=state)


@sso_router.get("/callback/{provider_id}")
async def handle_sso_callback(
    provider_id: str,
    # code/state are opaque VSCHAR per RFC 6749 Appendix A.11/A.5 (%x20-7E). Real
    # providers emit chars outside [A-Za-z0-9_-]: Google uses '/', Microsoft uses
    # '!*%', and our own session-bound state uses '.' as a separator
    # (sso_service._STATE_BINDING_SEPARATOR). Bound length only; downstream token
    # exchange and HMAC verification validate integrity.
    code: Optional[str] = Query(None, max_length=4096, description="Authorization code from SSO provider"),
    state: Optional[str] = Query(None, max_length=128, description="CSRF state parameter"),
    # error values are RFC 6749 Section 4.1.2.1 / 5.2 enum-like snake_case tokens
    # (invalid_request, unauthorized_client, access_denied, ...).
    error: QueryErrorCodeSso = None,
    error_description: Optional[str] = Query(None, max_length=500, description="OAuth error description"),
    request: Request = None,
    response: Response = None,
    db: Session = Depends(get_db),
):
    """Handle SSO authentication callback.

    Args:
        provider_id: SSO provider identifier
        code: Authorization code from provider (present on success)
        state: CSRF state parameter for validation
        error: OAuth error code (present on failure)
        error_description: OAuth error description (present on failure)
        request: FastAPI request object
        response: FastAPI response object
        db: Database session

    Returns:
        JWT access token and user information, or redirect to login with error.

    Raises:
        HTTPException: If SSO is disabled or authentication fails

    Examples:
        >>> import asyncio
        >>> asyncio.iscoroutinefunction(handle_sso_callback)
        True
    """
    # Third-Party
    from fastapi.responses import RedirectResponse

    if not settings.sso_enabled:
        raise HTTPException(status_code=404, detail="SSO authentication is disabled")

    # Get root path for URL construction
    root_path = resolve_root_path(request) if request else ""

    # Handle OAuth error responses from provider (RFC 6749 Section 4.1.2.1)
    if error:
        error_msg = error_description or error
        logger.warning("SSO callback error from provider '%s': %s - %s", provider_id, error, error_msg)

        error_mappings = {
            "access_denied": "sso_cancelled",
            "invalid_request": "sso_invalid_request",
            "unauthorized_client": "sso_unauthorized",
            "unsupported_response_type": "sso_config_error",
            "invalid_scope": "sso_invalid_scope",
            "server_error": "sso_server_error",
            "temporarily_unavailable": "sso_unavailable",
        }
        error_code = error_mappings.get(error, "sso_failed")
        return RedirectResponse(url=f"{root_path}/admin/login?error={error_code}", status_code=302)

    # Code and state are required if no error was returned
    if not code:
        logger.warning("SSO callback for provider '%s' missing both code and error parameters", provider_id)
        return RedirectResponse(url=f"{root_path}/admin/login?error=sso_failed", status_code=302)

    if not state:
        logger.warning("SSO callback for provider '%s' missing required state parameter", provider_id)
        return RedirectResponse(url=f"{root_path}/admin/login?error=sso_failed", status_code=302)

    sso_service = SSOService(db)

    # Handle OAuth callback — returns (user_info, token_data) or None
    user_info: Optional[Dict[str, object]] = None
    token_data: Dict[str, object] = {}

    browser_session_binding = request.cookies.get("sso_session_id") if request else None
    if not browser_session_binding:
        return RedirectResponse(url=f"{root_path}/admin/login?error=sso_failed", status_code=302)

    callback_result = await sso_service.handle_oauth_callback_with_tokens(provider_id, code, state, session_binding=browser_session_binding)
    if callback_result:
        user_info, token_data = callback_result

    if not user_info:
        return RedirectResponse(url=f"{root_path}/admin/login?error=sso_failed", status_code=302)

    # Authenticate or create user
    access_token = await sso_service.authenticate_or_create_user(user_info)
    if not access_token:
        return RedirectResponse(url=f"{root_path}/admin/login?error=user_creation_failed", status_code=302)

    # Determine redirect URL based on user's admin status and team membership
    # Decode token to get user info (no verification needed - we just created it)
    try:
        payload = jwt.decode(access_token, options={"verify_signature": False})
        user_data = payload.get("user", {})
        is_admin = user_data.get("is_admin", False)
        user_email = user_data.get("email") or payload.get("email")
    except Exception as e:
        logger.warning(f"Failed to decode SSO token for redirect determination: {e}")
        is_admin = False
        user_email = user_info.get("email")

    # Determine redirect URL
    redirect_url = f"{root_path}/admin"

    # For non-admin users, try to redirect to their first team's admin view
    if not is_admin and user_email:
        try:
            team_service = TeamManagementService(db)
            user_teams = await team_service.get_user_teams(user_email, include_personal=False)

            if user_teams:
                # Redirect to first team's admin view
                # Use first team in list (arbitrary selection - user can switch teams in UI)
                first_team_id = user_teams[0].id
                redirect_url = f"{root_path}/admin?team_id={first_team_id}"
                logger.info(f"Redirecting non-admin SSO user {sanitize_for_log(user_email)} to team-scoped admin: {first_team_id}")
            else:
                # User has no teams - redirect to admin gateways view
                # Redirecting to root (/) would create a loop when Admin UI is enabled,
                # as root redirects back to /admin/. The gateways section is accessible
                # to platform_viewer users (who have gateways.read permission).
                redirect_url = f"{root_path}/admin/#gateways"
                logger.info(f"Redirecting non-admin SSO user {sanitize_for_log(user_email)} with no teams to admin gateways view")
        except Exception as e:
            logger.warning(f"Failed to retrieve teams for SSO user {sanitize_for_log(user_email)}: {e}. Redirecting to /admin")
            # Fall back to /admin - middleware will handle permission check

    # Create redirect response
    redirect_response = RedirectResponse(url=redirect_url, status_code=302)

    # Set secure HTTP-only cookie using the same method as email auth
    # First-Party
    from mcpgateway.utils.security_cookies import CookieTooLargeError, set_auth_cookie

    try:
        set_auth_cookie(redirect_response, access_token, remember_me=False)
    except CookieTooLargeError:
        redirect_response = RedirectResponse(
            url=f"{root_path}/admin/login?error=token_too_large",
            status_code=302,
        )
        return redirect_response

    # Persist Keycloak ID token as short-lived, HTTP-only hint for RP-initiated logout.
    # Without id_token_hint, some Keycloak versions show confirmation and may preserve SSO.
    id_token = token_data.get("id_token")
    if provider_id == "keycloak" and isinstance(id_token, str) and id_token:
        if len(id_token) > 3800:  # Leave room for cookie metadata within browser 4KB limit
            logger.warning("Keycloak id_token too large for cookie storage. RP-initiated logout will not include id_token_hint.")
        else:
            use_secure = (settings.environment == "production") or settings.secure_cookies
            redirect_response.set_cookie(
                key="sso_id_token_hint",
                value=id_token,
                max_age=settings.token_expiry * 60,  # match session token lifetime
                httponly=True,
                secure=use_secure,
                samesite=settings.cookie_samesite,
                path=settings.app_root_path or "/",
            )

    return redirect_response


# Admin endpoints for SSO provider management
@sso_router.post("/admin/providers", response_model=Dict)
@require_permission("admin.sso_providers:create")
async def create_sso_provider(
    provider_data: SSOProviderCreateRequest,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> Dict:
    """Create new SSO provider configuration (Admin only).

    Args:
        provider_data: SSO provider configuration
        db: Database session
        user: Current authenticated user

    Returns:
        Created provider information.

    Raises:
        HTTPException: If provider already exists or creation fails
    """
    sso_service = SSOService(db)

    # Check if provider already exists
    existing = sso_service.get_provider(provider_data.id)
    if existing:
        raise HTTPException(status_code=409, detail=f"SSO provider '{provider_data.id}' already exists")

    try:
        provider = await sso_service.create_provider(provider_data.model_dump())
    except ValueError as exc:
        logger.warning(f"SSO provider create error: {exc}")
        raise HTTPException(status_code=400, detail="Invalid SSO provider configuration") from exc

    result = {
        "id": provider.id,
        "name": provider.name,
        "display_name": provider.display_name,
        "provider_type": provider.provider_type,
        "is_enabled": provider.is_enabled,
        "created_at": provider.created_at,
    }
    db.commit()
    db.close()
    invalidate_trusted_provider_cache()
    await invalidate_external_identity_cache()
    return result


@sso_router.get("/admin/providers", response_model=List[Dict])
@require_permission("admin.sso_providers:read")
async def list_all_sso_providers(
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> List[Dict]:
    """List all SSO providers including disabled ones (Admin only).

    Args:
        db: Database session
        user: Current authenticated user

    Returns:
        List of all SSO providers with configuration details.
    """
    # Third-Party
    from sqlalchemy import select

    # First-Party
    from mcpgateway.db import SSOProvider

    stmt = select(SSOProvider)
    result = db.execute(stmt)
    providers = result.scalars().all()

    result = [
        {
            "id": provider.id,
            "name": provider.name,
            "display_name": provider.display_name,
            "provider_type": provider.provider_type,
            "is_enabled": provider.is_enabled,
            "trusted_domains": provider.trusted_domains,
            "auto_create_users": provider.auto_create_users,
            "trusted_for_api_auth": provider.trusted_for_api_auth,
            "api_audience": provider.api_audience,
            "created_at": provider.created_at,
            "updated_at": provider.updated_at,
        }
        for provider in providers
    ]
    db.commit()
    db.close()
    return result


@sso_router.get("/admin/providers/{provider_id}", response_model=Dict)
@require_permission("admin.sso_providers:read")
async def get_sso_provider(
    provider_id: str,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> Dict:
    """Get SSO provider details (Admin only).

    Args:
        provider_id: Provider identifier
        db: Database session
        user: Current authenticated user

    Returns:
        Provider configuration details.

    Raises:
        HTTPException: If provider not found
    """
    sso_service = SSOService(db)
    provider = sso_service.get_provider(provider_id)

    if not provider:
        raise HTTPException(status_code=404, detail=f"SSO provider '{provider_id}' not found")

    result = {
        "id": provider.id,
        "name": provider.name,
        "display_name": provider.display_name,
        "provider_type": provider.provider_type,
        "client_id": provider.client_id,
        "authorization_url": provider.authorization_url,
        "token_url": provider.token_url,
        "userinfo_url": provider.userinfo_url,
        "issuer": provider.issuer,
        "jwks_uri": provider.jwks_uri,
        "scope": provider.scope,
        "trusted_domains": provider.trusted_domains,
        "auto_create_users": provider.auto_create_users,
        "trusted_for_api_auth": provider.trusted_for_api_auth,
        "api_audience": provider.api_audience,
        "team_mapping": provider.team_mapping,
        "is_enabled": provider.is_enabled,
        "created_at": provider.created_at,
        "updated_at": provider.updated_at,
        "provider_metadata": provider.provider_metadata,
    }
    db.commit()
    db.close()
    return result


@sso_router.put("/admin/providers/{provider_id}", response_model=Dict)
@require_permission("admin.sso_providers:update")
async def update_sso_provider(
    provider_id: str,
    provider_data: SSOProviderUpdateRequest,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> Dict:
    """Update SSO provider configuration (Admin only).

    Args:
        provider_id: Provider identifier
        provider_data: Updated provider configuration
        db: Database session
        user: Current authenticated user

    Returns:
        Updated provider information.

    Raises:
        HTTPException: If provider not found or update fails
    """
    sso_service = SSOService(db)

    # Filter out None values
    update_data = {k: v for k, v in provider_data.model_dump().items() if v is not None}
    if not update_data:
        raise HTTPException(status_code=400, detail="No update data provided")

    try:
        provider = await sso_service.update_provider(provider_id, update_data)
    except ValueError as exc:
        logger.warning(f"SSO provider update error: {exc}")
        raise HTTPException(status_code=400, detail="Invalid SSO provider configuration") from exc

    if not provider:
        raise HTTPException(status_code=404, detail=f"SSO provider '{provider_id}' not found")

    result = {
        "id": provider.id,
        "name": provider.name,
        "display_name": provider.display_name,
        "provider_type": provider.provider_type,
        "is_enabled": provider.is_enabled,
        "updated_at": provider.updated_at,
    }
    db.commit()
    db.close()
    invalidate_trusted_provider_cache()
    await invalidate_external_identity_cache()
    return result


@sso_router.delete("/admin/providers/{provider_id}")
@require_permission("admin.sso_providers:delete")
async def delete_sso_provider(
    provider_id: str,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> Dict:
    """Delete SSO provider configuration (Admin only).

    Args:
        provider_id: Provider identifier
        db: Database session
        user: Current authenticated user

    Returns:
        Deletion confirmation.

    Raises:
        HTTPException: If provider not found
    """
    sso_service = SSOService(db)

    if not sso_service.delete_provider(provider_id):
        raise HTTPException(status_code=404, detail=f"SSO provider '{provider_id}' not found")

    db.commit()
    db.close()
    invalidate_trusted_provider_cache()
    await invalidate_external_identity_cache()
    return {"message": f"SSO provider '{provider_id}' deleted successfully"}


# ---------------------------------------------------------------------------
# SSO User Approval Management Endpoints
# ---------------------------------------------------------------------------


class PendingUserApprovalResponse(BaseModel):
    """Response model for pending user approval."""

    id: str
    email: str
    full_name: str
    auth_provider: str
    requested_at: str
    expires_at: str
    status: str
    sso_metadata: Optional[Dict] = None


class ApprovalActionRequest(BaseModel):
    """Request model for approval actions."""

    action: str  # "approve" or "reject"
    reason: Optional[str] = None  # Required for rejection
    notes: Optional[str] = None


@sso_router.get("/pending-approvals", response_model=List[PendingUserApprovalResponse])
@require_permission("admin.user_management")
async def list_pending_approvals(
    include_expired: bool = Query(False, description="Include expired approval requests"),
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> List[PendingUserApprovalResponse]:
    """List pending SSO user approval requests (Admin only).

    Args:
        include_expired: Whether to include expired requests
        db: Database session
        user: Current authenticated admin user

    Returns:
        List of pending approval requests
    """
    # Third-Party
    from sqlalchemy import select

    # First-Party
    from mcpgateway.db import PendingUserApproval

    query = select(PendingUserApproval)

    if not include_expired:
        # First-Party
        from mcpgateway.db import utc_now

        query = query.where(PendingUserApproval.expires_at > utc_now())

    # Filter by status
    query = query.where(PendingUserApproval.status == "pending")
    query = query.order_by(PendingUserApproval.requested_at.desc())

    result = db.execute(query)
    pending_approvals = result.scalars().all()

    return [
        PendingUserApprovalResponse(
            id=approval.id,
            email=approval.email,
            full_name=approval.full_name,
            auth_provider=approval.auth_provider,
            requested_at=approval.requested_at.isoformat(),
            expires_at=approval.expires_at.isoformat(),
            status=approval.status,
            sso_metadata=approval.sso_metadata,
        )
        for approval in pending_approvals
    ]


@sso_router.post("/pending-approvals/{approval_id}/action")
@require_permission("admin.user_management")
async def handle_approval_request(
    approval_id: str,
    request: ApprovalActionRequest,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> Dict:
    """Approve or reject a pending SSO user registration (Admin only).

    Args:
        approval_id: ID of the approval request
        request: Approval action (approve/reject) with optional reason/notes
        db: Database session
        user: Current authenticated admin user

    Returns:
        Action confirmation message

    Raises:
        HTTPException: If approval not found or invalid action
    """
    # Third-Party
    from sqlalchemy import select

    # First-Party
    from mcpgateway.db import PendingUserApproval

    # Get pending approval
    approval = db.execute(select(PendingUserApproval).where(PendingUserApproval.id == approval_id)).scalar_one_or_none()

    if not approval:
        raise HTTPException(status_code=404, detail="Approval request not found")

    if approval.status != "pending":
        raise HTTPException(status_code=400, detail=f"Approval request is already {approval.status}")

    if approval.is_expired():
        approval.status = "expired"
        db.commit()
        raise HTTPException(status_code=400, detail="Approval request has expired")

    admin_email = user["email"]

    if request.action == "approve":
        approval.approve(admin_email, request.notes)
        db.commit()
        return {"message": f"User {approval.email} approved successfully"}

    elif request.action == "reject":
        if not request.reason:
            raise HTTPException(status_code=400, detail="Rejection reason is required")
        approval.reject(admin_email, request.reason, request.notes)
        db.commit()
        return {"message": f"User {approval.email} rejected"}

    else:
        raise HTTPException(status_code=400, detail="Invalid action. Must be 'approve' or 'reject'")
