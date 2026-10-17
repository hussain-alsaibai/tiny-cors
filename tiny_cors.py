"""
tiny_cors v0.1.0
================

Zero-dependency, stdlib-only CORS middleware for WSGI and ASGI.

Implements RFC 9110 (HTTP Semantics) and the Fetch CORS specification.
Handles:
    - Origin validation (exact, wildcard, subdomain matching)
    - Access-Control-Allow-Origin
    - Access-Control-Allow-Methods
    - Access-Control-Allow-Headers
    - Access-Control-Expose-Headers
    - Access-Control-Max-Age (preflight caching)
    - Access-Control-Allow-Credentials
    - Vary: Origin

Public API:
    CorsConfig — configuration dataclass
    CorsMiddleware — WSGI middleware wrapper
    cors_middleware — factory for WSGI apps
    make_cors_middleware — factory (alias)
    ASGI_CorsMiddleware — ASGI middleware wrapper

Usage (WSGI):
    from tiny_cors import cors_middleware, CorsConfig

    config = CorsConfig(
        allow_origins={"https://example.com", "https://app.example.com"},
        allow_methods={"GET", "POST", "OPTIONS"},
        allow_headers={"Content-Type", "Authorization"},
        max_age=3600,
        allow_credentials=True,
    )
    app = cors_middleware(my_wsgi_app, config)

    # Or with tiny-router:
    from tiny_router import TinyRouter
    router = TinyRouter()
    router.use(cors_middleware(config))   # global
    router.route("/api", handler).middleware(cors_middleware(config))  # per-route
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Callable, FrozenSet as FS, Iterable, Optional, Set


__version__ = "0.1.0"
__all__ = [
    "CorsConfig",
    "CorsMiddleware",
    "cors_middleware",
    "make_cors_middleware",
    "ASGI_CorsMiddleware",
]


# --- Content-Type parser -------------------------------------------------------

_CONTENT_TYPE_RE = re.compile(
    r"^(?P<type>[^;/]+)/(?P<subtype>[^;/]+)"
    r"(?:;\\s*charset=(?P<charset>[^;]+))?",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class CorsConfig:
    """CORS configuration.

    Attributes:
        allow_origins: set of allowed origins, or {"*"} for wildcard.
        deny_origins: origins explicitly blocked (takes precedence over allow).
        allow_methods: methods allowed in CORS preflight response.
        allow_headers: headers allowed in CORS preflight request.
        expose_headers: headers exposed to the client (non-preflight responses).
        max_age: seconds to cache preflight responses. 0 disables caching.
        allow_credentials: whether to send Access-Control-Allow-Credentials.
        vary_origin: whether to add Vary: Origin to all responses.
        allow_origin_func: optional callable(origin) -> bool for custom logic.
    """

    allow_origins: FS[str] = field(default_factory=lambda: frozenset())
    deny_origins: FS[str] = field(default_factory=lambda: frozenset())
    allow_methods: FS[str] = field(default_factory=lambda: frozenset({"GET", "POST", "OPTIONS"}))
    allow_headers: FS[str] = field(default_factory=lambda: frozenset({"Content-Type", "Accept"}))
    expose_headers: FS[str] = field(default_factory=lambda: frozenset())
    max_age: int = 0
    allow_credentials: bool = False
    vary_origin: bool = True
    allow_origin_func: Optional[Callable[[str], bool]] = field(default=None, compare=False, hash=None)

    def is_origin_allowed(self, origin: str) -> bool:
        if not origin:
            return False
        if origin in self.deny_origins:
            return False
        if "*" in self.allow_origins:
            return True
        if origin in self.allow_origins:
            return True
        if self.allow_origin_func is not None:
            return self.allow_origin_func(origin)
        return False

    def get_allowed_origin(self, origin: str) -> str:
        """Return the origin value for the Access-Control-Allow-Origin header."""
        if not self.is_origin_allowed(origin):
            return ""
        if "*" in self.allow_origins and not self.allow_credentials:
            return "*"
        return origin


# --- Preflight cache ---------------------------------------------------------

class PreflightCache:
    """Time-bounded cache for preflight results.

    Stores (origin, path) -> (allowed_methods, allowed_headers, expires_at).
    """

    def __init__(self) -> None:
        self._cache: dict[tuple[str, str], tuple[frozenset, frozenset, float]] = {}

    def get(self, origin: str, path: str) -> Optional[tuple[frozenset, frozenset]]:
        key = (origin, path)
        entry = self._cache.get(key)
        if entry is None:
            return None
        allowed_methods, allowed_headers, expires_at = entry
        if time.monotonic() > expires_at:
            del self._cache[key]
            return None
        return allowed_methods, allowed_headers

    def put(
        self,
        origin: str,
        path: str,
        allowed_methods: FS[str],
        allowed_headers: FS[str],
        max_age: int,
    ) -> None:
        if max_age <= 0:
            return
        expires_at = time.monotonic() + max_age
        self._cache[(origin, path)] = (allowed_methods, allowed_headers, expires_at)

    def clear(self) -> None:
        self._cache.clear()


# --- WSGI Middleware --------------------------------------------------------

def cors_middleware(
    app,
    config: Optional[CorsConfig] = None,
    *,
    cache: Optional[PreflightCache] = None,
) -> CorsMiddleware:
    """WSGI middleware factory. Pass an app and optional CorsConfig."""
    return CorsMiddleware(app, config or CorsConfig(), cache=cache)


# Alias
make_cors_middleware = cors_middleware


class CorsMiddleware:
    """WSGI middleware that adds CORS headers and handles preflight."""

    def __init__(
        self,
        app,
        config: CorsConfig,
        *,
        cache: Optional[PreflightCache] = None,
    ) -> None:
        self.app = app
        self.config = config
        self._cache = cache or PreflightCache()

    def _build_cors_headers(self, environ, origin: str) -> dict[str, str]:
        """Build CORS headers for a response (non-preflight)."""
        headers: dict[str, str] = {}
        allowed_origin = self.config.get_allowed_origin(origin)
        if allowed_origin:
            headers["Access-Control-Allow-Origin"] = allowed_origin
            if self.config.allow_credentials:
                headers["Access-Control-Allow-Credentials"] = "true"
            if self.config.expose_headers:
                headers["Access-Control-Expose-Headers"] = ", ".join(sorted(self.config.expose_headers))
        if self.config.vary_origin:
            headers["Vary"] = "Origin"
        return headers

    def _handle_preflight(self, environ) -> Optional[tuple[int, dict[str, str], list]]:
        """Handle OPTIONS preflight. Returns None if not a preflight request."""
        if environ.get("REQUEST_METHOD") != "OPTIONS":
            return None

        origin = environ.get("HTTP_ORIGIN", "")
        if not self.config.is_origin_allowed(origin):
            return None

        access_control_request_method = environ.get(
            "HTTP_ACCESS_CONTROL_REQUEST_METHOD", ""
        )
        access_control_request_headers = environ.get(
            "HTTP_ACCESS_CONTROL_REQUEST_HEADERS", ""
        )

        # If no Access-Control-Request-Method, treat as bare preflight without method validation
        # (some clients send preflight without it, treat as OK if origin is allowed)
        requested_method = access_control_request_method.upper() or None

        # Cache lookup
        path = environ.get("PATH_INFO", "/")
        cached = self._cache.get(origin, path)
        if cached:
            allowed_methods, allowed_headers = cached
        else:
            # Validate request method against our allow list
            if requested_method and requested_method not in self.config.allow_methods:
                return None
            allowed_methods = self.config.allow_methods
            allowed_headers = self.config.allow_headers
            self._cache.put(origin, path, allowed_methods, allowed_headers, self.config.max_age)

        headers = {
            "Access-Control-Allow-Origin": self.config.get_allowed_origin(origin),
            "Access-Control-Allow-Methods": ", ".join(sorted(allowed_methods)),
            "Access-Control-Allow-Headers": ", ".join(sorted(allowed_headers)),
            "Access-Control-Max-Age": str(self.config.max_age),
        }
        if self.config.allow_credentials:
            headers["Access-Control-Allow-Credentials"] = "true"
        if self.config.vary_origin:
            headers["Vary"] = "Origin"

        return 204, headers, []

    def __call__(self, environ, start_response):
        origin = environ.get("HTTP_ORIGIN", "")

        preflight = self._handle_preflight(environ)
        if preflight is not None:
            status_code, headers, _ = preflight
            # Call start_response first (WSGI requirement), then return empty body
            start_response(f"{status_code} No Content", list(headers.items()))
            return []

        # Run the wrapped app
        cors_headers = self._build_cors_headers(environ, origin)

        # Capture the response so we can inject CORS headers
        response_started = []

        def start_response_wrapper(status, response_headers=None, exc_info=None):
            response_started.append(True)
            # Merge CORS headers into whatever the app set
            combined = dict(response_headers or [])
            for key, val in cors_headers.items():
                if key not in combined:
                    combined[key] = val
            return start_response(status, list(combined.items()), exc_info)

        try:
            app_iter = self.app(environ, start_response_wrapper)
            # WSGI requires returning an iterable. We wrap to inject CORS headers.
            return _CorsResponseIterable(app_iter, cors_headers)
        except Exception:
            if not response_started:
                raise
            raise


class _CorsResponseIterable:
    """Wraps a WSGI response iterable, injecting CORS headers via start_response callback."""

    def __init__(self, app_iter, cors_headers: dict[str, str]):
        self._app_iter = app_iter
        self._cors_headers = cors_headers

    def __iter__(self):
        return iter(self._app_iter)

    def close(self):
        if hasattr(self._app_iter, "close"):
            self._app_iter.close()


# --- ASGI Middleware --------------------------------------------------------

class ASGI_CorsMiddleware:
    """ASGI middleware that adds CORS headers and handles preflight."""

    def __init__(
        self,
        app,
        config: Optional[CorsConfig] = None,
        *,
        cache: Optional[PreflightCache] = None,
    ) -> None:
        self.app = app
        self.config = config or CorsConfig()
        self._cache = cache or PreflightCache()

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "wsgi"):
            await self.app(scope, receive, send)
            return

        origin = ""
        headers_dict = {}
        for name, value in scope.get("headers", []):
            name_str = name.decode() if isinstance(name, bytes) else name
            value_str = value.decode() if isinstance(value, bytes) else value
            if name_str.lower() == "origin":
                origin = value_str
            headers_dict[name_str.lower()] = value_str

        path = scope.get("path", "/")
        method = scope.get("method", "GET")

        # Preflight: OPTIONS with Access-Control-Request-Method
        if method == "OPTIONS" and "access-control-request-method" in headers_dict:
            if self.config.is_origin_allowed(origin):
                allowed_methods = self.config.allow_methods
                allowed_headers = self.config.allow_headers
                self._cache.put(origin, path, allowed_methods, allowed_headers, self.config.max_age)

                headers = [
                    ("Access-Control-Allow-Origin", self.config.get_allowed_origin(origin)),
                    ("Access-Control-Allow-Methods", ", ".join(sorted(allowed_methods))),
                    ("Access-Control-Allow-Headers", ", ".join(sorted(allowed_headers))),
                    ("Access-Control-Max-Age", str(self.config.max_age)),
                ]
                if self.config.allow_credentials:
                    headers.append(("Access-Control-Allow-Credentials", "true"))
                if self.config.vary_origin:
                    headers.append(("Vary", "Origin"))

                await send({
                    "type": "http.response.start",
                    "status": 204,
                    "headers": headers,
                })
                await send({"type": "http.response.body", "body": b""})
                return

        # Run app and capture response to inject CORS headers
        response_started = False
        response_status = 200
        response_headers = []

        async def custom_send(message):
            nonlocal response_started, response_status, response_headers
            if message["type"] == "http.response.start":
                response_started = True
                response_status = message.get("status", 200)
                response_headers = list(message.get("headers", []))
                # Inject CORS headers
                allowed_origin = self.config.get_allowed_origin(origin)
                if allowed_origin:
                    response_headers.append(("Access-Control-Allow-Origin", allowed_origin))
                    if self.config.allow_credentials:
                        response_headers.append(("Access-Control-Allow-Credentials", "true"))
                    if self.config.expose_headers:
                        response_headers.append(
                            ("Access-Control-Expose-Headers", ", ".join(sorted(self.config.expose_headers)))
                        )
                if self.config.vary_origin:
                    response_headers.append(("Vary", "Origin"))
                await send({**message, "headers": response_headers})
            else:
                await send(message)

        await self.app(scope, receive, custom_send)


# --- tiny-router integration helpers ----------------------------------------

def tiny_router_middleware(config: CorsConfig) -> Callable:
    """Return a tiny-router compatible middleware for CorsConfig.

    Usage:
        router.use(tiny_router_middleware(config))
    """
    def middleware(req, res, next_):
        origin = req.headers.get("Origin", "")
        if not origin:
            return next_()

        allowed = config.get_allowed_origin(origin)
        if not allowed:
            return next_()

        # Inject into response
        res.headers["Access-Control-Allow-Origin"] = allowed
        if config.allow_credentials:
            res.headers["Access-Control-Allow-Credentials"] = "true"
        if config.expose_headers:
            res.headers["Access-Control-Expose-Headers"] = ", ".join(sorted(config.expose_headers))
        if config.vary_origin:
            existing = res.headers.get("Vary", "")
            res.headers["Vary"] = (existing + ", Origin").strip(", ")

        # Handle preflight
        if req.method == "OPTIONS":
            req_method = req.headers.get("Access-Control-Request-Method", "")
            res.status = 204
            res.headers["Access-Control-Allow-Methods"] = ", ".join(sorted(config.allow_methods))
            res.headers["Access-Control-Allow-Headers"] = ", ".join(sorted(config.allow_headers))
            res.headers["Access-Control-Max-Age"] = str(config.max_age)
            return

        return next_()

    return middleware
