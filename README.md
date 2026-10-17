# tiny-cors

**Zero-dependency, stdlib-only RFC-compliant CORS middleware for WSGI and ASGI.**

Stdlib only. MIT licensed. ~530 LOC.

```bash
pip install tiny-cors
```

---

## Why

CORS is everywhere. Every web API that serves a browser frontend needs it. Most CORS libraries either require Flask/Django/FastAPI, pull in httpx, or ship a 2000-line framework. `tiny-cors` is the 500-line WSGI/ASGI middleware that handles the Fetch CORS spec correctly — preflight caching, Vary: Origin, credentials rules, subdomain matching — without any dependencies.

---

## Supported features

- RFC 9110 / Fetch CORS spec compliance
- Wildcard (`*`) origin (with automatic `Access-Control-Allow-Credentials` restrictions)
- Subdomain and custom origin validation via callable
- Preflight response caching (`Access-Control-Max-Age`)
- Vary: Origin header on all responses
- `Access-Control-Allow-Credentials` support
- `Access-Control-Expose-Headers`
- Per-route and global middleware patterns
- WSGI and ASGI adapters
- `tiny-router` integration helper

---

## Quick start

```python
from tiny_cors import cors_middleware, CorsConfig

config = CorsConfig(
    allow_origins={"https://app.example.com", "https://admin.example.com"},
    allow_methods={"GET", "POST", "PUT", "DELETE", "OPTIONS"},
    allow_headers={"Content-Type", "Authorization", "X-Request-ID"},
    expose_headers={"X-Request-ID"},
    max_age=3600,
    allow_credentials=True,
)

app = cors_middleware(my_wsgi_app, config)
```

---

## Preflight caching

`Access-Control-Max-Age` is supported via an in-memory time-bounded cache. Multiple concurrent requests to the same `(origin, path)` are served from cache until expiry.

```python
config = CorsConfig(max_age=86400)  # cache preflight for 24h
```

---

## Tiny-router integration

```python
from tiny_router import TinyRouter
from tiny_cors import CorsConfig, tiny_router_middleware

router = TinyRouter()
cors = CorsConfig(allow_origins={"https://example.com"})

router.use(tiny_router_middleware(cors))   # global CORS
router.route("/api", handler)             # API routes
```

---

## ASGI usage

```python
from tiny_cors import ASGI_CorsMiddleware, CorsConfig

config = CorsConfig(allow_origins={"https://example.com"})
app = ASGI_CorsMiddleware(asgi_app, config)
```

---

## Public API

```python
CorsConfig(
    allow_origins=FrozenSet[str],      # empty = deny all
    deny_origins=FrozenSet[str],
    allow_methods=FrozenSet[str]={"GET", "POST", "OPTIONS"},
    allow_headers=FrozenSet[str]={"Content-Type", "Accept"},
    expose_headers=FrozenSet[str],
    max_age=int=0,
    allow_credentials=False,
    vary_origin=True,
    allow_origin_func=Callable[[str], bool] | None,
)

cors_middleware(app, config) -> CorsMiddleware
make_cors_middleware = cors_middleware
ASGI_CorsMiddleware(app, config) -> ASGI middleware
tiny_router_middleware(config) -> tiny-router compatible middleware
PreflightCache
```
