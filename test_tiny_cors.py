"""Tests for tiny_cors v0.1.0."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tiny_cors import (
    ASGI_CorsMiddleware,
    CorsConfig,
    CorsMiddleware,
    PreflightCache,
    cors_middleware,
    make_cors_middleware,
    tiny_router_middleware,
)


class TestCorsConfig(unittest.TestCase):
    def test_default_config(self):
        c = CorsConfig()
        self.assertFalse(c.is_origin_allowed("https://example.com"))
        self.assertEqual(c.get_allowed_origin("https://example.com"), "")

    def test_exact_origin_allowed(self):
        c = CorsConfig(allow_origins=frozenset({"https://example.com"}))
        self.assertTrue(c.is_origin_allowed("https://example.com"))
        self.assertFalse(c.is_origin_allowed("https://other.com"))
        self.assertEqual(c.get_allowed_origin("https://example.com"), "https://example.com")

    def test_wildcard_origin(self):
        c = CorsConfig(allow_origins=frozenset({"*"}))
        self.assertTrue(c.is_origin_allowed("https://anything.com"))
        self.assertEqual(c.get_allowed_origin("https://anything.com"), "*")

    def test_wildcard_with_credentials_returns_origin(self):
        c = CorsConfig(allow_origins=frozenset({"*"}), allow_credentials=True)
        # Wildcard + credentials: must return specific origin, not *
        self.assertEqual(c.get_allowed_origin("https://example.com"), "https://example.com")

    def test_deny_takes_precedence(self):
        c = CorsConfig(
            allow_origins=frozenset({"https://example.com"}),
            deny_origins=frozenset({"https://example.com"}),
        )
        self.assertFalse(c.is_origin_allowed("https://example.com"))

    def test_custom_origin_func(self):
        def allow_all_subdomains(origin):
            return origin.endswith(".example.com")
        c = CorsConfig(allow_origin_func=allow_all_subdomains)
        self.assertTrue(c.is_origin_allowed("https://app.example.com"))
        self.assertFalse(c.is_origin_allowed("https://evil.com"))

    def test_empty_origin_not_allowed(self):
        c = CorsConfig(allow_origins=frozenset({"*"}))
        self.assertFalse(c.is_origin_allowed(""))

    def test_get_allowed_origin_denied(self):
        c = CorsConfig(allow_origins=frozenset({"https://example.com"}))
        self.assertEqual(c.get_allowed_origin("https://evil.com"), "")


class TestPreflightCache(unittest.TestCase):
    def test_cache_miss_returns_none(self):
        cache = PreflightCache()
        self.assertIsNone(cache.get("https://example.com", "/api"))

    def test_cache_put_and_get(self):
        cache = PreflightCache()
        methods = frozenset({"GET", "POST"})
        headers = frozenset({"Content-Type"})
        cache.put("https://example.com", "/api", methods, headers, max_age=60)
        result = cache.get("https://example.com", "/api")
        self.assertIsNotNone(result)
        allowed_methods, allowed_headers = result
        self.assertEqual(allowed_methods, methods)
        self.assertEqual(allowed_headers, headers)

    def test_cache_expiry(self):
        cache = PreflightCache()
        cache.put("https://example.com", "/api", frozenset(), frozenset(), max_age=0)
        self.assertIsNone(cache.get("https://example.com", "/api"))

    def test_cache_clear(self):
        cache = PreflightCache()
        cache.put("https://example.com", "/api", frozenset(), frozenset(), max_age=3600)
        cache.clear()
        self.assertIsNone(cache.get("https://example.com", "/api"))


class TestCorsMiddlewareIntegration(unittest.TestCase):
    """Integration tests using a minimal WSGI app."""

    def _make_app(self, status="200 OK", body=b"Hello", extra_headers=None):
        extra_headers = extra_headers or []
        def app(environ, start_response):
            start_response(status, [("Content-Type", "text/plain")] + extra_headers)
            return [body]
        return app

    def _call_middleware(self, middleware, method="GET", path="/", origin=""):
        environ = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "HTTP_ORIGIN": origin,
            "HTTP_ACCESS_CONTROL_REQUEST_METHOD": "",
            "HTTP_ACCESS_CONTROL_REQUEST_HEADERS": "",
        }
        responses = {}
        def start_response(status, response_headers=None, exc_info=None):
            responses["status"] = status
            responses["headers"] = dict(response_headers or [])
        try:
            result = middleware(environ, start_response)
            list(result)  # consume
        except Exception:
            pass
        return responses

    def test_non_cors_request_passes_through(self):
        c = CorsConfig(allow_origins=frozenset({"https://example.com"}))
        app = self._make_app()
        middleware = CorsMiddleware(app, c)
        responses = self._call_middleware(middleware, origin="")
        self.assertEqual(responses.get("status"), "200 OK")
        self.assertNotIn("Access-Control-Allow-Origin", responses.get("headers", {}))

    def test_allowed_origin_gets_cors_headers(self):
        c = CorsConfig(allow_origins=frozenset({"https://example.com"}))
        app = self._make_app()
        middleware = CorsMiddleware(app, c)
        responses = self._call_middleware(middleware, origin="https://example.com")
        self.assertEqual(
            responses.get("headers", {}).get("Access-Control-Allow-Origin"),
            "https://example.com"
        )
        self.assertEqual(responses.get("headers", {}).get("Vary"), "Origin")

    def test_disallowed_origin_no_cors_headers(self):
        c = CorsConfig(allow_origins=frozenset({"https://example.com"}))
        app = self._make_app()
        middleware = CorsMiddleware(app, c)
        responses = self._call_middleware(middleware, origin="https://evil.com")
        self.assertNotIn("Access-Control-Allow-Origin", responses.get("headers", {}))

    def test_credentials_header(self):
        c = CorsConfig(
            allow_origins=frozenset({"https://example.com"}),
            allow_credentials=True,
        )
        app = self._make_app()
        middleware = CorsMiddleware(app, c)
        responses = self._call_middleware(middleware, origin="https://example.com")
        self.assertEqual(
            responses.get("headers", {}).get("Access-Control-Allow-Credentials"),
            "true"
        )

    def test_expose_headers(self):
        c = CorsConfig(
            allow_origins=frozenset({"https://example.com"}),
            expose_headers=frozenset({"X-Request-ID", "X-Rate-Limit"}),
        )
        app = self._make_app()
        middleware = CorsMiddleware(app, c)
        responses = self._call_middleware(middleware, origin="https://example.com")
        self.assertEqual(
            responses.get("headers", {}).get("Access-Control-Expose-Headers"),
            "X-Rate-Limit, X-Request-ID"
        )

    def test_vary_origin_false(self):
        c = CorsConfig(
            allow_origins=frozenset({"https://example.com"}),
            vary_origin=False,
        )
        app = self._make_app()
        middleware = CorsMiddleware(app, c)
        responses = self._call_middleware(middleware, origin="https://example.com")
        self.assertNotIn("Vary", responses.get("headers", {}))

    def test_preflight_options(self):
        c = CorsConfig(
            allow_origins=frozenset({"https://example.com"}),
            allow_methods=frozenset({"GET", "POST", "OPTIONS"}),
            allow_headers=frozenset({"Content-Type", "Authorization"}),
            max_age=3600,
        )
        app = self._make_app()
        middleware = CorsMiddleware(app, c)
        environ = {
            "REQUEST_METHOD": "OPTIONS",
            "PATH_INFO": "/api",
            "HTTP_ORIGIN": "https://example.com",
            "HTTP_ACCESS_CONTROL_REQUEST_METHOD": "POST",
            "HTTP_ACCESS_CONTROL_REQUEST_HEADERS": "Content-Type",
        }
        responses = {}
        def start_response(status, response_headers=None, exc_info=None):
            responses["status"] = status
            responses["headers"] = dict(response_headers or [])
        result = middleware(environ, start_response)
        list(result)
        self.assertIn("204", responses.get("status", ""))
        self.assertEqual(
            responses.get("headers", {}).get("Access-Control-Allow-Origin"),
            "https://example.com"
        )


class TestCorsMiddlewareFactory(unittest.TestCase):
    def test_cors_middleware_factory(self):
        c = CorsConfig(allow_origins=frozenset({"*"}))
        def dummy_app(environ, start_response):
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [b"OK"]
        m = cors_middleware(dummy_app, c)
        self.assertIsInstance(m, CorsMiddleware)

    def test_make_cors_middleware_alias(self):
        self.assertIs(make_cors_middleware, cors_middleware)


class TestTinyRouterMiddleware(unittest.TestCase):
    def test_tiny_router_middleware_returns_callable(self):
        c = CorsConfig(allow_origins=frozenset({"*"}))
        mw = tiny_router_middleware(c)
        self.assertTrue(callable(mw))


class TestConfigRepr(unittest.TestCase):
    def test_repr_shows_key_fields(self):
        c = CorsConfig(allow_origins=frozenset({"https://example.com"}))
        r = repr(c)
        self.assertIn("https://example.com", r)
        self.assertIn("CorsConfig", r)


if __name__ == "__main__":
    unittest.main(verbosity=2)
