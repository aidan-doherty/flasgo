from __future__ import annotations

from urllib.parse import urlsplit

from .request import Request
from .response import Response


def canonical_origin(value: str) -> str | None:
    """Normalize an exact http(s) origin to ``scheme://host`` or ``scheme://host:port``.

    Returns None for malformed origins and for values that include a path, query,
    fragment, or embedded credentials. CORS origin matching is intentionally exact
    so a hostile page can never trick the allowlist into a prefix match.
    """

    try:
        parsed = urlsplit(value.strip())
        port = parsed.port
    except ValueError:
        return None
    scheme = parsed.scheme.lower()
    if (
        scheme not in {"http", "https"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        return None
    default_port = 443 if scheme == "https" else 80
    if port is not None and port != default_port:
        return f"{scheme}://{parsed.hostname.lower()}:{port}"
    return f"{scheme}://{parsed.hostname.lower()}"


def allowed_origin(
    request_origin: str,
    *,
    allowed_origins: set[str],
    allow_credentials: bool,
) -> str | None:
    """Return the ``Access-Control-Allow-Origin`` header value for a request, or None when denied.

    A literal ``*`` entry only matches when credentials are disabled; browsers reject a
    credentialed ``*`` response, so Flasgo refuses to emit it. When allowed, the exact
    requesting origin is echoed back so credentialed requests never fall back to ``*``.
    """

    candidate = canonical_origin(request_origin)
    if candidate is None:
        return None
    if "*" in allowed_origins and not allow_credentials:
        return "*"
    for pattern in allowed_origins:
        if pattern == "*":
            continue
        if canonical_origin(pattern) == candidate:
            return candidate
    return None


def is_cors_preflight(req: Request) -> bool:
    return req.method == "OPTIONS" and req.headers.get("access-control-request-method") is not None


def requested_headers_allowed(request_headers: str | None, *, allowed_headers: set[str]) -> bool:
    """Return True when every requested preflight header is in the allowlist.

    Header names are compared case-insensitively per the CORS specification.
    """

    if request_headers is None:
        return True
    normalized_allowed = {header.strip().lower() for header in allowed_headers}
    for raw in request_headers.split(","):
        header = raw.strip().lower()
        if not header:
            continue
        if header not in normalized_allowed:
            return False
    return True


def build_cors_preflight_response(
    *,
    allow_methods: set[str],
    allow_headers: set[str],
    allow_credentials: bool,
    max_age: int,
) -> Response:
    """Build a ``204 No Content`` preflight response advertising the allowed CORS surface."""

    headers: dict[str, str] = {
        "access-control-allow-methods": ", ".join(sorted(method.upper() for method in allow_methods)),
        "vary": "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
    }
    if allow_headers:
        headers["access-control-allow-headers"] = ", ".join(sorted(allow_headers))
    if allow_credentials:
        headers["access-control-allow-credentials"] = "true"
    if max_age > 0:
        headers["access-control-max-age"] = str(max_age)
    return Response(body=b"", status_code=204, headers=headers)


def apply_cors_headers(
    response: Response,
    *,
    allow_origin: str,
    allow_credentials: bool,
    expose_headers: set[str] | None = None,
) -> None:
    """Attach CORS response headers to an already-produced response."""

    response.headers["access-control-allow-origin"] = allow_origin
    if allow_credentials:
        response.headers["access-control-allow-credentials"] = "true"
    if expose_headers:
        response.headers["access-control-expose-headers"] = ", ".join(sorted(expose_headers))
    _merge_vary(response.headers, "Origin")


def _merge_vary(headers: dict[str, str], token: str) -> None:
    current = headers.get("vary")
    tokens = {part.strip() for part in current.split(",")} if current else set()
    tokens.add(token)
    headers["vary"] = ", ".join(sorted(tokens))
