from __future__ import annotations

from collections.abc import Mapping

import pytest
from flasgo import Flasgo

ORIGIN = "https://app.example.com"


def _cors_app(**overrides: object) -> Flasgo:
    settings: dict[str, object] = {
        "CORS_ENABLED": True,
        "CORS_ALLOWED_ORIGINS": {ORIGIN},
        **overrides,
    }
    app = Flasgo(settings=settings)

    @app.get("/data")
    def data() -> dict[str, str]:
        return {"ok": "true"}

    @app.post("/submit")
    def submit() -> dict[str, str]:
        return {"accepted": "true"}

    return app


def _cors_headers(response_headers: Mapping[str, str]) -> dict[str, str]:
    return {key: value for key, value in response_headers.items() if key.startswith("access-control-")}


def test_cors_disabled_by_default() -> None:
    app = Flasgo()

    @app.get("/data")
    def data() -> dict[str, str]:
        return {"ok": "true"}

    client = app.test_client()
    response = client.get("/data", headers={"origin": ORIGIN})

    assert response.status_code == 200
    assert _cors_headers(response.headers) == {}


def test_simple_request_echoes_allowed_origin() -> None:
    client = _cors_app().test_client()
    response = client.get("/data", headers={"origin": ORIGIN})

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == ORIGIN
    assert "origin" in response.headers["vary"].lower()
    assert "access-control-allow-credentials" not in response.headers


def test_simple_request_from_denied_origin_gets_no_headers() -> None:
    client = _cors_app().test_client()
    response = client.get("/data", headers={"origin": "https://evil.example.com"})

    assert response.status_code == 200
    assert _cors_headers(response.headers) == {}


def test_simple_request_without_origin_gets_no_headers() -> None:
    client = _cors_app().test_client()
    response = client.get("/data")

    assert response.status_code == 200
    assert _cors_headers(response.headers) == {}


def test_preflight_from_allowed_origin() -> None:
    client = _cors_app().test_client()
    response = client.request(
        "OPTIONS",
        "/submit",
        headers={
            "origin": ORIGIN,
            "access-control-request-method": "POST",
            "access-control-request-headers": "x-csrf-token, content-type",
        },
    )

    assert response.status_code == 204
    assert response.headers["access-control-allow-origin"] == ORIGIN
    assert "POST" in response.headers["access-control-allow-methods"]
    assert "x-csrf-token" in response.headers["access-control-allow-headers"].lower()
    assert "origin" in response.headers["vary"].lower()
    assert "access-control-request-method" in response.headers["vary"].lower()
    assert "access-control-request-headers" in response.headers["vary"].lower()


def test_preflight_from_denied_origin_rejected() -> None:
    client = _cors_app().test_client()
    response = client.request(
        "OPTIONS",
        "/submit",
        headers={"origin": "https://evil.example.com", "access-control-request-method": "POST"},
    )

    assert response.status_code == 403
    assert _cors_headers(response.headers) == {}


def test_preflight_with_denied_method_rejected() -> None:
    client = _cors_app(CORS_ALLOWED_METHODS={"GET", "POST"}).test_client()
    response = client.request(
        "OPTIONS",
        "/submit",
        headers={"origin": ORIGIN, "access-control-request-method": "PATCH"},
    )

    assert response.status_code == 403
    assert _cors_headers(response.headers) == {}


def test_preflight_with_denied_header_rejected() -> None:
    client = _cors_app().test_client()
    response = client.request(
        "OPTIONS",
        "/submit",
        headers={
            "origin": ORIGIN,
            "access-control-request-method": "POST",
            "access-control-request-headers": "x-secret-header",
        },
    )

    assert response.status_code == 403
    assert _cors_headers(response.headers) == {}


def test_preflight_answers_before_route_matching() -> None:
    client = _cors_app().test_client()

    missing = client.request(
        "OPTIONS",
        "/does-not-exist",
        headers={"origin": ORIGIN, "access-control-request-method": "GET"},
    )
    post_only = client.request(
        "OPTIONS",
        "/submit",
        headers={"origin": ORIGIN, "access-control-request-method": "POST"},
    )

    assert missing.status_code == 204
    assert post_only.status_code == 204


def test_credentials_mode_echoes_exact_origin() -> None:
    client = _cors_app(CORS_ALLOW_CREDENTIALS=True).test_client()
    response = client.get("/data", headers={"origin": ORIGIN})

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == ORIGIN
    assert response.headers["access-control-allow-credentials"] == "true"


def test_wildcard_origin_without_credentials() -> None:
    client = _cors_app(CORS_ALLOWED_ORIGINS={"*"}).test_client()
    response = client.get("/data", headers={"origin": ORIGIN})

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "*"


def test_wildcard_with_credentials_rejected_at_startup() -> None:
    with pytest.raises(ValueError, match="CORS_ALLOW_CREDENTIALS"):
        _cors_app(CORS_ALLOWED_ORIGINS={"*"}, CORS_ALLOW_CREDENTIALS=True)


def test_invalid_origin_format_rejected_at_startup() -> None:
    with pytest.raises(ValueError, match="CORS_ALLOWED_ORIGINS"):
        _cors_app(CORS_ALLOWED_ORIGINS={"https://app.example.com/path"})


def test_expose_headers_added() -> None:
    client = _cors_app(CORS_EXPOSE_HEADERS={"x-total-count"}).test_client()
    response = client.get("/data", headers={"origin": ORIGIN})

    assert response.status_code == 200
    assert response.headers["access-control-expose-headers"] == "x-total-count"


def test_preflight_includes_max_age_when_configured() -> None:
    client = _cors_app(CORS_MAX_AGE=120).test_client()
    response = client.request(
        "OPTIONS",
        "/submit",
        headers={"origin": ORIGIN, "access-control-request-method": "POST"},
    )

    assert response.status_code == 204
    assert response.headers["access-control-max-age"] == "120"


def test_error_responses_carry_cors_headers() -> None:
    client = _cors_app().test_client()
    response = client.get("/does-not-exist", headers={"origin": ORIGIN})

    assert response.status_code == 404
    assert response.headers["access-control-allow-origin"] == ORIGIN


def test_csrf_still_enforced_for_cross_origin_unsafe_request() -> None:
    client = _cors_app().test_client()
    response = client.post("/submit", headers={"origin": ORIGIN})

    assert response.status_code == 403
