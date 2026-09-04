"""Redaction is best-effort, but the obvious cases must never survive."""

from __future__ import annotations

from recon_helper_pro.core.safety import REDACTED, Redactor


def test_secret_headers_are_removed() -> None:
    redactor = Redactor()
    cleaned = redactor.headers(
        {
            "Authorization": "Bearer abcdef123456",
            "Cookie": "session=abc",
            "Server": "nginx/1.18.0",
        }
    )
    assert cleaned["Authorization"] == REDACTED
    assert cleaned["Cookie"] == REDACTED
    assert cleaned["Server"] == "nginx/1.18.0"


def test_set_cookie_keeps_attributes_and_drops_the_value() -> None:
    redactor = Redactor()
    cleaned = redactor.set_cookie("sid=abc123secret; Path=/; Secure; HttpOnly; SameSite=Lax")
    assert cleaned.startswith("sid=" + REDACTED)
    assert "abc123secret" not in cleaned
    assert "HttpOnly" in cleaned and "SameSite=Lax" in cleaned


def test_tokens_and_keys_in_free_text() -> None:
    redactor = Redactor()
    text = (
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N\n"
        "aws_key AKIAIOSFODNN7EXAMPLE\n"
        "api_key=abcdef123456\n"
        "contact admin@example.com for help"
    )
    cleaned = redactor.text(text)
    assert "eyJhbGciOiJIUzI1NiJ9" not in cleaned
    assert "AKIAIOSFODNN7EXAMPLE" not in cleaned
    assert "abcdef123456" not in cleaned
    assert "admin@example.com" not in cleaned


def test_private_keys_are_removed() -> None:
    redactor = Redactor()
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK\n-----END RSA PRIVATE KEY-----"
    assert redactor.text(pem) == REDACTED


def test_ordinary_text_is_left_alone() -> None:
    redactor = Redactor()
    text = "Disallow: /admin/\nServer: Apache/2.4.29 (Ubuntu)"
    assert redactor.text(text) == text
