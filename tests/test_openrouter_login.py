"""OpenRouter OAuth PKCE login helper: PKCE math, auth URL, code exchange, .env upsert."""

import base64
import hashlib

import pytest

from ai_framework.openrouter_login import (
    build_auth_url,
    challenge_s256,
    exchange_code,
    generate_verifier,
    upsert_env_var,
    write_env,
)


def test_verifier_is_high_entropy_and_urlsafe():
    v = generate_verifier()
    assert 43 <= len(v) <= 128
    assert all(c.isalnum() or c in "-_" for c in v)
    assert generate_verifier() != generate_verifier()


def test_challenge_s256_matches_reference_and_is_unpadded():
    verifier = "test-verifier-123"
    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    assert challenge_s256(verifier) == expected
    assert "=" not in challenge_s256(verifier)


def test_build_auth_url_carries_pkce_params():
    url = build_auth_url("http://localhost:1234/callback", "CHAL")
    assert url.startswith("https://openrouter.ai/auth?")
    assert "callback_url=http%3A%2F%2Flocalhost%3A1234%2Fcallback" in url
    assert "code_challenge=CHAL" in url
    assert "code_challenge_method=S256" in url


def test_exchange_code_posts_pkce_body_and_returns_key():
    captured = {}

    def fake_post(url, payload):
        captured.update(url=url, payload=payload)
        return {"key": "sk-or-v1-abc", "user_id": "u1"}

    key = exchange_code("CODE", "VERIFIER", http_post=fake_post)
    assert key == "sk-or-v1-abc"
    assert captured["url"].endswith("/api/v1/auth/keys")
    assert captured["payload"] == {
        "code": "CODE",
        "code_verifier": "VERIFIER",
        "code_challenge_method": "S256",
    }


def test_exchange_code_raises_when_no_key():
    with pytest.raises(RuntimeError):
        exchange_code("c", "v", http_post=lambda u, p: {"error": "bad"})


def test_upsert_env_var_adds_then_replaces_without_touching_siblings():
    text = "SECFORGE_MODEL_BACKEND=offline\nANTHROPIC_API_KEY=\n"
    added = upsert_env_var(text, "OPENROUTER_API_KEY", "sk-1")
    assert "OPENROUTER_API_KEY=sk-1" in added
    assert "SECFORGE_MODEL_BACKEND=offline" in added  # sibling preserved

    replaced = upsert_env_var(added, "OPENROUTER_API_KEY", "sk-2")
    assert "OPENROUTER_API_KEY=sk-2" in replaced
    assert "sk-1" not in replaced
    assert replaced.count("OPENROUTER_API_KEY=") == 1  # no duplicate line


def test_write_env_creates_file_when_missing(tmp_path):
    path = tmp_path / ".env"
    write_env("sk-new", path=str(path))
    assert path.read_text(encoding="utf-8").strip() == "OPENROUTER_API_KEY=sk-new"
