"""jwt_attack: decode, alg-none forge, HS256 crack/forge/verify — all offline."""

import base64
import hashlib
import hmac
import json

from ai_framework.tools.base import ToolContext
from ai_framework.tools.jwt import JwtAttackTool


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _hs256(secret: str, claims: dict) -> str:
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}"
    sig = _b64(hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest())
    return f"{signing_input}.{sig}"


CTX = ToolContext()
TOOL = JwtAttackTool()


def test_decode_shows_header_and_payload():
    tok = _hs256("secret", {"user": "bob", "role": "user"})
    out = TOOL.run({"op": "decode", "token": tok}, CTX)
    assert '"role": "user"' in out and '"alg": "HS256"' in out


def test_alg_none_forge_overrides_claims_and_strips_signature():
    tok = _hs256("secret", {"user": "bob", "role": "user"})
    out = TOOL.run({"op": "alg-none", "token": tok, "claims": {"role": "admin"}}, CTX)
    forged = out.split("\n")[1].strip()
    assert forged.endswith(".")  # empty signature
    header, payload, _ = forged.split(".")
    assert json.loads(base64.urlsafe_b64decode(header + "==")) == {"alg": "none", "typ": "JWT"}
    assert json.loads(base64.urlsafe_b64decode(payload + "=="))["role"] == "admin"


def test_crack_hs256_finds_weak_secret():
    tok = _hs256("changeme", {"user": "bob"})
    out = TOOL.run({"op": "crack-hs256", "token": tok}, CTX)
    assert "CRACKED" in out and "'changeme'" in out


def test_crack_hs256_uses_supplied_wordlist():
    tok = _hs256("hunter2", {"user": "bob"})
    assert "not cracked" in TOOL.run({"op": "crack-hs256", "token": tok}, CTX)
    out = TOOL.run({"op": "crack-hs256", "token": tok, "secrets": ["hunter2"]}, CTX)
    assert "CRACKED" in out and "'hunter2'" in out


def test_forge_hs256_produces_a_token_that_verifies():
    tok = _hs256("changeme", {"user": "bob", "role": "user"})
    out = TOOL.run(
        {"op": "forge-hs256", "token": tok, "secret": "changeme", "claims": {"role": "admin"}}, CTX
    )
    forged = out.split("\n")[1].strip()
    # The forged token must verify under the same secret and carry the escalated claim.
    v = TOOL.run({"op": "verify-hs256", "token": forged, "secret": "changeme"}, CTX)
    assert "VALID" in v
    _, payload, _ = forged.split(".")
    assert json.loads(base64.urlsafe_b64decode(payload + "=="))["role"] == "admin"


def test_verify_rejects_wrong_secret():
    tok = _hs256("changeme", {"user": "bob"})
    assert "invalid" in TOOL.run({"op": "verify-hs256", "token": tok, "secret": "nope"}, CTX)


def test_forge_requires_secret():
    import pytest

    tok = _hs256("changeme", {"user": "bob"})
    with pytest.raises(ValueError, match="secret"):
        TOOL.run({"op": "forge-hs256", "token": tok}, CTX)
