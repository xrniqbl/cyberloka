import base64
import hashlib
import hmac
import json
import time

from cyberloka.active.jwt_audit import _decode_jwt, audit_token


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _make_jwt(header: dict, payload: dict, secret: str | None) -> str:
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    if secret is None:
        return f"{h}.{p}."
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url(sig)}"


def test_decode_jwt_round_trip():
    tok = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "u", "exp": 1}, "k")
    out = _decode_jwt(tok)
    assert out is not None
    header, payload, sig, _signing = out
    assert header["alg"] == "HS256"
    assert payload["sub"] == "u"
    assert sig != b""


def test_audit_alg_none_flags_critical():
    tok = _make_jwt({"alg": "none"}, {"sub": "u"}, secret=None)
    findings = audit_token(tok, "test")
    titles = [f.title for f in findings]
    assert any("alg=none" in t for t in titles)
    sevs = {f.severity.value for f in findings}
    assert "critical" in sevs


def test_audit_weak_hs256_secret_cracked():
    tok = _make_jwt({"alg": "HS256"}, {"sub": "u"}, secret="secret")
    findings = audit_token(tok, "test")
    assert any("secret lemah" in f.title for f in findings)


def test_audit_expired_token_low():
    tok = _make_jwt(
        {"alg": "HS256"},
        {"sub": "u", "exp": int(time.time()) - 3600},
        secret="some-strong-random-secret-not-in-list",
    )
    findings = audit_token(tok, "test")
    assert any("kedaluwarsa" in f.title for f in findings)
