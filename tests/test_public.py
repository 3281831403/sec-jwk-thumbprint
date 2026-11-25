"""Public acceptance tests for the JWK thumbprint exercise.

Exactly five scenarios are covered here: parsing, thumbprint stability,
selection by thumbprint, rejection of a duplicate identifier, and
per-message independence in a batch.  The hidden suite covers the remaining
parts of the contract.
"""

import base64
import hashlib
import hmac

from jwk.select import (
    check_unique_id,
    jwk_batch,
    parse_jwk,
    select_by_thumbprint,
    thumbprint,
    validate_keyset,
)


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _oct_key(kid: str, secret: bytes) -> dict:
    return {"kty": "oct", "kid": kid, "use": "sig", "k": _b64u(secret)}


def _secret(key: dict) -> bytes:
    text = key["k"]
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _message(key: dict, payload: str) -> dict:
    digest = hmac.new(
        _secret(key), payload.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return {
        "thumbprint": thumbprint(key),
        "payload": payload,
        "signature": digest,
    }


def test_parse_jwk_normalizes_text_members():
    raw = (
        '{"kty":"rsa","kid":" k1 ","use":"SIG",'
        '"n":"sXchZQ","e":"AQAB"}'
    )
    key = parse_jwk(raw)

    assert key["kty"] == "RSA"
    assert key["kid"] == "k1"
    assert key["use"] == "sig"
    assert key["n"] == "sXchZQ"
    assert key["e"] == "AQAB"


def test_thumbprint_is_stable_for_one_key():
    key = {
        "kty": "RSA",
        "kid": "k1",
        "use": "sig",
        "n": "sXchZQ",
        "e": "AQAB",
    }
    before = thumbprint(key)

    key["kid"] = "k2"
    key["use"] = "enc"
    key["alg"] = "RS256"
    key["x5t"] = "another-thumbprint"

    assert thumbprint(key) == before


def test_select_by_thumbprint_finds_the_matching_key():
    first = _oct_key("first", b"first-secret")
    second = _oct_key("second", b"second-secret")

    selected = select_by_thumbprint([first, second], thumbprint(second))

    assert selected["kid"] == "second"
    assert thumbprint(selected) == thumbprint(second)


def test_kid_conflict_is_rejected():
    first = _oct_key("shared", b"first-secret")
    second = _oct_key("shared", b"second-secret")
    keys = [first, second]

    assert check_unique_id(keys) == ["shared"]
    problems = validate_keyset(keys)
    assert any("kid" in problem.lower() and "shared" in problem for problem in problems)


def test_batch_verifies_each_message_with_its_own_key():
    first = _oct_key("first", b"first-secret")
    second = _oct_key("second", b"second-secret")
    messages = [_message(first, "alpha"), _message(second, "beta")]

    report = jwk_batch(messages, [first, second])

    assert report["valid"] is True
    assert [item["valid"] for item in report["results"]] == [True, True]
    assert [item["thumbprint"] for item in report["results"]] == [
        thumbprint(first),
        thumbprint(second),
    ]