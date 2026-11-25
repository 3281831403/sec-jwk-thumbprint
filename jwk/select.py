"""JWK key-set parsing, thumbprints, selection and batch verification.

The public API is deliberately small: every operation works on plain
dictionaries parsed from JSON.  Key material is represented with the usual
JWK member names.  An octet key uses ``k``, an RSA key uses ``n`` and ``e``,
and an elliptic-curve key uses ``crv``, ``x`` and ``y``.

A key set is a list of key dictionaries.  Keys used for signing carry
``use`` equal to ``sig``; keys used for encryption carry ``use`` equal to
``enc``.  A key is out of service when ``disabled`` is true, when ``active``
is false, or when ``status`` is one of ``disabled``, ``revoked``,
``inactive`` or ``retired``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
from collections import Counter

_FIELDS = {
    "RSA": ("kty", "n", "e"),
    "EC": ("kty", "crv", "x", "y"),
    "oct": ("kty", "k"),
}

_DISABLED_STATUS = {"disabled", "revoked", "inactive", "retired"}


def _canonical_kty(value):
    """Return the registered spelling of a key type."""

    if not isinstance(value, str) or not value.strip():
        raise ValueError("kty must be a non-empty string")
    wanted = value.strip().casefold()
    for name in _FIELDS:
        if name.casefold() == wanted:
            return name
    raise ValueError("unsupported kty: " + str(value))


def _is_disabled(jwk):
    """Return true when a key has been taken out of service."""

    if not isinstance(jwk, dict):
        return True
    if jwk.get("disabled"):
        return True
    if jwk.get("retired"):
        return True
    # An absent ``active`` member means the key is active; only an explicit
    # falsy value takes it out of service.
    if "active" in jwk and not jwk.get("active"):
        return True
    status = jwk.get("status")
    if isinstance(status, str) and status.strip().casefold() in _DISABLED_STATUS:
        return True
    return False


def _normalized_field(name, value):
    """Return the canonical text used for one thumbprint member."""

    if not isinstance(value, str):
        raise ValueError("thumbprint member " + name + " must be text")
    text = value.strip()
    if name in ("kty", "crv"):
        return text.upper()
    return text


def _decode_b64url(value):
    """Decode an unpadded base64url value used as octet key material."""

    if not isinstance(value, str) or not value.strip():
        raise ValueError("octet key material must be non-empty text")
    text = value.strip()
    padded = text + "=" * (-len(text) % 4)
    try:
        return base64.b64decode(
            padded.encode("ascii"), altchars=b"-_", validate=True
        )
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise ValueError("invalid base64url key material") from exc


def parse_jwk(text):
    """Parse one JWK JSON document into a dictionary.

    The input must be a JSON object with a supported ``kty``.  Text members
    are stripped of surrounding whitespace; the key type and curve name are
    upper-cased and the use is lower-cased.  The input document is not
    modified.
    """

    try:
        value = json.loads(text)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("JWK must be valid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("JWK must be a JSON object")
    if "kty" not in value:
        raise ValueError("JWK is missing kty")

    # Validate the key type while keeping the parsed members intact.
    _canonical_kty(value["kty"])
    for name in ("kid", "use"):
        if name in value and not isinstance(value[name], str):
            raise ValueError(name + " must be text")

    normalized = {}
    for name, member in value.items():
        if isinstance(member, str):
            member = member.strip()
            if name in ("kty", "crv"):
                member = member.upper()
            elif name == "use":
                member = member.lower()
        normalized[name] = member
    return normalized


def required_fields(kty):
    """Return the thumbprint members for a key type, in canonical order."""

    return list(_FIELDS[_canonical_kty(kty)])


def thumbprint(jwk):
    """Return the SHA-256 thumbprint of a JWK as a hexadecimal string.

    Only the required members for the key type participate.  They are
    serialized in the canonical order returned by :func:`required_fields`,
    after text normalization, with no insignificant whitespace.
    """

    if not isinstance(jwk, dict):
        raise ValueError("JWK must be a dictionary")

    canonical_kty = _canonical_kty(jwk.get("kty"))
    payload = {}
    for name in _FIELDS[canonical_kty]:
        # Pull only the required members, in the fixed canonical order, and
        # normalize their text so formatting noise cannot change the digest.
        payload[name] = _normalized_field(name, jwk.get(name))

    encoded = json.dumps(
        payload, ensure_ascii=False, separators=(",", ":"), sort_keys=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def check_unique_id(jwks):
    """Return the sorted identifiers that occur more than once in a set."""

    counts = Counter()
    for jwk in jwks or []:
        if not isinstance(jwk, dict):
            continue
        kid = jwk.get("kid")
        if isinstance(kid, str) and kid.strip():
            counts[kid.strip()] += 1
    return sorted(kid for kid, total in counts.items() if total > 1)


def select_by_thumbprint(jwks, print_value):
    """Select the one active key whose thumbprint equals ``print_value``.

    A key-set-wide duplicate identifier is rejected before any lookup.
    Disabled keys are not eligible, and a missing thumbprint is an error
    rather than a reason to fall back to another key.
    """

    # A conflicted identifier set is never usable, even if the requested
    # thumbprint would otherwise match one of its keys.
    conflicts = check_unique_id(jwks)
    if conflicts:
        raise ValueError("duplicate kid in key set: " + ", ".join(conflicts))

    for jwk in jwks or []:
        if not isinstance(jwk, dict) or _is_disabled(jwk):
            continue
        try:
            candidate = thumbprint(jwk)
        except (ValueError, TypeError, KeyError):
            # A malformed key cannot present a comparable thumbprint.
            continue
        if candidate == print_value:
            return jwk

    # Never guess by kid and never fall back to a default key.
    raise KeyError(print_value)


def check_use(jwk, purpose):
    """Return true only when a usable key has the requested purpose."""

    if not isinstance(jwk, dict) or _is_disabled(jwk):
        return False
    if not isinstance(purpose, str) or not purpose.strip():
        return False
    use = jwk.get("use")
    if not isinstance(use, str) or not use.strip():
        return False
    return use.strip().lower() == purpose.strip().lower()


def validate_keyset(jwks):
    """Return a deterministic list of problems found in a key set.

    The checks cover missing required members, duplicate identifiers and
    distinct keys that share the same thumbprint.  The returned strings are
    stable for a given input and are intended for diagnostics.
    """

    problems = []
    for index, jwk in enumerate(jwks or []):
        if not isinstance(jwk, dict):
            problems.append("key " + str(index) + ": not an object")
            continue

        kty = jwk.get("kty")
        if not isinstance(kty, str) or not kty.strip():
            problems.append("key " + str(index) + ": missing kty")
            continue
        try:
            fields = required_fields(kty)
        except ValueError:
            problems.append("key " + str(index) + ": unsupported kty " + str(kty))
            continue

        for name in fields:
            value = jwk.get(name)
            if (
                name not in jwk
                or value is None
                or (isinstance(value, str) and not value.strip())
            ):
                problems.append("key " + str(index) + ": missing " + name)

        kid = jwk.get("kid")
        if not isinstance(kid, str) or not kid.strip():
            problems.append("key " + str(index) + ": missing kid")

    for kid in check_unique_id(jwks or []):
        problems.append("duplicate kid: " + kid)

    thumbprint_counts = Counter()
    for jwk in jwks or []:
        if not isinstance(jwk, dict):
            continue
        try:
            printed = thumbprint(jwk)
        except (ValueError, TypeError, KeyError):
            # Missing or malformed required members are reported above.
            continue
        thumbprint_counts[printed] += 1
    for printed in sorted(
        printed for printed, total in thumbprint_counts.items() if total > 1
    ):
        problems.append("duplicate thumbprint: " + printed)

    return problems


def _check_signature(key, message):
    """Verify one message against an already selected key."""

    if not isinstance(message, dict):
        raise ValueError("message must be an object")
    payload = message.get("payload")
    signature = message.get("signature")
    if not isinstance(payload, str):
        raise ValueError("message payload must be text")
    if not isinstance(signature, str) or not signature.strip():
        raise ValueError("message signature must be non-empty text")

    purpose = message.get("purpose", "sig")
    if not isinstance(purpose, str) or not check_use(key, purpose):
        raise ValueError("key use does not match the message purpose")

    if _canonical_kty(key.get("kty")) != "oct":
        raise ValueError("batch verification requires an octet key")

    secret = _decode_b64url(key.get("k"))
    expected = hmac.new(
        secret, payload.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, signature.strip().lower()):
        raise ValueError("signature mismatch")


def jwk_batch(messages, jwks):
    """Verify a sequence of messages independently.

    Each message is an object with ``payload``, ``signature`` and
    ``thumbprint`` members; ``purpose`` defaults to ``sig``.  The signature
    is the lower-case SHA-256 HMAC hexadecimal digest of the UTF-8 payload,
    using the decoded octet key as the secret.  One result is produced per
    message and a bad message does not stop the remaining messages.
    """

    results = []
    for index, message in enumerate(messages or []):
        try:
            if not isinstance(message, dict):
                raise ValueError("message must be an object")
            printed = message.get("thumbprint")
            # Select afresh for every message so one result cannot influence
            # which key is used for the next message.
            key = select_by_thumbprint(jwks, printed)
            _check_signature(key, message)
            results.append(
                {
                    "index": index,
                    "valid": True,
                    "kid": key.get("kid"),
                    "thumbprint": thumbprint(key),
                    "error": None,
                }
            )
        except Exception as exc:
            results.append(
                {
                    "index": index,
                    "valid": False,
                    "kid": None,
                    "thumbprint": None,
                    "error": str(exc),
                }
            )

    return {"valid": all(item["valid"] for item in results), "results": results}