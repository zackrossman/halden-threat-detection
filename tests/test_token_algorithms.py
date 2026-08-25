"""This service accepts RS256 and nothing else.

That is the property the whole migration exists for. halden-identity holds the
private key; this service holds only the public half, so an attacker who reads
everything this service knows — its config, its environment, its pod — still
cannot mint a token.

Accepting any symmetric algorithm would give that back, because the only key
this service holds is public. Anyone could sign with it. So every test here is
a way of asking the same question: can something other than the holder of the
private key produce a token this service accepts?
"""

import base64
import hashlib
import hmac
import json

import jwt
import pytest

from app.auth import TOKEN_ALGORITHM
from tests.conftest import (
    TOKEN_PUBLIC_KEY,
    bearer,
    make_token,
    other_private_key,
)

ROUTE = "/v1/scans"

# Far future, so an expiry check is never what refuses these tokens.
FORGED_CLAIMS_BASE = {
    "iss": "halden-identity",
    "aud": "halden-threat-detection",
    "exp": 4102444800,
}


def hmac_token(key: str, claims: dict, algorithm: str = "HS256") -> str:
    """Build an HMAC-signed token by hand.

    PyJWT refuses to *sign* with a PEM key, so an attacker would not use it
    either. Assembling the token directly is what the attack looks like, and it
    is the only way to put this service's own verification under test.
    """
    digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[
        algorithm
    ]

    def segment(data: dict) -> bytes:
        return base64.urlsafe_b64encode(
            json.dumps(data, separators=(",", ":")).encode()
        ).rstrip(b"=")

    signing_input = b".".join(
        [segment({"alg": algorithm, "typ": "JWT"}), segment(claims)]
    )
    signature = hmac.new(key.encode(), signing_input, digest).digest()
    return (
        signing_input + b"." + base64.urlsafe_b64encode(signature).rstrip(b"=")
    ).decode()


def test_the_service_accepts_only_rs256():
    assert TOKEN_ALGORITHM == "RS256"


def test_a_token_from_the_real_signing_key_is_accepted(client):
    response = client.get(ROUTE, headers=bearer(make_token({"tenant_id": "northwind"})))

    assert response.status_code == 200
    assert response.json()["scope"] == "northwind"


def test_a_token_signed_by_another_private_key_is_refused(client):
    token = make_token({"tenant_id": "northwind"}, key=other_private_key())

    assert client.get(ROUTE, headers=bearer(token)).status_code == 401


# --- the attacks that a symmetric algorithm would open up ---


@pytest.mark.parametrize("algorithm", ["HS256", "HS384", "HS512"])
def test_the_public_key_used_as_an_hmac_secret_is_refused(client, algorithm):
    """The public key is not secret. Signing with it must prove nothing."""
    token = hmac_token(
        TOKEN_PUBLIC_KEY,
        {"tenant_id": "northwind", "sub": "auth0|attacker", **FORGED_CLAIMS_BASE},
        algorithm,
    )

    assert client.get(ROUTE, headers=bearer(token)).status_code == 401


def test_the_public_key_as_an_hmac_secret_cannot_reach_the_estate(client):
    """The same attack aimed at the estate-wide read, which is the prize."""
    token = hmac_token(
        TOKEN_PUBLIC_KEY,
        {
            "sub": "halden-identity/jobs",
            "scopes": ["platform:aggregate"],
            **FORGED_CLAIMS_BASE,
        },
    )

    assert client.get(ROUTE, headers=bearer(token)).status_code == 401


def test_an_hs256_token_from_any_secret_is_refused(client):
    """No shared secret exists any more; nothing signed with one is accepted."""
    token = hmac_token(
        "whatever-the-old-shared-secret-was",
        {"tenant_id": "northwind", "sub": "auth0|attacker", **FORGED_CLAIMS_BASE},
    )

    assert client.get(ROUTE, headers=bearer(token)).status_code == 401


def test_an_unsigned_token_is_refused(client):
    token = jwt.encode(
        {"tenant_id": "northwind", "sub": "auth0|attacker", **FORGED_CLAIMS_BASE},
        key="",
        algorithm="none",
    )

    assert client.get(ROUTE, headers=bearer(token)).status_code == 401


def test_a_token_with_no_algorithm_header_is_refused(client):
    real = make_token({"tenant_id": "northwind"})
    header, payload, signature = real.split(".")
    stripped = base64.urlsafe_b64encode(json.dumps({"typ": "JWT"}).encode()).rstrip(b"=")

    tampered = ".".join([stripped.decode(), payload, signature])

    assert client.get(ROUTE, headers=bearer(tampered)).status_code == 401


def test_a_real_token_with_its_header_rewritten_to_hs256_is_refused(client):
    """Downgrade attempt: keep a genuine payload, claim it was HMAC signed."""
    real = make_token({"tenant_id": "northwind"})
    _, payload, signature = real.split(".")
    downgraded_header = base64.urlsafe_b64encode(
        json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
    ).rstrip(b"=")

    tampered = ".".join([downgraded_header.decode(), payload, signature])

    assert client.get(ROUTE, headers=bearer(tampered)).status_code == 401


# --- configuration ---


def test_the_service_will_not_start_without_a_public_key(monkeypatch):
    """A missing key must fail at startup, not on every request afterwards.

    The pod then fails its readiness probe and the rollout stops, rather than
    coming up healthy and refusing all traffic.
    """
    import pydantic

    from app.config import Settings

    monkeypatch.delenv("HALDEN_INTERNAL_TOKEN_PUBLIC_KEY", raising=False)

    with pytest.raises(pydantic.ValidationError):
        Settings(_env_file=None)


def test_settings_no_longer_carry_a_shared_secret():
    from app.config import Settings

    assert "internal_token_secret" not in Settings.model_fields
