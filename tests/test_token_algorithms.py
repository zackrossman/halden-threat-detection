"""Which signature algorithms this service accepts, and which it must not.

The platform is migrating from the shared HS256 secret to RS256 signing, so
both are accepted for now. The risk that comes with accepting two is algorithm
confusion: an attacker takes the RSA public key, which is not a secret, uses it
as an HMAC key, and presents the result as HS256.

Two things refuse that token. PyJWT will not treat a PEM key as an HMAC secret,
and `verified_claims` picks the key and pins the algorithm in separate branches
so the public key never reaches the HMAC path. The first is the one doing the
work today; injecting the naive `algorithms=["HS256", "RS256"]` bug into
`verified_claims` does not make these tests fail, because PyJWT still catches
it. The branching is there so the service does not depend on that library
heuristic, and these tests pin the behaviour whichever layer enforces it.
"""

import base64
import hashlib
import hmac
import json

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.config import get_settings
from tests.conftest import TOKEN_ISSUER, TOKEN_AUDIENCE, bearer, make_token

ROUTE = "/v1/scans"


@pytest.fixture(scope="module")
def rsa_keypair() -> tuple[str, str]:
    """A throwaway RSA keypair, generated per run so no key is checked in."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = (
        key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    return private_pem, public_pem


@pytest.fixture
def configured_public_key(rsa_keypair, monkeypatch):
    """Install the public half as the key this service verifies RS256 with."""
    _, public_pem = rsa_keypair
    settings = get_settings()
    monkeypatch.setattr(settings, "internal_token_public_key", public_pem)
    return public_pem


def rs256_token(private_pem: str, claims: dict) -> str:
    return make_token(claims, secret=private_pem, algorithm="RS256")


def hs256_token_signed_by_hand(key: str, claims: dict) -> str:
    """Build an HS256 token without PyJWT.

    PyJWT refuses to *sign* with a PEM key, so an attacker would not use it
    either. Assembling the token by hand is what the attack looks like, and it
    is the only way to put this service's own verification under test.
    """
    def segment(data: dict) -> bytes:
        return base64.urlsafe_b64encode(
            json.dumps(data, separators=(",", ":")).encode()
        ).rstrip(b"=")

    signing_input = b".".join(
        [segment({"alg": "HS256", "typ": "JWT"}), segment(claims)]
    )
    signature = hmac.new(key.encode(), signing_input, hashlib.sha256).digest()
    return (
        signing_input + b"." + base64.urlsafe_b64encode(signature).rstrip(b"=")
    ).decode()


FORGED_CLAIMS_BASE = {
    "iss": TOKEN_ISSUER,
    "aud": TOKEN_AUDIENCE,
    "exp": 4102444800,  # far future, so expiry is never what refuses the token
}


def test_rs256_token_is_accepted_once_the_public_key_is_configured(
    client, rsa_keypair, configured_public_key
):
    private_pem, _ = rsa_keypair
    token = rs256_token(private_pem, {"tenant_id": "northwind"})

    response = client.get(ROUTE, headers=bearer(token))

    assert response.status_code == 200
    assert response.json()["scope"] == "northwind"


def test_rs256_token_is_refused_while_no_public_key_is_configured(client, rsa_keypair):
    # The default deployment has no public key yet; an RS256 token must be
    # turned away rather than trusted.
    private_pem, _ = rsa_keypair
    token = rs256_token(private_pem, {"tenant_id": "northwind"})

    assert client.get(ROUTE, headers=bearer(token)).status_code == 401


def test_rs256_token_signed_by_another_key_is_refused(client, configured_public_key):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_pem = other.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    token = rs256_token(other_pem, {"tenant_id": "northwind"})

    assert client.get(ROUTE, headers=bearer(token)).status_code == 401


def test_public_key_used_as_an_hmac_secret_is_refused(client, configured_public_key):
    """The algorithm-confusion attack this dual-accept window has to survive.

    The public key is not a secret. Signing with it under HS256 must not
    produce a token this service accepts.
    """
    token = hs256_token_signed_by_hand(
        configured_public_key,
        {"tenant_id": "northwind", "sub": "auth0|attacker", **FORGED_CLAIMS_BASE},
    )

    assert client.get(ROUTE, headers=bearer(token)).status_code == 401


def test_public_key_as_hmac_secret_is_refused_for_the_aggregate_scope(
    client, configured_public_key
):
    """The same attack aimed at the estate-wide read, which is the prize."""
    token = hs256_token_signed_by_hand(
        configured_public_key,
        {
            "sub": "halden-identity/jobs",
            "scopes": ["platform:aggregate"],
            **FORGED_CLAIMS_BASE,
        },
    )

    assert client.get(ROUTE, headers=bearer(token)).status_code == 401


def test_an_unsigned_token_is_refused(client):
    token = jwt.encode(
        {"tenant_id": "northwind", "sub": "auth0|attacker", **FORGED_CLAIMS_BASE},
        key="",
        algorithm="none",
    )

    assert client.get(ROUTE, headers=bearer(token)).status_code == 401


def test_a_token_naming_an_unaccepted_algorithm_is_refused(client):
    token = make_token({"tenant_id": "northwind"}, algorithm="HS512")

    assert client.get(ROUTE, headers=bearer(token)).status_code == 401
