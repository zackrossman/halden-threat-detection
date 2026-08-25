"""Verification of the internal tokens this service accepts.

Every `/v1` route expects `Authorization: Bearer <jwt>`. halden-identity signs
the token, and this module checks the signature and the registered claims
before any route runs. Once the token is verified, `read_scope` works out how
much of the detection data the caller is asking for.

Two signature algorithms are accepted while the platform moves off the shared
secret. The `alg` in the token header selects which key verifies the token, and
each branch pins the single algorithm its key can verify, so a token is never
checked against the wrong kind of key. In particular the RSA public key is
never handed to the HMAC path, where an attacker could sign with the public key
as the shared secret and have it accepted.
"""

import logging
from dataclasses import dataclass
from typing import Annotated

import jwt
from fastapi import Depends, Header, HTTPException

from app import audit
from app.config import get_settings

TOKEN_ISSUER = "halden-identity"
TOKEN_AUDIENCE = "halden-threat-detection"

# Signed with the shared secret. The platform is migrating away from this.
SYMMETRIC_ALGORITHM = "HS256"
# Signed with halden-identity's private key; this service holds only the public
# half, so reading this service's configuration does not let anyone mint tokens.
ASYMMETRIC_ALGORITHM = "RS256"

TOKEN_ALGORITHM = SYMMETRIC_ALGORITHM  # retained for callers that name the default

# `sub` is required so that every audit record names a caller. halden-identity
# sets it on both the customer and the platform token.
REQUIRED_CLAIMS = ["exp", "iss", "aud", "sub"]


def _refuse(status_code: int, detail: str, reason: str, **fields: object) -> HTTPException:
    """Build the error to raise, recording why the request was turned away."""
    audit.record(
        "authentication_failed" if status_code == 401 else "authorization_denied",
        level=logging.WARNING,
        outcome="refused",
        status_code=status_code,
        reason=reason,
        **fields,
    )
    return HTTPException(status_code=status_code, detail=detail)


def verified_claims(
    authorization: Annotated[str | None, Header()] = None,
) -> dict:
    """Return the claims of this request's bearer token.

    Rejects the request with a 401 when the header is absent or malformed, when
    the token is signed with an algorithm this service does not accept, when the
    signature does not check out, when `exp` has passed or is missing, when
    `sub` is missing, or when `iss` and `aud` are not the ones this service
    reads tokens for.
    """
    scheme, _, token = (authorization or "").partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token:
        raise _refuse(401, "missing bearer token", "no_bearer_token")

    try:
        algorithm = jwt.get_unverified_header(token).get("alg")
    except jwt.PyJWTError:
        raise _refuse(401, "invalid token", "unreadable_header") from None

    settings = get_settings()

    # Each branch names its algorithm literally rather than passing the header
    # value through, so the header can select a branch but can never widen the
    # set of algorithms a key is trusted for.
    if algorithm == ASYMMETRIC_ALGORITHM:
        public_key = settings.internal_token_public_key
        if not public_key:
            raise _refuse(401, "invalid token", "rs256_key_not_configured")
        claims = _decode(token, public_key, ASYMMETRIC_ALGORITHM)
    elif algorithm == SYMMETRIC_ALGORITHM:
        claims = _decode(token, settings.internal_token_secret, SYMMETRIC_ALGORITHM)
    else:
        raise _refuse(401, "invalid token", "unsupported_algorithm")

    return claims


def _decode(token: str, key: str, algorithm: str) -> dict:
    try:
        return jwt.decode(
            token,
            key,
            algorithms=[algorithm],
            issuer=TOKEN_ISSUER,
            audience=TOKEN_AUDIENCE,
            options={"require": REQUIRED_CLAIMS},
        )
    except jwt.PyJWTError as exc:
        # The exception class names which check failed (expiry, audience,
        # signature) without putting any token content in the log.
        raise _refuse(401, "invalid token", type(exc).__name__) from None


PLATFORM_AGGREGATE_SCOPE = "platform:aggregate"

# Subjects permitted to present the platform:aggregate scope. The estate-wide
# read is reserved for the platform's own scheduled principals; a token that
# carries the scope with any other subject is refused.
PLATFORM_PRINCIPALS = frozenset({"halden-identity/jobs"})


def read_scope(claims: dict) -> str | None:
    """Tenant this caller may read, or None for an estate-wide caller.

    Tokens issued for a signed-in customer carry `tenant_id` and are confined
    to that tenant. The `platform:aggregate` scope reports across the estate and
    is honored only for the platform's own scheduled principals: the subject is
    checked against the allowlist before estate-wide access is granted.
    """
    subject = claims.get("sub")
    if PLATFORM_AGGREGATE_SCOPE in claims.get("scopes", []):
        if subject not in PLATFORM_PRINCIPALS:
            raise _refuse(
                403,
                "platform:aggregate scope not permitted for this principal",
                "aggregate_scope_for_unlisted_principal",
                subject=subject,
            )
        return None
    tenant = claims.get("tenant_id")
    if not tenant:
        raise _refuse(
            403, "token carries no read scope", "no_read_scope", subject=subject
        )
    return tenant


@dataclass(frozen=True)
class Caller:
    """The verified caller of a route, and how far its read reaches."""

    subject: str
    # The tenant this caller is confined to, or None for an estate-wide read.
    scope: str | None

    @property
    def audited_scope(self) -> str:
        """The scope as it appears in an audit record."""
        return self.scope or "estate"


def caller(claims: Annotated[dict, Depends(verified_claims)]) -> Caller:
    """Route dependency: the verified caller and its read scope."""
    return Caller(subject=claims["sub"], scope=read_scope(claims))


def caller_read_scope(
    verified: Annotated[Caller, Depends(caller)],
) -> str | None:
    """Route dependency: the read scope of the verified caller."""
    return verified.scope
