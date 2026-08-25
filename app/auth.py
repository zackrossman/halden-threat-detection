"""Verification of the internal tokens this service accepts.

Every `/v1` route expects `Authorization: Bearer <jwt>`. halden-identity signs
the token, and this module checks the signature and the registered claims
before any route runs. Once the token is verified, `read_scope` works out how
much of the detection data the caller is asking for.

Tokens are signed RS256 with halden-identity's private key. This service holds
only the matching public key, so nothing in its configuration or its pod can
mint a token: an attacker who reads everything this service knows still cannot
forge one. No symmetric algorithm is accepted, which is what makes that true —
an HS256 token verified against the public key would let anyone sign with a
value that is not secret.
"""

import logging
import re
from dataclasses import dataclass
from typing import Annotated

import jwt
from fastapi import Depends, Header, HTTPException

from app import audit
from app.config import get_settings

TOKEN_ISSUER = "halden-identity"
TOKEN_AUDIENCE = "halden-threat-detection"

# The only algorithm this service accepts. halden-identity signs with the
# private half; this service holds only the public key, so reading its
# configuration does not let anyone mint a token.
TOKEN_ALGORITHM = "RS256"

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

    # The header selects nothing. It is read only to refuse anything that is
    # not RS256 with a reason worth logging; the algorithm passed to the
    # decoder is the constant below, never the header value, so a token cannot
    # nominate how it would like to be verified.
    if algorithm != TOKEN_ALGORITHM:
        raise _refuse(401, "invalid token", "unsupported_algorithm")

    claims = _decode(token, get_settings().internal_token_public_key)

    # Recording only refusals answers "who was turned away" and not "who got
    # in", which is where an investigation starts. The token is never recorded
    # — the registered claims say who presented it and who signed it, without
    # putting a usable credential in the log.
    audit.record(
        "token_verified",
        subject=claims.get("sub"),
        issuer=claims.get("iss"),
        audience=claims.get("aud"),
        algorithm=TOKEN_ALGORITHM,
    )
    return claims


def _decode(token: str, public_key: str) -> dict:
    try:
        return jwt.decode(
            token,
            public_key,
            algorithms=[TOKEN_ALGORITHM],
            issuer=TOKEN_ISSUER,
            audience=TOKEN_AUDIENCE,
            options={"require": REQUIRED_CLAIMS},
        )
    except jwt.PyJWTError as exc:
        # The exception class names which check failed (expiry, audience,
        # signature) without putting any token content in the log.
        raise _refuse(401, "invalid token", type(exc).__name__) from None


# A tenant id reaches this service inside a verified token, but a verified
# token only proves who minted it — not that the claim is well formed. The id
# is used as a query filter and as an artifact path segment, so it is held to a
# single safe shape here rather than trusted for those uses downstream.
TENANT_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]+$")

# How much of a rejected tenant id is recorded. Enough to recognise the attempt,
# not enough for a long value to bloat the log.
LOGGED_TENANT_ID_CHARS = 64


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
    if not isinstance(tenant, str) or not TENANT_ID_PATTERN.match(tenant):
        raise _refuse(
            400,
            "invalid tenant_id format",
            "malformed_tenant_id",
            subject=subject,
            rejected_tenant_id=str(tenant)[:LOGGED_TENANT_ID_CHARS],
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
