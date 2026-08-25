"""Verification of the internal tokens this service accepts.

Every `/v1` route expects `Authorization: Bearer <jwt>`. The token is signed
with the shared secret in `HALDEN_INTERNAL_TOKEN_SECRET`, and this module
checks the signature and the registered claims before any route runs. Once the
token is verified, `read_scope` works out how much of the detection data the
caller is asking for.
"""

from typing import Annotated

import jwt
from fastapi import Depends, Header, HTTPException

from app.config import get_settings

TOKEN_ALGORITHM = "HS256"
TOKEN_ISSUER = "halden-identity"
TOKEN_AUDIENCE = "halden-threat-detection"


def verified_claims(
    authorization: Annotated[str | None, Header()] = None,
) -> dict:
    """Return the claims of this request's bearer token.

    Rejects the request with a 401 when the header is absent or malformed, when
    the signature does not check out, when `exp` has passed or is missing, or
    when `iss` and `aud` are not the ones this service reads tokens for.
    """
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(status_code=401, detail="missing bearer token")

    try:
        return jwt.decode(
            token.strip(),
            get_settings().internal_token_secret,
            algorithms=[TOKEN_ALGORITHM],
            issuer=TOKEN_ISSUER,
            audience=TOKEN_AUDIENCE,
            options={"require": ["exp", "iss", "aud"]},
        )
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="invalid token") from None


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
    if PLATFORM_AGGREGATE_SCOPE in claims.get("scopes", []):
        if claims.get("sub") not in PLATFORM_PRINCIPALS:
            raise HTTPException(
                status_code=403,
                detail="platform:aggregate scope not permitted for this principal",
            )
        return None
    tenant = claims.get("tenant_id")
    if not tenant:
        raise HTTPException(status_code=403, detail="token carries no read scope")
    return tenant


def caller_read_scope(
    claims: Annotated[dict, Depends(verified_claims)],
) -> str | None:
    """Route dependency: the read scope of the verified caller."""
    return read_scope(claims)
