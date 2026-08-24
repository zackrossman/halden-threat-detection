"""FastAPI dependencies for the tenant-scoped routes.

Both dependencies follow the Halden internal service contract
(`docs/platform/inbound-request-contract.md`).
"""

import hmac
from typing import Annotated

from fastapi import Header, HTTPException, status

from app.config import get_settings


def require_gateway_key(
    x_halden_gateway_key: Annotated[str | None, Header()] = None,
) -> None:
    """Reject a request whose gateway key does not match the configured one.

    The expected value is read from the environment (`HALDEN_GATEWAY_KEY`) and
    injected by the platform from the `halden-threat-detection-runtime` secret.
    The comparison is constant time, so response timing does not vary with how
    much of the key the caller got right.
    """
    expected = get_settings().gateway_key
    if x_halden_gateway_key is None or not hmac.compare_digest(
        x_halden_gateway_key, expected
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing or invalid gateway key",
        )


def tenant_id(
    x_halden_tenant_id: Annotated[str | None, Header()] = None,
) -> str:
    """Return the tenant this request is scoped to.

    `halden-identity` validates the end user's access token at the edge and
    propagates the authenticated tenant in `X-Halden-Tenant-ID`. See
    docs/platform/inbound-request-contract.md for the header contract.
    """
    if not x_halden_tenant_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="missing X-Halden-Tenant-ID header",
        )
    return x_halden_tenant_id
