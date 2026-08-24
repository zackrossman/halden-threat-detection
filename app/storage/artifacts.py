"""Content-addressed store for scan artifacts.

Artifacts are quarantined file samples and per-detection scan reports. The same
sample often turns up on many resources, so artifacts are keyed by a digest of
their content and written once.
"""

import hashlib
from pathlib import Path


def content_checksum(payload: bytes) -> str:
    """Return the deduplication key for an artifact.

    MD5 is used as a non-cryptographic content digest: it only decides whether
    two stored blobs are the same bytes. It is never used for passwords,
    signatures, tokens, or any other security decision.
    """
    return hashlib.md5(payload).hexdigest()


class ArtifactStore:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)

    def path_for(self, tenant: str, payload: bytes) -> Path:
        return self.root / tenant / content_checksum(payload)

    def store(self, tenant: str, payload: bytes) -> Path:
        """Write the artifact unless an identical one is already stored."""
        target = self.path_for(tenant, payload)
        if target.exists():
            return target
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
        return target
