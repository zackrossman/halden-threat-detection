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

    def tenant_dir(self, tenant: str) -> Path:
        """The directory holding one tenant's artifacts.

        The tenant id arrives from a token claim. A verified token proves who
        minted it, not that the claim is a safe path segment, so the id is
        checked here rather than trusted. A value carrying a separator or `..`
        would otherwise resolve outside this tenant's directory and read or
        write another tenant's artifacts.

        Both paths are resolved before comparison, so `..` and a symlinked root
        are settled before the containment check rather than after it.
        """
        root = self.root.resolve()
        candidate = (root / tenant).resolve()
        if not candidate.is_relative_to(root) or candidate == root:
            raise ValueError(f"tenant id escapes the artifact root: {tenant!r}")
        if candidate.parent != root:
            raise ValueError(f"tenant id is not a single path segment: {tenant!r}")
        return candidate

    def path_for(self, tenant: str, payload: bytes) -> Path:
        return self.tenant_dir(tenant) / content_checksum(payload)

    def store(self, tenant: str, payload: bytes) -> Path:
        """Write the artifact unless an identical one is already stored."""
        target = self.path_for(tenant, payload)
        if target.exists():
            return target
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
        return target
