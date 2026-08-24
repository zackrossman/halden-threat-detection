"""Load demo detections for the seeded tenants.

Run against a fresh database: `python -m scripts.seed`.
"""

import json
from datetime import datetime, timedelta, timezone

from app.config import get_settings
from app.db import create_schema, session_factory
from app.models import Detection
from app.storage.artifacts import ArtifactStore

BASE = datetime(2026, 8, 20, 9, 0, tzinfo=timezone.utc)

SEED_DETECTIONS = [
    Detection(
        id="scan_nw_0001",
        tenant_id="northwind",
        resource_name="//nwfs01/finance/quarterly-forecast.xlsx",
        malware_family="Akira",
        severity="critical",
        detected_at=BASE,
        status="quarantined",
    ),
    Detection(
        id="scan_nw_0002",
        tenant_id="northwind",
        resource_name="//nwfs01/logistics/route-planner.exe",
        malware_family="Qakbot",
        severity="high",
        detected_at=BASE + timedelta(hours=3),
        status="quarantined",
    ),
    Detection(
        id="scan_nw_0003",
        tenant_id="northwind",
        resource_name="//nwfs02/archive/2019-invoices.zip",
        malware_family="Emotet",
        severity="medium",
        detected_at=BASE + timedelta(days=1),
        status="under_review",
    ),
    Detection(
        id="scan_ct_0001",
        tenant_id="contoso",
        resource_name="//contoso-nas01/hr/onboarding-pack.docm",
        malware_family="Dridex",
        severity="high",
        detected_at=BASE + timedelta(hours=1),
        status="quarantined",
    ),
    Detection(
        id="scan_ct_0002",
        tenant_id="contoso",
        resource_name="//contoso-nas01/legal/merger-notes.pdf",
        malware_family="Snake Keylogger",
        severity="medium",
        detected_at=BASE + timedelta(hours=6),
        status="under_review",
    ),
    Detection(
        id="scan_ct_0003",
        tenant_id="contoso",
        resource_name="//contoso-nas03/backups/vm-images/build-server.vhdx",
        malware_family="LockBit",
        severity="critical",
        detected_at=BASE + timedelta(days=2),
        status="remediated",
    ),
]


def report_payload(detection: Detection) -> bytes:
    return json.dumps(
        {
            "scan_id": detection.id,
            "resource": detection.resource_name,
            "family": detection.malware_family,
            "severity": detection.severity,
        },
        sort_keys=True,
    ).encode()


def main() -> None:
    create_schema()
    store = ArtifactStore(get_settings().artifact_dir)
    with session_factory()() as session:
        for detection in SEED_DETECTIONS:
            session.merge(detection)
            store.store(detection.tenant_id, report_payload(detection))
        session.commit()
    print(f"seeded {len(SEED_DETECTIONS)} detections")


if __name__ == "__main__":
    main()
