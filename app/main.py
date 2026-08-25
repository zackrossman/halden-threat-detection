"""halden-threat-detection service entrypoint."""

from fastapi import FastAPI

from app.audit import configure_audit_logging
from app.routers import scans

configure_audit_logging()

app = FastAPI(
    title="Halden Threat Detection",
    version="2.0.0",
    description=(
        "Serves malware detections raised by Halden's backup scanning pipeline. "
        "The `/v1` routes read a signed internal token from the `Authorization` "
        "header. halden-identity is the caller that issues those tokens."
    ),
)

app.include_router(scans.router)


@app.get("/healthz", tags=["ops"])
def healthz() -> dict[str, str]:
    return {"status": "ok"}
