"""halden-threat-detection service entrypoint."""

from fastapi import FastAPI

from app.routers import scans

app = FastAPI(
    title="Halden Threat Detection",
    version="1.0.0",
    description=(
        "Serves malware detections raised by Halden's backup scanning pipeline. "
        "Called by halden-identity; see docs/platform/inbound-request-contract.md."
    ),
)

app.include_router(scans.router)


@app.get("/healthz", tags=["ops"])
def healthz() -> dict[str, str]:
    return {"status": "ok"}
