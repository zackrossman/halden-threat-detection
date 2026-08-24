# halden-threat-detection

Serves the malware detections that Halden's backup scanning pipeline raises
against customer data. Each detection records the protected resource, the
malware family, a severity, when it was seen, and where it is in the
remediation workflow.

## Position in the platform

`halden-identity` is the caller. It takes customer traffic, validates the Auth0
access token, and calls this service with the tenant in `X-Halden-Tenant-ID`
plus the shared `X-Halden-Gateway-Key`. This service runs in the `halden`
namespace on port 8000.

The contract both services follow is in
[docs/platform/inbound-request-contract.md](docs/platform/inbound-request-contract.md).

## API

| Route | Purpose |
|---|---|
| `GET /v1/scans` | Detections for the tenant in `X-Halden-Tenant-ID`, plus counts by severity |
| `GET /v1/scans/{scan_id}` | One detection, matched on that tenant and the id |
| `GET /healthz` | Liveness and readiness probe |

`X-Halden-Tenant-ID` and `X-Halden-Gateway-Key` are required on both `/v1/scans`
routes. `X-Halden-Request-ID`, `X-Halden-Client-Version` and `X-Halden-Locale`
are forwarded for log correlation and carry no authority. The full schema is in
[openapi.yaml](openapi.yaml).

## Run it

```sh
cp .env.example .env          # then set HALDEN_GATEWAY_KEY and HALDEN_DATABASE_URL
pip install -r requirements.txt
python -m scripts.seed        # creates the schema and loads the demo tenants
uvicorn app.main:app --port 8000
```

The seed loads two tenants, `northwind` and `contoso`.

`HALDEN_GATEWAY_KEY` and `HALDEN_DATABASE_URL` are both required and have no
defaults; the service will not start without them. In the cluster they come from
the `halden-threat-detection-runtime` secret. `HALDEN_ARTIFACT_DIR` needs to be a
writable path — it is the only directory the service writes to, so the rest of the
filesystem can be mounted read-only. Extra `HALDEN_`-prefixed variables are
ignored, so the deployment can pass additional environment metadata.

```sh
curl -H "X-Halden-Tenant-ID: northwind" \
     -H "X-Halden-Gateway-Key: $HALDEN_GATEWAY_KEY" \
     http://localhost:8000/v1/scans
```

In a container:

```sh
docker build -t halden/threat-detection:1.0.0 .
docker run --rm -p 8000:8000 \
  -e HALDEN_GATEWAY_KEY -e HALDEN_DATABASE_URL \
  halden/threat-detection:1.0.0
```

## Tests

```sh
python -m pytest -q
```

The suite runs against in-memory SQLite and covers tenant scoping, the gateway
key check, the summary queries, and the artifact store.

## Layout

```
app/deps.py              gateway key check and tenant resolution
app/routers/scans.py     the two tenant-scoped routes
app/reporting/summary.py detection counts grouped by an internal dimension
app/storage/artifacts.py content-addressed artifact store
scripts/seed.py          demo data for northwind and contoso
```
