# halden-threat-detection

Serves the malware detections that Halden's backup scanning pipeline raises
against customer data. Each detection records the protected resource, the
malware family, a severity, when it was seen, and where it is in the
remediation workflow.

## Position in the platform

`halden-identity` is the caller: it takes customer traffic, validates the Auth0
access token, and calls this service with a short-lived signed token. This
service verifies that token and reads detections for the scope the token
carries. It runs in the `halden` namespace on port 8000.

## Authentication

Every `/v1` route requires `Authorization: Bearer <token>`. The token is an
HS256 JWT signed with `HALDEN_INTERNAL_TOKEN_SECRET`; the service checks the
signature, `exp`, `iss` (`halden-identity`) and `aud` (`halden-threat-detection`)
before any route runs.

The verified token resolves a read scope:

- a token carrying `tenant_id` reads that tenant's detections;
- a token carrying the `platform:aggregate` scope reads across the estate — this
  is the scope the nightly rollup runs with;
- a token carrying neither is rejected.

`X-Halden-Request-ID`, `X-Halden-Client-Version` and `X-Halden-Locale` are
forwarded for log correlation and carry no authority.

## API

| Route | Purpose |
|---|---|
| `GET /v1/scans` | Detections for the caller's scope, plus counts by severity |
| `GET /v1/scans/{scan_id}` | One detection within the caller's scope |
| `GET /v1/scans/summary` | Detection totals and recent items for the caller's scope |
| `GET /healthz` | Liveness and readiness probe |

The full schema is in [openapi.yaml](openapi.yaml).

## Run it

```sh
cp .env.example .env          # then set HALDEN_INTERNAL_TOKEN_SECRET and HALDEN_DATABASE_URL
pip install -r requirements.txt
python -m scripts.seed        # creates the schema and loads the demo tenants
uvicorn app.main:app --port 8000
```

The seed loads two tenants, `northwind` and `contoso`.

`HALDEN_INTERNAL_TOKEN_SECRET` and `HALDEN_DATABASE_URL` are both required and
have no defaults; the service will not start without them. In the cluster they
come from the `halden-threat-detection-runtime` secret. `HALDEN_ARTIFACT_DIR`
needs to be a writable path; it is the only directory this service's own code
writes to.

In a container:

```sh
docker build -t halden/threat-detection:1.0.0 .
docker run --rm -p 8000:8000 \
  -e HALDEN_INTERNAL_TOKEN_SECRET -e HALDEN_DATABASE_URL \
  halden/threat-detection:1.0.0
```

## Tests

```sh
python -m pytest -q
```

The suite runs against in-memory SQLite and covers token verification, read
scoping, the summary route, the reporting counts, and the artifact store.

## Layout

```
app/auth.py              token verification and read-scope resolution
app/routers/scans.py     the detection routes
app/reporting/summary.py detection counts grouped by an internal dimension
app/storage/artifacts.py content-addressed artifact store
scripts/seed.py          demo data for northwind and contoso
```
