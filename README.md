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

Every `/v1` route requires `Authorization: Bearer <token>`. The service checks
the signature, `exp`, `sub`, `iss` (`halden-identity`) and `aud`
(`halden-threat-detection`) before any route runs. A token that names no
subject is refused, so every audit record names a caller.

Tokens are signed **RS256** with halden-identity's private key and verified
against the PEM in `HALDEN_INTERNAL_TOKEN_PUBLIC_KEY`. This service holds only
the public half, so an attacker who reads everything it knows — its config, its
environment, its pod — still cannot mint a token.

No symmetric algorithm is accepted, and that is what makes the above true: the
only key this service holds is public, so an HS256 token verified against it
could be signed by anyone. The header's `alg` selects nothing; it is read only
to refuse anything that is not RS256.

The `tenant_id` claim is checked against `^[a-zA-Z0-9_-]+$` before it is used.
A verified token proves who minted it, not that the claim is a safe value, and
the id becomes both a query filter and a directory name in the artifact store.
The store repeats the check its own way, refusing any tenant id that does not
resolve to a single directory directly beneath the artifact root.

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
| `GET /v1/scans` | One page of detections for the caller's scope, plus counts by severity |
| `GET /v1/scans/{scan_id}` | One detection within the caller's scope |
| `GET /v1/scans/summary` | Detection totals and recent items for the caller's scope |
| `GET /healthz` | Liveness and readiness probe |

`GET /v1/scans` returns a page at a time. `limit` defaults to 100 and cannot
exceed 1000; `offset` walks through the pages. The response repeats the `limit`
and `offset` it used and reports `total`, the number of detections in the
caller's scope altogether, so a caller knows whether to ask for more.

The full schema is in [openapi.yaml](openapi.yaml).

## Transport

The service listens on `HALDEN_LISTEN_PORT` (8000 by default). Setting
`HALDEN_TLS_CERT_FILE` and `HALDEN_TLS_KEY_FILE` moves the listener to TLS,
conventionally on 8443. Both must be set together; one without the other is
refused at startup rather than falling back to plaintext, because a deployment
that set one meant to encrypt.

Setting `HALDEN_TLS_CLIENT_CA_FILE` additionally turns on mutual TLS. A caller
without a certificate signed by that CA is refused at the handshake, before any
request is read.

Requests carry bearer tokens in the `Authorization` header, so an unencrypted
hop exposes them to anything that can watch pod-to-pod traffic. TLS is off by
default only so the service can be deployed before certificates exist.

## Audit log

Authentication failures, refused scopes and every read are written to stdout as
one JSON object per line, which is what the cluster's log shipper collects.
Each record names the caller's `subject` and the `scope` the read ran under.
Tokens and secrets are never recorded. See [app/audit.py](app/audit.py).

## Run it

```sh
cp .env.example .env          # then set HALDEN_INTERNAL_TOKEN_PUBLIC_KEY and HALDEN_DATABASE_URL
pip install -r requirements.txt
python -m scripts.seed        # creates the schema and loads the demo tenants
uvicorn app.main:app --port 8000
```

The seed loads two tenants, `northwind` and `contoso`.

`HALDEN_INTERNAL_TOKEN_PUBLIC_KEY` and `HALDEN_DATABASE_URL` are both required
and have no defaults; the service will not start without them. A missing public
key fails at startup rather than refusing every request afterwards, so a
misconfigured rollout stops at the readiness probe instead of coming up healthy
and serving 401s. In the cluster both come from the
`halden-threat-detection-runtime` secret. `HALDEN_ARTIFACT_DIR` needs to be a
writable path; it is the only directory this service's own code writes to.
`HALDEN_QUERY_TIMEOUT_MS` bounds a single database statement and defaults to
5000.

`HALDEN_DATABASE_URL` must carry `sslmode=require` or stronger when it points at
Postgres. Detection records cross the cluster network, and libpq's default
(`prefer`) downgrades to an unencrypted connection without reporting it, so the
service refuses to start on a URL that permits plaintext rather than running
unencrypted.

In a container:

```sh
docker build -t halden/threat-detection:1.0.0 .
docker run --rm -p 8000:8000 \
  -e HALDEN_INTERNAL_TOKEN_PUBLIC_KEY -e HALDEN_DATABASE_URL \
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
app/audit.py             structured audit records
app/routers/scans.py     the detection routes
app/reporting/summary.py detection counts grouped by an internal dimension
app/storage/artifacts.py content-addressed artifact store
scripts/seed.py          demo data for northwind and contoso
```
