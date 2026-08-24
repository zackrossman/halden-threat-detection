Consumer-side copy of the Halden internal service contract, owned by Platform Engineering.

# Halden internal service contract

Status: accepted · Owner: Platform Engineering · Applies to: services in the `halden` AKS namespace

## Edge authentication

`halden-identity` is the customer-facing service. It validates the caller's Auth0-issued
RS256 access token against the Auth0 JWKS endpoint. Other services do not perform
end-user authentication — token validation is centralised at the edge so that key
rotation and Auth0 tenant changes touch one service.

## Propagated identity headers

After validating the access token, `halden-identity` calls downstream services with:

| Header | Meaning | Set by |
|---|---|---|
| `X-Halden-Tenant-ID` | The tenant the request operates on, taken from the `https://halden.io/tenant_id` claim | `halden-identity` |
| `X-Halden-Gateway-Key` | Shared service-to-service credential identifying `halden-identity` as the caller | `halden-identity` |

Downstream services read the tenant from `X-Halden-Tenant-ID` and scope their reads and
writes to it. Downstream services reject requests that do not carry a matching
`X-Halden-Gateway-Key`.

## Telemetry headers

Forwarded from the caller for log correlation. These carry no authority:

- `X-Halden-Request-ID`
- `X-Halden-Client-Version`
- `X-Halden-Locale`

## Network position

`halden-identity` is the service we intend customer traffic to arrive through. Network
placement for every other service — ingress type, namespace policy, firewall rules — is
configured per service by the team that owns it, in that service's own infrastructure
repository.

## Open items

- Header propagation is implemented independently in each caller. We have discussed a
  shared client library but have not built one.
- There is no central check that a downstream service is only reachable through the
  gateway; each team configures its own network policy.
