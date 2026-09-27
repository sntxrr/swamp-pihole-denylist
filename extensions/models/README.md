# @sntxrr/pihole-denylist

Declare a Pi-hole v6 **exact-deny list** in swamp and converge an appliance to
it. Complements `@magistr/pihole`, which manages local DNS records but not the
deny list.

Why a deny entry rather than a `0.0.0.0` local record: a deny entry blocks
every query type (A, AAAA, HTTPS, ...), shows up as *blocked* in the query log,
and lives on a separate config surface from your service records, so tidying
those never removes it.

## Model: `@sntxrr/pihole-denylist`

| global argument | meaning |
|---|---|
| `host` | appliance, e.g. `192.0.2.53` or `dns.example.lan:8080` (may carry a scheme) |
| `password` | web/app password (sensitive; use a vault reference) |
| `scheme` | `http` (default) or `https` |
| `caCert` | optional inline PEM for a self-signed HTTPS appliance |
| `domains` | the declared exact-deny list (hostnames only; lower-cased and de-duplicated) |
| `comment` | written on entries the model adds or re-enables |
| `groups` | group ids for added entries (default `[0]`) |

| method | writes to the appliance? |
|---|---|
| `list` | never; records the current exact-deny entries as `deny-list` |
| `converge` | **only with `dryRun: false`**; records the plan and outcome as `converge-result` |

`converge` arguments:

- `dryRun` (default **true**): plan only. The plan lists `add`, `enable`
  (declared but disabled on the appliance), `unchanged`, `remove` and
  `unmanaged`.
- `prune` (default false): undeclared exact-deny entries are removed. Without
  it they are reported as `unmanaged` and left alone.
- `maxRemovals` (default 20): a prune that would remove more is refused before
  anything is written.

Only the **exact** deny list is read or written. Regex deny entries and allow
lists are never touched.

## Example

```yaml
# models/@sntxrr/pihole-denylist/<uuid>.yaml
type: '@sntxrr/pihole-denylist'
name: denylist-heron
globalArguments:
  host: 192.0.2.53
  password: ${{ vault.get(my-vault, "pihole/password") }}
  domains:
    - telemetry.example.com
    - update.vendor.example
```

```bash
swamp model method run denylist-heron converge                       # plan
swamp model method run denylist-heron converge --input dryRun=false  # apply
```

In a workflow, run one `converge` step per appliance with
`dryRun: false` and, for a fully declarative list, `prune: true`.

## Behaviour worth knowing

- Sessions follow the FTL contract: FTL answers `200` even on a wrong password,
  so `session.valid` is checked, and every session is released with
  `DELETE /api/auth` so the appliance's session limit is never exhausted.
- Adds go in one `POST` with the domain array. Per-domain errors from
  `processed.errors` are recorded individually and fail the method *after*
  the result is written, so a partial apply is visible, not silent.
- Password, session id and CSRF token are redacted from every error message.
- Over plain `http` the password crosses the network in cleartext; the method
  logs a warning. Prefer `https` or an encrypted tunnel.
