# STRIDE

Microsoft's STRIDE taxonomy for threat modeling traditional software. Six
categories: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of
Service, Elevation of Privilege. Use this workflow when the system is a
conventional web app, REST API, CLI, mobile app, or background service. For
LLM-driven systems use `MAESTRO.md` instead.

The output of this workflow is a threat table and a list of atomic ISCs. The
threat table goes into the PRD's Security section. The ISCs go into the PRD's
Criteria section via `SecurityISCs.md`.

## How to run STRIDE

1. Build a Data Flow Diagram first. Without a DFD you do not know which
   processes, stores, and flows you are reasoning about. Use
   `DataFlowDiagram.md`.
2. Walk every element on the DFD and ask the six STRIDE questions for each.
   Not every category applies to every element, but you must consider all six
   for every element so omissions are explicit.
3. For each identified threat, record: ID, category, threat shape, asset,
   impact, likelihood, mitigation pattern, residual risk.
4. Translate each threat to an ISC via `SecurityISCs.md`.

## S — Spoofing

Spoofing is the impersonation of a principal — a user, a service, a device, or
a process — so that the system treats the attacker as someone they are not. The
attacker forges or steals credentials, session tokens, signatures, or
identifiers and then operates under the assumed identity. Spoofing is an attack
on authentication.

### Generic web app

- Attacker uses a stolen session cookie from a public Wi-Fi packet capture to
  impersonate a logged-in user.
- Attacker registers a domain that visually resembles the application's domain
  and harvests credentials via a phishing page.
- Attacker exploits a missing CSRF token to issue authenticated state-changing
  requests on behalf of a logged-in victim.

### REST API

- Attacker reuses a long-lived API key leaked in a public GitHub commit to
  call privileged endpoints.
- Attacker forges a JWT after discovering the application accepts the
  `none` algorithm or a weak shared secret.
- Attacker performs a replay of a valid signed request whose nonce or
  timestamp is not validated server-side.

### CLI tool

- Attacker drops a same-named binary earlier on the user's `PATH` and
  intercepts credentials passed via argv.
- Attacker substitutes a malicious config file at a default location the CLI
  reads without integrity checking.
- Attacker performs an SSH agent hijack against a CLI that forwards
  authentication.

### Mitigation patterns

- Strong authentication for all principals. Passwords meet a tested strength
  policy; service-to-service traffic uses mutual TLS or signed tokens.
- Short-lived bearer tokens with rotation; refresh tokens bound to a device
  or session fingerprint.
- Anti-CSRF tokens or `SameSite=Strict` cookies on all state-changing
  endpoints.
- Replay protection via nonces, monotonic timestamps, or signed request
  envelopes.
- Credentials never accepted via argv on multi-user systems; CLI reads from
  stdin, files with `0600` permissions, or OS keychain.
- Domain and certificate transparency monitoring to catch lookalike domains
  early.

### Map to ISC

```
ISC-N: All session cookies are flagged Secure, HttpOnly, SameSite=Strict.
ISC-N: JWT verification rejects alg=none and alg=HS256-with-public-key.
ISC-N: Anti: Long-lived static API keys must not appear in client-shipped code.
```

## T — Tampering

Tampering is the unauthorized modification of data — in flight, at rest, or in
memory — so that downstream consumers act on values the attacker chose. The
attacker's goal is to change state without authorization. Tampering attacks
integrity.

### Generic web app

- Attacker modifies a hidden form field on a checkout page to change the
  shipping address after price calculation.
- Attacker injects a payload via a stored XSS that rewrites the DOM of every
  subsequent visitor.
- Attacker swaps a signed JWT body but keeps the original signature, hoping
  the server only validates structure.

### REST API

- Attacker modifies a `userId` path parameter to escalate the action to
  another tenant.
- Attacker performs SQL injection through an unparameterized search filter to
  alter records belonging to other users.
- Attacker tampers with a `Content-Type` header to coerce the server into
  parsing untrusted JSON as YAML with code execution.

### CLI tool

- Attacker writes to a world-writable lock file the CLI uses to coordinate
  state between invocations.
- Attacker modifies a cached download artifact on disk between integrity
  checks (TOCTOU).
- Attacker injects shell metacharacters into an argument the CLI passes to
  `system()` without escaping.

### Mitigation patterns

- All persisted data crosses a parameterized boundary. SQL via prepared
  statements, NoSQL via parameterized clients, shell via argv arrays not
  string concatenation.
- All user-controlled data is treated as untrusted input. Input validation
  happens at trust boundaries, output encoding happens at sinks.
- All cryptographic state (tokens, signatures, MACs) is verified before any
  field inside it is read.
- Files written by the CLI live in user-private directories with `0600` /
  `0700` permissions; lock files include a process owner check.
- Time-of-check / time-of-use issues collapsed by holding file descriptors
  open from check to use, or by atomic rename.

### Map to ISC

```
ISC-N: Every SQL query is built via parameterized statements; concatenation rejected by lint.
ISC-N: All authenticated mutations re-authorize the resource by tenant ID server-side.
ISC-N: Anti: User-controlled strings must not appear unescaped in shell, SQL, or HTML sinks.
```

## R — Repudiation

Repudiation is the ability of a principal to plausibly deny an action they
performed. The attacker's goal is not technical compromise but legal or
operational deniability — the audit trail does not prove who did what.
Repudiation attacks accountability.

### Generic web app

- Attacker exploits an admin action endpoint that does not log the actor,
  leaving only the affected resource in the audit log.
- Attacker logs in via an SSO link sharing a session with another user; logs
  show the wrong identity for the action.
- Attacker performs a destructive action and then deletes the audit log
  before backups run.

### REST API

- Attacker uses a service account whose key is shared between three engineers
  to execute a deletion; the log records the service, not the human.
- Attacker triggers an action via a webhook whose signature is not verified;
  any party who knows the URL could have caused the event.
- Attacker performs a chain of micro-actions, each individually under the
  audit threshold, that aggregate to the policy-violating action.

### CLI tool

- Attacker uses a CLI that does not log to a server and only writes to local
  rotated files an attacker can prune.
- Attacker invokes the CLI with `--quiet --no-log` flags that disable the
  audit feed.
- Attacker tampers with the local clock so that audit records are written
  with implausible timestamps.

### Mitigation patterns

- Every state-changing action emits an audit event with: actor, time,
  resource, before-state, after-state, request ID.
- Audit events are written to an append-only sink (signed log, WORM bucket,
  syslog forwarder) the actor cannot delete.
- Service accounts are per-purpose, never shared between humans; human
  actions traverse SSO with audited identity.
- Webhook payloads validated by HMAC over the body with a per-tenant key
  before any state change is applied.
- Audit timestamps come from a trusted time source (NTP-disciplined server
  clock, not local user clock).
- Rate-limiting and aggregation alerts catch sub-threshold action chains.

### Map to ISC

```
ISC-N: Every authenticated mutation produces an audit row with actor_id, ts, resource_id, action.
ISC-N: Audit log is write-only from the application; only a separate role can read or rotate it.
ISC-N: Anti: Production code paths must not include flags that disable audit logging.
```

## I — Information Disclosure

Information disclosure is the exposure of data to a principal who is not
authorized to see it. The attacker's goal is to read what they should not be
able to read. Disclosure attacks confidentiality.

### Generic web app

- Attacker enumerates sequential resource IDs on a `/invoice/123` URL and
  reads other tenants' invoices.
- Attacker reads detailed stack traces returned in production error
  responses, learning the framework, ORM, and file paths.
- Attacker views a debug endpoint left enabled in production that prints
  environment variables including secrets.

### REST API

- Attacker uses a verbose `?include=*` query parameter that joins through to
  fields the caller has no claim to.
- Attacker reads response timing differences to infer whether a username
  exists in the user table.
- Attacker scrapes a paginated list endpoint that does not filter by tenant
  and returns global rows.

### CLI tool

- Attacker reads the CLI's debug log written to `/tmp` with world-readable
  permissions, recovering bearer tokens.
- Attacker inspects the OS process list and sees credentials passed via
  argv.
- Attacker reads the CLI's history file (`.bash_history`,
  `.zsh_history`) that captured a `--password` flag.

### Mitigation patterns

- All resource access is authorized by tenant or owner ID, evaluated
  server-side, after authentication.
- Errors returned to clients are generic; full traces are logged server-side
  with a correlation ID the client may quote.
- No debug endpoints in production. If they exist, they require a separate
  authentication and are denied at the network layer.
- Field-level filtering on responses; the client cannot expand to fields not
  on its allowed-list.
- Constant-time string comparison on identifiers used in lookup paths
  vulnerable to timing oracles.
- CLI never accepts secrets via argv; reads from stdin, file with `0600`,
  or OS keychain.

### Map to ISC

```
ISC-N: All resource fetches join on tenant_id from the authenticated session, not from input.
ISC-N: Production error responses contain no stack traces, file paths, or framework versions.
ISC-N: Anti: Secrets must not be passed via argv on multi-user systems.
```

## D — Denial of Service

Denial of service is the consumption of finite resources — CPU, memory,
storage, network, money — at a rate or volume that prevents legitimate use.
The attacker's goal is unavailability or financial pain. DoS attacks
availability.

### Generic web app

- Attacker submits a large file upload that the server buffers entirely in
  memory before validating size.
- Attacker requests a regex-backed search endpoint with a pathological input
  that triggers catastrophic backtracking.
- Attacker performs a slowloris attack holding many partial connections open
  on a non-buffered server.

### REST API

- Attacker calls an unbounded list endpoint with `?limit=1000000` and the
  server complies.
- Attacker abuses an expensive aggregation endpoint at high concurrency,
  exhausting database connection pools.
- Attacker sends crafted JSON with deep nesting that causes the parser to
  exceed stack limits.

### CLI tool

- Attacker provides an input file that causes the CLI to allocate `O(n^2)`
  memory in n.
- Attacker symlinks the CLI's output path to `/dev/full` so writes fail
  unpredictably.
- Attacker provides a malformed config that triggers an infinite retry loop
  with no backoff.

### Mitigation patterns

- All inputs have explicit size limits enforced before parsing. Streaming
  parsers preferred for media.
- All endpoints have per-user and per-IP rate limits with exponential backoff
  on burst.
- All list endpoints enforce a hard maximum `limit` parameter and require
  pagination.
- All regex inputs come from trusted sources or use a non-backtracking engine
  (RE2, Hyperscan).
- Connection pools, query timeouts, and circuit breakers configured for
  every downstream dependency.
- CLI implements exponential backoff with maximum retries and a global
  timeout.

### Map to ISC

```
ISC-N: All file uploads streamed to disk with a hard size cap before further processing.
ISC-N: Every list endpoint enforces limit ≤ 100 server-side regardless of input.
ISC-N: Anti: Untrusted regex must not run on the application's regex engine if it is backtracking.
```

## E — Elevation of Privilege

Elevation of privilege is the acquisition of a capability the attacker did
not have. The attacker starts as an unauthenticated user, an authenticated
low-privilege user, or a tenant member, and ends with capabilities reserved
for higher-privilege principals. EoP attacks authorization.

### Generic web app

- Attacker calls an admin-only endpoint that is gated by URL path obscurity
  rather than role check.
- Attacker exploits insecure direct object reference to perform actions on
  another tenant's resources.
- Attacker uploads a file whose extension passes the deny-list but whose
  content is interpreted as a server-side script.

### REST API

- Attacker exploits a missing role check on a "soft" admin action (export,
  copy, share) that is technically a read but operationally a privilege
  escalation.
- Attacker exploits a race between role assignment and request handling to
  gain a role mid-request.
- Attacker uses an OAuth scope creep where an integration was granted broad
  scopes for a narrow purpose.

### CLI tool

- Attacker exploits a CLI's `sudo`-prompted subcommand that re-uses the
  cached `sudo` token longer than expected.
- Attacker exploits a setuid CLI binary that executes a child process
  inheriting privileges.
- Attacker exploits a privilege boundary blur where the CLI reads its config
  from a path the unprivileged user can write.

### Mitigation patterns

- Authorization decisions made by a single, central, server-side policy
  layer. Every endpoint declares the role and resource it requires.
- Object access verified by ownership or tenancy joined from the
  authenticated session, never from input.
- File uploads stored outside the document root, served via a controller
  that does not interpret content.
- OAuth scopes minimized; expansions require a fresh consent flow.
- Setuid avoided. When necessary, the privileged code is a small,
  audited core; the rest runs unprivileged.
- Privileged config files owned by root and `0600`; user-writable inputs are
  validated, not trusted.

### Map to ISC

```
ISC-N: Every endpoint declares required_role and required_resource in a single policy table.
ISC-N: Uploaded files are served via a controller that sets Content-Type explicitly and X-Content-Type-Options: nosniff.
ISC-N: Anti: No production endpoint relies on URL path obscurity for access control.
```

---

## Worked example: STRIDE for a Python web API with magic-link auth and user file upload

System under analysis: a Python web API exposing a REST surface. Authentication
is by magic link (one-time link emailed to the user). Authenticated users can
upload files which are stored in object storage and listed back to the user.
There is a Postgres database and an S3-compatible bucket. There is no
multi-tenancy; each user owns their own data.

### Threat table

| ID | Category | Threat | Asset | Impact | Likelihood | Mitigation | Residual |
| --- | --- | --- | --- | --- | --- | --- | --- |
| T-01 | Spoofing | Magic-link token leaked in URL appears in browser history and HTTP `Referer` headers | User identity | High | Medium | Single-use, short-TTL, server-deletes-on-use, `Referrer-Policy: no-referrer` | Low |
| T-02 | Spoofing | Magic-link token guessable due to insufficient entropy | User identity | High | Low | 256-bit cryptographic random; rate-limited validation | Low |
| T-03 | Tampering | Multipart upload modifies fields after price/quota calc | Quota integrity | Medium | Medium | Atomic transaction; quota counted from object-storage truth, not request | Low |
| T-04 | Tampering | SQL injection via unparameterized `?q=` search | DB integrity | High | Low | Prepared statements, asyncpg parameter binding | Low |
| T-05 | Repudiation | File deletion endpoint logs only object key, not actor | Audit trail | Medium | High | Audit row per delete with actor_id, ts, key, before-size | Low |
| T-06 | Repudiation | Magic-link login does not record IP or user agent | Audit trail | Medium | High | Login event row with ip, ua, ts | Low |
| T-07 | Information Disclosure | List endpoint returns globally listed objects when bucket prefix omitted | User data | High | Low | Bucket prefix enforced server-side from session user_id | Low |
| T-08 | Information Disclosure | Direct S3 URLs returned to client expose the bucket key namespace | User data | Medium | Medium | Pre-signed URLs scoped to single object, short TTL | Low |
| T-09 | Information Disclosure | Production tracebacks exposed via 500 responses | System internals | Medium | Medium | Generic 500 + correlation ID; full trace server-side only | Low |
| T-10 | Denial of Service | Attacker uploads 10 GB file, server buffers in RAM | Availability | High | Medium | Streaming upload with hard cap (e.g. 100 MB) before parsing | Low |
| T-11 | Denial of Service | Magic-link request endpoint allows unbounded email send | Email reputation, $ | Medium | High | Per-IP and per-email rate limit; daily cap | Low |
| T-12 | Denial of Service | Search regex from user input runs in backtracking engine | Availability | High | Low | RE2-style non-backtracking engine, or whitelist | Low |
| T-13 | Elevation of Privilege | List endpoint accepts `user_id` query param and returns that user's files | User data | High | Low | user_id derived from session, not input | Low |
| T-14 | Elevation of Privilege | Uploaded HTML file served from same origin runs scripts in app context | User session | High | Medium | Files served from a sandbox subdomain with `Content-Disposition: attachment` | Low |

### ISCs ready for the PRD's `## Criteria` section

```
- [ ] ISC-1: Magic-link tokens are 256-bit cryptographically random and single-use.
- [ ] ISC-2: Magic-link tokens have a server-enforced TTL of ≤ 10 minutes.
- [ ] ISC-3: Magic-link validation endpoint is rate-limited to 5 attempts per token.
- [ ] ISC-4: Every API page sets Referrer-Policy: no-referrer.
- [ ] ISC-5: Every SQL query is constructed via parameterized statements; string concatenation in queries fails CI lint.
- [ ] ISC-6: File-upload endpoint streams to disk and rejects requests exceeding 100 MB before further parsing.
- [ ] ISC-7: Magic-link request endpoint is rate-limited to 3 per email per hour and 10 per IP per hour.
- [ ] ISC-8: Search input is matched by a non-backtracking regex engine or via a whitelist.
- [ ] ISC-9: List-files endpoint derives user_id from the authenticated session, never from input.
- [ ] ISC-10: Every file delete writes an audit row with actor_id, timestamp, object_key, prior_size.
- [ ] ISC-11: Every login event writes a row with user_id, timestamp, ip, user_agent.
- [ ] ISC-12: Object URLs returned to clients are pre-signed with TTL ≤ 5 minutes and scoped to a single object key.
- [ ] ISC-13: Uploaded user files are served from a sandbox subdomain with Content-Disposition: attachment.
- [ ] ISC-14: Anti: Production 500 responses must not contain stack traces, file paths, or framework versions.
- [ ] ISC-15: Anti: No endpoint accepts a user_id input parameter that overrides the session user.
- [ ] ISC-16: Anti: User-uploaded files must not be served from the primary application origin.
```

The companion Test Strategy rows are produced by `SecurityISCs.md`.

---

Cited: <https://learn.microsoft.com/en-us/security/engineering/stride>
