# SecurityISCs

This is the most important workflow in the skill. Threat lists are documents.
ISCs are testable acceptance criteria. The bridge between the two is a
deterministic translation table from threat shape to ISC string and
verification probe.

A PRD whose `## Criteria` section contains a flat list of ISCs lets the
Algorithm verify the build at every iteration. A PRD whose security section
contains only narrative does not. The goal of this workflow is to make the
translation mechanical so that two analysts produce the same ISC for the
same threat shape.

## ISC contract

A good ISC is:

- **Atomic** — one binary thing the build either does or does not do. If you
  cannot answer it with one tool probe, split it.
- **Tool-verifiable** — there exists a probe (curl, grep, query, scanner,
  unit test, fuzz harness) that returns pass or fail without human judgment.
- **Concrete** — names a specific endpoint, header, table, file, or
  configuration value. "Auth is good" is not concrete; "JWT verification
  rejects alg=none" is concrete.
- **Stable in language** — the same threat shape produces the same ISC
  string across runs of the workflow. Use the canonical phrasings below.
- **Bounded in surface** — phrased so that the build can satisfy it without
  having to satisfy unrelated criteria.

ISCs come in two flavors:

- **Positive ISC** — the system must do this thing.
  Format: `ISC-N: <thing>`
- **Anti-ISC** — the system must not do this thing.
  Format: `ISC-N: Anti: <thing>`

Roughly one in five ISCs in a security set is an Anti-ISC. Anti-ISCs are
where the build can drift over time as features get added; without them, the
suite passes by accumulation rather than by intent.

## Translation tables

Each table maps a category from STRIDE or MAESTRO to canonical threat
shapes, the ISC text those shapes produce, and the verification probe that
proves the ISC. Replace bracketed placeholders with the system's specifics.

### Spoofing → ISC

| Threat shape                                                         | ISC text                                                                              | Verification probe                                                       |
| -------------------------------------------------------------------- | ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| Attacker reuses session token after logout                           | `ISC-N: After logout, the prior JWT cannot access /api/me`                            | `curl -H "Authorization: Bearer $STALE" /api/me` expects HTTP 401        |
| JWT accepts alg=none                                                 | `ISC-N: JWT verification rejects alg=none and alg=HS256-with-public-key`              | Unit test forges JWT with alg=none; expects rejection                    |
| CSRF on state-changing endpoint                                      | `ISC-N: All state-changing endpoints require a same-site cookie or anti-CSRF token`   | Cross-origin POST without cookie expects HTTP 403                        |
| Magic-link token reused                                              | `ISC-N: Magic-link tokens are server-side single-use`                                 | Replay token after first use; expects HTTP 401                           |
| Long-lived static API key in client code                             | `ISC-N: Anti: Long-lived static API keys must not appear in client-shipped code`      | grep client bundle for known key prefixes; expects no match              |

### Tampering → ISC

| Threat shape                                                | ISC text                                                                                 | Verification probe                                                                  |
| ----------------------------------------------------------- | ---------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| SQL injection on search                                     | `ISC-N: Every SQL query is built via parameterized statements`                           | Lint forbids `f"{...}"` and `+` inside SQL; CI fails on match                       |
| Hidden form field rewrites price                            | `ISC-N: Server recomputes monetary totals from authoritative records, never from input`  | Submit checkout with mutated client-side price; server recomputes                   |
| Path traversal on file write                                | `ISC-N: File-write resolves the target path under a configured root and rejects escapes` | Send `../../etc/passwd`; expects HTTP 400                                            |
| TOCTOU on lock file                                         | `ISC-N: Locks are acquired and held via a single open file descriptor, not by name`      | Race test simulates rename between check and use; expects no double-acquire         |

### Repudiation → ISC

| Threat shape                                              | ISC text                                                                                 | Verification probe                                                                |
| --------------------------------------------------------- | ---------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| Admin action logs only the resource, not the actor        | `ISC-N: Every authenticated mutation produces an audit row with actor_id, ts, action`    | Trigger every mutation endpoint in test; assert audit row count incremented       |
| Audit log can be deleted by the application               | `ISC-N: Audit log is write-only from the application; reads gated by a separate role`    | Application role attempts DELETE on audit table; expects permission denied        |
| Webhook accepts events without signature                  | `ISC-N: Webhook handlers verify HMAC over the body before any state change`              | Send unsigned webhook; expects HTTP 401 and no DB row                              |
| Production accepts `--no-log` flag                        | `ISC-N: Anti: Production code paths must not include flags that disable audit logging`   | grep deployment manifest for known no-log flags; expects no match                 |

### Information Disclosure → ISC

| Threat shape                                                | ISC text                                                                                  | Verification probe                                                          |
| ----------------------------------------------------------- | ----------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| Sequential ID enumeration                                   | `ISC-N: Resource fetches authorize by tenant_id from the session, not from input`          | Bob requests Alice's resource by ID; expects HTTP 403                       |
| 500 leaks stack trace                                       | `ISC-N: Anti: Production 500 responses must not contain stack traces or framework versions` | Force 500; assert response body matches generic schema                      |
| Debug endpoint enabled in prod                              | `ISC-N: No debug endpoints respond in production builds`                                   | Hit known debug paths; expects 404                                          |
| Username timing oracle                                      | `ISC-N: Login timing variance between known and unknown users is < 5 ms over 100 trials`   | Statistical timing test in eval                                             |

### Denial of Service → ISC

| Threat shape                                              | ISC text                                                                                | Verification probe                                                            |
| --------------------------------------------------------- | --------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| Unbounded upload buffered in RAM                          | `ISC-N: Uploads stream to disk and reject requests exceeding the per-file cap`           | POST a payload above the cap; expects HTTP 413 before allocation             |
| Catastrophic regex backtracking                           | `ISC-N: Anti: User-supplied regex must not run on a backtracking engine`                  | Submit ReDoS pattern; assert request completes < 1 s                         |
| List endpoint returns all rows                            | `ISC-N: Every list endpoint enforces server-side limit ≤ 100 regardless of input`        | Request limit=10000; expect 100 rows in response                              |
| Email-send endpoint unbounded                             | `ISC-N: Email-send endpoints are rate-limited per email and per IP`                      | Burst 50 requests; expect 429 after threshold                                |

### Elevation of Privilege → ISC

| Threat shape                                              | ISC text                                                                                | Verification probe                                                            |
| --------------------------------------------------------- | --------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| Admin endpoint guarded by URL obscurity                   | `ISC-N: Every endpoint declares required_role in a single policy table`                  | Authenticate as low-priv user; hit admin path; expect HTTP 403                |
| user_id query param                                       | `ISC-N: Anti: No endpoint accepts a user_id input parameter that overrides the session` | grep route definitions for `user_id` query usage; expects no match            |
| Uploaded HTML interpreted at app origin                   | `ISC-N: User-uploaded files are served from a sandbox subdomain with attachment disposition` | Fetch uploaded `.html`; expect Content-Disposition: attachment header     |
| OAuth scope creep                                         | `ISC-N: OAuth scopes requested are the minimum required for the displayed feature set`   | Manual review of scope list against feature inventory                         |

### MAESTRO Foundation Models → ISC

| Threat shape                                              | ISC text                                                                                | Verification probe                                                            |
| --------------------------------------------------------- | --------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| Direct prompt injection in user input                     | `ISC-N: User content is wrapped in a delimited "untrusted data" envelope before insertion` | Eval set includes 100 known injection prompts; expect ≥ 95 % refusal       |
| Provider model upgrade changes refusal                    | `ISC-N: Every model call pins model_id and version; logs include both`                   | grep call sites for hardcoded model_id; assert version field present          |
| User content concatenated into system prompt              | `ISC-N: Anti: User content must not be concatenated into the system prompt slot`         | Code review of prompt builder; tests cover each slot                          |

### MAESTRO Data Operations → ISC

| Threat shape                                              | ISC text                                                                                | Verification probe                                                            |
| --------------------------------------------------------- | --------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| Indirect injection via retrieved web doc                  | `ISC-N: Retrieved content is wrapped in an "untrusted data" envelope before context insertion` | Eval set includes 50 poisoned documents; expect ≥ 95 % refusal of embedded directives |
| Vector store anonymous writes                             | `ISC-N: Vector store writes require an authenticated principal logged with provenance`   | Anonymous write attempt; expect rejection                                      |
| Tool call dispatched from retrieved text                  | `ISC-N: Anti: Retrieved text must not be parsed for tool-call directives`                 | Adversarial corpus runs; assert zero tool calls originate from retrieved text |

### MAESTRO Agent Frameworks → ISC

| Threat shape                                              | ISC text                                                                                | Verification probe                                                            |
| --------------------------------------------------------- | --------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| Remote tool description swapped between sessions          | `ISC-N: Tool schemas are loaded from a manifest pinned by SHA-256 verified at startup`   | Modify schema file; expect startup failure                                     |
| Free-form planner text dispatches tool                    | `ISC-N: Planner output is parsed into a typed plan; unparsed text never dispatches`      | Inject planner output that parses partially; expect dispatcher to refuse       |
| Tool dispatched with unknown argument                     | `ISC-N: Tool dispatcher validates arguments against a schema; unknown fields rejected`   | Send call with extra field; expect rejection                                   |

### MAESTRO Deployment & Infrastructure → ISC

| Threat shape                                              | ISC text                                                                                | Verification probe                                                            |
| --------------------------------------------------------- | --------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| Code-execution tool escapes sandbox                       | `ISC-N: Code-execution runs in a sandbox with no host bind mounts and an egress allow-list` | Test escape attempts (open `/etc/passwd`, dial unrelated host); expect denied |
| MCP binary unverified                                     | `ISC-N: MCP server binaries are pinned by checksum and verified before each session`     | Tamper binary; expect startup refusal                                         |
| World-writable hook script                                | `ISC-N: Anti: Hook scripts must not be writable by any user other than the deployer`     | `stat -c %a` on hook files; expect ≤ 0755                                     |

### MAESTRO Evaluation & Observability → ISC

| Threat shape                                              | ISC text                                                                                | Verification probe                                                            |
| --------------------------------------------------------- | --------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| Eval set silently mutated                                 | `ISC-N: Every eval run records the SHA-256 of the eval set and the model_id under test` | Eval log inspection; expect both fields present                                |
| Log injection via control characters                      | `ISC-N: Log writers escape control characters in any line containing user input`        | Submit user input with `\x1b[2J`; assert log contains escaped form             |

### MAESTRO Security & Compliance → ISC

| Threat shape                                              | ISC text                                                                                | Verification probe                                                            |
| --------------------------------------------------------- | --------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| Secret enters model context                               | `ISC-N: Secrets are referenced by handle in the model context; resolved server-side`     | grep prompt builder for env-var or `KEY` strings; expect no match              |
| Plaintext API key in logs                                 | `ISC-N: Anti: API keys must not appear in any log, including model-input logs`           | Output secret-scanner across log corpus; expect zero matches                   |

### MAESTRO Agent Ecosystem → ISC

| Threat shape                                              | ISC text                                                                                | Verification probe                                                            |
| --------------------------------------------------------- | --------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| Typo-squat skill installed                                | `ISC-N: Install documentation publishes the SHA-256 of the official skill bundle`        | Doc lint; expect SHA-256 reference present                                    |
| Cross-agent injected message accepted                     | `ISC-N: Cross-agent messages carry an origin label; consumers treat external as untrusted` | Test peer agent sending instruction-shaped payload; expect treated as data |

## How to drop ISCs into a PRD

Three concrete ISCs from the STRIDE worked example, reformatted for the
PRD's `## Criteria` section, with their corresponding Test Strategy rows.

### `## Criteria`

```
- [ ] ISC-1: Magic-link tokens are 256-bit cryptographically random and single-use.
- [ ] ISC-7: Magic-link request endpoint is rate-limited to 3 per email per hour and 10 per IP per hour.
- [ ] ISC-14: Anti: Production 500 responses must not contain stack traces, file paths, or framework versions.
```

### `## Test Strategy`

| ISC ID | Probe                                                                                              | Pass criterion                                                                       |
| ------ | -------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| ISC-1  | Unit test generates 1000 tokens, asserts entropy ≥ 256 bits and replays each: second use returns 401 | All 1000 are unique; replay returns 401                                              |
| ISC-7  | Burst 5 magic-link requests for the same email in 1 minute                                         | Requests 4 and 5 return HTTP 429 with `Retry-After`                                  |
| ISC-14 | Force a 500 by submitting a known-bad payload to a chosen endpoint                                 | Response body matches `{"error": "<generic>", "request_id": "<uuid>"}` schema only   |

The Algorithm or PRD-authoring agent paste these blocks directly. The
translation is reproducible: the same threat shape produces the same ISC
text on every run.
