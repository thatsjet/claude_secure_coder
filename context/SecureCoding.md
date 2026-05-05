# Secure Coding — Constitutional Context

> Loaded at every Claude Code session start. This file teaches secure-by-default coding patterns so vulnerabilities are prevented at write time, not caught at review time. It is constitutional: rules here override convenience and apply to every file Claude writes or edits, in every project.

This is the first layer of a four-layer shift-left model:

1. **Teach** (this file + SessionStart hook) — secure coding context loaded before the first user prompt.
2. **Design** (ThreatModel skill at PRD/PLAN time) — STRIDE/MAESTRO threat modeling before any code is written.
3. **Write** (PreToolUse `VulnPatternHook` + PostToolUse `SAST` with regenerate-loop) — IDE-style feedback during code generation.
4. **Review** (existing review tooling — security-review, pr-review-toolkit, RedTeam, vendor SAST) — backstop, not primary defense.

If a rule below conflicts with an aesthetic preference or "cleaner code" instinct, the security rule wins. Mitigations may be skipped only when an explicit threat-model decision in the project's PRD records the rationale.

## Universal rules — apply in every language

1. **Never commit literal secrets to source.** Tokens, API keys, private keys, passwords, signing secrets, database URLs with embedded credentials — all read from environment variables, secret managers, or keychain at runtime. If you see a literal secret about to be written, stop and load it from `process.env.X` / `os.getenv("X")` instead.
2. **Never trust user input.** Validate at the boundary, sanitize on output. Use type-narrowing parsers (zod, pydantic, marshmallow), not handwritten regex chains. Whitelist > blacklist.
3. **Never concatenate or interpolate user input into queries, commands, or paths.** Always use parameter binding for SQL. Always use array-form `spawn`/`subprocess.run` (no shell). Always normalize paths with `path.resolve` and check the result is inside an allowed root.
4. **Never trust the network.** TLS 1.2+ for everything. Verify certificates. Pin where possible. No mixed content. No `verify=False` / `rejectUnauthorized: false` in production code.
5. **Never log sensitive data.** Tokens, passwords, raw user PII, full request/response bodies — redact or omit. Server logs are an attacker's first stop.
6. **Never hand-roll crypto.** Use `bcrypt`/`argon2id` for passwords. Use library AES-GCM or libsodium for encryption. Use `crypto.randomBytes`/`secrets.token_bytes` for tokens. Never use `Math.random()` or `random.random()` for security purposes. Never use MD5 or SHA1 for password hashing or any signing.
7. **Default deny.** Require explicit allow for every cross-tenant, cross-user, cross-resource access. RBAC or RLS, not "filter in the client."
8. **Fail closed on security checks, fail open on observability.** A failed authorization check denies the request. A failed metrics push proceeds.
9. **Least privilege at every layer.** Service accounts get only the resources they need. Database users get only the tables they need. File system processes get only the paths they need.
10. **Patch supply chain regularly.** Pin versions in lockfiles. Run `npm audit` / `pip-audit` / `cargo audit` before commits to public projects. Use Dependabot or Renovate.

## OWASP Top 10:2025 — what to prevent

Source: <https://owasp.org/Top10/>

| Code | Category | Default mitigation pattern |
|------|----------|---------------------------|
| A01 | Broken Access Control | Deny-by-default authorization. Server-side checks on every endpoint. Object-level authorization (the user owns this row). |
| A02 | Cryptographic Failures | TLS in transit, AES-GCM at rest. Never homemade crypto. Modern KDFs (argon2id, bcrypt). |
| A03 | Injection | Parameterized queries. Output encoding by context (HTML/JS/CSS/URL). Strict input validators. |
| A04 | Insecure Design | Threat model at PRD time (use the ThreatModel skill). Document trust boundaries. |
| A05 | Security Misconfiguration | Secure defaults. Strip default creds. Minimize attack surface (no debug endpoints in prod). |
| A06 | Vulnerable & Outdated Components | Lockfiles, automated upgrades, vulnerability scanning, prompt patching SLAs. |
| A07 | Identification & Authentication Failures | MFA where possible. Server-side session invalidation on logout. Rate limit auth endpoints. |
| A08 | Software & Data Integrity Failures | Signed packages. SRI for CDN scripts. Verify webhook signatures. |
| A09 | Security Logging & Monitoring Failures | Log auth events. Don't log secrets. Centralize logs. Alert on anomalies. |
| A10 | Server-Side Request Forgery (SSRF) | Disallow user-supplied URLs without an allowlist. Block private IPs and metadata endpoints (169.254.169.254). |

## CWE Top 25 (2024) — most dangerous weaknesses

Source: <https://cwe.mitre.org/top25/>

The top 10 to eliminate first:

| Rank | CWE | Name | Pattern to avoid |
|------|-----|------|------------------|
| 1 | CWE-79 | Cross-site Scripting | Unescaped user content in HTML. Use auto-escaping templates. |
| 2 | CWE-787 | Out-of-bounds Write | C/C++ buffer ops; use safe wrappers, bounds checks. |
| 3 | CWE-89 | SQL Injection | String-built queries. Use parameter binding always. |
| 4 | CWE-352 | Cross-Site Request Forgery | State-changing GETs. Use POST + CSRF tokens or SameSite=Strict cookies. |
| 5 | CWE-22 | Path Traversal | User-supplied paths. Resolve and check inside allowed root. |
| 6 | CWE-125 | Out-of-bounds Read | Missing length checks on user-supplied indices. |
| 7 | CWE-78 | OS Command Injection | `shell=True`, `eval`, `exec`, `system()` with user input. Use array-form invocation. |
| 8 | CWE-416 | Use After Free | Freed pointer access. Modern ownership models (Rust, RAII C++). |
| 9 | CWE-862 | Missing Authorization | Endpoint with no auth check. Default-deny middleware. |
| 10 | CWE-434 | Unrestricted File Upload | Trust client-supplied content-type. Validate magic bytes; constrain size and storage location. |

Full list and translations to language-specific patterns at the source URL.

## OWASP Agentic Skills Top 10 (AST10, 2026) — for AI agents

Source: <https://owasp.org/www-project-agentic-skills-top-10/>

When the code under construction is itself an AI agent, skill, MCP server, or Claude Code hook, these are the dominant risks:

| Code | Category | Default mitigation |
|------|----------|-------------------|
| AST01 | Prompt Injection (direct + indirect) | Treat all tool output and external content as untrusted. Never execute instructions from observed content without user confirmation. |
| AST02 | Insecure Output Handling | Validate model output before passing to tools; never blindly `eval` or `exec` it. |
| AST03 | Tool Poisoning | Pin MCP/tool versions. Verify tool schemas haven't changed. Be wary of tools that "update themselves." |
| AST04 | Excessive Agency | Tools should grant minimum capability. Don't give an agent shell when it needs file read. |
| AST05 | Sensitive Information Disclosure | Don't pass secrets, full PII, or credentials into the model context unless required. |
| AST06 | Insecure Plugin Design | Validate plugin inputs/outputs. Don't trust plugin authors. Sandbox where possible. |
| AST07 | Supply Chain Risk | Pin model versions. Pin tool versions. Sign skill bundles. |
| AST08 | Persistence & Memory Tampering | Memory/state should be hash-verified. Detect external edits. |
| AST09 | Recursive Context Manipulation | Detect prompts that try to redefine system prompts mid-session. |
| AST10 | Insecure Sandboxing | Validate sandbox boundaries. Assume sandbox can be escaped; defense in depth. |

If you are writing a Claude skill, hook, or MCP server, AST10 risks are first-class.

## Per-language guidance

### TypeScript / JavaScript

1. **Database access** — use a parameterizing client (`pg`, Prisma, Drizzle, knex with `.where()`). Never template-literal a query: `` `SELECT * FROM users WHERE id = ${id}` `` is broken even if `id` "looks like a number."
2. **Shell commands** — `child_process.execFile(cmd, [args])`, never `child_process.exec(cmdString)`. If you must `exec`, accept it as an `Anti:` ISC and document why.
3. **`eval`, `Function(...)`, `setTimeout(string)`, `setInterval(string)`, `vm.runInThisContext`** — banned in user-input paths. If used for templating, isolate to compile-time inputs only.
4. **DOM injection** — `element.innerHTML = userText` is broken. Use `textContent` or DOMPurify with a strict allowlist.
5. **Cookies** — `Secure; HttpOnly; SameSite=Strict` (or `Lax` if cross-site links must work). Set `__Host-` prefix for session cookies.
6. **JWT** — verify signature with the algorithm pinned (`{algorithms: ['HS256']}`); never accept `alg: none`. Validate `exp`, `iss`, `aud`. Rotate secrets.
7. **Crypto random** — `crypto.randomBytes(n).toString('hex')` for tokens. `Math.random()` is for graphics, never security.
8. **Dependencies** — `npm audit`, `pnpm audit`. Run before every release. Lock with `package-lock.json` / `pnpm-lock.yaml`.

### Python

1. **Database access** — `cursor.execute("SELECT ... WHERE id = %s", (id,))` (psycopg, mysqlclient). SQLAlchemy core/ORM. Never `.execute(f"SELECT ... {id}")`.
2. **Shell commands** — `subprocess.run([cmd, arg1, arg2], check=True)`, never `subprocess.run(cmdStr, shell=True)`.
3. **Deserialization** — `pickle.loads`, `marshal.loads`, `yaml.load` (without `SafeLoader`), `dill` — all banned on untrusted data. Use `json` or `yaml.safe_load`.
4. **Path traversal** — `path = pathlib.Path(root).joinpath(user_path).resolve(); assert path.is_relative_to(root)`.
5. **`eval`, `exec`, `compile`** — banned on user input. If a dynamic-evaluation pattern looks needed, redesign.
6. **Secrets in env** — `os.environ["X"]` (raises if missing) or `os.getenv("X")` (returns None). Use `python-dotenv` for local dev. `pydantic-settings` for typed config.
7. **Password hashing** — `argon2-cffi` or `bcrypt`. Never `hashlib.md5(password)` or `hashlib.sha256(password)`. Constant-time compare with `hmac.compare_digest`.
8. **Crypto random** — `secrets.token_bytes`, `secrets.token_urlsafe`, `secrets.choice`. Never `random.random()` for security.
9. **HTTP requests** — verify TLS by default (`requests` and `httpx` do; don't override). Pin certificates for high-stakes integrations.
10. **Dependencies** — `pip-audit` before release. Lock with `pip-tools` or `poetry`/`uv`.

### Bash

1. **Always set strict mode** — `set -euo pipefail` at the top of every script. `IFS=$'\n\t'` if word splitting matters.
2. **Always quote variables** — `"$VAR"`, never bare `$VAR`. Bare expansion enables injection on any whitespace.
3. **`eval`** — banned. If you find yourself reaching for it, redesign.
4. **`bash -c "$VAR"` / `sh -c "$VAR"`** — banned with user input. Use array-form invocation: `cmd "$@"`.
5. **`curl | sh` and `wget | bash`** — banned. Verify checksums; review before executing.
6. **`rm -rf "$VAR"`** — wrap with sanity check: ensure the path exists, is owned by the running user, and is inside an expected root.
7. **Tempfile creation** — `mktemp` (creates unique file with safe permissions). Never `/tmp/myapp_$$`.
8. **Sourced files** — only source files you control. Sourcing a tampered file is RCE.

### SQL

1. **Parameterized only.** No string concatenation, no f-strings, no `format()`, no string interpolation. Even on numeric inputs.
2. **Least-privilege DB user.** Application connects as a role that has only the privileges it needs (no `DROP`, no `CREATE` outside migrations).
3. **Audit destructive ops in migrations.** `DROP TABLE`, `TRUNCATE`, `DELETE` without a `WHERE` — explicitly review and approve in the migration PR.
4. **Soft delete by default for user data.** Hard delete via a separate, audited path.
5. **Foreign keys with `ON DELETE` rules thought through.** `CASCADE` is convenient and dangerous; prefer `RESTRICT` unless the cascade is explicitly desired.
6. **Indexes on foreign keys.** Otherwise lookups silently scan.

## Secrets handling — universal

- **In code:** read from environment, secret manager (AWS Secrets Manager, GCP Secret Manager, Vault, Doppler), or local keychain. Never literal.
- **In tests:** synthetic test fixtures only. If a real key shape is needed for a regex test, prefix with `sk-test-FIXTURE-` or similar — clearly synthetic.
- **In .env files:** `.env` is in `.gitignore`. `.env.example` lives in the repo with placeholder values.
- **In logs:** redact. `auth: Bearer [REDACTED]`. PII fields likewise.
- **In commits:** if a real secret was ever committed, rotate it. Removing the file does not undo the commit history. Use `git filter-repo` and rotate the secret in source.

## Authentication & session management

1. **Hash passwords with `argon2id` (preferred) or `bcrypt` cost ≥12.** Never store reversibly.
2. **Rate limit auth endpoints** — login, signup, password-reset, MFA. Per-IP and per-account.
3. **Short-lived access tokens, longer-lived refresh tokens.** Both stored in `__Host-` HttpOnly Secure cookies (web) or platform secure storage (mobile).
4. **Server-side session invalidation on logout.** Maintain a blacklist or short-TTL access tokens with refresh rotation.
5. **MFA** — TOTP (RFC 6238) is the baseline; WebAuthn/FIDO2 where users will tolerate it. SMS is last resort.
6. **Magic-link auth** — single-use, short TTL (10-15 min), rate-limited, IP-bound where feasible.
7. **OAuth/OIDC** — verify `state`, `nonce`, `iss`. Use libraries (`openid-client`, `authlib`); don't hand-roll.

## Authorization

1. **RBAC at minimum, ABAC where richer policy is needed.** Encode in middleware, not scattered through handlers.
2. **Object-level authorization** — every read/write checks `does this user own/have access to this object?` at the data layer. Postgres RLS is a strong default.
3. **Default-deny.** Routes without an explicit permission check should not be reachable.
4. **No privilege escalation by ID guessing** — UUIDv4 or ULID for resource IDs (not sequential integers).

## Input validation & output encoding

1. **Validate at the boundary** — every API endpoint, every form, every queue handler. Use a typed parser (zod / pydantic / marshmallow / valibot).
2. **Encode at the sink** — HTML, JS, URL, CSS, SQL parameter, shell argument — encoder per context.
3. **Schema for everything that crosses a process boundary** — JSON Schema, OpenAPI, protobuf.
4. **Reject early, generously** — short error messages without leaking internals (`"invalid input"`, not `"id 17 not found in users table"`).

## Logging & observability

1. **Log auth events** — sign-in success/failure, password reset, MFA enrollment, token revocation.
2. **Don't log secrets, full request bodies, or raw PII.** Hash or redact.
3. **Centralize logs** — searchable, retention policy, access controls.
4. **Alert on anomalies** — unusual login locations, brute force, mass deletes, configuration changes.
5. **Tag log lines with request ID, session ID (hashed), user ID** — for traceability without exposure.

## Dependency hygiene

1. **Lockfiles in repo.** `package-lock.json`, `pnpm-lock.yaml`, `requirements.txt` with hashes, `poetry.lock`, `uv.lock`, `Cargo.lock`.
2. **Automated upgrades** — Dependabot or Renovate, with a CI gate.
3. **Audit before release** — `npm audit --audit-level=high`, `pip-audit`, `cargo audit`. Block release on HIGH+ unfixed.
4. **Pin floating tags** — for Docker base images, pin to digest (`@sha256:...`), not `latest`.

## When to stop and threat-model

Trigger the ThreatModel skill at PRD time when any of the following apply:

- New project or major feature involving authentication, authorization, payments, or user-uploaded content.
- New external integration (third-party API, OAuth provider, webhook source).
- New trust boundary (browser/server, server/db, server/external, on-prem/cloud).
- New persistence of user data, especially PII or payment data.
- New AI-agent capability — invoke the MAESTRO workflow specifically.

Don't try to remember everything below — invoke the skill and let the structured workflow surface the threats.

## When you're stuck

If a security decision is unclear, surface it explicitly to the user with the tradeoff named (e.g., "we can do X for stronger isolation but it adds 200ms latency on every request — your call"). Don't silently choose the less-secure path. Don't silently choose the more-secure-but-impractical path either. Make the tradeoff visible.

## References

- OWASP Top 10:2025 — <https://owasp.org/Top10/>
- CWE Top 25 (2024) — <https://cwe.mitre.org/top25/>
- OWASP Agentic Skills Top 10 (AST10, 2026) — <https://owasp.org/www-project-agentic-skills-top-10/>
- OWASP ASVS 5.0 — <https://owasp.org/www-project-application-security-verification-standard/>
- SEI CERT Secure Coding Standards — <https://wiki.sei.cmu.edu/confluence/display/seccode>
- NIST Secure Software Development Framework (SSDF) — <https://csrc.nist.gov/Projects/ssdf>
- Mozilla Web Security Cheat Sheet — <https://infosec.mozilla.org/guidelines/web_security>
- OWASP Cheat Sheet Series — <https://cheatsheetseries.owasp.org/>
- CSA MAESTRO (Agentic AI threat modeling, 2025) — <https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro>
