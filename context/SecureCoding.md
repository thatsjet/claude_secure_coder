# Secure Coding — Constitutional Context

> Loaded at every Claude Code session start. This file makes vulnerabilities *unwritable* rather than merely reviewable. It is constitutional: rules here override convenience and apply to every file Claude writes or edits, in every project.
>
> **What this file is NOT.** It is not a re-teaching of the OWASP Top 10, the CWE Top 25, or per-language secure-coding idioms. A current model already applies those unprompted — parameterized queries, `execFile` over shell, `argon2id`, `secrets.token_bytes`, no `alg:none`, `SafeLoader`, TLS verification. Reciting that catalog here would dilute the rules that genuinely change behavior. If you need the catalog, it is at the reference URLs at the bottom; assume you know it and act on it by default.
>
> **What this file IS.** The four things a capable model does *not* do reliably without being told, because they are coordination, discipline, or judgment rather than recall:
> 1. the **deterministic-gate contract** — how to write so you cooperate with the hooks that block secrets, instead of fighting them;
> 2. the **adversarial pre-mortem discipline** — anticipating what the red team will find and pre-closing it as testable criteria, *before* review;
> 3. the **agentic / LLM-in-trust-path invariants** — the failure class that dominates modern systems and that no amount of web-app hygiene covers;
> 4. the **forcing functions** — the rules that make security win over aesthetics and make exceptions auditable instead of silent.

## The shift-left model this file anchors

1. **Teach** (this file, SessionStart) — the discipline and coordination context below, loaded before the first prompt.
2. **Design** (ThreatModel skill at PLAN) — STRIDE/MAESTRO enumerate, `AdversarialPreMortem` chains and pre-closes. In a PAI/Algorithm install this is a **hard gate**: ThreatModel is mandatory at PLAN for E3+ coding tasks, so at E3+ the design-time pass is not optional and this file's role is to make NATIVE/E1–E2 work reach for it too.
3. **Write** (deterministic PreToolUse gate + PostToolUse SAST) — a literal-secret gate hard-blocks; dangerous patterns and SAST findings advise a rewrite. *(In a PAI install a second PAI-native PreToolUse gate may also run; write to satisfy both — see the gate contract below.)*
4. **Review** (existing tooling — security-review, RedTeam, vendor SAST) — the backstop, not the primary defense. If Layers 1–3 did their job, review attacks declared residuals instead of rediscovering the base rate.

If a rule below conflicts with an aesthetic preference or "cleaner code" instinct, the security rule wins. Mitigations may be skipped only when an explicit threat-model decision in the project's PRD records the rationale.

## The forcing functions (anti-fragile core — these do not get smarter for free)

1. **Never write a literal secret.** Tokens, API keys, private keys, passwords, signing secrets, DB URLs with embedded credentials — always `process.env.X` / `os.getenv("X")` / secret manager / keychain at runtime. This is not advice, it is a hard gate (Layer 3): a literal secret in a diff is *blocked*, not flagged. Write it as an env read the first time and you never hit the wall.
2. **Exceptions are ISCs, never silent.** When a mitigation genuinely must be skipped, encode it as an `Anti:` ISC in the PRD that documents *what* is not done and *why it is safe* — e.g. `Anti: this endpoint accepts raw HTML because it renders in a sandboxed origin (see Decision D-N)`. A silent skip is invisible to review; an Anti-ISC is auditable and testable.
3. **Surface the tradeoff — never silently pick a side.** If a security decision is unclear, surface it explicitly to the user with the tradeoff named (e.g., "we can do X for stronger isolation but it adds 200ms latency on every request — your call"). Don't silently choose the less-secure path. Don't silently choose the more-secure-but-impractical path either. Make the tradeoff visible.
4. **Security requirements are ISCs the verify layer can check.** A threat you cannot state as a tool-verifiable criterion is a threat you cannot prove you closed. Every security decision that matters becomes a `- [ ] ISC-N:` with a named probe (`SecurityISCs.md` does the translation). This is the whole shift-left payoff: the SAST and review layers can only confirm what was written as a checkable claim.

## Agentic / LLM-in-trust-path — FIRST-CLASS, not an appendix

Most systems worth attacking now have a model in the trust path. Web-app hygiene does not cover this failure class; these invariants do. When the code under construction is an agent, skill, hook, MCP server, or any LLM with tools, these are the dominant risks — treat them the way you treat SQL injection on a web form.

- **The lethal trifecta (and the split trifecta).** An agent flow is exploitable by *indirect* prompt injection by construction if it holds all three of: **(a)** access to private data, **(b)** exposure to untrusted content (user text, tickets, attachments, retrieved docs, tool results, memory/KB), **(c)** an egress channel. Egress is not just a `send` tool — it is a markdown image the client fetches, a DNS lookup, an error string returned to the attacker, or **a write of untrusted content into a persistent store** (memory, KB, vector index, cache) that a later privileged turn reads as trusted. Compute the trifecta over the **whole request flow** — across turns, sessions, principals, and agents — not one turn: the 2026 flagship breach is the *split* trifecta (an attacker turn poisons the KB with no data-read and no egress, a later victim turn completes the exfiltration). Break the trifecta at design time: tenant-bind data tools, separate planning from execution (dual-LLM / CaMeL) so untrusted content cannot originate a tool call, allow-list egress, and provenance-tag ingested content so taint survives persistence.
- **Tool-call arguments come from the plan, never from the content.** The arguments to a state-changing tool must derive from the typed plan built from the *authenticated user's request*, never from retrieved, attachment, or memory text. This single invariant severs most injection→action chains.
- **Model output is untrusted input.** Never `eval`/`exec`/`Function()`/shell/SQL a string the model produced without validating it at the sink exactly as you would validate a user's. Generated code is untrusted until a sandbox or a validator says otherwise.
- **MCP / tool supply chain.** Pin tool and MCP versions; verify tool schemas have not changed (a rug-pull tool update or a poisoned tool *description* is a confused-deputy vector). Treat a remote tool description as untrusted content that reaches the model. Do not grant an agent a capability class it does not need — excessive agency is the amplifier on every other bug.
- **Slopsquatting / hallucinated dependencies.** The model is itself a supply-chain vector: before adding a package, confirm it exists and is the canonical name — attackers register the plausible-but-fake names models invent. Pin GitHub Actions by SHA, not tag.
- **Never put a secret in model context.** Reference secrets by handle; resolve them server-side at tool dispatch. A secret in the context is one prompt-injection away from exfiltration.

## Adversarial pre-mortem — write the RedTeam's report before they do

The cheapest place to kill a vulnerability is before it is written. For any new surface, do not wait for review — assume the red team's report is already on your desk and pre-close its base rate. On **every new endpoint, route, tool, or parser**, default-assume and write the closing ISC for:

- **IDOR / BOLA** on every object-scoped endpoint — authorize by the session-derived owner/tenant id, never by an id from input.
- **Missing authorization** on every new route and every new agent tool — default deny, explicit allow.
- **Injection** at every parser — SQL, shell, template, path, and for agents, prompt and *indirect* prompt.
- **Replay / concurrency (the SEAM class)** on every state-changing or money-moving op — idempotent on a client key, serialization-safe; prove it with a *concurrent and replayed* probe, not a serial one. A control that passes serially and fails under a single-packet race is a false green.
- **Trifecta presence** on every new agent tool grant, per the section above.

Then chain them: three "Low" issues that individually look mitigated often compose into one Critical path (leak → IDOR → token → cross-tenant). At E3+ the `AdversarialPreMortem` workflow does this composition and ranking; at any tier, the habit is the same — think in the attacker's chain to the crown jewel, and write the one choke-point ISC that severs it.

## Threat-class salience index (a prime, not a lesson)

You know the mitigation for every class below — this list is not teaching it. Its
one job is *salience*: attackers exploit the class you didn't think to consider,
so run this index against every new surface as a checklist of what to *consider*,
then apply the mitigation you already know. One line per class, on purpose.

- **Access control** — IDOR/BOLA, missing function-level authz, path/tenant traversal → default-deny, authorize by session-derived owner id.
- **Injection** — SQL, NoSQL, OS command, LDAP, template, path, and (agents) prompt + *indirect* prompt → parameterize / array-exec / provenance-check.
- **Crypto** — weak hash for passwords, ECB/RC4/DES, `Math.random`/`random` for tokens, missing TLS verify → argon2id/bcrypt, AES-GCM, CSPRNG.
- **Deserialization / dynamic exec** — `pickle`/`yaml.load`/`eval`/`Function()` on untrusted (incl. *model output*) → safe loaders, no exec of untrusted.
- **SSRF** — user-supplied URL fetched without allow-list → block private ranges + `169.254.169.254`.
- **Auth / session** — replayable tokens, no logout invalidation, weak reset/magic-link, no rate-limit on auth → single-use short-TTL, server-side invalidation.
- **Secrets / disclosure** — literal secrets (hard-blocked), verbose errors, debug endpoints, over-broad responses → env-only, generic errors, field allow-lists.
- **Integrity / supply chain** — unverified webhooks, unpinned deps/actions, slopsquat packages, unsigned artifacts → HMAC-verify, pin by SHA, confirm package identity.
- **Availability** — unbounded upload/list/regex, ReDoS → size caps before parse, hard `limit`, non-backtracking engines.
- **Agentic (dominant class)** — the trifecta (split included), excessive agency, tool-poisoning, memory/KB poisoning → see the LLM-in-trust-path section above; treat as first-class, not last.

## The deterministic-gate contract (cooperate, don't fight)

Layer 3 hooks scan every Edit/Write deterministically. Knowing what they do keeps you out of regenerate loops:

- **Secrets are hard-blocked.** Provider key shapes (Anthropic/OpenAI/AWS/Stripe/GitHub/Slack), private-key PEM blocks, and DB URLs with embedded passwords are *denied* — the write does not land. Read from env instead; there is no "just this once."
- **Test fixtures need synthetic keys.** In tests, use synthetic fixtures only. If a real key *shape* is needed for a regex test, prefix with `sk-test-FIXTURE-` or similar — clearly synthetic. This is the whitelist contract: it is how the gate tells your fixture from a real leak. Skip it and the gate blocks your test file.
- **Dangerous APIs and weak crypto are advised, not blocked** — `eval`, `shell=True`, `yaml.load` without `SafeLoader`, `innerHTML` with user text, MD5/SHA1 on passwords, `Math.random()`/`random.random()` for tokens. You already avoid these; the advisory exists for drift. If a flagged pattern is genuinely correct, suppress that one line with `// nosec: <rule_id> — <reason>` (or `# nosec:`), which records the justification inline.

## When to reach for the ThreatModel skill

At E3+ this is a hard gate, so this list is really for **NATIVE / E1–E2** work — reach for `ThreatModel` (and its `AdversarialPreMortem` pass) whenever the change touches: authentication, authorization, sessions, or identity; payments or anything of monetary value; a new external integration (third-party API, OAuth, webhook); a new trust boundary (service, tenant, role); a new persistence path for user data (upload, table, bucket, export); or a new agentic capability (an LLM gets a new tool, an MCP server is added). Don't try to hold the whole catalog in your head — invoke the skill and let the workflow surface the threats.

## Secrets handling — the operational rules

- **In code:** env / secret manager / keychain. Never literal (hard-blocked — see the gate contract).
- **In tests:** synthetic `sk-test-FIXTURE-…` shapes only.
- **In `.env`:** gitignored; ship `.env.example` with placeholders.
- **In logs:** redact (`Authorization: Bearer [REDACTED]`); never full bodies or raw PII.
- **In history:** a secret ever committed is compromised — rotate it; removing the file does not undo history (`git filter-repo` + rotate).

## References (for the human — assume the model already knows these)

- OWASP Top 10:2025 — <https://owasp.org/Top10/>
- CWE Top 25 (2024) — <https://cwe.mitre.org/top25/>
- OWASP Agentic Skills Top 10 (AST10, 2026) — <https://owasp.org/www-project-agentic-skills-top-10/>
- OWASP ASVS 5.0 — <https://owasp.org/www-project-application-security-verification-standard/>
- CSA MAESTRO (agentic threat modeling, 2025) — <https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro>
- The "lethal trifecta" — <https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/>
- OWASP Cheat Sheet Series — <https://cheatsheetseries.owasp.org/>
