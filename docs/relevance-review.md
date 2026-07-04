# Relevance review — claude_secure_coder under Fable-5 + mature harness

> Design-review memo. Written 2026-07-04, reviewing a toolkit last edited in the
> Opus 4.6 era. Verdict first, evidence second, live-install drift last.

## Verdict: KEEP-AND-UPGRADE

Not archive. Not fold-into-harness. The four-layer model earns its keep because
each layer holds **anti-fragile coordination knowledge that no model upgrade
replaces** — but the harness matured underneath it, and roughly 55–60% of every
layer had drifted into Fable-5-redundant recited taxonomy (OWASP/CWE/STRIDE/
MAESTRO tables) that actively dilutes that core on every load. The upgrade this
session trims the recited half and invests the reclaimed budget in the one thing
2026 demands and every layer lacked: **attack-chain and LLM-in-trust-path
adversarial reasoning** — which is verbatim what the principal asked for,
"excellent advice before the RedTeam has a chance to break things."

### Why not archive

The deterministic gates and the threat→ISC translation have no substitute
anywhere in the system:

- The **literal-secret PreToolUse deny gate** is the single most valuable
  artifact in the stack — a regex a prompt-injected model *cannot argue past*.
  Recited knowledge gets better as the model improves; a deterministic gate is
  the thing that stays true when the model is wrong.
- The **`sk-test-FIXTURE-` prefix** is the whitelist contract that keeps that
  gate from regenerate-looping on test fixtures — coordination knowledge no
  model invents on its own.
- The **threat-shape → ISC deterministic mapping** (`SecurityISCs.md`) is the
  only thing in the system that turns a threat into a *tool-verifiable
  acceptance criterion*. Without it a threat model is prose; with it, it is a
  gate the verify layer can run.

### Why not fold-into-harness

The layer boundaries are themselves forcing functions against scope creep
(Teach ≠ Design ≠ Write ≠ Review), and the design-time advisor is exactly the
principal's stated need. Dissolving it into generic harness rules loses the
boundary discipline.

## The harness-maturity facts that forced the upgrade

All verified live on this machine, 2026-07-04:

1. **ThreatModel is now a hard gate.** In Algorithm v6.23.0, `capabilities.md`
   marks ThreatModel **MANDATORY at PLAN for E3+** coding tasks. The toolkit's
   patches and docs still targeted v6.4.0 and cited retired vocabulary (Silas is
   no longer a live agent; Cato was folded into Forge audit mode 2026-06-17).
   Consequence: the Teach layer's generic "when to threat-model" trigger list
   duplicated a hard gate — its only residual value is NATIVE/E1–E2 coverage, so
   it was rescoped to that.
2. **The executing model is Fable 5** (Jan-2026 cutoff). It reproduces the OWASP
   Top 10, CWE Top 25, and per-language idioms unprompted. Teaching them is
   belt-on-belt and dilutes the coordination content.
3. **Two PreToolUse gates now fire** on every Edit/Write (see drift, below).
4. **The digest swap already conceded the point** — the live install @-imports a
   2.5 KB digest precisely because the full 17 KB teach doc was too heavy.

## Per-layer calls

| Layer | Call | The one action taken (or recommended) |
|-------|------|----------------------------------------|
| **Teach** (`context/SecureCoding.md`) | trim + strengthen | Cut the OWASP/CWE tables and the generic auth/authz/validation/logging/dependency checklists (~110 lines Fable-5 recites verbatim); rebuilt as a lean constitutional file whose four sections are the *only* things a capable model doesn't do reliably: the deterministic-gate contract, the adversarial pre-mortem discipline, the agentic/LLM-in-trust-path invariants (now first-class, not an appendix), and the forcing functions. Every anti-fragile element preserved verbatim (FIXTURE contract, Anti-ISC escape hatch, surface-the-tradeoff rule). |
| **Design** (`skills/ThreatModel/`) | trim + strengthen | Shipped **`AdversarialPreMortem.md`** as the genuine sixth workflow (the description already claimed "six" while only five existed) — the synthesis pass that chains enumerated atoms into ranked kill chains and writes a choke-point ISC per chain. Sharpened `SKILL.md`: Distinguished-Architect framing, new routing + decision-tree step, and a mandatory Gotchas section. |
| **Write** (`hooks/`, `config/VulnPatterns.yaml`) | keep now; strengthen next | Behavior is sound and left unchanged this pass (the ask was the pre-review advisor). See *Recommended follow-ups* for the gate-hardening backlog. |
| **Review** (Layer 4 pointer in `docs/architecture.md`) | trim next | The pointer list has rotted (names retired agents and v6.4.0). Recommend trimming to "review is out of csc scope" plus a review-handoff brief. Not done this pass. |

## What changed this session

- **NEW** `skills/ThreatModel/Workflows/AdversarialPreMortem.md` — flagship
  design-time adversarial review: attack chains, RedTeam-first ranking, the
  trifecta *data-flow* test (catches the split trifecta), the SEAM composition
  pass (TOCTOU/replay/etc.), and choke-point ISCs with race-aware probes. Two
  worked examples (agentic Support Copilot; traditional multi-tenant web/API).
  Its design was adversarially reviewed by three independent skeptics; three
  load-bearing gaps they found were folded in before shipping.
- **EDIT** `skills/ThreatModel/SKILL.md` — description, `# ThreatModel` framing,
  routing row, decision-tree step 6, Gotchas section, Constraints clarification.
- **REWRITE** `context/SecureCoding.md` — BPE trim + agentic elevation (above),
  plus a compact **threat-class salience index** (one line per class, framed as a
  retrieval *prime*, not a lesson) so trimming the OWASP/CWE tables keeps their
  one legitimate runtime function — making a class *salient* — without re-teaching
  a mitigation the model already knows.
- **NEW** `ISA.md` — the project's Ideal State Artifact (system of record).

Nothing under `~/.claude/` was touched — the edits are to the source repo; the
install is a separate, deliberate act for the principal.

## Live-install drift (recommendation, NOT applied)

Two drift artifacts, verified read-only on this machine. **Not touched** —
changing Jet's live `~/.claude` config is design-shaping and his call.

### 1. Double PreToolUse gate

On every Edit/Write/MultiEdit, two hooks fire: PAI's `SecurityPipeline.hook.ts`
(inspector chain Pattern → Egress → Rules; its PatternInspector reads
`USER/SECURITY/PATTERNS.yaml`) **and** csc's standalone
`hooks/csc/VulnPatternHook.hook.ts` on the identical `Edit|Write|MultiEdit`
matcher (reads `VulnPatterns.yaml`). The consolidation adapter csc shipped for
exactly this — `VulnPatternInspector.ts` — was copied into the live
`hooks/security/inspectors/` at install but never wired into the chain, so it is
dormant dead code *and* a maintenance trap (the next reader assumes it is active).

**Recommendation (preference order):**
- **(a) Preferred, low-blast-radius:** keep the standalone csc hook as the single
  csc gate, **delete the dormant `VulnPatternInspector.ts`** from the live
  inspectors dir, and de-scope `VulnPatterns.yaml` to *secrets + a new agentic
  rule class only* — drop `dangerous_apis`/`weak_crypto`, which PAI's
  PatternInspector and the PostToolUse semgrep pass already cover. This stops csc
  from re-flagging what the other two gates catch and touches no PAI-guarded file.
- **(b) Cleaner architecture, more invasive:** wire `VulnPatternInspector` into
  the chain and drop the standalone registration — but this edits
  `SecurityPipeline.hook.ts`, which PAI's `PATTERNS.yaml` protects as read-only,
  so it couples csc to PAI's chain evolution.

Either way, the dormant adapter is the concrete artifact to remove.

### 2. Digest swap is half-complete

`CLAUDE.md` @-imports `SecureCodingDigest.md` (correct for subagents, which get
digest-only), but main sessions *also* still receive the full `SecureCoding.md`
via the live `SecureCodingContext.hook.ts` SessionStart hook — a partial
double-load where the digest is a strict subset of the full doc.

**Recommendation:** do **not** revert the swap. Complete it — land this session's
Teach-layer trim into the install first; once the full doc and the digest
converge on the lean content, the double-load collapses. Then either promote the
lean doc to the single canonical artifact and retire the separate digest, or keep
the digest as the subagent-slim variant against the now-lean main doc. Sequence
is **trim-then-reconcile, never revert-then-rebuild.**

## Recommended follow-ups (not done this pass; the ask was the pre-review advisor)

1. **Harden the deny gate against model-usable bypasses** (Write layer): stop
   printing the `nosec` bypass recipe in the block message and honor `nosec` only
   when it already exists on-disk; never downgrade provider-token/verified-secret
   denies on test paths; extend deterministic coverage to Bash redirection/
   heredoc/`sed` writes, `NotebookEdit`, and harness-config paths
   (`settings.json`, `hooks/`, `.mcp.json`, `CLAUDE.md`).
2. **Add an agentic rule class to `VulnPatterns.yaml`**: `exec`/`eval` of model
   output, LLM JSON flowing into shell/SQL sinks, `--dangerously-skip-permissions`,
   unpinned MCP, `verify=False`.
3. **Update the patch target** from Algorithm v6.4.0 to current, and drop the
   retired Silas/Cato references.
4. **Trim the Review-layer pointer** and add a review-handoff brief (chains
   considered, ISCs + evidence, gate-firing log) so RedTeam attacks residuals.
5. ~~Fix `docs/architecture.md`~~ — done this pass (five → six, live enforcement
   reality, retired-agent note).
6. **Empirically A/B the value claim** (advisor's point, and the right instinct
   for a security tool): run one seeded-vulnerability design review with the old
   skill vs. the new, and compare finding recall across the threat classes. The
   whole claim is "better advice before RedTeam breaks things" — that is testable
   cheaply, and a clean lint of the new files is not a substitute for it. If
   new-skill recall drops on even one seeded class, the salience index needs a
   line back. (This is a live-session experiment; it cannot be run from the repo,
   so it is not asserted as verified here.)
