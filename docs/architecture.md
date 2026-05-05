# Architecture

The four-layer shift-left model and how the components fit.

## The mental model

Mature security organizations work this way:

1. **Teach** developers secure-coding patterns up front.
2. They **write** better code from the start.
3. **IDE feedback** catches mistakes during writing.
4. **Review** has less to catch.

`claude_secure_coder` makes Claude Code work this way too. Each layer compensates for what the previous one misses.

## Layer 1 — Teach (SessionStart context)

`hooks/SecureCodingContext.hook.ts` fires at SessionStart, reads `context/SecureCoding.md`, detects the project's primary language(s), and emits the relevant subset as `additionalContext` to Claude before the first prompt.

**What it includes:**
- OWASP Top 10:2025 (current as of 2025)
- CWE Top 25 (2024)
- OWASP AST10 (Agentic Skills Top 10, 2026) — for AI-agent / skill / hook / MCP work
- Universal rules (10 rules apply in every language)
- Per-language guidance (Python, TypeScript/JavaScript, Bash, SQL — extend as needed)
- Auth, authz, input validation, output encoding, logging, dependency hygiene sections

**Performance:** first run ~5-30 seconds (full file read + language detection); subsequent runs under 5 seconds (cached).

**Where it lives after install:** `~/.claude/PAI/USER/SECURITY/SecureCoding.md` (PAI users) or `~/.claude/secure_coding/SecureCoding.md` (stock).

## Layer 2 — Design (ThreatModel skill)

`skills/ThreatModel/` is a Claude Code skill with five workflows:

| Workflow | When | Output |
|----------|------|--------|
| **STRIDE** | Traditional web/API/CLI/mobile apps | Threat table per category, ISCs |
| **MAESTRO** | Agentic AI / Claude Code skills / MCP servers | Layer-by-layer threat table, ISCs |
| **DataFlowDiagram** | Visualize trust boundaries | Mermaid DFD + boundary table |
| **AbuseCases** | Generate misuse stories from user stories | Misuse story list with defense ISCs |
| **SecurityISCs** | Convert threat list into atomic ISCs | ISC list ready to paste into PRD `## Criteria` |

**When to invoke:** at PRD/PLAN time, before any code is written. The skill produces text the calling code pastes into the PRD's security section.

**Auto-include (PAI users):** Algorithm v6.4.0 doctrine adds ThreatModel to the closed-enumeration thinking-capability list and auto-includes it at PLAN for E3+ coding tasks. Silas additionally auto-includes at PLAN for E4+.

## Layer 3 — Write (PreToolUse + PostToolUse hooks)

Two hooks split by latency budget.

### `VulnPatternHook.hook.ts` (PreToolUse — fast deterministic, <200ms)

Matches the proposed `content` against `config/VulnPatterns.yaml`:
- **secrets** (CRITICAL, action=deny): Anthropic, OpenAI, AWS, Stripe, GitHub, Slack tokens; private key blocks; database URLs with embedded passwords.
- **dangerous_apis** (HIGH, action=alert): eval/exec/Function/setTimeout(string), pickle.loads, yaml.load (no SafeLoader), subprocess(shell=True), unquoted bash $VAR.
- **weak_crypto** (MEDIUM, action=alert): MD5/SHA1 in password context, DES/3DES/RC4/ECB, Math.random()/random.random() in security context.

Hard-blocks via `permissionDecision: deny` on action=deny findings. Advisories go through `additionalContext`.

**Test-path override:** files matching `*test*`, `*spec*`, `*fixture*`, `tests/`, `__tests__/`, `__fixtures__/` only get advisories on secret findings (so test fixtures don't hard-block).

**Allowlist annotation:** `// nosec: <rule_id>` (TS) or `# nosec: <rule_id>` (Python) on the same line suppresses that finding.

### `PostToolUseSAST.hook.ts` (PostToolUse — slow heuristic, <15s)

After every Edit/Write/MultiEdit, runs whichever of these are installed (in parallel):
- **semgrep** (`--config auto --json --quiet --timeout 12 --metrics=off`) — logic vulnerability rules, severity ERROR → HIGH, WARNING → MEDIUM, INFO → LOW
- **trufflehog** (`filesystem --no-update --json --only-verified --no-fail`) — verified live secrets only (low false positive rate), severity CRITICAL
- **gitleaks** (`detect --source ... --no-git --report-format json --exit-code 0`) — fast secret regex, severity HIGH

Aggregates findings. **Advisory rewrite-guidance** on HIGH/CRITICAL: returns `additionalContext` with explicit "ACTION: Rewrite this file to fix these findings" so Claude is strongly nudged to rewrite in the next turn. Bounded at 2 iterations per file per session. Note: Claude Code's PostToolUse hook protocol does not have a guaranteed `decision: regenerate` type — the additional-context channel is advisory. We rely on Claude reading the structured findings + ACTION line and self-correcting; this is the same pattern Anthropic's published Semgrep plugin uses.

**Per-project ignore:** `<project>/.claude/security/sast-ignore.yaml` filters known false positives.

**Telemetry:** `~/.claude/PAI/MEMORY/OBSERVABILITY/sast-scans.jsonl` (or `os.tmpdir()/claude-sast-scans.jsonl` for non-PAI users).

### Pattern: PreToolUse hard-blocks deterministic, PostToolUse advises rewrite for heuristic

Latency is the gating constraint. PreToolUse must complete fast (under ~1s) because it runs before every Edit/Write — slow PreToolUse freezes the entire agent turn. So PreToolUse only runs deterministic regex matchers (literal API keys, banned imports, weak crypto patterns) where false positives are nearly impossible.

PostToolUse can take longer because it runs after the file is written. Slower SAST tools (semgrep) and verified secret scanners (trufflehog) live there. The advisory rewrite-guidance loop replaces hard-blocking with "rewrite this file to fix the findings" — Claude reads its own diff feedback and self-corrects.

This pattern is what Anthropic's published Semgrep plugin uses (<https://claude.com/plugins/semgrep>). We adopted it because the alternative (PreToolUse with semgrep) blocks the agent for 2-15 seconds per Edit and frustrates flow.

## Layer 4 — Review (existing tooling, unchanged)

The existing review layer remains as a backstop:
- Anthropic's Claude Security (cloud-hosted post-hoc review)
- The `security-review` slash command
- The `pr-review-toolkit` agent suite
- PAI's `Silas`, `Cato`, `RedTeam` for Algorithm-driven review at VERIFY
- Vendor SAST in CI

These should catch only residual issues if Layers 1-3 are working.

## Composition: how the layers compound

A typical end-to-end flow on a coding-shaped task (PAI user, E4):

1. **SessionStart**: `SecureCodingContext.hook.ts` loads OWASP/CWE/AST10 + per-language rules. Claude is now aware of the rule set.
2. **OBSERVE**: Algorithm v6.4.0 doctrine prompts the ISA scaffold to generate security-category ISCs (input validation, auth, authz, secrets, crypto, deserialization, rate limiting, dependency hygiene).
3. **PLAN**: ThreatModel skill auto-included. STRIDE workflow runs. Threat table generated. SecurityISCs workflow appends atomic ISCs to the ISA `## Criteria`. At E4+, Silas spawned for adversarial pre-build pass.
4. **EXECUTE**: Forge generates code. Each Edit/Write triggers VulnPatternHook (PreToolUse, fast). If a literal secret is in the diff, hard-blocked. If `eval(userInput)` is in the diff, advisory feedback is added to context.
5. **EXECUTE (continued)**: After each Edit/Write succeeds, PostToolUseSAST fires. semgrep + trufflehog scan the file. HIGH-severity finding → advisory rewrite-guidance with structured findings + ACTION line → Claude reads its own diff feedback and rewrites the file (advisory, not protocol-enforced; pattern matches Anthropic's published Semgrep plugin).
6. **VERIFY**: Existing review tooling (Cato, security-review) verifies the security ISCs. Catches residual issues.
7. **LEARN**: Telemetry (`sast-scans.jsonl`, `vulnpattern-scans.jsonl`) records what fired. Feedback informs future rule tuning.

## Why Apache 2.0 not MIT

Apache 2.0 includes an explicit patent grant. For security tooling that may be incorporated into commercial products, the patent grant matters. It also matches Daniel Miessler's PAI license, simplifying any future upstream PR.
