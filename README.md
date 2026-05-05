# claude_secure_coder

Shift-left security tooling for Claude Code. Get Claude doing the secure-coding work **before** code is written, not after — so vulnerabilities are prevented at write time instead of caught at review time.

Works with stock Claude Code or Daniel Miessler's [PAI](https://github.com/danielmiessler/PAI). Apache 2.0.

## The problem

The default Claude Code workflow puts security at the end: write code, then run a review pass. By that point the architecture is committed, the threat model is implicit, and vulnerabilities are expensive to fix. Mature security organizations work the other way around — teach developers the patterns, design with threats in mind, get IDE-style feedback while typing, and let review catch only the residue.

`claude_secure_coder` makes Claude Code work that way.

## The four layers

| Layer | When | Component |
|-------|------|-----------|
| **1. Teach** | SessionStart | `SecureCodingContext.hook.ts` injects OWASP Top 10:2025, CWE Top 25, OWASP AST10 (agentic), and per-language rules into Claude's context before the first prompt. |
| **2. Design** | PRD / PLAN | `ThreatModel` skill — STRIDE for traditional apps, MAESTRO for agentic AI, plus DataFlowDiagram, AbuseCases, and SecurityISCs workflows. |
| **3. Write** | Each Edit / Write | `VulnPatternHook` (PreToolUse, <200ms) hard-blocks literal secrets and flags dangerous APIs / weak crypto. `PostToolUseSAST` runs semgrep + trufflehog + gitleaks after every write and feeds findings back as rewrite guidance. |
| **4. Review** | Pre-merge | Existing review tooling (`security-review`, `pr-review-toolkit`, PAI's `Silas` / `Cato` / `RedTeam`, vendor SAST in CI) — now a backstop, not the primary defense. |

Each layer compensates for what the previous one misses. See [docs/architecture.md](docs/architecture.md) for the full design.

## Quick start

```bash
git clone https://github.com/thatsjet/claude_secure_coder.git
cd claude_secure_coder
bash install.sh
```

The installer detects PAI vs stock Claude Code, places `SecureCoding.md` in the right location, drops the three hooks into `~/.claude/hooks/csc/`, copies the `ThreatModel` skill, and idempotently registers everything in `~/.claude/settings.json` and `~/.claude/CLAUDE.md`. Restart Claude Code and the next session loads the secure-coding context.

PAI users get an additional patch (`patches/pai/apply.sh`) that installs Algorithm v6.4.0 doctrine — auto-includes `ThreatModel` at PLAN for E3+ coding tasks and `Silas` at PLAN for E4+ — and wires `VulnPatternInspector` into the PAI security pipeline.

For SAST coverage, install at least one of `semgrep`, `trufflehog`, or `gitleaks`. The hook fails open if none are present.

Full instructions, verification, troubleshooting, and uninstall: [INSTALL.md](INSTALL.md).

## What's in this repo

| Path | Purpose |
|------|---------|
| `context/SecureCoding.md` | The constitutional secure-coding rule set loaded at SessionStart. |
| `hooks/SecureCodingContext.hook.ts` | Layer 1 — emits relevant rules as `additionalContext`. |
| `hooks/VulnPatternHook.hook.ts` | Layer 3a — PreToolUse deterministic pattern matcher. |
| `hooks/PostToolUseSAST.hook.ts` | Layer 3b — PostToolUse SAST orchestrator. |
| `config/VulnPatterns.yaml` | Pattern rules for VulnPatternHook (secrets, dangerous APIs, weak crypto). |
| `skills/ThreatModel/` | Layer 2 — STRIDE / MAESTRO / DFD / abuse-case / SecurityISCs workflows. |
| `patches/pai/` | Optional PAI integration (Algorithm v6.4.0 + inspector wiring). |
| `install.sh` | Single-step installer with `--uninstall` flag. |
| `tests/run-tests.sh` | Six-test suite verifying the install. |
| `docs/architecture.md` | Full design rationale and layer-by-layer detail. |
| `docs/tool-installation.md` | Notes on what each SAST tool catches. |

## Design choices worth knowing

- **PreToolUse hard-blocks; PostToolUse advises.** PreToolUse runs before every Edit/Write, so it must complete in under ~1s — only deterministic matchers (literal keys, banned imports) live there. Semgrep and trufflehog are too slow for that budget; they run PostToolUse and feed findings back as rewrite guidance. This matches the pattern in Anthropic's published Semgrep plugin.
- **Test-path override.** Files matching `*test*` / `*spec*` / `*fixture*` and directories like `tests/` only get advisories on secret findings, so test fixtures don't hard-block.
- **Allowlist annotation.** `// nosec: <rule_id>` (TS) or `# nosec: <rule_id>` (Python) on the same line suppresses a specific rule when the match is a false positive.
- **Apache 2.0, not MIT.** Explicit patent grant matters for security tooling that ends up in commercial products, and it matches PAI's license for any future upstream PR.

## License

Apache 2.0. See [LICENSE](LICENSE).
