# PAI Integration Patch — Algorithm v6.4.0

This directory contains the integration between `claude_secure_coder` and Daniel Miessler's PAI (Personal AI Infrastructure, <https://github.com/danielmiessler/Personal_AI_Infrastructure>). Applying this patch elevates the toolkit's shift-left mechanisms into PAI's Algorithm doctrine.

**This patch is OPTIONAL.** The toolkit's hooks and ThreatModel skill work standalone for any Claude Code user without PAI installed. The patch only matters if you run PAI and want the security layer integrated into the Algorithm phases (OBSERVE / PLAN / EXECUTE / VERIFY).

## What this patch does

1. **Adds `~/.claude/PAI/ALGORITHM/v6.4.0.md`** — new doctrine version with a "Shift-Left Security Doctrine" section. v6.3.0.md is preserved unchanged for rollback.
2. **Sets `~/.claude/PAI/ALGORITHM/LATEST` → `6.4.0`**.
3. **Adds `ThreatModel`** to the closed-enumeration thinking-capability list (was 19 entries, now 20).
4. **Auto-includes `ThreatModel` at PLAN** for E3+ coding-shaped tasks.
5. **Auto-includes `Silas` at PLAN** for E4+ coding-shaped tasks (in addition to existing VERIFY presence).
6. **Documents security ISC categories** at OBSERVE — a 12-row table mapping (Input validation, Auth, Authz, Secrets, Crypto, Deserialization, Path/command injection, Rate limiting, Dependency hygiene, Logging, AST agentic) to OWASP/CWE/AST10.
7. **(Optional) Wires `VulnPatternInspector` into PAI's `SecurityPipeline.hook.ts`** at priority 70 (between Egress and Rules inspectors). This is **optional** — the portable `VulnPatternHook.hook.ts` is already registered as a standalone PreToolUse hook by `install.sh`, providing identical coverage. The Inspector form is a code-organization preference for PAI users who prefer one inspector chain over two parallel hooks. Skipping this leaves coverage intact. PAI's own PATTERNS.yaml protects `SecurityPipeline.hook.ts` as read-only, so applying this requires the user to lift the protection temporarily; we never bypass it automatically.
8. **Prepends a v6.4.0 changelog entry** to `~/.claude/PAI/ALGORITHM/changelog.md`.

## Files in this directory

| File | Purpose |
|------|---------|
| `apply.sh` | Idempotent installer / uninstaller. Backs up modified files for rollback. |
| `algorithm/v6.4.0.md` | New PAI Algorithm doctrine (overlays into `~/.claude/PAI/ALGORITHM/`). |
| `algorithm/LATEST` | New `LATEST` content (`6.4.0`). |
| `algorithm/capabilities.md.additions` | Hand-merged additions for `capabilities.md`. |
| `algorithm/changelog.md.additions` | Hand-merged additions for `changelog.md`. |
| `VulnPatternInspector.ts` | Inspector adapter that plugs the portable hook logic into PAI's SecurityPipeline. |
| `SecurityPipeline-registration.md` | Step-by-step instructions for the small SecurityPipeline.hook.ts edit (manual). |

## Why some changes need manual merge

Two of the modifications (`capabilities.md` additions, `changelog.md` additions, and the `SecurityPipeline.hook.ts` registration) are intentionally NOT applied automatically. Reasons:

1. **Apache 2.0 / upstream respect.** `apply.sh` will not auto-edit Daniel Miessler's PAI files. We provide the literal text to add and the location, so the user (or a maintainer reviewing a future PR) can review and apply it themselves.
2. **Upstream churn.** PAI's `capabilities.md` and `changelog.md` evolve frequently. Auto-patches break on minor upstream edits. Hand-merging is robust to that.
3. **Reviewability.** `.additions` files are clearly labeled with where each block goes. The signal-to-noise on a code review is much higher than a unified diff over a moving target.

`apply.sh` does fully apply the new files (`v6.4.0.md`, `LATEST`, `VulnPatternInspector.ts`) — those are additions, not modifications, and there's no upstream conflict.

## Usage

```bash
# Apply (interactive — prints what's about to change)
bash patches/pai/apply.sh

# Dry run (show what would change, no writes)
bash patches/pai/apply.sh --dry-run

# Uninstall (restore most recent backup)
bash patches/pai/apply.sh --uninstall
```

## Backups & rollback

Every apply creates a timestamped backup at `~/.claude/PAI/ALGORITHM/.csc-backup/<UTC>/` containing:
- The previous `LATEST` content
- The previous `capabilities.md` and `changelog.md` (only if they were modified)
- A marker for files added (`v6.4.0.md.added`, `VulnPatternInspector.ts.removed`)

`bash apply.sh --uninstall` restores the most recent backup. The Algorithm version drops back to whatever it was (typically v6.3.0). The portable hooks (`SessionStart`, `VulnPatternHook`, `PostToolUseSAST`) remain installed — uninstall those via the project root `install.sh --uninstall`.

## Path forward — separate repo or PR upstream?

This patch is currently bundled inside `claude_secure_coder`. Two future paths:

**Option A — separate repo**: extract `patches/pai/` into its own `claude_secure_coder_pai_integration` repo, depend on `claude_secure_coder` as a sibling install. Cleaner separation, easier for non-PAI users.

**Option B — upstream PR to PAI**: open a PR against `danielmiessler/Personal_AI_Infrastructure` adding v6.4.0.md, the capabilities.md additions, the changelog entry, and a SecurityPipeline.hook.ts modification that imports VulnPatternInspector conditionally (gated on `claude_secure_coder` install).

The patch is intentionally structured so either path is mechanical. The `apply.sh` boundaries (file-add vs file-modify) match the boundaries upstream would care about in code review.

## See also

- Project root README: portable hooks and ThreatModel skill that don't need this patch
- `patches/pai/algorithm/v6.4.0.md`: full doctrine (long, but every line is referenced from existing v6.3.0 with additions clearly marked)
- The Algorithm change rationale in `algorithm/changelog.md.additions`: full C/R/L (conjecture / refutation / learning) format
