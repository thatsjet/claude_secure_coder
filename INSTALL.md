# Installation

This guide covers installing `claude_secure_coder` for both stock Claude Code users and Daniel Miessler's PAI users.

## Prerequisites

- **Claude Code** — <https://docs.claude.com/en/docs/claude-code/quickstart>
- **Bun** — used for hook execution. Install: <https://bun.sh>
- **Git** — to clone the repo
- **(Recommended)** at least one of: `semgrep`, `trufflehog`, `gitleaks` — for write-time SAST. Hook fails open if none are installed but you lose Layer 3 coverage.

## Quick install (any Claude Code user)

```bash
git clone https://github.com/thatsjet/claude_secure_coder.git
cd claude_secure_coder
bash install.sh
```

That's it. The installer:
1. Detects whether you have PAI (`~/.claude/PAI/`) or stock Claude Code.
2. Copies `SecureCoding.md` to the appropriate location (`~/.claude/PAI/USER/SECURITY/` for PAI users, `~/.claude/secure_coding/` for stock).
3. Copies the three hooks to `~/.claude/hooks/csc/`.
4. Copies the `ThreatModel` skill to `~/.claude/skills/ThreatModel/`.
5. Adds hook registration entries to `~/.claude/settings.json` (idempotent — running twice is safe).
6. Adds an `@`-import line to `~/.claude/CLAUDE.md` so `SecureCoding.md` loads at every session start.

Restart Claude Code. The next session will load the secure-coding context, and write-time hooks will fire on every Edit/Write.

## PAI integration (optional, for PAI users)

After running `install.sh`, also run:

```bash
bash patches/pai/apply.sh
```

This adds:
- `~/.claude/PAI/ALGORITHM/v6.4.0.md` — new doctrine that auto-includes `ThreatModel` at PLAN for E3+ coding tasks and `Silas` at PLAN for E4+ coding tasks
- `~/.claude/PAI/ALGORITHM/LATEST` → `6.4.0`
- `VulnPatternInspector.ts` wired into PAI's `SecurityPipeline.hook.ts` inspector chain

Two manual edits remain (the apply script tells you exactly what to do):
- Append `ThreatModel` row to `~/.claude/PAI/ALGORITHM/capabilities.md`
- Prepend v6.4.0 entry to `~/.claude/PAI/ALGORITHM/changelog.md`
- Register `VulnPatternInspector` in `~/.claude/hooks/SecurityPipeline.hook.ts`

The reason these are manual: respect for upstream Apache 2.0 maintainers. The literal text and exact location are provided in `patches/pai/algorithm/*.additions` and `patches/pai/SecurityPipeline-registration.md`.

## Install external SAST tools

Installing at least one of these activates Layer 3 (write-time SAST):

```bash
# macOS
brew install semgrep trufflehog gitleaks

# Linux (per-tool)
# semgrep:    pip install semgrep
# trufflehog: https://github.com/trufflesecurity/trufflehog#installation
# gitleaks:   https://github.com/gitleaks/gitleaks#installing
```

Recommended pairing: `semgrep` (logic vulnerability rules) + `trufflehog` (verifies live secrets, low false positives). `gitleaks` is faster than trufflehog but matches by regex without verification — useful for fast pre-commit scanning, less precise as a runtime SAST.

See [docs/tool-installation.md](docs/tool-installation.md) for what each tool catches and how the hook composes results.

## Verify the install

```bash
bash tests/run-tests.sh
```

Expected output:
```
[csc-test] 1/6 SessionStart hook produces valid JSON ... PASS
[csc-test] 2/6 VulnPatternHook denies Anthropic API key in source ... PASS
[csc-test] 3/6 VulnPatternHook advises (no deny) on eval(userInput) ... PASS
[csc-test] 4/6 VulnPatternHook downgrades key in tests/fixtures/ ... PASS
[csc-test] 5/6 PostToolUseSAST runs available scanner(s) ... PASS (semgrep,trufflehog)
[csc-test] 6/6 ThreatModel skill discoverable ... PASS
[csc-test] all 6 tests passed
```

If any test fails, the script prints the specific failure with diagnostic details.

## Uninstall

```bash
bash install.sh --uninstall
```

Removes hooks, skill, and reverts `settings.json` and `CLAUDE.md` to the most recent backup at `~/.claude/.csc-backup/`.

For PAI users, also run:

```bash
bash patches/pai/apply.sh --uninstall
```

This restores `LATEST` to `6.3.0`, removes `v6.4.0.md`, and reverts `SecurityPipeline.hook.ts`.

## Troubleshooting

**Hooks not firing after install**:
- Restart Claude Code (hooks load at session start)
- Check `~/.claude/settings.json` — your three csc entries should be there
- Run `bun ~/.claude/hooks/csc/SecureCodingContext.hook.ts < /dev/null` directly — should print JSON

**SAST hook reports "no tools installed"**:
- Verify `which semgrep`, `which trufflehog`, `which gitleaks`. Install at least one.
- The advisory is one-time per session; if you missed it, run `rm /tmp/claude-sast-advised-*` and re-trigger.

**Hard-blocked by VulnPatternHook on a legitimate file**:
- If it's a test fixture: name the file `*test*`, `*spec*`, `*fixture*`, or put it under `tests/` / `__tests__/`.
- If it's a real-but-non-secret pattern: add `// nosec: <rule_id>` (TS) or `# nosec: <rule_id>` (Python) on the same line.
- If the rule itself is wrong: edit `~/.claude/hooks/csc/lib/VulnPatterns.yaml` to disable or refine the rule.

**PAI Algorithm not loading v6.4.0**:
- Check `cat ~/.claude/PAI/ALGORITHM/LATEST` returns `6.4.0`
- Check `~/.claude/PAI/ALGORITHM/v6.4.0.md` exists
- Restart Claude Code
- If still on v6.3.0, the `apply.sh` may have skipped the `LATEST` write — re-run with `--dry-run` to see what it would do
