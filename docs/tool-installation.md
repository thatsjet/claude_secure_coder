# External tool installation

The PostToolUse SAST hook delegates to industry-standard CLI scanners. None are required — the hook fails open if all are missing — but installing at least one activates Layer 3 (write-time SAST coverage).

## Quick recommendation

| Use case | Pick |
|----------|------|
| You want one tool that catches the most | **semgrep** |
| You want fastest secret detection | **gitleaks** |
| You want low-false-positive secret detection | **trufflehog** |
| You want both logic vulns + verified secrets | **semgrep + trufflehog** (the canonical pairing) |

The hook auto-detects which are installed and runs all available in parallel.

## semgrep

Logic vulnerability scanner. Open-source rule packs for OWASP Top 10, CWE Top 25, language idioms.

```bash
# macOS
brew install semgrep

# Linux / any
pip install semgrep
# or
python3 -m pip install --user semgrep
```

Verify: `semgrep --version` (need ≥1.0).

The hook calls: `semgrep --config auto --json --quiet --timeout 12 --metrics=off "$file"`. Auto-config selects rule packs by detected language. No network calls at runtime; rule database is bundled in the binary.

## trufflehog

Verified secret scanner. Strong differentiator: actively verifies a found credential is live (e.g., calls the relevant API to check the token works) before flagging — drastically lower false positive rate than regex-only scanners.

```bash
# macOS
brew install trufflehog

# Linux / any (download from releases)
# https://github.com/trufflesecurity/trufflehog/releases
# Or via Go:
go install github.com/trufflesecurity/trufflehog/v3@latest
```

Verify: `trufflehog --version`.

The hook calls: `trufflehog filesystem --no-update --json --only-verified --no-fail "$file"`. The `--only-verified` flag is what makes the difference — only credentials confirmed to be live get reported.

**Network access:** trufflehog with `--only-verified` makes outbound calls to verify each candidate (e.g., to api.openai.com to check an `sk-` token). If your environment forbids this, run without `--only-verified` (more findings, more false positives) or use gitleaks instead.

## gitleaks

Fast pre-commit-style secret scanner. Pure regex, no verification, much faster than trufflehog. Best for fast-feedback layers.

```bash
# macOS
brew install gitleaks

# Linux / any
# https://github.com/gitleaks/gitleaks/releases
```

Verify: `gitleaks version`.

The hook calls: `gitleaks detect --source "$file" --no-banner --report-format json --report-path /tmp/... --no-git --exit-code 0`. The `--no-git` flag is important — we want to scan the file as-is, not git history.

## Composition

If all three are installed, the PostToolUse hook runs them in parallel:

| Tool | What it catches | False positive rate | Speed |
|------|-----------------|---------------------|-------|
| semgrep | Logic vulns (eval, SQL concat, weak crypto, unsafe deserialization, etc.) | Medium (rule-dependent) | Slow (1-12s) |
| trufflehog | Verified live secrets only | Very low | Slow (verification calls) |
| gitleaks | Secret patterns (regex) | High | Fast (<1s) |

The hook normalizes severities:
- semgrep ERROR → HIGH; WARNING → MEDIUM; INFO → LOW
- trufflehog (verified) → CRITICAL
- gitleaks → HIGH

An advisory rewrite-guidance message is emitted when ANY HIGH or CRITICAL finding is reported. It contains structured findings + an explicit ACTION line nudging Claude to rewrite the file. This is advisory, not protocol-enforced — Claude Code's PostToolUse hook contract does not have a guaranteed `decision: regenerate` type.

## What if I can't install any of these?

The PostToolUse hook fails open with a one-time advisory:

> Install at least one of semgrep / trufflehog / gitleaks for shift-left SAST. See <https://github.com/thatsjet/claude_secure_coder#install>

You still get Layer 1 (SessionStart context) and Layer 3a (VulnPatternHook deterministic checks). Layer 3b (PostToolUse SAST) is the only piece that doesn't function. The rest of the toolkit works fine.

## Why not bundle these tools?

Three reasons:
1. **Distribution size**: semgrep alone is ~200MB. trufflehog is ~50MB. Bundling would bloat the repo and require platform-specific binaries.
2. **Update cadence**: each tool's rule database updates independently. Bundling pins us to whatever version we shipped with.
3. **Trust**: each is a well-known open-source tool with its own security audit history. Users should install from the canonical source, not from an opaque bundle.

The trade is a small install step in exchange for fresh rules and proper tool isolation.

## Tuning

Per-project rule overrides go in `<project>/.claude/security/sast-ignore.yaml`:

```yaml
ignore_files:
  - "tests/fixtures/**"
  - "vendor/**"
ignore_rules:
  - "javascript.eval"           # semgrep rule ID
  - "anthropic_api_key"         # VulnPatternHook rule ID
  - "GitHub Personal Access Token"  # gitleaks rule name
```

The PostToolUse hook reads this file and filters findings before emitting.

For VulnPatternHook (PreToolUse), edit the rule set directly: `~/.claude/hooks/csc/lib/VulnPatterns.yaml` (or per-project override at `<project>/.claude/security/VulnPatterns.yaml`, which the hook merges).

## Future: MCP integration

Semgrep ships an MCP server (<https://semgrep.dev/docs/mcp>) that exposes scanning as a Claude Code tool. Once stable, this can replace the CLI invocation in PostToolUseSAST. The hook would call the MCP tool and let Claude orchestrate the rewrite loop.
