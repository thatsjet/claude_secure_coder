#!/usr/bin/env bun
/**
 * SecureCodingContext.hook.ts — SessionStart hook
 *
 * Loads OWASP Top 10:2025, CWE Top 25, OWASP AST10 (2026), and per-language
 * secure-coding context into every Claude Code session at start. Detects
 * project language(s) from the working directory and adds language-specific
 * guidance so the context stays focused.
 *
 * TRIGGER: SessionStart
 * PROTOCOL: returns hookSpecificOutput.additionalContext (string) loaded
 *           into Claude's session context before the first prompt.
 *
 * Portable — no PAI dependency. Works with stock Claude Code.
 */

import { existsSync, readFileSync, mkdirSync, writeFileSync, statSync } from "fs";
import { homedir, tmpdir } from "os";
import { join, basename, dirname } from "path";

interface HookInput {
  session_id?: string;
  cwd?: string;
  hook_event_name?: string;
}

interface HookOutput {
  hookSpecificOutput: {
    hookEventName: "SessionStart";
    additionalContext: string;
  };
}

// Resolve the SecureCoding.md location. Two install layouts:
//   1) installed into ~/.claude/PAI/USER/SECURITY/SecureCoding.md (PAI users)
//   2) installed into ~/.claude/secure_coding/SecureCoding.md (non-PAI users)
//   3) repo-relative (devmode) at ../context/SecureCoding.md
function resolveSecureCodingPath(): string | null {
  const candidates = [
    join(homedir(), ".claude", "PAI", "USER", "SECURITY", "SecureCoding.md"),
    join(homedir(), ".claude", "secure_coding", "SecureCoding.md"),
    join(homedir(), ".claude", "context", "SecureCoding.md"),
    // Devmode fallback — when this hook is invoked from the repo
    join(dirname(import.meta.path ?? __filename), "..", "context", "SecureCoding.md"),
  ];
  for (const c of candidates) {
    try {
      if (existsSync(c)) return c;
    } catch {
      // ignore — keep trying
    }
  }
  return null;
}

// Detect languages present in the project root by sniffing manifest files.
// Returns a deduplicated, prioritized list (most-likely primary first).
function detectLanguages(cwd: string): string[] {
  const found = new Set<string>();
  const checks: Array<[string, string]> = [
    ["package.json", "typescript"],
    ["tsconfig.json", "typescript"],
    ["pyproject.toml", "python"],
    ["requirements.txt", "python"],
    ["Pipfile", "python"],
    ["uv.lock", "python"],
    ["poetry.lock", "python"],
    ["Cargo.toml", "rust"],
    ["go.mod", "go"],
    ["Gemfile", "ruby"],
    ["composer.json", "php"],
    ["pom.xml", "java"],
    ["build.gradle", "java"],
    ["build.gradle.kts", "kotlin"],
    [".csproj", "csharp"],
    ["mix.exs", "elixir"],
  ];
  for (const [marker, lang] of checks) {
    try {
      // Check both as exact filename and as a glob in cwd
      if (existsSync(join(cwd, marker))) found.add(lang);
    } catch {
      // ignore
    }
  }
  // SQL and Bash are detected loosely — if any .sh / .sql file is present
  try {
    const dir = readdirSafe(cwd);
    for (const f of dir) {
      const ext = f.split(".").pop()?.toLowerCase() ?? "";
      if (ext === "sh" || ext === "bash") found.add("bash");
      if (ext === "sql") found.add("sql");
      if (ext === "py") found.add("python");
      if (ext === "ts" || ext === "tsx" || ext === "js" || ext === "jsx") {
        found.add("typescript");
      }
    }
  } catch {
    // ignore
  }
  return Array.from(found);
}

function readdirSafe(dir: string): string[] {
  try {
    const { readdirSync } = require("fs");
    return readdirSync(dir).filter((f: string) => !f.startsWith("."));
  } catch {
    return [];
  }
}

// Cache key: hash of (SecureCoding.md mtime + detected languages). If cache
// hits, we still return the context (so it loads each session) but skip the
// disk re-read of large files. Cache lives in tmpdir, scoped per session.
function cacheKey(securePath: string, languages: string[]): string {
  try {
    const stat = statSync(securePath);
    const mtime = stat.mtimeMs.toString(36);
    return `${mtime}-${languages.sort().join(",")}`;
  } catch {
    return `nocache-${Date.now().toString(36)}`;
  }
}

function getCachedContext(sessionId: string, key: string): string | null {
  const cacheFile = join(tmpdir(), `claude-secure-coding-${sessionId}.cache`);
  try {
    if (!existsSync(cacheFile)) return null;
    const raw = readFileSync(cacheFile, "utf-8");
    const parsed = JSON.parse(raw) as { key: string; context: string };
    if (parsed.key === key) return parsed.context;
    return null;
  } catch {
    return null;
  }
}

function setCachedContext(sessionId: string, key: string, context: string): void {
  const cacheFile = join(tmpdir(), `claude-secure-coding-${sessionId}.cache`);
  try {
    writeFileSync(cacheFile, JSON.stringify({ key, context }), "utf-8");
  } catch {
    // ignore — cache miss next time is acceptable
  }
}

// Build language-specific subset by extracting the per-language section from
// SecureCoding.md. Sections are H3-level (`### TypeScript / JavaScript`,
// `### Python`, etc.). We pass the universal sections through always.
function buildContext(
  fullDoc: string,
  languages: string[]
): string {
  const universalHeader = "# Secure Coding Context (loaded by claude_secure_coder)";
  const intro =
    "The following secure-coding rules are in effect for this session. " +
    "If a rule below conflicts with an aesthetic instinct, the security " +
    "rule wins unless an explicit threat-model decision in the project's " +
    "PRD records the rationale. Apply these rules at write time — do not " +
    "wait for review to catch them.";

  // Always include the universal sections (the part of the doc up to the
  // "Per-language guidance" heading) and then only the requested languages.
  const perLangAnchor = "## Per-language guidance";
  const langSplitIdx = fullDoc.indexOf(perLangAnchor);
  const universalSection =
    langSplitIdx === -1 ? fullDoc : fullDoc.slice(0, langSplitIdx);
  const langSection =
    langSplitIdx === -1 ? "" : fullDoc.slice(langSplitIdx);

  const languageHeaders = new Map<string, string>([
    ["typescript", "### TypeScript / JavaScript"],
    ["javascript", "### TypeScript / JavaScript"],
    ["python", "### Python"],
    ["bash", "### Bash"],
    ["sql", "### SQL"],
  ]);

  const langExtracts: string[] = [];
  const seen = new Set<string>();
  for (const lang of languages) {
    const header = languageHeaders.get(lang.toLowerCase());
    if (!header || seen.has(header)) continue;
    seen.add(header);
    const idx = langSection.indexOf(header);
    if (idx === -1) continue;
    // Find the next H3 (or H2) after this section's start
    const nextH3 = langSection.indexOf("\n### ", idx + header.length);
    const nextH2 = langSection.indexOf("\n## ", idx + header.length);
    const cuts = [nextH3, nextH2].filter((n) => n > 0);
    const end = cuts.length === 0 ? langSection.length : Math.min(...cuts);
    langExtracts.push(langSection.slice(idx, end).trim());
  }

  // Always include the trailing universal sections (Secrets, Auth, Authz, etc.)
  const tailAnchor = "## Secrets handling — universal";
  const tailIdx = fullDoc.indexOf(tailAnchor);
  const tail = tailIdx === -1 ? "" : fullDoc.slice(tailIdx);

  let body = universalSection;
  if (langExtracts.length > 0) {
    body += "\n\n## Per-language guidance (active for this project)\n\n";
    body += langExtracts.join("\n\n");
    body += "\n\n";
  }
  if (tail) {
    body += tail;
  }

  return [universalHeader, "", intro, "", body].join("\n");
}

async function main(): Promise<void> {
  let input: HookInput = {};
  try {
    const raw = readFileSync("/dev/stdin", "utf-8");
    if (raw.trim()) {
      input = JSON.parse(raw) as HookInput;
    }
  } catch {
    // Continue with defaults — better to load context than fail silently
  }

  const sessionId = input.session_id ?? "unknown";
  const cwd = input.cwd ?? process.cwd();

  const securePath = resolveSecureCodingPath();
  if (!securePath) {
    // Cannot find SecureCoding.md — emit a tiny notice so the user knows
    // the install isn't complete, but don't fail the session.
    const notice =
      "# Secure Coding Context (not found)\n\n" +
      "claude_secure_coder is registered but `SecureCoding.md` was not found. " +
      "Install with `bash install.sh` from the claude_secure_coder repo to " +
      "enable shift-left security context.";
    emit(notice);
    return;
  }

  const languages = detectLanguages(cwd);
  const key = cacheKey(securePath, languages);

  let context = getCachedContext(sessionId, key);
  if (context === null) {
    let fullDoc = "";
    try {
      fullDoc = readFileSync(securePath, "utf-8");
    } catch {
      // Read failed — emit a minimal notice and exit
      emit(
        "# Secure Coding Context (read error)\n\n" +
          `Could not read ${securePath}. Verify file permissions.`
      );
      return;
    }
    context = buildContext(fullDoc, languages);
    setCachedContext(sessionId, key, context);
  }

  // Telemetry — append a single JSONL line. Best-effort; never blocks.
  try {
    const obsDir = join(homedir(), ".claude", "PAI", "MEMORY", "OBSERVABILITY");
    const obsFile = existsSync(obsDir)
      ? join(obsDir, "secure-coding-context.jsonl")
      : join(tmpdir(), "claude-secure-coding-context.jsonl");
    if (!existsSync(dirname(obsFile))) mkdirSync(dirname(obsFile), { recursive: true });
    const line = JSON.stringify({
      ts: new Date().toISOString(),
      session_id: sessionId,
      cwd,
      languages,
      context_chars: context.length,
      cache: key,
    });
    writeFileSync(obsFile, line + "\n", { flag: "a" });
  } catch {
    // ignore — telemetry is never load-bearing
  }

  emit(context);
}

function emit(context: string): void {
  const out: HookOutput = {
    hookSpecificOutput: {
      hookEventName: "SessionStart",
      additionalContext: context,
    },
  };
  console.log(JSON.stringify(out));
  process.exit(0);
}

main().catch(() => process.exit(0));
