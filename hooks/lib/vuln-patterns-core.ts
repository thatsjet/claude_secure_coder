/**
 * vuln-patterns-core.ts — Shared matcher core for the claude_secure_coder
 * shift-left vulnerability pattern toolkit.
 *
 * This is the ONLY module in the toolkit that loads patterns from YAML
 * and runs regex matching against proposed code. Both
 *   - hooks/VulnPatternHook.hook.ts (standalone Claude Code PreToolUse hook)
 *   - patches/pai/VulnPatternInspector.ts (PAI SecurityPipeline adapter)
 * delegate to the functions exported here.
 *
 * Design constraints:
 *   - No npm dependencies. The YAML rule format is intentionally narrow
 *     (list of objects with string fields) so we hand-roll a parser.
 *   - Read-only. Never mutates input files. Never writes anything except
 *     append-only telemetry through a caller-supplied path.
 *   - <200ms wall budget on a 1000-line content. Compile every regex
 *     exactly once at first load. Use String.prototype.matchAll with
 *     line-tracked offsets — no per-line splits, no quadratic scans.
 *   - Never write a secret value to disk. The Finding.excerpt is capped
 *     at 80 chars and replaces every captured-secret value with the
 *     literal token `[REDACTED:<rule_id>]`.
 */

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type Action = 'deny' | 'alert';
export type Category = 'secret' | 'dangerous_api' | 'weak_crypto';
export type Language = 'typescript' | 'python' | 'bash' | 'sql' | 'generic';

export interface Rule {
  id: string;
  pattern: string;
  severity: Severity;
  action: Action;
  description?: string;
  cwe?: string;
}

interface CompiledRule extends Rule {
  regex: RegExp;
}

export interface RuleSet {
  secrets: CompiledRule[];
  dangerous_apis: Record<Language, CompiledRule[]>;
  weak_crypto: CompiledRule[];
}

export interface Finding {
  category: Category;
  rule_id: string;
  severity: Severity;
  action: Action;
  line: number;
  excerpt: string;
}

export interface MatchResult {
  findings: Finding[];
  decision: 'deny' | 'allow';
  denyReasons: string[];
  language: Language;
  testPath: boolean;
}

// ─────────────────────────────────────────────────────────────────────────────
// YAML loader (minimal, schema-specific)
// ─────────────────────────────────────────────────────────────────────────────
//
// The rule YAML uses a deliberately tiny subset:
//   top-level keys: secrets, dangerous_apis, weak_crypto
//   secrets / weak_crypto: list of {id, pattern, severity, action, ...}
//   dangerous_apis: map of language → list of rules
//
// We parse by walking lines and tracking indentation. Rule fields are all
// strings; values may be quoted with single or double quotes. We do NOT
// support: anchors, aliases, flow-style, multi-line strings other than
// the single-line forms below.

function unquote(raw: string): string {
  const s = raw.trim();
  if (s.length >= 2) {
    const first = s[0];
    const last = s[s.length - 1];
    if ((first === '"' && last === '"') || (first === "'" && last === "'")) {
      // Unescape \" inside double-quoted strings; YAML single-quoted strings
      // escape an embedded ' as ''.
      if (first === '"') return s.slice(1, -1).replace(/\\"/g, '"').replace(/\\\\/g, '\\');
      return s.slice(1, -1).replace(/''/g, "'");
    }
  }
  return s;
}

interface RawRule {
  id?: string;
  pattern?: string;
  severity?: string;
  action?: string;
  description?: string;
  cwe?: string;
}

interface RawConfig {
  secrets: RawRule[];
  dangerous_apis: Record<string, RawRule[]>;
  weak_crypto: RawRule[];
}

function indentOf(line: string): number {
  let n = 0;
  while (n < line.length && line[n] === ' ') n++;
  return n;
}

export function parseRulesYaml(text: string): RawConfig {
  const out: RawConfig = { secrets: [], dangerous_apis: {}, weak_crypto: [] };
  // Strip BOM, normalize CRLF, drop full-line comments and empty lines.
  const lines = text.replace(/^﻿/, '').replace(/\r\n/g, '\n').split('\n');

  type TopKey = 'secrets' | 'dangerous_apis' | 'weak_crypto';
  let topKey: TopKey | null = null;
  let langKey: string | null = null; // only used inside dangerous_apis
  let currentList: RawRule[] | null = null;
  let currentRule: RawRule | null = null;
  let currentRuleIndent = -1;

  const flushRule = () => {
    if (currentRule && currentList) {
      currentList.push(currentRule);
    }
    currentRule = null;
    currentRuleIndent = -1;
  };

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    // Drop comment-only lines and blank lines.
    const stripped = raw.replace(/\s+$/, '');
    if (!stripped.trim() || stripped.trim().startsWith('#')) continue;

    const indent = indentOf(stripped);
    const body = stripped.slice(indent);

    // Top-level key (zero indent, ends with ":" and no value).
    if (indent === 0) {
      flushRule();
      const m = body.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*:\s*$/);
      if (!m) {
        topKey = null;
        langKey = null;
        currentList = null;
        continue;
      }
      const key = m[1];
      if (key === 'secrets') {
        topKey = 'secrets';
        langKey = null;
        currentList = out.secrets;
      } else if (key === 'weak_crypto') {
        topKey = 'weak_crypto';
        langKey = null;
        currentList = out.weak_crypto;
      } else if (key === 'dangerous_apis') {
        topKey = 'dangerous_apis';
        langKey = null;
        currentList = null;
      } else {
        topKey = null;
        langKey = null;
        currentList = null;
      }
      continue;
    }

    // Inside dangerous_apis: language sub-key at indent 2 ("typescript:" etc).
    if (topKey === 'dangerous_apis' && indent === 2) {
      flushRule();
      const m = body.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*:\s*$/);
      if (!m) {
        langKey = null;
        currentList = null;
        continue;
      }
      langKey = m[1];
      if (!out.dangerous_apis[langKey]) out.dangerous_apis[langKey] = [];
      currentList = out.dangerous_apis[langKey];
      continue;
    }

    // List item start — "- key: value" — opens a new rule.
    if (body.startsWith('- ')) {
      flushRule();
      currentRule = {};
      currentRuleIndent = indent;
      // The remainder after "- " may be a "key: value" pair.
      const rest = body.slice(2);
      const m = rest.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)$/);
      if (m) {
        const key = m[1];
        const val = m[2].trim();
        if (val.length > 0) {
          (currentRule as Record<string, string>)[key] = unquote(val);
        }
      }
      continue;
    }

    // Continuation field of the current rule — "  key: value".
    if (currentRule && indent > currentRuleIndent) {
      const m = body.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)$/);
      if (m) {
        const key = m[1];
        const val = m[2].trim();
        (currentRule as Record<string, string>)[key] = unquote(val);
      }
      continue;
    }
  }

  flushRule();
  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Rule compilation
// ─────────────────────────────────────────────────────────────────────────────

function compileRule(raw: RawRule, fallbackCategory: string): CompiledRule | null {
  if (!raw.id || !raw.pattern || !raw.severity || !raw.action) return null;
  const sev = raw.severity.toUpperCase() as Severity;
  if (sev !== 'CRITICAL' && sev !== 'HIGH' && sev !== 'MEDIUM' && sev !== 'LOW') return null;
  const act = raw.action.toLowerCase() as Action;
  if (act !== 'deny' && act !== 'alert') return null;

  // Test compile once. Fail-closed by skipping invalid rules — better to lose
  // one rule than crash the pipeline.
  let regex: RegExp;
  try {
    regex = new RegExp(raw.pattern, 'g');
  } catch {
    return null;
  }
  void fallbackCategory; // category is implicit by which list the rule lives in
  return {
    id: raw.id,
    pattern: raw.pattern,
    severity: sev,
    action: act,
    description: raw.description,
    cwe: raw.cwe,
    regex,
  };
}

function compileList(list: RawRule[] | undefined, category: string): CompiledRule[] {
  if (!list) return [];
  const out: CompiledRule[] = [];
  for (const r of list) {
    const c = compileRule(r, category);
    if (c) out.push(c);
  }
  return out;
}

function emptyLangMap(): Record<Language, CompiledRule[]> {
  return { typescript: [], python: [], bash: [], sql: [], generic: [] };
}

// ─────────────────────────────────────────────────────────────────────────────
// Cached rule loading
// ─────────────────────────────────────────────────────────────────────────────

let cachedRuleSet: RuleSet | null = null;
let cachedRuleSetPath: string | null = null;

export async function loadRuleSet(yamlPath: string): Promise<RuleSet> {
  if (cachedRuleSet && cachedRuleSetPath === yamlPath) return cachedRuleSet;

  const file = Bun.file(yamlPath);
  const exists = await file.exists();
  if (!exists) {
    // Fail-open with empty rule set (allow). The hook's behavior on a missing
    // YAML is documented: silently allow rather than block all writes.
    const empty: RuleSet = {
      secrets: [],
      dangerous_apis: emptyLangMap(),
      weak_crypto: [],
    };
    cachedRuleSet = empty;
    cachedRuleSetPath = yamlPath;
    return empty;
  }

  const text = await file.text();
  const raw = parseRulesYaml(text);

  const langs = emptyLangMap();
  for (const [k, v] of Object.entries(raw.dangerous_apis || {})) {
    if (k === 'typescript' || k === 'python' || k === 'bash' || k === 'sql' || k === 'generic') {
      langs[k] = compileList(v, 'dangerous_api');
    }
  }

  const set: RuleSet = {
    secrets: compileList(raw.secrets, 'secret'),
    dangerous_apis: langs,
    weak_crypto: compileList(raw.weak_crypto, 'weak_crypto'),
  };

  cachedRuleSet = set;
  cachedRuleSetPath = yamlPath;
  return set;
}

/** Test-only: drop the in-memory rule cache. */
export function clearRuleSetCache(): void {
  cachedRuleSet = null;
  cachedRuleSetPath = null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Default config path resolution
// ─────────────────────────────────────────────────────────────────────────────

import { resolve as pathResolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Resolve the default VulnPatterns.yaml path relative to this module's
 * location. The repo layout is:
 *   <repo>/hooks/lib/vuln-patterns-core.ts   (this file)
 *   <repo>/config/VulnPatterns.yaml          (rules)
 * so `../../config/VulnPatterns.yaml` from this file's dir is correct.
 *
 * The standalone hook and the inspector adapter may override this path
 * (the hook accepts a CSC_RULES_PATH env var; the inspector accepts an
 * explicit constructor arg).
 */
export function defaultRulesPath(): string {
  // Search order:
  //   1. CSC_RULES_PATH env var (explicit override)
  //   2. <module-dir>/VulnPatterns.yaml              (lib-colocated install layout)
  //   3. <module-dir>/../../config/VulnPatterns.yaml (source repo layout)
  //   4. <cwd>/config/VulnPatterns.yaml              (last-resort fallback)
  // The first existing path wins. Handles both the source-repo layout
  // (hooks/lib/ + config/ siblings) and the install layout
  // (everything under ~/.claude/hooks/csc/{lib,*.hook.ts}).
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const fs = require('node:fs') as typeof import('node:fs');

  const envOverride = process.env.CSC_RULES_PATH;
  if (envOverride && envOverride.length > 0) return envOverride;

  let here: string | null = null;
  try {
    here = fileURLToPath(import.meta.url);
  } catch {
    here = null;
  }

  const candidates: string[] = [];
  if (here) {
    const dir = dirname(here);
    candidates.push(pathResolve(dir, 'VulnPatterns.yaml'));
    candidates.push(pathResolve(dir, '..', '..', 'config', 'VulnPatterns.yaml'));
  }
  candidates.push(pathResolve(process.cwd(), 'config', 'VulnPatterns.yaml'));

  for (const c of candidates) {
    try {
      if (fs.existsSync(c)) return c;
    } catch {
      // skip
    }
  }
  return candidates[0] ?? pathResolve(process.cwd(), 'config', 'VulnPatterns.yaml');
}

// ─────────────────────────────────────────────────────────────────────────────
// Language and test-path detection
// ─────────────────────────────────────────────────────────────────────────────

export function detectLanguage(filePath: string | undefined | null): Language {
  if (!filePath) return 'generic';
  const lower = filePath.toLowerCase();
  if (/\.(ts|tsx|js|jsx|mjs|cjs)$/.test(lower)) return 'typescript';
  if (/\.py$/.test(lower)) return 'python';
  if (/\.(sh|bash|zsh)$/.test(lower)) return 'bash';
  if (/\.sql$/.test(lower)) return 'sql';
  return 'generic';
}

const TEST_PATH_PATTERNS = [
  /\btests?\//,
  /\b__tests__\//,
  /\b__fixtures__\//,
  /\bfixtures?\//,
  /\.test\./,
  /\.spec\./,
  /test_[^/]*$/,
  /_test\.[^/]+$/,
];

export function isTestPath(filePath: string | undefined | null): boolean {
  if (!filePath) return false;
  const lower = filePath.toLowerCase();
  for (const re of TEST_PATH_PATTERNS) {
    if (re.test(lower)) return true;
  }
  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// Allowlist directives ( // nosec: rule_id  or  # nosec: rule_id )
// ─────────────────────────────────────────────────────────────────────────────

const NOSEC_DIRECTIVE = /(?:\/\/|#)\s*nosec\s*:\s*([A-Za-z0-9_,\s-]+)/;

/**
 * Returns a Set of rule IDs that are suppressed on the given (1-based) line.
 * A directive `// nosec: rule_a, rule_b` on the same line as a finding
 * suppresses both rule_a and rule_b for that line.
 *
 * We do NOT support file-level or block-level directives — only same-line.
 * That keeps the surface area small and resists accidental over-suppression.
 */
function suppressionsForLine(lineText: string): Set<string> {
  const m = lineText.match(NOSEC_DIRECTIVE);
  if (!m) return new Set();
  return new Set(
    m[1]
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Excerpt construction (with secret redaction)
// ─────────────────────────────────────────────────────────────────────────────

const EXCERPT_MAX = 80;

function buildExcerpt(
  lineText: string,
  matchStart: number,
  matchEnd: number,
  category: Category,
  ruleId: string,
): string {
  // For secrets we never reveal the matched span. Replace with REDACTED token
  // and centre a window around it.
  if (category === 'secret') {
    const before = lineText.slice(Math.max(0, matchStart - 20), matchStart);
    const after = lineText.slice(matchEnd, matchEnd + 20);
    const redacted = `[REDACTED:${ruleId}]`;
    let out = `${before}${redacted}${after}`;
    if (out.length > EXCERPT_MAX) out = out.slice(0, EXCERPT_MAX - 1) + '…';
    return out.replace(/\s+/g, ' ').trim();
  }

  // Non-secret: show a window around the match, no redaction.
  const start = Math.max(0, matchStart - 20);
  const end = Math.min(lineText.length, matchEnd + 40);
  let excerpt = lineText.slice(start, end);
  if (excerpt.length > EXCERPT_MAX) excerpt = excerpt.slice(0, EXCERPT_MAX - 1) + '…';
  return excerpt.replace(/\s+/g, ' ').trim();
}

// ─────────────────────────────────────────────────────────────────────────────
// Line offset index (built once per content)
// ─────────────────────────────────────────────────────────────────────────────

interface LineIndex {
  /** offsets[i] = absolute offset of the start of line (i+1). 1-indexed lines. */
  offsets: number[];
  text: string;
}

function buildLineIndex(text: string): LineIndex {
  const offsets: number[] = [0];
  for (let i = 0; i < text.length; i++) {
    if (text.charCodeAt(i) === 10 /* \n */) {
      offsets.push(i + 1);
    }
  }
  return { offsets, text };
}

function lineOf(idx: LineIndex, absoluteOffset: number): number {
  // Binary search for the largest start <= absoluteOffset.
  const a = idx.offsets;
  let lo = 0;
  let hi = a.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >>> 1;
    if (a[mid] <= absoluteOffset) lo = mid;
    else hi = mid - 1;
  }
  return lo + 1;
}

function lineTextOf(idx: LineIndex, line1: number): string {
  const start = idx.offsets[line1 - 1] ?? 0;
  const end = idx.offsets[line1] ?? idx.text.length;
  // Trim the trailing newline if present.
  const slice = idx.text.slice(start, end);
  return slice.endsWith('\n') ? slice.slice(0, -1) : slice;
}

// ─────────────────────────────────────────────────────────────────────────────
// Core matcher
// ─────────────────────────────────────────────────────────────────────────────

export interface MatchOptions {
  /** Path of the file being written/edited. Drives language and test-path detection. */
  filePath?: string | null;
  /** The proposed code content to scan. */
  content: string;
  /** Pre-loaded rule set. */
  ruleSet: RuleSet;
}

/**
 * Scan the given content against the rule set and return findings + a
 * top-level decision. Pure function — no I/O, no globals mutated.
 *
 * Behavior summary (matches the F3 spec):
 *   - Run the secrets list always.
 *   - Run dangerous_apis[<language>] for the detected language.
 *   - Run weak_crypto for typescript/python (the only languages where the
 *     starter rules apply); other languages get a no-op.
 *   - If filePath looks like a test/fixture path, every secrets rule's
 *     action is downgraded to 'alert' (test fixtures must not hard-block).
 *   - `// nosec: <rule_id>` or `# nosec: <rule_id>` on the SAME LINE as
 *     a finding suppresses that finding.
 */
export function scanContent(opts: MatchOptions): MatchResult {
  const { content, ruleSet } = opts;
  const filePath = opts.filePath ?? null;
  const language = detectLanguage(filePath);
  const testPath = isTestPath(filePath);
  const idx = buildLineIndex(content);

  const findings: Finding[] = [];

  const runRules = (rules: CompiledRule[], category: Category) => {
    for (const rule of rules) {
      // Reset lastIndex defensively — RegExp objects are reused across calls.
      rule.regex.lastIndex = 0;
      // matchAll yields all non-overlapping matches in one pass.
      for (const m of content.matchAll(rule.regex)) {
        const start = m.index ?? 0;
        const end = start + (m[0]?.length ?? 0);
        const line1 = lineOf(idx, start);
        const lineText = lineTextOf(idx, line1);

        // Same-line nosec directives suppress this finding.
        const suppressed = suppressionsForLine(lineText);
        if (suppressed.has(rule.id)) continue;

        // Test-path override: secrets in test/fixture paths become advisory.
        let action: Action = rule.action;
        if (testPath && category === 'secret' && action === 'deny') {
          action = 'alert';
        }

        findings.push({
          category,
          rule_id: rule.id,
          severity: rule.severity,
          action,
          line: line1,
          excerpt: buildExcerpt(lineText, start - idx.offsets[line1 - 1], end - idx.offsets[line1 - 1], category, rule.id),
        });
      }
    }
  };

  runRules(ruleSet.secrets, 'secret');

  const langRules = ruleSet.dangerous_apis[language] || [];
  if (langRules.length > 0) runRules(langRules, 'dangerous_api');

  // weak_crypto rules apply to typescript / python source. Skip on bash/sql
  // where the patterns produce noise.
  if (language === 'typescript' || language === 'python' || language === 'generic') {
    runRules(ruleSet.weak_crypto, 'weak_crypto');
  }

  const denyFindings = findings.filter((f) => f.action === 'deny');
  const decision: 'deny' | 'allow' = denyFindings.length > 0 ? 'deny' : 'allow';
  const denyReasons = Array.from(new Set(denyFindings.map((f) => f.rule_id)));

  return { findings, decision, denyReasons, language, testPath };
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool-input → content extraction
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Pull the content-to-be-scanned out of a Claude Code PreToolUse tool_input
 * payload. Returns null when there's nothing scannable (e.g. an Edit that
 * only deletes content, or a malformed payload). Callers treat null as
 * "allow silently".
 */
export function extractScanContent(
  toolName: string,
  toolInput: unknown,
): { content: string; filePath: string | null } | null {
  if (!toolInput || typeof toolInput !== 'object') return null;
  const input = toolInput as Record<string, unknown>;
  const filePath = typeof input.file_path === 'string' ? input.file_path : null;

  if (toolName === 'Write') {
    const c = input.content;
    if (typeof c !== 'string' || c.length === 0) return null;
    return { content: c, filePath };
  }

  if (toolName === 'Edit') {
    const c = input.new_string;
    if (typeof c !== 'string' || c.length === 0) return null;
    return { content: c, filePath };
  }

  if (toolName === 'MultiEdit') {
    const edits = input.edits;
    if (!Array.isArray(edits) || edits.length === 0) return null;
    const parts: string[] = [];
    for (const e of edits) {
      if (e && typeof e === 'object') {
        const ns = (e as Record<string, unknown>).new_string;
        if (typeof ns === 'string' && ns.length > 0) parts.push(ns);
      }
    }
    if (parts.length === 0) return null;
    return { content: parts.join('\n'), filePath };
  }

  return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Telemetry
// ─────────────────────────────────────────────────────────────────────────────

import { homedir, tmpdir } from 'node:os';
import { mkdirSync, existsSync, appendFileSync } from 'node:fs';

export interface TelemetryRecord {
  ts: string;
  session_id: string | null;
  file: string | null;
  language: Language;
  findings_count: number;
  decision: 'deny' | 'allow';
  latency_ms: number;
}

/**
 * Resolve the telemetry path. Prefers
 *   $HOME/.claude/PAI/MEMORY/OBSERVABILITY/vulnpattern-scans.jsonl
 * but falls back to os.tmpdir()/vulnpattern-scans.jsonl when the PAI
 * memory dir is not writable. The fallback keeps the standalone hook
 * useful in non-PAI installs.
 */
export function resolveTelemetryPath(): string {
  const primaryDir = `${homedir()}/.claude/PAI/MEMORY/OBSERVABILITY`;
  try {
    if (!existsSync(primaryDir)) {
      mkdirSync(primaryDir, { recursive: true });
    }
    return `${primaryDir}/vulnpattern-scans.jsonl`;
  } catch {
    return `${tmpdir()}/vulnpattern-scans.jsonl`;
  }
}

/**
 * Append one JSON line to the telemetry log. Telemetry MUST NOT contain
 * findings — only counts — because we never want a secret value to land
 * in a log file.
 */
export function writeTelemetry(record: TelemetryRecord, path?: string): void {
  const line = JSON.stringify(record) + '\n';
  const target = path ?? resolveTelemetryPath();
  try {
    appendFileSync(target, line, { encoding: 'utf-8' });
  } catch {
    // Telemetry failures are silent. They must never block the user.
  }
}
