#!/usr/bin/env bun
/**
 * VulnPatternHook.hook.ts — Standalone Claude Code PreToolUse hook for the
 * claude_secure_coder shift-left toolkit.
 *
 * Runs on Edit / Write / MultiEdit. Hard-blocks on literal-secret detections.
 * Surfaces dangerous-API and weak-crypto findings as `additionalContext`
 * advisories that Claude reads but that do NOT block the action.
 *
 * Hook contract:
 *   - stdin: JSON object with session_id, tool_name, tool_input
 *   - stdout (deny):     {"hookSpecificOutput": {"hookEventName":"PreToolUse",
 *                          "permissionDecision":"deny", "permissionDecisionReason":"..."}}
 *   - stdout (advisory): {"hookSpecificOutput": {"hookEventName":"PreToolUse",
 *                          "additionalContext":"..."}}
 *   - exit code: ALWAYS 0. Decisions go through permissionDecision.
 *
 * This file is intentionally thin. All matching lives in lib/vuln-patterns-core.ts
 * so the PAI inspector adapter can reuse the same code.
 */

import {
  loadRuleSet,
  scanContent,
  extractScanContent,
  defaultRulesPath,
  writeTelemetry,
  type Finding,
  type MatchResult,
} from './lib/vuln-patterns-core';

interface HookInput {
  session_id?: string;
  tool_name?: string;
  tool_input?: Record<string, unknown>;
}

async function readStdin(): Promise<string> {
  // Bun.stdin.stream() is the documented streaming entry point. We accumulate
  // chunks because the input is small (a single JSON object) and we want to
  // be safe under any encoding.
  const chunks: Uint8Array[] = [];
  const reader = (Bun.stdin.stream() as ReadableStream<Uint8Array>).getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) chunks.push(value);
  }
  let total = 0;
  for (const c of chunks) total += c.byteLength;
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    merged.set(c, offset);
    offset += c.byteLength;
  }
  return new TextDecoder().decode(merged);
}

function emitAllow(): void {
  // No output body needed for the default-allow case. The hook simply
  // exits 0 with no JSON, which Claude Code treats as "no opinion".
  process.exit(0);
}

function emitDeny(reasons: string[], findings: Finding[]): void {
  const ruleList = reasons.join(', ');
  const detail = findings
    .filter((f) => f.action === 'deny')
    .map((f) => `  - ${f.rule_id} (line ${f.line}, ${f.severity}): ${f.excerpt}`)
    .join('\n');
  const reason =
    `[claude_secure_coder] BLOCKED — literal secret detected: ${ruleList}\n` +
    detail +
    `\n\nRemove the secret value before re-running. To suppress a specific rule on a single line, ` +
    `add an inline directive (e.g. \`// nosec: ${reasons[0] ?? 'rule_id'}\` or \`# nosec: ${reasons[0] ?? 'rule_id'}\`). ` +
    `Real secrets must NEVER be checked in.`;
  const out = {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: reason,
    },
  };
  process.stdout.write(JSON.stringify(out));
  process.exit(0);
}

function emitAdvisory(findings: Finding[]): void {
  const lines = findings.map((f) => {
    const tag = f.category.toUpperCase();
    return `  [${f.severity}] ${tag} ${f.rule_id} (line ${f.line}): ${f.excerpt}`;
  });
  const additionalContext =
    `[claude_secure_coder] ${findings.length} security finding(s) — advisory, not blocking:\n` +
    lines.join('\n');
  const out = {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      additionalContext,
    },
  };
  process.stdout.write(JSON.stringify(out));
  process.exit(0);
}

async function main(): Promise<void> {
  const t0 = performance.now();

  // Parse stdin. Any malformed input ⇒ silent allow. A hook that crashes the
  // model's tool call on parse errors is a worse failure than a hook that
  // misses one detection.
  let raw: string;
  try {
    raw = await readStdin();
  } catch {
    return emitAllow();
  }
  if (!raw.trim()) return emitAllow();

  let input: HookInput;
  try {
    input = JSON.parse(raw) as HookInput;
  } catch {
    return emitAllow();
  }

  const toolName = input.tool_name ?? '';
  if (toolName !== 'Edit' && toolName !== 'Write' && toolName !== 'MultiEdit') {
    return emitAllow();
  }

  const extracted = extractScanContent(toolName, input.tool_input);
  if (!extracted) return emitAllow();

  // Resolve rules path. CSC_RULES_PATH overrides for testing.
  const rulesPath = process.env.CSC_RULES_PATH || defaultRulesPath();

  let ruleSet;
  try {
    ruleSet = await loadRuleSet(rulesPath);
  } catch {
    return emitAllow();
  }

  let result: MatchResult;
  try {
    result = scanContent({
      filePath: extracted.filePath,
      content: extracted.content,
      ruleSet,
    });
  } catch {
    return emitAllow();
  }

  const latency_ms = Math.round(performance.now() - t0);

  // Telemetry: counts only, never finding payloads.
  writeTelemetry({
    ts: new Date().toISOString(),
    session_id: input.session_id ?? null,
    file: extracted.filePath,
    language: result.language,
    findings_count: result.findings.length,
    decision: result.decision,
    latency_ms,
  });

  if (result.decision === 'deny') {
    return emitDeny(result.denyReasons, result.findings);
  }

  if (result.findings.length > 0) {
    return emitAdvisory(result.findings);
  }

  return emitAllow();
}

// Top-level error guard: on ANY unexpected failure, allow rather than block.
// A hook that hard-fails on its own bug is worse than a hook that no-ops.
main().catch(() => {
  emitAllow();
});
