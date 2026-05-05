/**
 * VulnPatternInspector.ts — PAI SecurityPipeline adapter for the
 * claude_secure_coder shift-left vulnerability pattern toolkit.
 *
 * Designed to live at:  ~/.claude/hooks/security/inspectors/VulnPatternInspector.ts
 *
 * It mirrors the local PAI inspector pattern (PatternInspector at priority
 * 100, EgressInspector at 90, this inspector at 70, RulesInspector at 50).
 * The inspector imports the matcher core from the
 * claude_secure_coder repo via a path resolved from the CSC_HOOK_DIR env
 * var, with a sensible default so the file works on a fresh install.
 *
 * Responsibilities of this adapter:
 *   - Translate PAI's InspectionContext into a vuln-patterns-core scan call.
 *   - Translate the scan result back into a PAI InspectionResult.
 *   - Surface deny-class findings as `deny`, alert-class findings as `alert`.
 *   - Run only on Write/Edit/MultiEdit; allow other tools through.
 *
 * NOT responsibilities of this adapter:
 *   - It does NOT load YAML, compile regexes, or do matching. That all
 *     lives in `vuln-patterns-core.ts`. There is exactly one source of truth.
 */

import type { Inspector, InspectionContext, InspectionResult } from '../types';
import { ALLOW, deny, alert } from '../types';
import { homedir } from 'node:os';
import { existsSync } from 'node:fs';
import { resolve as pathResolve } from 'node:path';

// ─────────────────────────────────────────────────────────────────────────────
// Resolve the matcher core path
// ─────────────────────────────────────────────────────────────────────────────
//
// The standalone hook ships in the claude_secure_coder repo. The PAI install
// script copies or symlinks this adapter into ~/.claude/hooks/security/
// inspectors/ but does NOT relocate the matcher core. We therefore resolve
// the core dynamically.
//
// Resolution order:
//   1. $CSC_HOOK_DIR (must point at the directory containing
//      lib/vuln-patterns-core.ts)
//   2. ~/projects/claude_secure_coder/hooks   (the canonical clone path)
//   3. ~/code/claude_secure_coder/hooks       (alternate clone path)
//
// If none of those resolve, the inspector becomes a no-op — it logs a single
// alert on the first call so an operator notices, then allows everything.

function resolveCoreDir(): string | null {
  const candidates: string[] = [];
  if (process.env.CSC_HOOK_DIR) candidates.push(process.env.CSC_HOOK_DIR);
  const home = homedir();
  candidates.push(pathResolve(home, 'projects', 'claude_secure_coder', 'hooks'));
  candidates.push(pathResolve(home, 'code', 'claude_secure_coder', 'hooks'));

  for (const dir of candidates) {
    const corePath = pathResolve(dir, 'lib', 'vuln-patterns-core.ts');
    if (existsSync(corePath)) return dir;
  }
  return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Lazy-loaded matcher core
// ─────────────────────────────────────────────────────────────────────────────
//
// We dynamic-import the core so that:
//   - The PAI security pipeline doesn't pay the import cost on every session
//     when this inspector isn't actually used.
//   - The path can be resolved at runtime from CSC_HOOK_DIR.

type CoreModule = typeof import('../../../../../projects/claude_secure_coder/hooks/lib/vuln-patterns-core');

let cachedCore: CoreModule | null = null;
let cachedCoreFailed = false;

async function loadCore(): Promise<CoreModule | null> {
  if (cachedCore) return cachedCore;
  if (cachedCoreFailed) return null;

  const dir = resolveCoreDir();
  if (!dir) {
    cachedCoreFailed = true;
    return null;
  }
  const corePath = pathResolve(dir, 'lib', 'vuln-patterns-core.ts');
  try {
    // The dynamic import string is computed, not literal — TypeScript can't
    // type-check it, so we cast to CoreModule at the boundary.
    const mod = (await import(/* @vite-ignore */ corePath)) as CoreModule;
    cachedCore = mod;
    return mod;
  } catch {
    cachedCoreFailed = true;
    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Inspector
// ─────────────────────────────────────────────────────────────────────────────

const HANDLED_TOOLS = new Set(['Write', 'Edit', 'MultiEdit']);

class VulnPatternInspector implements Inspector {
  name = 'VulnPatternInspector';
  priority = 70;

  async inspect(ctx: InspectionContext): Promise<InspectionResult> {
    if (!HANDLED_TOOLS.has(ctx.toolName)) return ALLOW;

    const core = await loadCore();
    if (!core) {
      // Core unavailable — emit one advisory and allow. We do NOT block
      // because that would shut down all writes on a misconfigured install.
      return alert(
        'VulnPatternInspector: vuln-patterns-core.ts not found. ' +
          'Set CSC_HOOK_DIR or clone claude_secure_coder to a known path. ' +
          'Inspector running in no-op mode.',
      );
    }

    // Pull the content out of the tool input.
    const extracted = core.extractScanContent(ctx.toolName, ctx.toolInput);
    if (!extracted) return ALLOW;

    // Resolve the rules path. CSC_RULES_PATH wins; otherwise default.
    const rulesPath = process.env.CSC_RULES_PATH || core.defaultRulesPath();

    let ruleSet;
    try {
      ruleSet = await core.loadRuleSet(rulesPath);
    } catch {
      return ALLOW;
    }

    let result;
    try {
      result = core.scanContent({
        filePath: extracted.filePath,
        content: extracted.content,
        ruleSet,
      });
    } catch {
      return ALLOW;
    }

    if (result.findings.length === 0) return ALLOW;

    // Telemetry — counts only, never findings.
    try {
      core.writeTelemetry({
        ts: new Date().toISOString(),
        session_id: ctx.sessionId,
        file: extracted.filePath,
        language: result.language,
        findings_count: result.findings.length,
        decision: result.decision,
        latency_ms: 0, // PAI pipeline measures latency at a higher layer
      });
    } catch {
      // Telemetry is best-effort; never fail the inspection on log errors.
    }

    if (result.decision === 'deny') {
      const ruleList = result.denyReasons.join(', ');
      const denyDetail = result.findings
        .filter((f) => f.action === 'deny')
        .map((f) => `${f.rule_id}@L${f.line}`)
        .join(', ');
      return deny(
        `vuln_pattern: literal secret detected (${ruleList}). Findings: ${denyDetail}. ` +
          `Severity: critical. Remove the secret before continuing.`,
        `vuln_pattern:${result.denyReasons[0] ?? 'secret'}`,
      );
    }

    // No deny-class findings — emit a single alert summarising the advisories.
    const summary = result.findings
      .map((f) => `${f.severity} ${f.rule_id}@L${f.line}`)
      .join('; ');
    return alert(`vuln_pattern: ${result.findings.length} advisory finding(s) — ${summary}`);
  }
}

export function createVulnPatternInspector(): Inspector {
  return new VulnPatternInspector();
}
