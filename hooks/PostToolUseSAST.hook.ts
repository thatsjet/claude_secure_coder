#!/usr/bin/env bun
/**
 * PostToolUseSAST.hook.ts — shift-left SAST for Claude Code
 *
 * Claude Code PostToolUse hook (matcher: Edit|Write|MultiEdit) that runs
 * available SAST tools (semgrep, trufflehog, gitleaks) on the file just
 * edited/written and feeds findings back to Claude via additionalContext.
 *
 * High-severity findings produce an explicit ACTION line that asks Claude
 * to rewrite the file before continuing. Medium/low findings are advisory.
 * Per-file regenerate iterations are bounded to 2 per session.
 *
 * This hook is read-only and never makes outbound network calls.
 * Exit code is always 0 (PostToolUse must not block).
 *
 * Hook protocol: https://code.claude.com/docs/en/hooks
 */

import { spawn } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, statSync } from "node:fs";
import { appendFileSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

// ---------- types ----------

type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
type ToolName = "semgrep" | "trufflehog" | "gitleaks";

interface Finding {
    tool: ToolName;
    severity: Severity;
    rule_id: string;
    message: string;
    file: string;
    line: number;
    snippet?: string;
}

interface ToolAvailability {
    semgrep: boolean;
    trufflehog: boolean;
    gitleaks: boolean;
    detected_at: number;
}

interface RegenState {
    [filePath: string]: number;
}

interface ProjectIgnore {
    ignore_files: string[];
    ignore_rules: string[];
}

interface HookInput {
    session_id?: string;
    tool_name?: string;
    tool_input?: { file_path?: string; [k: string]: unknown };
    tool_response?: unknown;
}

// ---------- constants ----------

const TOOL_TIMEOUT_MS = 12_000;
const HOOK_BUDGET_MS = 14_500;
const MAX_REGEN_PER_FILE = 2;

const SKIP_PATTERNS: RegExp[] = [
    /(^|\/)node_modules(\/|$)/,
    /(^|\/)\.venv(\/|$)/,
    /(^|\/)venv(\/|$)/,
    /(^|\/)dist(\/|$)/,
    /(^|\/)build(\/|$)/,
    /(^|\/)\.next(\/|$)/,
    /(^|\/)\.git(\/|$)/,
    /\.lock$/,
    /\.min\.js$/,
    /\.min\.css$/,
];

// ---------- entrypoint ----------

void main().catch(() => {
    // Never propagate. PostToolUse must not block.
    process.exit(0);
});

async function main(): Promise<void> {
    const started = Date.now();

    // Hard wall-clock guardrail in case some inner await hangs.
    const guard = setTimeout(() => process.exit(0), HOOK_BUDGET_MS);
    guard.unref?.();

    const stdinRaw = await readStdin();
    const input = parseHookInput(stdinRaw);
    if (!input) return exitSilently();

    const sessionId = input.session_id ?? "unknown";
    const filePath = input.tool_input?.file_path;
    if (!filePath || typeof filePath !== "string") return exitSilently();

    const absFile = resolveAbsolute(filePath);
    if (!absFile || !safeFileExists(absFile)) return exitSilently();

    if (shouldSkipPath(absFile)) return exitSilently();

    if (matchesGitignore(absFile)) return exitSilently();
    if (matchesProjectSastIgnore(absFile)) return exitSilently();

    const tools = await getToolAvailability(sessionId);

    if (!tools.semgrep && !tools.trufflehog && !tools.gitleaks) {
        emitOneTimeNoToolsAdvisory(sessionId);
        return;
    }

    const ignoreCfg = loadProjectIgnore(absFile);
    if (ignoreCfg && fileMatchesIgnoreFiles(absFile, ignoreCfg)) {
        return exitSilently();
    }

    const findings = await runScanners(absFile, tools);
    const filtered = applyIgnoreRules(findings, ignoreCfg);

    const regenStatePath = join(tmpdir(), `claude-sast-regen-${sessionId}.json`);
    const regenState = loadRegenState(regenStatePath);
    const priorRegenCount = regenState[absFile] ?? 0;

    const sevCounts = countSeverities(filtered);
    const hasHigh =
        (sevCounts.CRITICAL ?? 0) > 0 || (sevCounts.HIGH ?? 0) > 0;
    const advisoryOnly = priorRegenCount >= MAX_REGEN_PER_FILE;

    let message: string | null = null;
    let regenerated = false;

    if (hasHigh && !advisoryOnly) {
        message = buildRegenerateMessage(absFile, filtered);
        regenState[absFile] = priorRegenCount + 1;
        saveRegenState(regenStatePath, regenState);
        regenerated = true;
    } else if (hasHigh && advisoryOnly) {
        message =
            buildAdvisoryMessage(absFile, filtered, true /* maxedOut */) ??
            null;
    } else if (filtered.length > 0) {
        message = buildAdvisoryMessage(absFile, filtered, false);
    }

    writeTelemetry({
        ts: new Date().toISOString(),
        session_id: sessionId,
        file: absFile,
        tools_run: enumerateRunTools(tools),
        finding_count: filtered.length,
        severities: sevCounts,
        latency_ms: Date.now() - started,
        regenerated,
    });

    if (message) {
        emitAdditionalContext(message);
    }
}

// ---------- stdin ----------

async function readStdin(): Promise<string> {
    if (process.stdin.isTTY) return "";
    return await new Promise<string>((resolveFn) => {
        const chunks: Buffer[] = [];
        let done = false;
        const finish = () => {
            if (done) return;
            done = true;
            resolveFn(Buffer.concat(chunks).toString("utf8"));
        };
        process.stdin.on("data", (c) => chunks.push(Buffer.from(c)));
        process.stdin.on("end", finish);
        process.stdin.on("error", finish);
        // Safety: if stdin never closes, give up after 2s.
        setTimeout(finish, 2000).unref?.();
    });
}

function parseHookInput(raw: string): HookInput | null {
    if (!raw || raw.trim().length === 0) return null;
    try {
        const v = JSON.parse(raw) as HookInput;
        if (typeof v !== "object" || v === null) return null;
        return v;
    } catch {
        return null;
    }
}

// ---------- path / skip logic ----------

function resolveAbsolute(p: string): string | null {
    try {
        return isAbsolute(p) ? p : resolve(process.cwd(), p);
    } catch {
        return null;
    }
}

function safeFileExists(p: string): boolean {
    try {
        const s = statSync(p);
        return s.isFile();
    } catch {
        return false;
    }
}

function shouldSkipPath(absFile: string): boolean {
    return SKIP_PATTERNS.some((rx) => rx.test(absFile));
}

function findRepoRoot(startFile: string): string | null {
    let cur = dirname(startFile);
    for (let i = 0; i < 64; i++) {
        if (existsSync(join(cur, ".git"))) return cur;
        const parent = dirname(cur);
        if (parent === cur) break;
        cur = parent;
    }
    return null;
}

function matchesGitignore(absFile: string): boolean {
    const root = findRepoRoot(absFile);
    if (!root) return false;
    const giPath = join(root, ".gitignore");
    if (!existsSync(giPath)) return false;
    let patterns: string[];
    try {
        patterns = readFileSync(giPath, "utf8")
            .split("\n")
            .map((l) => l.trim())
            .filter((l) => l.length > 0 && !l.startsWith("#"));
    } catch {
        return false;
    }
    const rel = relative(root, absFile).split(sep).join("/");
    for (const p of patterns) {
        if (matchesGitignorePattern(rel, p)) return true;
    }
    return false;
}

function matchesGitignorePattern(rel: string, pattern: string): boolean {
    let pat = pattern;
    if (pat.startsWith("!")) return false; // Negations not supported; fail-safe.
    const anchored = pat.startsWith("/");
    if (anchored) pat = pat.slice(1);
    const trailingSlash = pat.endsWith("/");
    if (trailingSlash) pat = pat.slice(0, -1);
    const rx = globToRegex(pat, anchored);
    if (rx.test(rel)) return true;
    // Directory match: any segment of the path equals the pattern.
    if (!pat.includes("/")) {
        const parts = rel.split("/");
        if (parts.includes(pat)) return true;
    }
    return false;
}

function matchesProjectSastIgnore(absFile: string): boolean {
    const root = findRepoRoot(absFile);
    if (!root) return false;
    const ignoreFile = join(root, ".claude", "security", "sast-ignore");
    if (!existsSync(ignoreFile)) return false;
    let patterns: string[];
    try {
        patterns = readFileSync(ignoreFile, "utf8")
            .split("\n")
            .map((l) => l.trim())
            .filter((l) => l.length > 0 && !l.startsWith("#"));
    } catch {
        return false;
    }
    const rel = relative(root, absFile).split(sep).join("/");
    return patterns.some((p) => globToRegex(p, false).test(rel));
}

function globToRegex(glob: string, anchored: boolean): RegExp {
    let out = "";
    for (let i = 0; i < glob.length; i++) {
        const ch = glob[i];
        if (ch === "*") {
            if (glob[i + 1] === "*") {
                out += ".*";
                i++;
                if (glob[i + 1] === "/") i++;
            } else {
                out += "[^/]*";
            }
        } else if (ch === "?") {
            out += "[^/]";
        } else if (".+^$(){}|[]\\".includes(ch ?? "")) {
            out += "\\" + ch;
        } else {
            out += ch;
        }
    }
    return new RegExp((anchored ? "^" : "(^|/)") + out + "($|/)");
}

// ---------- project ignore (yaml) ----------

function loadProjectIgnore(absFile: string): ProjectIgnore | null {
    const root = findRepoRoot(absFile);
    if (!root) return null;
    const cfg = join(root, ".claude", "security", "sast-ignore.yaml");
    if (!existsSync(cfg)) return null;
    try {
        const text = readFileSync(cfg, "utf8");
        return parseSimpleYaml(text);
    } catch {
        return null;
    }
}

function parseSimpleYaml(text: string): ProjectIgnore {
    const out: ProjectIgnore = { ignore_files: [], ignore_rules: [] };
    let current: keyof ProjectIgnore | null = null;
    for (const rawLine of text.split("\n")) {
        const line = rawLine.replace(/\r$/, "");
        if (!line.trim() || line.trim().startsWith("#")) continue;
        const top = line.match(/^(ignore_files|ignore_rules)\s*:\s*$/);
        if (top) {
            current = top[1] as keyof ProjectIgnore;
            continue;
        }
        const item = line.match(/^\s*-\s*(.+?)\s*$/);
        if (item && current) {
            const v = stripQuotes(item[1]!);
            out[current].push(v);
        }
    }
    return out;
}

function stripQuotes(s: string): string {
    if (
        (s.startsWith("\"") && s.endsWith("\"")) ||
        (s.startsWith("'") && s.endsWith("'"))
    ) {
        return s.slice(1, -1);
    }
    return s;
}

function fileMatchesIgnoreFiles(absFile: string, cfg: ProjectIgnore): boolean {
    const root = findRepoRoot(absFile);
    if (!root) return false;
    const rel = relative(root, absFile).split(sep).join("/");
    return cfg.ignore_files.some((g) => globToRegex(g, false).test(rel));
}

function applyIgnoreRules(
    findings: Finding[],
    cfg: ProjectIgnore | null,
): Finding[] {
    if (!cfg || cfg.ignore_rules.length === 0) return findings;
    const ruleSet = new Set(cfg.ignore_rules);
    return findings.filter((f) => !ruleSet.has(f.rule_id));
}

// ---------- tool availability ----------

async function getToolAvailability(sessionId: string): Promise<ToolAvailability> {
    const cachePath = join(tmpdir(), `claude-sast-tools-${sessionId}.json`);
    if (existsSync(cachePath)) {
        try {
            const v = JSON.parse(readFileSync(cachePath, "utf8")) as ToolAvailability;
            if (
                typeof v.semgrep === "boolean" &&
                typeof v.trufflehog === "boolean" &&
                typeof v.gitleaks === "boolean"
            ) {
                return v;
            }
        } catch {
            // fall through to re-detect
        }
    }
    const [semgrep, trufflehog, gitleaks] = await Promise.all([
        which("semgrep"),
        which("trufflehog"),
        which("gitleaks"),
    ]);
    const v: ToolAvailability = {
        semgrep,
        trufflehog,
        gitleaks,
        detected_at: Date.now(),
    };
    try {
        writeFileSync(cachePath, JSON.stringify(v));
    } catch {
        // non-fatal
    }
    return v;
}

async function which(bin: string): Promise<boolean> {
    return await new Promise<boolean>((resolveFn) => {
        const p = spawn("which", [bin], { stdio: ["ignore", "pipe", "ignore"] });
        let out = "";
        p.stdout?.on("data", (d) => (out += d.toString()));
        p.on("error", () => resolveFn(false));
        p.on("close", (code) => resolveFn(code === 0 && out.trim().length > 0));
    });
}

function enumerateRunTools(t: ToolAvailability): ToolName[] {
    const r: ToolName[] = [];
    if (t.semgrep) r.push("semgrep");
    if (t.trufflehog) r.push("trufflehog");
    if (t.gitleaks) r.push("gitleaks");
    return r;
}

// ---------- scanners ----------

async function runScanners(
    file: string,
    tools: ToolAvailability,
): Promise<Finding[]> {
    const tasks: Promise<Finding[]>[] = [];
    if (tools.semgrep) tasks.push(withTimeout(runSemgrep(file), TOOL_TIMEOUT_MS));
    if (tools.trufflehog)
        tasks.push(withTimeout(runTrufflehog(file), TOOL_TIMEOUT_MS));
    if (tools.gitleaks) tasks.push(withTimeout(runGitleaks(file), TOOL_TIMEOUT_MS));
    const results = await Promise.all(tasks.map((t) => t.catch(() => [])));
    return results.flat();
}

function withTimeout<T>(p: Promise<T[]>, ms: number): Promise<T[]> {
    return new Promise<T[]>((resolveFn) => {
        let done = false;
        const timer = setTimeout(() => {
            if (!done) {
                done = true;
                resolveFn([] as T[]);
            }
        }, ms);
        timer.unref?.();
        p.then((v) => {
            if (!done) {
                done = true;
                clearTimeout(timer);
                resolveFn(v);
            }
        }).catch(() => {
            if (!done) {
                done = true;
                clearTimeout(timer);
                resolveFn([] as T[]);
            }
        });
    });
}

interface ProcResult {
    stdout: string;
    stderr: string;
    code: number | null;
}

function runProc(cmd: string, args: string[]): Promise<ProcResult> {
    return new Promise<ProcResult>((resolveFn) => {
        let stdout = "";
        let stderr = "";
        try {
            const p = spawn(cmd, args, {
                stdio: ["ignore", "pipe", "pipe"],
                env: { ...process.env, NO_COLOR: "1" },
            });
            p.stdout?.on("data", (d) => (stdout += d.toString()));
            p.stderr?.on("data", (d) => (stderr += d.toString()));
            p.on("error", () => resolveFn({ stdout, stderr, code: -1 }));
            p.on("close", (code) => resolveFn({ stdout, stderr, code }));
        } catch {
            resolveFn({ stdout, stderr, code: -1 });
        }
    });
}

async function runSemgrep(file: string): Promise<Finding[]> {
    const r = await runProc("semgrep", [
        "--config",
        "auto",
        "--json",
        "--quiet",
        "--timeout",
        "12",
        "--metrics=off",
        file,
    ]);
    if (!r.stdout.trim()) return [];
    try {
        const parsed = JSON.parse(r.stdout) as {
            results?: Array<{
                check_id?: string;
                path?: string;
                start?: { line?: number };
                extra?: {
                    severity?: string;
                    message?: string;
                    lines?: string;
                };
            }>;
        };
        const out: Finding[] = [];
        for (const it of parsed.results ?? []) {
            const sevRaw = (it.extra?.severity ?? "").toUpperCase();
            const severity: Severity =
                sevRaw === "ERROR"
                    ? "HIGH"
                    : sevRaw === "WARNING"
                        ? "MEDIUM"
                        : sevRaw === "INFO"
                            ? "LOW"
                            : "LOW";
            out.push({
                tool: "semgrep",
                severity,
                rule_id: it.check_id ?? "semgrep.unknown",
                message: it.extra?.message ?? "(no message)",
                file: it.path ?? file,
                line: it.start?.line ?? 0,
                snippet: it.extra?.lines,
            });
        }
        return out;
    } catch {
        return [];
    }
}

async function runTrufflehog(file: string): Promise<Finding[]> {
    const r = await runProc("trufflehog", [
        "filesystem",
        "--no-update",
        "--json",
        "--only-verified",
        "--no-fail",
        file,
    ]);
    if (!r.stdout.trim()) return [];
    const out: Finding[] = [];
    for (const ln of r.stdout.split("\n")) {
        const line = ln.trim();
        if (!line) continue;
        try {
            const obj = JSON.parse(line) as {
                DetectorName?: string;
                Verified?: boolean;
                SourceMetadata?: {
                    Data?: {
                        Filesystem?: { file?: string; line?: number };
                    };
                };
                Raw?: string;
            };
            if (obj.Verified !== true) continue;
            const fs = obj.SourceMetadata?.Data?.Filesystem;
            out.push({
                tool: "trufflehog",
                severity: "CRITICAL",
                rule_id: `trufflehog.${obj.DetectorName ?? "unknown"}`,
                message: `Verified live secret detected (${obj.DetectorName ?? "unknown"}).`,
                file: fs?.file ?? file,
                line: fs?.line ?? 0,
            });
        } catch {
            continue;
        }
    }
    return out;
}

async function runGitleaks(file: string): Promise<Finding[]> {
    const sessionToken = process.env.CLAUDE_SESSION_ID ?? `${process.pid}-${Date.now()}`;
    const reportPath = join(tmpdir(), `gitleaks-${sessionToken}.json`);
    await runProc("gitleaks", [
        "detect",
        "--source",
        file,
        "--no-banner",
        "--report-format",
        "json",
        "--report-path",
        reportPath,
        "--no-git",
        "--exit-code",
        "0",
    ]);
    if (!existsSync(reportPath)) return [];
    let raw = "";
    try {
        raw = readFileSync(reportPath, "utf8");
    } catch {
        return [];
    }
    if (!raw.trim()) return [];
    try {
        const parsed = JSON.parse(raw) as Array<{
            RuleID?: string;
            Description?: string;
            File?: string;
            StartLine?: number;
            Match?: string;
        }>;
        if (!Array.isArray(parsed)) return [];
        return parsed.map((it) => ({
            tool: "gitleaks" as const,
            severity: "HIGH" as const,
            rule_id: `gitleaks.${it.RuleID ?? "unknown"}`,
            message: it.Description ?? "Potential secret detected by gitleaks.",
            file: it.File ?? file,
            line: it.StartLine ?? 0,
            snippet: it.Match,
        }));
    } catch {
        return [];
    }
}

// ---------- regen state ----------

function loadRegenState(p: string): RegenState {
    if (!existsSync(p)) return {};
    try {
        const v = JSON.parse(readFileSync(p, "utf8")) as RegenState;
        if (typeof v === "object" && v !== null) return v;
        return {};
    } catch {
        return {};
    }
}

function saveRegenState(p: string, s: RegenState): void {
    try {
        writeFileSync(p, JSON.stringify(s));
    } catch {
        // non-fatal
    }
}

// ---------- message building ----------

function countSeverities(findings: Finding[]): Record<Severity, number> {
    const out: Record<Severity, number> = {
        CRITICAL: 0,
        HIGH: 0,
        MEDIUM: 0,
        LOW: 0,
        INFO: 0,
    };
    for (const f of findings) out[f.severity]++;
    return out;
}

function buildRegenerateMessage(file: string, findings: Finding[]): string {
    const high = findings.filter(
        (f) => f.severity === "HIGH" || f.severity === "CRITICAL",
    );
    const lines: string[] = [];
    lines.push(
        `🚨 SHIFT-LEFT SAST: ${high.length} high-severity finding(s) in ${file}:`,
    );
    for (const f of high) {
        lines.push(
            `  - [${f.tool}] ${f.rule_id} at line ${f.line}: ${truncate(f.message, 240)}`,
        );
    }
    lines.push(
        "ACTION: Rewrite this file to fix these findings before continuing. " +
        "Each finding must be addressed (or explicitly justified inline as a " +
        "comment with `// nosec: <rule_id> — <reason>` or " +
        "`# nosec: <rule_id> — <reason>`).",
    );
    return lines.join("\n");
}

function buildAdvisoryMessage(
    file: string,
    findings: Finding[],
    maxedOut: boolean,
): string | null {
    if (findings.length === 0) return null;
    const lines: string[] = [];
    lines.push(`⚠️ SAST advisory for ${file}: ${findings.length} finding(s):`);
    for (const f of findings) {
        lines.push(
            `  - [${f.tool}/${f.severity}] ${f.rule_id} at line ${f.line}: ${truncate(f.message, 240)}`,
        );
    }
    if (maxedOut) {
        lines.push(
            "Max regenerate iterations reached for this file; surface to user.",
        );
    }
    return lines.join("\n");
}

function truncate(s: string, n: number): string {
    if (s.length <= n) return s;
    return s.slice(0, n - 1) + "…";
}

// ---------- one-time no-tools advisory ----------

function emitOneTimeNoToolsAdvisory(sessionId: string): void {
    const sentinel = join(tmpdir(), `claude-sast-advised-${sessionId}`);
    if (existsSync(sentinel)) return;
    try {
        writeFileSync(sentinel, String(Date.now()));
    } catch {
        // non-fatal; if we can't write the sentinel, still emit once for this run
    }
    emitAdditionalContext(
        "Install at least one of semgrep / trufflehog / gitleaks for shift-left SAST. " +
        "See https://github.com/thatsjet/claude_secure_coder#install",
    );
}

// ---------- output ----------

function emitAdditionalContext(message: string): void {
    const payload = {
        hookSpecificOutput: {
            hookEventName: "PostToolUse",
            additionalContext: message,
        },
    };
    process.stdout.write(JSON.stringify(payload));
}

function exitSilently(): void {
    // No stdout, no stderr. Exit 0.
    process.exit(0);
}

// ---------- telemetry ----------

interface TelemetryEvent {
    ts: string;
    session_id: string;
    file: string;
    tools_run: ToolName[];
    finding_count: number;
    severities: Record<Severity, number>;
    latency_ms: number;
    regenerated: boolean;
}

function writeTelemetry(ev: TelemetryEvent): void {
    const home = process.env.HOME ?? homedir();
    const paiDir = join(home, ".claude", "PAI", "MEMORY", "OBSERVABILITY");
    let target: string;
    if (safeDirExists(paiDir)) {
        target = join(paiDir, "sast-scans.jsonl");
    } else {
        target = join(tmpdir(), "claude-sast-scans.jsonl");
    }
    try {
        // Best-effort: ensure parent dir for fallback case (tmpdir always exists).
        const parent = dirname(target);
        if (!existsSync(parent)) mkdirSync(parent, { recursive: true });
        appendFileSync(target, JSON.stringify(ev) + "\n");
    } catch {
        // non-fatal
    }
}

function safeDirExists(p: string): boolean {
    try {
        return statSync(p).isDirectory();
    } catch {
        return false;
    }
}
