#!/usr/bin/env bun
/**
 * register-hooks.ts — idempotent hook registration in settings.json
 *
 * Reads settings.json, ensures the three claude_secure_coder hooks are
 * registered under hooks.SessionStart, hooks.PreToolUse, and hooks.PostToolUse.
 * If an identical entry already exists, leaves it alone.
 *
 * Usage: bun register-hooks.ts <settings_path> <hooks_dst>
 */

import { readFileSync, writeFileSync, existsSync } from "fs";

interface HookCommand {
  type: "command";
  command: string;
}

interface HookEntry {
  matcher?: string;
  hooks: HookCommand[];
}

interface Settings {
  hooks?: Record<string, HookEntry[]>;
  [key: string]: unknown;
}

const args = process.argv.slice(2);
if (args.length !== 2) {
  console.error("usage: bun register-hooks.ts <settings_path> <hooks_dst>");
  process.exit(1);
}

const [settingsPath, hooksDst] = args;

let settings: Settings = {};
if (existsSync(settingsPath)) {
  try {
    settings = JSON.parse(readFileSync(settingsPath, "utf-8"));
  } catch (e) {
    console.error(`failed to parse ${settingsPath}: ${e}`);
    process.exit(1);
  }
}

settings.hooks = settings.hooks ?? {};

const sessionStartCmd = `${hooksDst}/SecureCodingContext.hook.ts`;
const preToolUseCmd = `${hooksDst}/VulnPatternHook.hook.ts`;
const postToolUseCmd = `${hooksDst}/PostToolUseSAST.hook.ts`;
const writeMatcher = "Edit|Write|MultiEdit";

function ensureHookRegistered(
  event: "SessionStart" | "PreToolUse" | "PostToolUse",
  command: string,
  matcher?: string
): boolean {
  const list = (settings.hooks![event] ?? []) as HookEntry[];
  for (const entry of list) {
    if (entry.matcher === matcher) {
      for (const h of entry.hooks ?? []) {
        if (h.type === "command" && h.command === command) {
          return false; // already registered
        }
      }
      // matcher matches but command absent — append command to this entry
      entry.hooks = [...(entry.hooks ?? []), { type: "command", command }];
      settings.hooks![event] = list;
      return true;
    }
  }
  // no matching matcher — append a new entry
  list.push({
    ...(matcher ? { matcher } : {}),
    hooks: [{ type: "command", command }],
  });
  settings.hooks![event] = list;
  return true;
}

const changes: string[] = [];
if (ensureHookRegistered("SessionStart", sessionStartCmd)) {
  changes.push(`SessionStart → ${sessionStartCmd}`);
}
if (ensureHookRegistered("PreToolUse", preToolUseCmd, writeMatcher)) {
  changes.push(`PreToolUse(${writeMatcher}) → ${preToolUseCmd}`);
}
if (ensureHookRegistered("PostToolUse", postToolUseCmd, writeMatcher)) {
  changes.push(`PostToolUse(${writeMatcher}) → ${postToolUseCmd}`);
}

if (changes.length === 0) {
  console.log("[register-hooks] no changes — all entries already present");
  process.exit(0);
}

writeFileSync(settingsPath, JSON.stringify(settings, null, 2) + "\n", "utf-8");
console.log("[register-hooks] applied changes:");
for (const c of changes) {
  console.log(`  + ${c}`);
}
process.exit(0);
