# Registering VulnPatternInspector in SecurityPipeline.hook.ts (OPTIONAL)

> **This step is optional.** The portable `VulnPatternHook.hook.ts` is already registered as a standalone PreToolUse hook by `install.sh`, and provides identical coverage. The Inspector form is a code-organization preference for PAI users who prefer one inspector chain over two parallel hooks. **Skipping this section leaves coverage intact** — your literal-secret denies, dangerous-API advisories, and weak-crypto advisories all fire from `VulnPatternHook.hook.ts` regardless.

Daniel Miessler's PAI ships `~/.claude/hooks/SecurityPipeline.hook.ts` with a fixed inspector chain. To consolidate `VulnPatternInspector` (priority 70) into that chain, apply the small edit below by hand.

**Why this isn't auto-applied:**
1. PAI's own `PATTERNS.yaml` protects `SecurityPipeline.hook.ts` as a read-only path — modifying it triggers PAI's PatternInspector deny. We never bypass user-set guardrails automatically.
2. Upstream PAI evolves and an automatic patch could break on the next PAI update.
3. Inspector form duplicates the standalone hook's coverage; running both is redundant. Pick one.

## Current chain

```typescript
import { createPatternInspector } from './security/inspectors/PatternInspector';
import { createEgressInspector } from './security/inspectors/EgressInspector';
import { createRulesInspector } from './security/inspectors/RulesInspector';

const pipeline = new InspectorPipeline([
  createPatternInspector(),
  createEgressInspector(),
  createRulesInspector(),
]);
```

## Add VulnPatternInspector

```typescript
import { createPatternInspector } from './security/inspectors/PatternInspector';
import { createEgressInspector } from './security/inspectors/EgressInspector';
import { createVulnPatternInspector } from './security/inspectors/VulnPatternInspector';
import { createRulesInspector } from './security/inspectors/RulesInspector';

const pipeline = new InspectorPipeline([
  createPatternInspector(),     // priority 100
  createEgressInspector(),      // priority 90
  createVulnPatternInspector(), // priority 70 (NEW v6.4.0 — claude_secure_coder)
  createRulesInspector(),       // priority 50
]);
```

(InjectionInspector and PromptInspector are not in the inline chain in stock PAI — they fire from different hook entry points. VulnPatternInspector belongs in the Edit/Write/MultiEdit chain only.)

## Verify

```bash
echo '{"session_id":"test","tool_name":"Write","tool_input":{"file_path":"/tmp/x.py","content":"key = \"sk-ant-api03-FAKEKEY1234567890123456789012345\""}}' \
  | bun ~/.claude/hooks/SecurityPipeline.hook.ts
```

Expected output:

```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"...vuln_pattern: anthropic_api_key..."}}
```

If you see this, the inspector is wired. If you see `"permissionDecision":"allow"` or no output, walk through `apply.sh` again and confirm `VulnPatternInspector.ts` lives at `~/.claude/hooks/security/inspectors/VulnPatternInspector.ts` and `CSC_HOOK_DIR` is set in your shell rc.

## Rollback

Remove the import line and the `createVulnPatternInspector()` entry from the array. The other inspectors are unchanged. Or run `bash patches/pai/apply.sh --uninstall` which restores the pre-patch `SecurityPipeline.hook.ts` from the backup directory.
