# Registering VulnPatternInspector in SecurityPipeline.hook.ts

Daniel Miessler's PAI ships `~/.claude/hooks/SecurityPipeline.hook.ts` with a fixed inspector chain. To add `VulnPatternInspector` (priority 70), apply this small edit by hand. We avoid auto-editing because the upstream file may evolve and an automatic patch would break on the next PAI update.

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
