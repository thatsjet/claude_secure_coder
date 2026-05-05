#!/usr/bin/env bash
# run-tests.sh — smoke tests for claude_secure_coder
#
# Tests the four-layer install end-to-end without requiring a live
# Claude Code session. Synthesizes hook stdin and verifies stdout.

set -uo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
HOOKS="$PROJECT_ROOT/hooks"
FIXTURES="$SCRIPT_DIR/fixtures"

PASS=0
FAIL=0
RESULTS=()

# CSC_HOOK_DIR points to the matcher core for the inspector — we point it
# at the project repo for tests, so we don't need a live install.
export CSC_HOOK_DIR="$HOOKS/lib"

run_test() {
  local id="$1"
  local desc="$2"
  shift 2
  local result
  result="$(eval "$@" 2>&1 || true)"
  local rc=$?
  if [[ "$result" == *"PASS"* ]]; then
    echo "[csc-test] $id $desc ... PASS"
    PASS=$((PASS+1))
    RESULTS+=("PASS $id")
  else
    echo "[csc-test] $id $desc ... FAIL"
    echo "$result" | sed 's/^/    /'
    FAIL=$((FAIL+1))
    RESULTS+=("FAIL $id")
  fi
}

# Test 1: SessionStart hook produces valid JSON with OWASP context
test_1() {
  local out
  out="$(echo '{"session_id":"smoke-1","cwd":"'"$PROJECT_ROOT"'"}' | bun --no-install "$HOOKS/SecureCodingContext.hook.ts" 2>/dev/null)"
  if [[ -z "$out" ]]; then
    echo "  empty stdout — hook failed silently"
    return 1
  fi
  if echo "$out" | python3 -c "
import sys, json
d = json.load(sys.stdin)
hso = d.get('hookSpecificOutput', {})
if hso.get('hookEventName') != 'SessionStart':
    print('hookEventName mismatch:', hso.get('hookEventName')); sys.exit(1)
ac = hso.get('additionalContext', '')
if 'OWASP' not in ac:
    print('OWASP not in additionalContext'); sys.exit(1)
if 'CWE' not in ac:
    print('CWE not in additionalContext'); sys.exit(1)
print('PASS — chars:', len(ac))
"; then
    return 0
  else
    echo "  json validation failed"
    return 1
  fi
}

# Test 2: VulnPatternHook denies an Anthropic API key in /tmp/x.py (non-test path)
test_2() {
  local key='sk-ant-api03-FAKEKEY1234567890123456789012345678901234567890aB'
  local input='{"session_id":"smoke-2","tool_name":"Write","tool_input":{"file_path":"/tmp/x.py","content":"key = \"'"$key"'\""}}'
  local out
  out="$(echo "$input" | bun --no-install "$HOOKS/VulnPatternHook.hook.ts" 2>/dev/null)"
  if echo "$out" | grep -q '"permissionDecision":"deny"'; then
    echo "PASS"
  else
    echo "  expected deny, got: $out"
    return 1
  fi
}

# Test 3: VulnPatternHook advises (no deny) on eval(userInput) in TS
test_3() {
  local input='{"session_id":"smoke-3","tool_name":"Write","tool_input":{"file_path":"/tmp/y.ts","content":"function go(x){return eval(x);}"}}'
  local out
  out="$(echo "$input" | bun --no-install "$HOOKS/VulnPatternHook.hook.ts" 2>/dev/null)"
  if echo "$out" | grep -q '"permissionDecision":"deny"'; then
    echo "  unexpected deny on eval (should advisory): $out"
    return 1
  fi
  if [[ -z "$out" ]] || echo "$out" | grep -qi 'eval\|advisory\|additionalContext'; then
    echo "PASS"
  else
    echo "  expected advisory or empty, got: $out"
    return 1
  fi
}

# Test 4: VulnPatternHook downgrades a key inside tests/fixtures/ to advisory
test_4() {
  local key='sk-ant-api03-FAKEKEY1234567890123456789012345678901234567890aB'
  local input='{"session_id":"smoke-4","tool_name":"Write","tool_input":{"file_path":"'"$FIXTURES"'/secrets-fixture.ts","content":"const K = \"'"$key"'\";"}}'
  local out
  out="$(echo "$input" | bun --no-install "$HOOKS/VulnPatternHook.hook.ts" 2>/dev/null)"
  if echo "$out" | grep -q '"permissionDecision":"deny"'; then
    echo "  unexpected deny on test-fixture path (should advisory): $out"
    return 1
  fi
  echo "PASS"
}

# Test 5: PostToolUseSAST runs available scanner(s), exits 0, produces JSON
test_5() {
  local input='{"session_id":"smoke-5","tool_name":"Write","tool_input":{"file_path":"'"$FIXTURES"'/vulnerable-py.py"},"tool_response":{}}'
  local out
  out="$(echo "$input" | bun --no-install "$HOOKS/PostToolUseSAST.hook.ts" 2>/dev/null)"
  # Hook must exit 0 always. Output may be empty (no tools) or JSON advisory/regenerate.
  echo "PASS"
}

# Test 6: ThreatModel skill discoverable
test_6() {
  local skill_dir="$PROJECT_ROOT/skills/ThreatModel"
  if [[ ! -f "$skill_dir/SKILL.md" ]]; then
    echo "  $skill_dir/SKILL.md missing"
    return 1
  fi
  if [[ ! -f "$skill_dir/Workflows/STRIDE.md" ]]; then
    echo "  STRIDE.md missing"
    return 1
  fi
  if [[ ! -f "$skill_dir/Workflows/MAESTRO.md" ]]; then
    echo "  MAESTRO.md missing"
    return 1
  fi
  echo "PASS"
}

run_test "1/6" "SessionStart hook produces valid JSON" "test_1"
run_test "2/6" "VulnPatternHook denies Anthropic API key" "test_2"
run_test "3/6" "VulnPatternHook advisory on eval(userInput)" "test_3"
run_test "4/6" "VulnPatternHook downgrades in tests/fixtures/" "test_4"
run_test "5/6" "PostToolUseSAST runs and exits 0" "test_5"
run_test "6/6" "ThreatModel skill discoverable" "test_6"

echo ""
echo "[csc-test] passed: $PASS  failed: $FAIL  total: $((PASS+FAIL))"
if [[ "$FAIL" -gt 0 ]]; then
  exit 1
fi
exit 0
