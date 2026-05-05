#!/usr/bin/env bash
# install.sh — install claude_secure_coder for the current user
#
# Idempotent. Detects PAI vs stock Claude Code and adapts paths.
# Backs up modified files for rollback via --uninstall.
#
# Usage:
#   bash install.sh              # install
#   bash install.sh --dry-run    # show what would change
#   bash install.sh --uninstall  # remove all installed files and revert settings

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLAUDE_DIR="${HOME}/.claude"
HOOKS_DST="${CLAUDE_DIR}/hooks/csc"
SKILLS_DST="${CLAUDE_DIR}/skills/ThreatModel"
SETTINGS_FILE="${CLAUDE_DIR}/settings.json"
CLAUDE_MD="${CLAUDE_DIR}/CLAUDE.md"
BACKUP_ROOT="${CLAUDE_DIR}/.csc-backup"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_DIR="${BACKUP_ROOT}/${TIMESTAMP}"

DRY_RUN=0
UNINSTALL=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    --uninstall) UNINSTALL=1 ;;
    -h|--help) head -15 "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 1 ;;
  esac
done

log() { echo "[csc-install] $*"; }

detect_pai() {
  if [[ -d "${CLAUDE_DIR}/PAI" ]]; then
    echo "pai"
  else
    echo "stock"
  fi
}

uninstall() {
  log "uninstall: removing claude_secure_coder"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "  (dry-run) would remove $HOOKS_DST"
    log "  (dry-run) would remove $SKILLS_DST"
    log "  (dry-run) would restore $SETTINGS_FILE and $CLAUDE_MD from latest backup"
    exit 0
  fi
  latest=""
  if [[ -d "$BACKUP_ROOT" ]]; then
    latest="$(ls -1 "$BACKUP_ROOT" 2>/dev/null | sort -r | head -1 || true)"
  fi
  rm -rf "$HOOKS_DST" "$SKILLS_DST"
  log "  removed $HOOKS_DST and $SKILLS_DST"
  if [[ -n "$latest" ]] && [[ -f "$BACKUP_ROOT/$latest/settings.json" ]]; then
    cp "$BACKUP_ROOT/$latest/settings.json" "$SETTINGS_FILE"
    log "  restored settings.json from $BACKUP_ROOT/$latest/"
  else
    log "  no settings.json backup found — leaving current settings (may have csc entries)"
  fi
  if [[ -n "$latest" ]] && [[ -f "$BACKUP_ROOT/$latest/CLAUDE.md" ]]; then
    cp "$BACKUP_ROOT/$latest/CLAUDE.md" "$CLAUDE_MD"
    log "  restored CLAUDE.md from $BACKUP_ROOT/$latest/"
  fi
  log "  PAI integration patches NOT touched — run patches/pai/apply.sh --uninstall to roll those back."
  log "uninstall complete."
  exit 0
}

backup_file() {
  local src="$1"
  local rel="$2"
  if [[ -f "$src" ]]; then
    mkdir -p "$BACKUP_DIR"
    cp "$src" "$BACKUP_DIR/$rel"
  fi
}

resolve_secure_coding_dst() {
  local layout="$1"
  if [[ "$layout" == "pai" ]]; then
    echo "${CLAUDE_DIR}/PAI/USER/SECURITY/SecureCoding.md"
  else
    echo "${CLAUDE_DIR}/secure_coding/SecureCoding.md"
  fi
}

install_context() {
  local layout="$1"
  local dst
  dst="$(resolve_secure_coding_dst "$layout")"
  log "1/5 install context → $dst"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "  (dry-run) would copy SecureCoding.md to $dst"
    return
  fi
  mkdir -p "$(dirname "$dst")"
  cp "$SCRIPT_DIR/context/SecureCoding.md" "$dst"
  log "  copied → $dst"
}

install_hooks() {
  log "2/5 install hooks → $HOOKS_DST"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "  (dry-run) would copy 3 hook files + lib/ to $HOOKS_DST"
    return
  fi
  mkdir -p "$HOOKS_DST/lib"
  cp "$SCRIPT_DIR/hooks/SecureCodingContext.hook.ts" "$HOOKS_DST/SecureCodingContext.hook.ts"
  cp "$SCRIPT_DIR/hooks/VulnPatternHook.hook.ts" "$HOOKS_DST/VulnPatternHook.hook.ts"
  cp "$SCRIPT_DIR/hooks/PostToolUseSAST.hook.ts" "$HOOKS_DST/PostToolUseSAST.hook.ts"
  cp "$SCRIPT_DIR/hooks/lib/vuln-patterns-core.ts" "$HOOKS_DST/lib/vuln-patterns-core.ts"
  cp "$SCRIPT_DIR/config/VulnPatterns.yaml" "$HOOKS_DST/lib/VulnPatterns.yaml"
  chmod +x "$HOOKS_DST"/*.hook.ts
  log "  installed 3 hooks + matcher core + rule config"
}

install_skill() {
  log "3/5 install ThreatModel skill → $SKILLS_DST"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "  (dry-run) would copy skills/ThreatModel/ to $SKILLS_DST"
    return
  fi
  mkdir -p "$SKILLS_DST"
  cp -R "$SCRIPT_DIR/skills/ThreatModel/." "$SKILLS_DST/"
  log "  installed ThreatModel skill"
}

ensure_settings_entries() {
  log "4/5 register hooks in $SETTINGS_FILE"
  if [[ ! -f "$SETTINGS_FILE" ]]; then
    log "  $SETTINGS_FILE not found — creating minimal one"
    if [[ "$DRY_RUN" -eq 0 ]]; then
      mkdir -p "$(dirname "$SETTINGS_FILE")"
      echo '{"hooks":{}}' > "$SETTINGS_FILE"
    fi
  fi
  backup_file "$SETTINGS_FILE" "settings.json"

  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "  (dry-run) would register 3 hooks in settings.json:"
    log "    SessionStart: $HOOKS_DST/SecureCodingContext.hook.ts"
    log "    PreToolUse (Edit|Write|MultiEdit): $HOOKS_DST/VulnPatternHook.hook.ts"
    log "    PostToolUse (Edit|Write|MultiEdit): $HOOKS_DST/PostToolUseSAST.hook.ts"
    return
  fi

  bun "$SCRIPT_DIR/install/register-hooks.ts" "$SETTINGS_FILE" "$HOOKS_DST" \
    || {
      log "  bun-based registration failed; falling back to manual instructions:"
      log "  Open $SETTINGS_FILE and add to hooks.SessionStart/PreToolUse/PostToolUse:"
      log "    See $SCRIPT_DIR/config/settings.json.example"
      return
    }
  log "  registered hooks (idempotent — duplicates skipped)"
}

ensure_claudemd_import() {
  log "5/5 ensure CLAUDE.md @-imports SecureCoding.md"
  if [[ ! -f "$CLAUDE_MD" ]]; then
    log "  $CLAUDE_MD not found — skipping (create it manually if you want session-start context)"
    return
  fi
  backup_file "$CLAUDE_MD" "CLAUDE.md"
  local layout
  layout="$(detect_pai)"
  local dst
  dst="$(resolve_secure_coding_dst "$layout")"
  local rel_dst="${dst/${HOME}/\$HOME}"
  local import_line="@${dst/${HOME}\//}"

  if grep -qF "$import_line" "$CLAUDE_MD" 2>/dev/null; then
    log "  $import_line already present in CLAUDE.md — skipping"
    return
  fi
  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "  (dry-run) would append: $import_line"
    return
  fi
  printf '\n# claude_secure_coder context (added by csc-install)\n%s\n' "$import_line" >> "$CLAUDE_MD"
  log "  appended @-import to $CLAUDE_MD"
}

main() {
  if [[ "$UNINSTALL" -eq 1 ]]; then
    uninstall
  fi
  log "installing claude_secure_coder (timestamp: $TIMESTAMP, dry-run: $DRY_RUN)"
  layout="$(detect_pai)"
  log "detected layout: $layout"
  install_context "$layout"
  install_hooks
  install_skill
  ensure_settings_entries
  ensure_claudemd_import
  if [[ "$DRY_RUN" -eq 0 ]]; then
    log ""
    log "DONE. Backup at $BACKUP_DIR (run with --uninstall to revert)."
    log ""
    log "Next steps:"
    log "  1. Restart Claude Code so hooks are picked up."
    log "  2. (optional) Install semgrep / trufflehog / gitleaks for write-time SAST."
    log "     See docs/tool-installation.md."
    log "  3. (PAI users) Run: bash patches/pai/apply.sh"
    log "  4. (verify) Run: bash tests/run-tests.sh"
  else
    log "DONE (dry-run). Re-run without --dry-run to apply."
  fi
}

main "$@"
