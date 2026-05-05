#!/usr/bin/env bash
# apply.sh — apply the PAI integration patch for claude_secure_coder
#
# This script integrates the claude_secure_coder shift-left security toolkit
# with Daniel Miessler's PAI (Personal AI Infrastructure). It is OPTIONAL —
# the toolkit's hooks and skill work standalone. PAI integration adds:
#   1. Algorithm v6.4.0 doctrine (security at OBSERVE/PLAN/EXECUTE/VERIFY)
#   2. ThreatModel as a closed-enumeration thinking capability
#   3. VulnPatternInspector wired into PAI's SecurityPipeline.hook.ts
#   4. capabilities.md and changelog.md additions
#
# Idempotent — running twice is safe. Backs up modified files to
# ~/.claude/PAI/ALGORITHM/.csc-backup/<timestamp>/ for rollback.
#
# Usage:
#   bash patches/pai/apply.sh              # apply all PAI patches
#   bash patches/pai/apply.sh --dry-run    # show what would change
#   bash patches/pai/apply.sh --uninstall  # restore from most recent backup

set -euo pipefail
IFS=$'\n\t'

# Resolve script directory and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PAI_DIR="${HOME}/.claude/PAI"
ALGORITHM_DIR="${PAI_DIR}/ALGORITHM"
INSPECTORS_DIR="${HOME}/.claude/hooks/security/inspectors"
BACKUP_ROOT="${ALGORITHM_DIR}/.csc-backup"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_DIR="${BACKUP_ROOT}/${TIMESTAMP}"

DRY_RUN=0
UNINSTALL=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    --uninstall) UNINSTALL=1 ;;
    -h|--help)
      head -25 "$0"
      exit 0
      ;;
    *)
      echo "unknown option: $arg" >&2
      exit 1
      ;;
  esac
done

log() { echo "[csc-pai-apply] $*"; }

ensure_pai_present() {
  if [[ ! -d "$PAI_DIR" ]]; then
    log "ERROR: PAI not found at $PAI_DIR. Install Daniel Miessler's PAI first:"
    log "  https://github.com/danielmiessler/Personal_AI_Infrastructure"
    exit 1
  fi
  if [[ ! -d "$ALGORITHM_DIR" ]]; then
    log "ERROR: PAI Algorithm directory missing at $ALGORITHM_DIR"
    exit 1
  fi
  log "PAI detected at $PAI_DIR"
}

uninstall() {
  log "uninstall: looking for most recent backup in $BACKUP_ROOT"
  if [[ ! -d "$BACKUP_ROOT" ]]; then
    log "no backup directory found — nothing to restore"
    exit 0
  fi
  latest="$(ls -1 "$BACKUP_ROOT" 2>/dev/null | sort -r | head -1 || true)"
  if [[ -z "$latest" ]]; then
    log "no backups found — nothing to restore"
    exit 0
  fi
  log "restoring from $BACKUP_ROOT/$latest"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "(dry-run) would restore: $(ls "$BACKUP_ROOT/$latest")"
    exit 0
  fi
  for f in "$BACKUP_ROOT/$latest"/*; do
    name="$(basename "$f")"
    case "$name" in
      LATEST|capabilities.md|changelog.md|v6.3.0.md) cp "$f" "$ALGORITHM_DIR/$name" ;;
      VulnPatternInspector.ts.removed) rm -f "$INSPECTORS_DIR/VulnPatternInspector.ts" ;;
      v6.4.0.md.added) rm -f "$ALGORITHM_DIR/v6.4.0.md" ;;
      SecurityPipeline.hook.ts) cp "$f" "${HOME}/.claude/hooks/SecurityPipeline.hook.ts" ;;
    esac
  done
  log "uninstall complete. backup retained at $BACKUP_ROOT/$latest"
  exit 0
}

backup_file() {
  local src="$1"
  local rel="$2"
  if [[ -f "$src" ]]; then
    mkdir -p "$BACKUP_DIR"
    cp "$src" "$BACKUP_DIR/$rel"
    log "  backed up $rel"
  fi
}

apply_algorithm_v640() {
  log "1/4 algorithm doctrine: writing v6.4.0.md and updating LATEST"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "  (dry-run) would copy $SCRIPT_DIR/algorithm/v6.4.0.md → $ALGORITHM_DIR/v6.4.0.md"
    log "  (dry-run) would write '6.4.0' to $ALGORITHM_DIR/LATEST"
    return
  fi
  backup_file "$ALGORITHM_DIR/LATEST" "LATEST"
  touch "$BACKUP_DIR/v6.4.0.md.added"  # marker for uninstall
  cp "$SCRIPT_DIR/algorithm/v6.4.0.md" "$ALGORITHM_DIR/v6.4.0.md"
  echo "6.4.0" > "$ALGORITHM_DIR/LATEST"
  log "  wrote $ALGORITHM_DIR/v6.4.0.md ($(wc -l < "$ALGORITHM_DIR/v6.4.0.md") lines)"
  log "  set LATEST → 6.4.0"
}

apply_capabilities_additions() {
  log "2/4 capabilities.md: applying additions"
  local target="$ALGORITHM_DIR/capabilities.md"
  if ! grep -q "^| \\*\\*ThreatModel\\*\\*" "$target" 2>/dev/null; then
    if [[ "$DRY_RUN" -eq 1 ]]; then
      log "  (dry-run) would add ThreatModel row to Thinking & Analysis table"
      log "  (dry-run) would add Security Capabilities subsection"
      return
    fi
    backup_file "$target" "capabilities.md"
    log "  manual merge required — see $SCRIPT_DIR/algorithm/capabilities.md.additions"
    log "  for Apache 2.0 reasons we do not edit Daniel Miessler's PAI files automatically;"
    log "  open the .additions file and merge by hand. The ThreatModel row addition is"
    log "  tiny — one row in the Thinking & Analysis table."
  else
    log "  ThreatModel row already present — skipping"
  fi
}

apply_changelog_additions() {
  log "3/4 changelog.md: prepending v6.4.0 entry"
  local target="$ALGORITHM_DIR/changelog.md"
  if ! grep -q "^- \\*\\*v6\\.4\\.0\\*\\*" "$target" 2>/dev/null; then
    if [[ "$DRY_RUN" -eq 1 ]]; then
      log "  (dry-run) would prepend v6.4.0 entry to Index Current section"
      log "  (dry-run) would append v6.3.0 → v6.4.0 to Full History"
      return
    fi
    backup_file "$target" "changelog.md"
    log "  manual merge required — see $SCRIPT_DIR/algorithm/changelog.md.additions"
    log "  for Apache 2.0 reasons we do not edit Daniel Miessler's PAI files automatically;"
    log "  open the .additions file and merge by hand. Both sections in the .additions file"
    log "  are clearly marked with where to insert."
  else
    log "  v6.4.0 entry already present — skipping"
  fi
}

apply_inspector() {
  log "4/4 VulnPatternInspector: installing into SecurityPipeline"
  if [[ ! -d "$INSPECTORS_DIR" ]]; then
    log "  inspectors directory not present at $INSPECTORS_DIR — skipping (PAI may not be using SecurityPipeline)"
    return
  fi
  local src="$SCRIPT_DIR/VulnPatternInspector.ts"
  local dst="$INSPECTORS_DIR/VulnPatternInspector.ts"
  if [[ ! -f "$src" ]]; then
    log "  ERROR: $src not found — nothing to install"
    return
  fi
  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "  (dry-run) would copy $src → $dst"
    log "  (dry-run) would set CSC_HOOK_DIR=$PROJECT_ROOT/hooks/lib in user shell rc"
    return
  fi
  if [[ -f "$dst" ]]; then
    backup_file "$dst" "VulnPatternInspector.ts.previous"
  else
    touch "$BACKUP_DIR/VulnPatternInspector.ts.removed"  # marker for uninstall
  fi
  cp "$src" "$dst"
  log "  copied → $dst"
  log "  IMPORTANT: VulnPatternInspector reads CSC_HOOK_DIR env var to locate"
  log "  vuln-patterns-core.ts. Set it in your shell rc:"
  log "    export CSC_HOOK_DIR=\"$PROJECT_ROOT/hooks/lib\""
  log ""
  log "  ALSO: register VulnPatternInspector in SecurityPipeline.hook.ts."
  log "  Manual merge — see $SCRIPT_DIR/SecurityPipeline-registration.md."
}

main() {
  ensure_pai_present
  if [[ "$UNINSTALL" -eq 1 ]]; then
    uninstall
  fi
  log "applying PAI integration patch (timestamp: $TIMESTAMP, dry-run: $DRY_RUN)"
  apply_algorithm_v640
  apply_capabilities_additions
  apply_changelog_additions
  apply_inspector
  if [[ "$DRY_RUN" -eq 0 ]]; then
    log "DONE. backup at $BACKUP_DIR (run with --uninstall to restore)"
  else
    log "DONE (dry-run). re-run without --dry-run to apply."
  fi
}

main "$@"
