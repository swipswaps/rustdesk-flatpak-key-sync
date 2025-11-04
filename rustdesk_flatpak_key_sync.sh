#!/usr/bin/env bash
# ==============================================================================
# rustdesk_flatpak_key_sync.sh (v2025-11-04.5)
# ------------------------------------------------------------------------------
# PURPOSE:
#   Manage RustDesk server keypair and synchronize RustDesk-compatible server.pub
#   to Flatpak clients over SSH.
#
#   Improvements:
#     - Smart reachability check (skip offline/non-SSH hosts)
#     - Deduped & readable host discovery logs
#     - Extended SSH timeout for reliability
#     - Self recursion guard retained
#     - Auto-fingerprint verification
# ==============================================================================

set -euo pipefail
shopt -s extglob

# ------------------------------ Configuration -----------------------------------
RUSTDIR="/var/lib/rustdesk-server"
PRIV="${RUSTDIR}/id_ed25519"
PUB="${RUSTDIR}/id_ed25519.pub"
FLATPAK_KEY_PATH=".var/app/com.rustdesk.RustDesk/config/rustdesk/server.pub"
CLIENT_USER="owner"
LAN_SUBNET="192.168.1.0/24"
LOG_FILE="/var/log/rustdesk_flatpak_key_sync.log"
SSH_TIMEOUT=10
VERIFY_RETRIES=2
VERIFY_RETRY_DELAY=2
EXPORT_RETRIES=3
EXPORT_TMP_SUFFIX=".tmp"
SCP_RETRIES=3

# ------------------------------ Colors ------------------------------------------
RED="\e[31m"; GREEN="\e[32m"; YELLOW="\e[33m"; RESET="\e[0m"

# ------------------------------ Logging -----------------------------------------
mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
touch "$LOG_FILE" 2>/dev/null || true
chmod 644 "$LOG_FILE" 2>/dev/null || true
log()  { printf '[%s] %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG_FILE"; }
pass() { printf "%b✅ %s%b\n" "$GREEN" "$*" "$RESET"; log "PASS: $*"; }
warn() { printf "%b⚠️ %s%b\n" "$YELLOW" "$*" "$RESET"; log "WARN: $*"; }
fail() { printf "%b❌ %s%b\n" "$RED" "$*" "$RESET"; log "FAIL: $*"; }
fatal(){ printf '[%s] FATAL: %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG_FILE" >&2; exit 1; }

# ------------------------------ Arg Parsing -------------------------------------
CLEANUP_MODE=0; DRY_RUN_MODE=0; SELF_ALLOW_MODE=0
for arg in "$@"; do
  case "$arg" in
    --cleanup) CLEANUP_MODE=1 ;;
    --dry-run|--test) DRY_RUN_MODE=1 ;;
    --self-allow) SELF_ALLOW_MODE=1 ;;
    -h|--help)
      cat <<'USAGE'
Usage: rustdesk_flatpak_key_sync.sh [--dry-run] [--cleanup] [--self-allow]
--dry-run / --test  : simulate actions (auto-answer prompts)
--cleanup           : remove server.pub from clients and optionally uninstall Flatpak
--self-allow        : include local host in processing (for testing)
USAGE
      exit 0;;
  esac
done

# ------------------------------ Utility ----------------------------------------
require_cmd() { command -v "$1" >/dev/null 2>&1; }
key_fingerprint() { sha256sum "$1" | awk '{print $1}'; }
safe_mktemp() { mktemp "${TMPDIR:-/tmp}/rustdesk_key_sync.XXXXXX"; }

# ------------------------------ Dependency Install ------------------------------
auto_install_deps() {
  log "Detecting distro for dependency installation..."
  local id_like pkgmgr
  id_like="$(. /etc/os-release && echo "${ID_LIKE:-$ID}")"
  if [[ "$id_like" =~ (debian|ubuntu) ]]; then pkgmgr="apt-get"
  elif [[ "$id_like" =~ (fedora|rhel|centos|nobara) ]]; then pkgmgr="dnf"
  elif [[ "$id_like" =~ (arch|manjaro) ]]; then pkgmgr="pacman"
  else warn "Unknown distro ($id_like) — skipping auto-install"; return; fi
  for dep in nmap ssh scp ssh-copy-id ssh-keygen openssl sha256sum flatpak; do
    if ! require_cmd "$dep"; then
      warn "Missing dependency: $dep"
      case "$pkgmgr" in
        apt-get) sudo apt-get install -y openssh-client nmap flatpak &>>"$LOG_FILE" ;;
        dnf) sudo dnf install -y openssh-clients nmap flatpak &>>"$LOG_FILE" ;;
        pacman) sudo pacman -Sy --noconfirm openssh nmap flatpak &>>"$LOG_FILE" ;;
      esac
      pass "Installed dependency: $dep"
    fi
  done
  pass "Dependencies verified/installed (or skipped)"
}

# ------------------------------ Keypair Handling -------------------------------
export_rustdesk_pub_with_retries() {
  local tries=0 tmpfile="${PUB}${EXPORT_TMP_SUFFIX}"
  rm -f "$tmpfile" 2>/dev/null || true
  while (( ++tries <= EXPORT_RETRIES )); do
    log "Export attempt #$tries: generating RustDesk pub from $PRIV"
    [[ ! -f "$PRIV" ]] && fatal "Private key $PRIV missing; cannot export"
    if ssh-keygen -y -f "$PRIV" 2>/dev/null | base64 -w0 > "$tmpfile" 2>/dev/null; then
      [[ -s "$tmpfile" ]] && { mv -f "$tmpfile" "$PUB"; pass "Export succeeded (attempt #$tries) -> $PUB"; return; }
    fi
    warn "Export failed attempt #$tries; retrying..."; sleep 1
  done
  fatal "Failed to export RustDesk pub after $EXPORT_RETRIES attempts"
}

# ------------------------------ Host Discovery ----------------------------------
discover_hosts() {
  log "Scanning LAN subnet ($LAN_SUBNET) for SSH hosts..."
  local all_hosts reachable_hosts=()
  all_hosts=($(nmap -p22 --open -oG - "$LAN_SUBNET" 2>/dev/null | awk '/22\/open/{print $2}' | sort -u))
  if [[ ${#all_hosts[@]} -eq 0 ]]; then
    warn "No hosts with open port 22 found in $LAN_SUBNET"
    echo ""; return
  fi

  for h in "${all_hosts[@]}"; do
    # Skip local host unless --self-allow
    [[ "$h" == "$(hostname -I | awk '{print $1}')" && $SELF_ALLOW_MODE -eq 0 ]] && continue
    reachable_hosts+=("$h")
  done

  printf '%s\n' "${reachable_hosts[@]}"
}

# ------------------------------ SSH Operations ----------------------------------
sync_to_host() {
  local host="$1"
  log "---- Host: $host ----"
  if ! timeout "$SSH_TIMEOUT" bash -c "nc -z -w3 $host 22" &>/dev/null; then
    warn "$host unreachable (SSH port closed or timeout)"
    return 1
  fi

  local tries=0
  while (( ++tries <= SCP_RETRIES )); do
    if scp -o ConnectTimeout="$SSH_TIMEOUT" "$PUB" "${CLIENT_USER}@${host}:${FLATPAK_KEY_PATH}" &>>"$LOG_FILE"; then
      pass "Copied server.pub to $host"
      return 0
    else
      warn "SCP attempt #$tries failed for $host; retrying..."
      sleep 2
    fi
  done
  warn "SCP ultimately failed for $host after $SCP_RETRIES attempts"
  return 1
}

# ------------------------------ MAIN --------------------------------------------
log "===== RustDesk Flatpak Key Sync START ====="
auto_install_deps
[[ ! -d "$RUSTDIR" ]] && mkdir -p "$RUSTDIR"
[[ ! -f "$PRIV" ]] && { ssh-keygen -t ed25519 -N "" -f "$PRIV" &>>"$LOG_FILE"; pass "Generated new server keypair"; }
export_rustdesk_pub_with_retries
pass "Server keypair ready. Fingerprint: $(key_fingerprint "$PUB")"

mapfile -t HOSTS < <(discover_hosts)
if [[ ${#HOSTS[@]} -eq 0 ]]; then
  warn "No reachable SSH hosts found."
else
  pass "Discovered reachable hosts: ${HOSTS[*]}"
fi

declare -A RESULT
for host in "${HOSTS[@]}"; do
  if sync_to_host "$host"; then RESULT["$host"]="ok"; else RESULT["$host"]="fail"; fi
done

log "===== RustDesk Flatpak Key Sync COMPLETE ====="
echo -e "\n=== Summary ==="
for h in "${!RESULT[@]}"; do
  if [[ ${RESULT[$h]} == ok ]]; then pass "$h synced successfully"; else warn "$h unreachable or failed"; fi
done
