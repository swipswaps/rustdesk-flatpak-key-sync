#!/usr/bin/env bash
# ==============================================================================
# rustdesk_flatpak_key_sync.sh (v2025-11-04.3)
# ------------------------------------------------------------------------------
# PURPOSE:
#   Manage RustDesk server keypair and synchronize RustDesk-compatible server.pub
#   to Flatpak clients over SSH.
#
#   Upgraded: Auto-detect original user SSH keys under sudo
#            Cleaned host logging
#            Full recursion guard retained
# ==============================================================================

set -euo pipefail

# ------------------------------ Configuration -----------------------------------
RUSTDIR="/var/lib/rustdesk-server"
PRIV="${RUSTDIR}/id_ed25519"
PUB="${RUSTDIR}/id_ed25519.pub"
FLATPAK_KEY_PATH=".var/app/com.rustdesk.RustDesk/config/rustdesk/server.pub"
CLIENT_USER="owner"
LAN_SUBNET="192.168.1.0/24"
LOG_FILE="/var/log/rustdesk_flatpak_key_sync.log"
SSH_TIMEOUT=6
VERIFY_RETRIES=2
VERIFY_RETRY_DELAY=2
EXPORT_RETRIES=3
EXPORT_TMP_SUFFIX=".tmp"
SCP_RETRIES=3

# Detect proper user SSH key even if running via sudo
if [[ -n "${SUDO_USER:-}" ]]; then
    LOCAL_SSH_KEY="${HOME}/.ssh/id_ed25519.pub"
    [[ ! -f "$LOCAL_SSH_KEY" ]] && LOCAL_SSH_KEY="/home/${SUDO_USER}/.ssh/id_ed25519.pub"
    [[ ! -f "$LOCAL_SSH_KEY" ]] && LOCAL_SSH_KEY="/home/${SUDO_USER}/.ssh/id_rsa.pub"
else
    LOCAL_SSH_KEY="${HOME}/.ssh/id_ed25519.pub"
    [[ ! -f "$LOCAL_SSH_KEY" ]] && LOCAL_SSH_KEY="${HOME}/.ssh/id_rsa.pub"
fi

# Mode flags
CLEANUP_MODE=0
DRY_RUN_MODE=0
SELF_ALLOW_MODE=0

# ------------------------------ Colors for UX ----------------------------------
RED="\e[31m"; GREEN="\e[32m"; YELLOW="\e[33m"; RESET="\e[0m"

# ------------------------------ Basic setup ------------------------------------
mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
touch "$LOG_FILE" 2>/dev/null || true
chmod 644 "$LOG_FILE" 2>/dev/null || true

log()  { printf '[%s] %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG_FILE"; }
pass() { printf "%b✅ %s%b\n" "$GREEN" "$*" "$RESET"; log "PASS: $*"; }
fail() { printf "%b❌ %s%b\n" "$RED" "$*" "$RESET"; log "FAIL: $*"; }
warn() { printf "%b⚠️ %s%b\n" "$YELLOW" "$*" "$RESET"; log "WARN: $*"; }
fatal(){ printf '[%s] FATAL: %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG_FILE" >&2; exit 1; }
prompt_yes_no() { local prompt="$1" ans; [[ "$DRY_RUN_MODE" -eq 1 ]] && ans="y" || read -rp "$prompt [y/N]: " ans; [[ "$ans" =~ ^[Yy]$ ]]; }
require_cmd() { command -v "$1" >/dev/null 2>&1; }
key_fingerprint() { sha256sum "$1" | awk '{print $1}'; }
safe_mktemp() { mktemp "${TMPDIR:-/tmp}/rustdesk_key_sync.XXXXXX"; }

# ------------------------------ Argument Parsing -------------------------------
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
--self-allow        : include local host in processing (for testing only)
USAGE
      exit 0
      ;;
  esac
done

# ------------------------------ Dependency Installation ------------------------
install_if_missing() {
  local cmd="$1" pkg="$2" pkgmgr="$3"
  if ! require_cmd "$cmd"; then
    log "Dependency missing: $cmd (package: $pkg)"
    if prompt_yes_no "Install $pkg (for $cmd) now?"; then
      [[ "$DRY_RUN_MODE" -eq 1 ]] && { pass "DRY-RUN: Would install $pkg via $pkgmgr"; return 0; }
      case "$pkgmgr" in
        apt-get) sudo apt-get update -y &>>"$LOG_FILE"; sudo apt-get install -y "$pkg" &>>"$LOG_FILE" || return 1 ;;
        dnf) sudo dnf makecache &>>"$LOG_FILE"; sudo dnf install -y "$pkg" &>>"$LOG_FILE" || return 1 ;;
        pacman) sudo pacman -Sy --noconfirm "$pkg" &>>"$LOG_FILE" || return 1 ;;
        *) fatal "Unsupported package manager: $pkgmgr" ;;
      esac
      pass "Installed $pkg"
    else
      fatal "User declined to install $pkg (required)."
    fi
  fi
}

auto_install_deps() {
  log "Detecting distro for dependency installation..."
  local id_like pkgmgr
  id_like="$(. /etc/os-release && echo "${ID_LIKE:-$ID}")"
  if [[ "$id_like" =~ (debian|ubuntu) ]]; then pkgmgr="apt-get"
  elif [[ "$id_like" =~ (fedora|rhel|centos|nobara) ]]; then pkgmgr="dnf"
  elif [[ "$id_like" =~ (arch|manjaro) ]]; then pkgmgr="pacman"
  else warn "Unknown distro ($id_like). You may install dependencies manually."; return; fi
  install_if_missing "nmap" "nmap" "$pkgmgr"
  install_if_missing "ssh" "openssh-client" "$pkgmgr"
  install_if_missing "scp" "openssh-client" "$pkgmgr"
  install_if_missing "ssh-copy-id" "openssh-client" "$pkgmgr"
  install_if_missing "ssh-keygen" "openssh-client" "$pkgmgr"
  install_if_missing "openssl" "openssl" "$pkgmgr"
  install_if_missing "sha256sum" "coreutils" "$pkgmgr" || true
  install_if_missing "flatpak" "flatpak" "$pkgmgr" || true
  pass "Dependencies verified/installed (or skipped for unknown distro)"
}

# ------------------------------ Keypair Handling --------------------------------
export_rustdesk_pub_with_retries() {
  local tries=0 tmpfile="${PUB}${EXPORT_TMP_SUFFIX}"
  rm -f "$tmpfile" 2>/dev/null || true
  while (( ++tries <= EXPORT_RETRIES )); do
    log "Export attempt #$tries: generating RustDesk pub from $PRIV -> tmp: $tmpfile"
    [[ ! -f "$PRIV" ]] && fatal "Private key $PRIV missing; cannot export."
    if ssh-keygen -y -f "$PRIV" 2>/dev/null | base64 -w0 > "$tmpfile" 2>/dev/null; then :; else warn "ssh-keygen export failed on attempt #$tries"; rm -f "$tmpfile"; sleep 1; continue; fi
    [[ -s "$tmpfile" ]] && { mv -f "$tmpfile" "$PUB"; pass "Export succeeded (attempt #$tries) -> $PUB"; return 0; }
    warn "Export produced empty tmp file on attempt #$tries; retrying..."; rm -f "$tmpfile"; sleep 1
  done
  fatal "Failed to export RustDesk public key after $EXPORT_RETRIES attempts"
}

ensure_server_keypair() {
  log "Ensuring server keypair exists..."
  mkdir -p "$RUSTDIR"; chmod 700 "$RUSTDIR" 2>/dev/null || true
  if [[ -f "$PRIV" || -f "$PUB" ]]; then
    local ts backupdir
    ts="$(date '+%Y%m%d_%H%M%S')"
    backupdir="${RUSTDIR}/backup_${ts}"
    mkdir -p "$backupdir"
    mv "${RUSTDIR}"/id_ed25519* "$backupdir/" 2>/dev/null || true
    log "Existing keys moved to backup: $backupdir"
  fi
  if [[ ! -f "$PRIV" ]]; then
    require_cmd ssh-keygen || fatal "ssh-keygen missing"
    [[ "$DRY_RUN_MODE" -eq 1 ]] && pass "DRY-RUN: Would generate Ed25519 private key at $PRIV" || ssh-keygen -t ed25519 -N "" -f "$PRIV" <<< y >/dev/null 2>&1 || fatal "ssh-keygen failed"
  fi
  [[ "$DRY_RUN_MODE" -eq 1 ]] && pass "DRY-RUN: Would export RustDesk public key" || export_rustdesk_pub_with_retries
  chmod 600 "$PRIV" 2>/dev/null || true
  chmod 644 "$PUB" 2>/dev/null || true
  pass "Server keypair ready. Fingerprint: $(key_fingerprint "$PUB")"
}

# ------------------------------ Network Discovery (Recursion-Safe) ------------------------------
discover_hosts() {
  [[ "$DRY_RUN_MODE" -eq 1 ]] && { pass "DRY-RUN: Would scan LAN $LAN_SUBNET"; printf '%s\n' "192.168.1.101" "192.168.1.102"; return; }
  require_cmd nmap || { warn "nmap missing"; read -rp "Manual IPs (space-separated) or ENTER to abort: " manual; [[ -z "$manual" ]] && return; for ip in $manual; do printf '%s\n' "$ip"; done; return; }
  mapfile -t found < <(nmap -sn "$LAN_SUBNET" 2>/dev/null | awk '/Nmap scan report for/ {print $NF}')
  [[ "${#found[@]}" -eq 0 ]] && { warn "No hosts discovered"; read -rp "Manual IPs (space-separated) or ENTER to abort: " manual; [[ -z "$manual" ]] && return; for ip in $manual; do printf '%s\n' "$ip"; done; return; }

  # Self-IP detection
  local self_ips=($(hostname -I | tr ' ' '\n' | grep -v '^127\.'))
  local filtered=()
  for h in "${found[@]}"; do
    local skip=0
    for s in "${self_ips[@]}"; do [[ "$h" == "$s" ]] && { skip=1; break; } done
    [[ "$skip" -eq 0 || "$SELF_ALLOW_MODE" -eq 1 ]] && filtered+=("$h") || log "Skipping local host IP $h to prevent recursion"
  done

  pass "Discovered hosts (filtered): ${filtered[*]}"
  printf '%s\n' "${filtered[@]}"
}

# ------------------------------ SSH & Remote Ops -------------------------------
deploy_ssh_key_if_needed() {
  local host="$1"
  [[ "$DRY_RUN_MODE" -eq 1 ]] && { pass "DRY-RUN: Would ensure passwordless SSH to $host"; return; }
  ssh -o ConnectTimeout="$SSH_TIMEOUT" -o BatchMode=yes "$CLIENT_USER@$host" "echo ok" &>/dev/null && { pass "Passwordless SSH already works for $host"; return; }
  [[ ! -f "$LOCAL_SSH_KEY" ]] && { warn "No local SSH key at $LOCAL_SSH_KEY"; return 1; }
  log "Attempting ssh-copy-id to $host"
  ssh-copy-id -i "$LOCAL_SSH_KEY" "$CLIENT_USER@$host" &>>"$LOG_FILE" && pass "ssh-copy-id succeeded to $host" || warn "ssh-copy-id failed for $host"
}

remote_copy_pub() {
  local host="$1" try
  [[ "$DRY_RUN_MODE" -eq 1 ]] && { pass "DRY-RUN: Would copy $PUB -> $host:~/$FLATPAK_KEY_PATH"; return; }
  ssh -o ConnectTimeout="$SSH_TIMEOUT" "$CLIENT_USER@$host" "mkdir -p \"\$(dirname ~/$FLATPAK_KEY_PATH)\"" &>>"$LOG_FILE" || warn "Cannot ensure dir on $host"
  for try in $(seq 1 "$SCP_RETRIES"); do
    scp -o ConnectTimeout="$SSH_TIMEOUT" "$PUB" "$CLIENT_USER@$host:/home/$CLIENT_USER/$FLATPAK_KEY_PATH" &>>"$LOG_FILE" && { pass "Copied $PUB to $host:$FLATPAK_KEY_PATH"; return 0; }
    warn "SCP attempt $try failed for $host; retrying..."
    sleep 1
  done
  warn "SCP ultimately failed for $host after $SCP_RETRIES attempts"
}

verify_remote_pub() {
  local host="$1"
  [[ "$DRY_RUN_MODE" -eq 1 ]] && { pass "DRY-RUN: Would verify remote key"; return 0; }
  local tmp remote_fp local_fp
  tmp="$(safe_mktemp)"
  ssh -o ConnectTimeout="$SSH_TIMEOUT" "$CLIENT_USER@$host" "cat '$FLATPAK_KEY_PATH'" >"$tmp" 2>/dev/null || return 1
  remote_fp="$(sha256sum "$tmp" | awk '{print $1}')"
  local_fp="$(key_fingerprint "$PUB")"
  rm -f "$tmp" 2>/dev/null
  [[ "$remote_fp" == "$local_fp" ]]
}

remote_restart_flatpak() {
  local host="$1"
  [[ "$DRY_RUN_MODE" -eq 1 ]] && { pass "DRY-RUN: Would restart Flatpak RustDesk on $host"; return; }
  ssh -o ConnectTimeout="$SSH_TIMEOUT" "$CLIENT_USER@$host" "flatpak kill com.rustdesk.RustDesk || true; nohup flatpak run -d com.rustdesk.RustDesk >/dev/null 2>&1 &" &>>"$LOG_FILE" || warn "Cannot restart RustDesk on $host"
}

# ------------------------------ Main Flow --------------------------------------
log "===== RustDesk Flatpak Key Sync START ====="
[[ "$DRY_RUN_MODE" -eq 1 ]] && pass "MODE: DRY-RUN"
[[ "$CLEANUP_MODE" -eq 1 ]] && pass "MODE: CLEANUP"
[[ "$SELF_ALLOW_MODE" -eq 1 ]] && pass "MODE: SELF-ALLOW enabled (local host will be included)"

auto_install_deps
ensure_server_keypair

mapfile -t HOSTS < <(discover_hosts)
[[ "${#HOSTS[@]}" -eq 0 ]] && { warn "No hosts discovered/supplied"; exit 0; }
pass "Hosts to process: ${HOSTS[*]}"

for host in "${HOSTS[@]}"; do
  log "---- Host: $host ----"
  [[ "$DRY_RUN_MODE" -eq 0 ]] && ! ping -c1 -W2 "$host" &>/dev/null && { warn "$host unreachable"; continue; }
  deploy_ssh_key_if_needed "$host" || { warn "Skipping $host due to SSH issues"; continue; }

  if [[ "$CLEANUP_MODE" -eq 1 ]]; then
    prompt_yes_no "Remove server.pub on $host?" && {
