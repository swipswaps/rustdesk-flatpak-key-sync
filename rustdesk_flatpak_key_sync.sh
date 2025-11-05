#!/usr/bin/env bash
# ==============================================================================
# rustdesk_flatpak_key_sync.sh (v2025-11-05.7)
# ------------------------------------------------------------------------------
# MIL-STD/PRF-Compliant, Code-as-Truth Edition
# Self-healing RustDesk Flatpak/Native key sync utility
# - All existing features preserved.
# - All subprocesses stream verbatim output to terminal & log (via tee).
# - Each command prints contextual start/stop with exit codes.
# - Fully auditable, unbuffered, human-readable in real time.
# ==============================================================================

set -euo pipefail
shopt -s extglob

# ------------------------------ Configuration -----------------------------------
RUSTDIR="/var/lib/rustdesk-server"
PRIV="${RUSTDIR}/id_ed25519"
PUB="${RUSTDIR}/id_ed25519.pub"
CALLER_USER="${SUDO_USER:-$USER}"
CALLER_HOME="$(getent passwd "$CALLER_USER" | cut -d: -f6)"
SSH_DIR="${CALLER_HOME}/.ssh"
CLIENT_USER="owner"
LAN_SUBNET="192.168.1.0/24"
LOG_FILE="/var/log/rustdesk_flatpak_key_sync.log"
SSH_TIMEOUT=10
VERIFY_RETRIES=2
EXPORT_RETRIES=3
EXPORT_TMP_SUFFIX=".tmp"
SCP_RETRIES=3
AVAHI_FALLBACK=1
ENV_FILE="${CALLER_HOME}/.rustdesk_sync_env"

# ------------------------------ Colors & Logging --------------------------------
RED="\e[31m"; GREEN="\e[32m"; YELLOW="\e[33m"; CYAN="\e[36m"; RESET="\e[0m"
mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
touch "$LOG_FILE"; chmod 644 "$LOG_FILE"

log()  { printf '[%s] %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG_FILE"; }
pass() { printf "%b[%s] ✅ %s%b\n" "$GREEN" "$(date '+%F %T')" "$*" "$RESET" | tee -a "$LOG_FILE"; }
warn() { printf "%b[%s] ⚠️ %s%b\n" "$YELLOW" "$(date '+%F %T')" "$*" "$RESET" | tee -a "$LOG_FILE"; }
info() { printf "%b[%s] ℹ️ %s%b\n" "$CYAN" "$(date '+%F %T')" "$*" "$RESET" | tee -a "$LOG_FILE"; }
fatal(){ printf "%b[%s] ❌ FATAL: %s%b\n" "$RED" "$(date '+%F %T')" "$*" "$RESET" | tee -a "$LOG_FILE"; exit 1; }

# ------------------------------ Command Runner -----------------------------------
run_cmd() {
  local context="$1"; shift
  log ">>> [START] $context"
  printf "\n---- BEGIN COMMAND: %s ----\n" "$*" | tee -a "$LOG_FILE"
  "$@" 2>&1 | tee -a "$LOG_FILE"
  local rc=${PIPESTATUS[0]}
  printf "---- END COMMAND (exit code: %d) ----\n\n" "$rc" | tee -a "$LOG_FILE"
  if (( rc == 0 )); then pass "$context succeeded (exit $rc)"
  else warn "$context failed (exit $rc)"; fi
  return $rc
}

# ------------------------------ Dependencies ------------------------------------
require_cmd() { command -v "$1" >/dev/null 2>&1; }

auto_install_deps() {
  log "[INIT] Checking dependencies..."
  local id_like pkgmgr
  id_like="$(. /etc/os-release && echo "${ID_LIKE:-$ID}")"
  if [[ "$id_like" =~ (debian|ubuntu) ]]; then pkgmgr="apt-get"
  elif [[ "$id_like" =~ (fedora|rhel|centos|nobara) ]]; then pkgmgr="dnf"
  elif [[ "$id_like" =~ (arch|manjaro) ]]; then pkgmgr="pacman"
  else warn "Unknown distro: $id_like"; return; fi

  for dep in nmap ssh scp ssh-keygen openssl flatpak avahi-browse nc sshpass; do
    if ! require_cmd "$dep"; then
      warn "Installing missing dependency: $dep"
      case "$pkgmgr" in
        apt-get) run_cmd "Install $dep" sudo apt-get install -y "$dep" ;;
        dnf) run_cmd "Install $dep" sudo dnf install -y "$dep" ;;
        pacman) run_cmd "Install $dep" sudo pacman -Sy --noconfirm "$dep" ;;
      esac
    fi
  done
  pass "Dependencies verified"
}

# ------------------------------ Keypair -----------------------------------------
key_fingerprint() { sha256sum "$1" | awk '{print $1}'; }

export_rustdesk_pub_with_retries() {
  local tries=0 tmpfile="${PUB}${EXPORT_TMP_SUFFIX}"
  while (( ++tries <= EXPORT_RETRIES )); do
    [[ -f "$PRIV" ]] || fatal "Private key missing: $PRIV"
    run_cmd "Export RustDesk public key (attempt $tries)" ssh-keygen -y -f "$PRIV" > "$tmpfile"
    if [[ -s "$tmpfile" ]]; then
      mv -f "$tmpfile" "$PUB"
      pass "Exported pubkey on attempt $tries"
      return
    fi
    warn "Export attempt #$tries failed — retrying..."
    sleep 1
  done
  fatal "Failed to export RustDesk pubkey"
}

# ------------------------------ Discovery ---------------------------------------
discover_hosts() {
  local local_ip
  local_ip="$(hostname -I | awk '{print $1}')"
  info "[DISCOVERY] Scanning LAN subnet $LAN_SUBNET..."
  run_cmd "Nmap discovery" nmap -p22 --open -oG - "$LAN_SUBNET"
  mapfile -t nmap_hosts < <(grep '/open' "$LOG_FILE" | awk '/22\/open/{print $2}' | sort -u)
  local mdns_hosts=()
  if (( AVAHI_FALLBACK )); then
    run_cmd "Avahi mDNS discovery" avahi-browse -art
    mapfile -t mdns_hosts < <(grep "_workstation._tcp" "$LOG_FILE" | awk -F';' '/IPv4/ {print $8}' | sort -u)
  fi
  local combined=($(printf "%s\n" "${nmap_hosts[@]}" "${mdns_hosts[@]}" | sort -u))
  local filtered=()
  for h in "${combined[@]}"; do [[ "$h" != "$local_ip" ]] && filtered+=("$h"); done
  printf '%s\n' "${filtered[@]}"
}

# ------------------------------ SSH Bootstrap -----------------------------------
bootstrap_ssh_key() {
  local host="$1"
  local pass_var="SSH_PASS_${host//./_}"
  local password=""
  [[ -f "$ENV_FILE" ]] && source "$ENV_FILE"
  password="${!pass_var:-}"
  [[ -z "$password" ]] && { warn "$host: No password in $ENV_FILE"; return 1; }

  run_cmd "$host: mkdir ~/.ssh" sshpass -p "$password" ssh -o StrictHostKeyChecking=no -o ConnectTimeout="$SSH_TIMEOUT" "$CLIENT_USER@$host" "mkdir -p ~/.ssh && chmod 700 ~/.ssh"
  run_cmd "$host: upload pubkey" sshpass -p "$password" scp -o StrictHostKeyChecking=no -o ConnectTimeout="$SSH_TIMEOUT" "$PUB" "$CLIENT_USER@$host:~/.ssh/tmpkey.pub"
  run_cmd "$host: append pubkey" sshpass -p "$password" ssh -o StrictHostKeyChecking=no -o ConnectTimeout="$SSH_TIMEOUT" "$CLIENT_USER@$host" "cat ~/.ssh/tmpkey.pub >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && rm -f ~/.ssh/tmpkey.pub"
}

# ------------------------------ SSH Validation -----------------------------------
ensure_ssh_access() {
  local host="$1"
  run_cmd "$host: test TCP/22 connectivity" nc -z -w3 "$host" 22
  local ssh_opts=(-o ConnectTimeout="$SSH_TIMEOUT" -o StrictHostKeyChecking=no -o UserKnownHostsFile="${SSH_DIR}/known_hosts" -o LogLevel=ERROR)
  if run_cmd "$host: SSH test" sudo -u "$CALLER_USER" ssh "${ssh_opts[@]}" -o BatchMode=yes "$CLIENT_USER@$host" 'echo ok'; then
    return 0
  fi
  warn "$host: key login failed, attempting bootstrap..."
  if bootstrap_ssh_key "$host"; then
    run_cmd "$host: SSH re-test" sudo -u "$CALLER_USER" ssh "${ssh_opts[@]}" -o BatchMode=yes "$CLIENT_USER@$host" 'echo ok'
  else
    return 1
  fi
}

# ------------------------------ SSH Sync ---------------------------------------
sync_to_host() {
  local host="$1" dest_path
  log "[SYNC] Host: $host"
  local ssh_exec=(sudo -u "$CALLER_USER" ssh -o ConnectTimeout=$SSH_TIMEOUT -o StrictHostKeyChecking=no -o UserKnownHostsFile=${SSH_DIR}/known_hosts)
  if "${ssh_exec[@]}" "$CLIENT_USER@$host" "test -d ~/.var/app/com.rustdesk.RustDesk/config/rustdesk" | tee -a "$LOG_FILE"; then
    dest_path="~/.var/app/com.rustdesk.RustDesk/config/rustdesk/server.pub"
  elif "${ssh_exec[@]}" "$CLIENT_USER@$host" "test -d ~/.config/rustdesk" | tee -a "$LOG_FILE"; then
    dest_path="~/.config/rustdesk/server.pub"
  else
    run_cmd "$host: mkdir ~/.config/rustdesk" "${ssh_exec[@]}" "$CLIENT_USER@$host" "mkdir -p ~/.config/rustdesk"
    dest_path="~/.config/rustdesk/server.pub"
  fi

  for ((i=1; i<=SCP_RETRIES; i++)); do
    run_cmd "$host: scp pubkey attempt $i" sudo -u "$CALLER_USER" scp -o ConnectTimeout="$SSH_TIMEOUT" -o StrictHostKeyChecking=no "$PUB" "${CLIENT_USER}@${host}:${dest_path}" && return 0
    sleep 2
  done
  warn "$host: SCP failed after $SCP_RETRIES attempts"
  return 1
}

# ------------------------------ MAIN --------------------------------------------
log "===== RustDesk Flatpak Key Sync START ====="
auto_install_deps
mkdir -p "$RUSTDIR"
[[ -f "$PRIV" ]] || run_cmd "Generate RustDesk keypair" ssh-keygen -t ed25519 -N "" -f "$PRIV"
export_rustdesk_pub_with_retries
pass "Server key ready. Fingerprint: $(key_fingerprint "$PUB")"

mapfile -t HOSTS < <(discover_hosts)
if (( ${#HOSTS[@]} == 0 )); then warn "No hosts found"; exit 0; fi

echo -e "\nDiscovered hosts:"
for i in "${!HOSTS[@]}"; do printf "[%d] %s\n" $((i+1)) "${HOSTS[$i]}"; done
read -rp $'\nSelect hosts to sync (comma-separated or "a" for all): ' selection

declare -a SELECTED
if [[ "$selection" =~ ^[Aa]$ ]]; then SELECTED=("${HOSTS[@]}")
else
  IFS=',' read -ra choices <<< "$selection"
  for c in "${choices[@]}"; do (( c>=1 && c<=${#HOSTS[@]} )) && SELECTED+=("${HOSTS[$((c-1))]}"); done
fi

if (( ${#SELECTED[@]} == 0 )); then warn "No valid selections. Exiting."; exit 0; fi
pass "Selected hosts: ${SELECTED[*]}"

declare -A RESULT
for host in "${SELECTED[@]}"; do
  if ensure_ssh_access "$host"; then
    sync_to_host "$host" && RESULT["$host"]="ok" || RESULT["$host"]="fail"
  else
    RESULT["$host"]="unreachable"
  fi
done

log "===== RustDesk Flatpak Key Sync COMPLETE ====="
echo -e "\n=== Summary ==="
for h in "${!RESULT[@]}"; do
  case "${RESULT[$h]}" in
    ok)   pass "$h synced successfully" ;;
    fail) warn "$h failed during sync" ;;
    unreachable) warn "$h not reachable via SSH" ;;
  esac
done
