#!/usr/bin/env bash
# ==============================================================================
# rustdesk_flatpak_key_sync.sh (v2025-11-05.5)
# ------------------------------------------------------------------------------
# Self-healing RustDesk Flatpak/Native key sync utility
#  - Detects valid clients via SSH
#  - Lists discovered hosts for user confirmation before sync
#  - Skips non-client hosts (e.g., NAS, Proxmox)
#  - Preserves sudo caller SSH env
#  - Auto-creates config folder if missing
#  - Auto-bootstraps SSH key to new hosts (via sshpass)
#  - Fully non-interactive with .env password list
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

log()  { printf '[%s] %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG_FILE" >&2; }
pass() { printf "%b✅ %s%b\n" "$GREEN" "$*" "$RESET" | tee -a "$LOG_FILE" >&2; }
warn() { printf "%b⚠️ %s%b\n" "$YELLOW" "$*" "$RESET" | tee -a "$LOG_FILE" >&2; }
info() { printf "%bℹ️ %s%b\n" "$CYAN" "$*" "$RESET" | tee -a "$LOG_FILE" >&2; }
fatal(){ printf '[%s] FATAL: %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG_FILE" >&2; exit 1; }

# ------------------------------ Dependencies ------------------------------------
require_cmd() { command -v "$1" >/dev/null 2>&1; }

auto_install_deps() {
  log "Checking dependencies..."
  local id_like pkgmgr
  id_like="$(. /etc/os-release && echo "${ID_LIKE:-$ID}")"
  if [[ "$id_like" =~ (debian|ubuntu) ]]; then pkgmgr="apt-get"
  elif [[ "$id_like" =~ (fedora|rhel|centos|nobara) ]]; then pkgmgr="dnf"
  elif [[ "$id_like" =~ (arch|manjaro) ]]; then pkgmgr="pacman"
  else warn "Unknown distro: $id_like"; return; fi

  for dep in nmap ssh scp ssh-keygen openssl flatpak avahi-browse nc sshpass; do
    require_cmd "$dep" || {
      warn "Installing $dep..."
      case "$pkgmgr" in
        apt-get) sudo apt-get install -y openssh-client nmap avahi-utils flatpak netcat-openbsd sshpass ;;
        dnf) sudo dnf install -y openssh-clients nmap avahi flatpak nmap-ncat sshpass ;;
        pacman) sudo pacman -Sy --noconfirm openssh nmap avahi flatpak nmap sshpass ;;
      esac &>>"$LOG_FILE"
    }
  done
  pass "Dependencies verified"
}

# ------------------------------ Keypair -----------------------------------------
key_fingerprint() { sha256sum "$1" | awk '{print $1}'; }

export_rustdesk_pub_with_retries() {
  local tries=0 tmpfile="${PUB}${EXPORT_TMP_SUFFIX}"
  while (( ++tries <= EXPORT_RETRIES )); do
    [[ ! -f "$PRIV" ]] && fatal "Private key missing: $PRIV"
    ssh-keygen -y -f "$PRIV" 2>/dev/null | base64 -w0 > "$tmpfile" 2>/dev/null || true
    [[ -s "$tmpfile" ]] && { mv -f "$tmpfile" "$PUB"; pass "Exported pubkey ($tries)"; return; }
    warn "Retry export attempt #$tries"; sleep 1
  done
  fatal "Failed to export RustDesk pubkey"
}

# ------------------------------ Discovery ---------------------------------------
discover_hosts() {
  local local_ip
  local_ip="$(hostname -I | awk '{print $1}')"
  log "Scanning LAN subnet ($LAN_SUBNET)..."
  mapfile -t nmap_hosts < <(nmap -p22 --open -oG - "$LAN_SUBNET" 2>/dev/null | awk '/22\/open/{print $2}' | sort -u)
  local mdns_hosts=()
  (( AVAHI_FALLBACK )) && mapfile -t mdns_hosts < <(avahi-browse -art 2>/dev/null | awk -F';' '/IPv4/ && /_workstation\._tcp/ {print $8}' | sort -u)
  local combined=($(printf "%s\n" "${nmap_hosts[@]}" "${mdns_hosts[@]}" | sort -u))
  local filtered=()
  for h in "${combined[@]}"; do
    [[ "$h" == "$local_ip" ]] && continue
    filtered+=("$h")
  done
  printf '%s\n' "${filtered[@]}"
}

# ------------------------------ SSH Bootstrap -----------------------------------
bootstrap_ssh_key() {
  local host="$1"
  local pass_var="SSH_PASS_${host//./_}"
  local password=""

  if [[ -f "$ENV_FILE" ]]; then
    source "$ENV_FILE"
    password="${!pass_var:-}"
  fi

  if [[ -z "$password" ]]; then
    warn "No password found for $host in $ENV_FILE — skipping bootstrap"
    return 1
  fi

  if ! require_cmd sshpass; then
    warn "sshpass not installed, cannot bootstrap $host"
    return 1
  fi

  info "$host: Bootstrapping SSH key via password login..."
  sshpass -p "$password" ssh -o StrictHostKeyChecking=no -o ConnectTimeout="$SSH_TIMEOUT" "$CLIENT_USER@$host" "mkdir -p ~/.ssh && chmod 700 ~/.ssh" &>>"$LOG_FILE" || return 1
  sshpass -p "$password" scp -o StrictHostKeyChecking=no -o ConnectTimeout="$SSH_TIMEOUT" "$PUB" "$CLIENT_USER@$host:~/.ssh/tmpkey.pub" &>>"$LOG_FILE" || return 1
  sshpass -p "$password" ssh -o StrictHostKeyChecking=no -o ConnectTimeout="$SSH_TIMEOUT" "$CLIENT_USER@$host" \
    "cat ~/.ssh/tmpkey.pub >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && rm -f ~/.ssh/tmpkey.pub" &>>"$LOG_FILE" || return 1
  pass "$host: SSH key bootstrapped successfully"
  return 0
}

# ------------------------------ SSH Validation -----------------------------------
ensure_ssh_access() {
  local host="$1"
  timeout "$SSH_TIMEOUT" bash -c "nc -z -w3 $host 22" &>/dev/null || return 1
  local ssh_opts=(-o ConnectTimeout="$SSH_TIMEOUT" -o StrictHostKeyChecking=no -o UserKnownHostsFile="${SSH_DIR}/known_hosts" -o LogLevel=ERROR)
  if sudo -u "$CALLER_USER" SSH_AUTH_SOCK="${SSH_AUTH_SOCK:-}" ssh "${ssh_opts[@]}" -o BatchMode=yes "$CLIENT_USER@$host" 'echo ok' &>/dev/null; then
    return 0
  fi
  warn "$host: SSH key login failed, checking for password bootstrap..."
  if bootstrap_ssh_key "$host"; then
    info "$host: Retesting SSH key login..."
    if sudo -u "$CALLER_USER" SSH_AUTH_SOCK="${SSH_AUTH_SOCK:-}" ssh "${ssh_opts[@]}" -o BatchMode=yes "$CLIENT_USER@$host" 'echo ok' &>/dev/null; then
      pass "$host: SSH now passwordless"
      return 0
    fi
  fi
  warn "$host: SSH not ready or requires password"
  return 1
}

# ------------------------------ SSH Sync ---------------------------------------
sync_to_host() {
  local host="$1" dest_path
  log "---- Host: $host ----"
  local ssh_exec="sudo -u \"$CALLER_USER\" SSH_AUTH_SOCK=\"${SSH_AUTH_SOCK:-}\" ssh -o ConnectTimeout=$SSH_TIMEOUT -o StrictHostKeyChecking=no -o UserKnownHostsFile=${SSH_DIR}/known_hosts"
  if $ssh_exec "$CLIENT_USER@$host" "test -d ~/.var/app/com.rustdesk.RustDesk/config/rustdesk" &>/dev/null; then
    dest_path="~/.var/app/com.rustdesk.RustDesk/config/rustdesk/server.pub"
    info "$host: Detected Flatpak RustDesk"
  elif $ssh_exec "$CLIENT_USER@$host" "test -d ~/.config/rustdesk" &>/dev/null; then
    dest_path="~/.config/rustdesk/server.pub"
    info "$host: Detected native RustDesk"
  else
    warn "$host: No RustDesk config found — creating ~/.config/rustdesk"
    $ssh_exec "$CLIENT_USER@$host" "mkdir -p ~/.config/rustdesk" &>>"$LOG_FILE" || { warn "$host: cannot create dir"; return 2; }
    dest_path="~/.config/rustdesk/server.pub"
  fi

  for ((i=1; i<=SCP_RETRIES; i++)); do
    if sudo -u "$CALLER_USER" SSH_AUTH_SOCK="${SSH_AUTH_SOCK:-}" scp -o ConnectTimeout="$SSH_TIMEOUT" -o StrictHostKeyChecking=no "$PUB" "${CLIENT_USER}@${host}:${dest_path}" &>>"$LOG_FILE"; then
      pass "$host: Key synced to ${dest_path}"
      return 0
    fi
    warn "$host: SCP retry $i failed"; sleep 2
  done
  warn "$host: SCP failed after $SCP_RETRIES attempts"
  return 1
}

# ------------------------------ MAIN --------------------------------------------
log "===== RustDesk Flatpak Key Sync START ====="
auto_install_deps
mkdir -p "$RUSTDIR"
[[ -f "$PRIV" ]] || { ssh-keygen -t ed25519 -N "" -f "$PRIV" &>>"$LOG_FILE"; pass "Generated server keypair"; }
export_rustdesk_pub_with_retries
pass "Server key ready. Fingerprint: $(key_fingerprint "$PUB")"

mapfile -t HOSTS < <(discover_hosts)
if (( ${#HOSTS[@]} == 0 )); then warn "No hosts found"; exit 0; fi

echo -e "\nDiscovered hosts:"
for i in "${!HOSTS[@]}"; do
  printf "[%d] %s\n" $((i+1)) "${HOSTS[$i]}"
done
read -rp $'\nSelect hosts to sync (comma-separated or "a" for all): ' selection

declare -a SELECTED
if [[ "$selection" =~ ^[Aa]$ ]]; then
  SELECTED=("${HOSTS[@]}")
else
  IFS=',' read -ra choices <<< "$selection"
  for c in "${choices[@]}"; do
    (( c>=1 && c<=${#HOSTS[@]} )) && SELECTED+=("${HOSTS[$((c-1))]}")
  done
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
