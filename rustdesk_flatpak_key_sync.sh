#!/usr/bin/env bash
# ==============================================================================
# rustdesk_flatpak_key_sync.sh (v2025-11-06.21)
# ------------------------------------------------------------------------------
# Auto-syncs RustDesk server.pub to LAN clients, with full SSH auto-bootstrap.
# Fixes: agent context loss under sudo; adds auto keyscan + password fallback.
# Implements “If it can be typed, it MUST be scripted!” rule.
# ==============================================================================

set -euo pipefail
shopt -s extglob

RUSTDIR="/var/lib/rustdesk-server"
PRIV="${RUSTDIR}/id_ed25519"
PUB="${RUSTDIR}/id_ed25519.pub"
TMP_PUB="/tmp/rustdesk_sync_key.pub"
CALLER_USER="${SUDO_USER:-$USER}"
CALLER_HOME="$(getent passwd "$CALLER_USER" | cut -d: -f6)"
SSH_DIR="${CALLER_HOME}/.ssh"
CLIENT_USER="owner"
LAN_SUBNET="192.168.1.0/24"
LOG_FILE="/var/log/rustdesk_flatpak_key_sync.log"
SSH_TIMEOUT=10
VERIFY_RETRIES=2
EXPORT_RETRIES=3
SCP_RETRIES=3
AVAHI_FALLBACK=1
ENV_FILE="${CALLER_HOME}/.rustdesk_sync_env"

mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
touch "$LOG_FILE"; chmod 644 "$LOG_FILE"

RED="\e[31m"; GREEN="\e[32m"; YELLOW="\e[33m"; CYAN="\e[36m"; RESET="\e[0m"

log()  { printf -- '[%s] %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG_FILE" >&2; }
pass() { printf -- "%b[%s] ✅ %s%b\n" "$GREEN" "$(date '+%F %T')" "$*" "$RESET" | tee -a "$LOG_FILE" >&2; }
warn() { printf -- "%b[%s] ⚠️ %s%b\n" "$YELLOW" "$(date '+%F %T')" "$*" "$RESET" | tee -a "$LOG_FILE" >&2; }
info() { printf -- "%b[%s] ℹ️ %s%b\n" "$CYAN" "$(date '+%F %T')" "$*" "$RESET" | tee -a "$LOG_FILE" >&2; }
fatal(){ printf -- "%b[%s] ❌ %s%b\n" "$RED" "$(date '+%F %T')" "$*" "$RESET" | tee -a "$LOG_FILE" >&2; exit 1; }

run_cmd() {
  local context="$1"; shift
  log ">>> [START] $context"
  printf -- "\n---- BEGIN COMMAND: %s ----\n" "$*" | tee -a "$LOG_FILE" >&2
  "$@" 2>&1 | tee -a "$LOG_FILE"
  local rc=${PIPESTATUS[0]}
  printf -- "---- END COMMAND (exit code: %d) ----\n\n" "$rc" | tee -a "$LOG_FILE" >&2
  (( rc == 0 )) && pass "$context succeeded" || warn "$context failed"
  return $rc
}

require_cmd() { command -v "$1" >/dev/null 2>&1; }

auto_install_deps() {
  log "[INIT] Checking dependencies..."
  local id_like pkgmgr
  id_like="$(. /etc/os-release && echo "${ID_LIKE:-$ID}")"
  if [[ "$id_like" =~ (debian|ubuntu) ]]; then pkgmgr="apt-get"
  elif [[ "$id_like" =~ (fedora|rhel|centos|nobara) ]]; then pkgmgr="dnf"
  elif [[ "$id_like" =~ (arch|manjaro) ]]; then pkgmgr="pacman"
  else warn "Unknown distro: $id_like"; return; fi

  for dep in nmap ssh scp ssh-keygen openssl flatpak avahi-browse nc sshpass ssh-keyscan; do
    if ! require_cmd "$dep"; then
      warn "Installing missing dependency: $dep"
      case "$pkgmgr" in
        apt-get) sudo apt-get install -y "$dep" ;;
        dnf) sudo dnf install -y "$dep" ;;
        pacman) sudo pacman -Sy --noconfirm "$dep" ;;
      esac
    fi
  done
  pass "Dependencies verified"
}

key_fingerprint() { sha256sum "$1" | awk '{print $1}'; }

export_rustdesk_pub_with_retries() {
  local tries=0 tmpfile="${PUB}.tmp"
  while (( ++tries <= EXPORT_RETRIES )); do
    [[ -f "$PRIV" ]] || fatal "Private key missing: $PRIV"
    ssh-keygen -y -f "$PRIV" > "$tmpfile" && mv -f "$tmpfile" "$PUB" && pass "Pubkey exported" && return
    warn "Export attempt $tries failed"
    sleep 1
  done
  fatal "Failed to export RustDesk pubkey"
}

discover_hosts() {
  local local_ip nmap_out avahi_out
  local_ip="$(hostname -I | awk '{print $1}')"
  info "[DISCOVERY] Scanning LAN subnet $LAN_SUBNET..."
  nmap_out="$(mktemp)"
  avahi_out="$(mktemp)"
  nmap -p22 --open -oG - "$LAN_SUBNET" | tee "$nmap_out" >/dev/null
  mapfile -t nmap_hosts < <(awk '/22\/open/{print $2}' "$nmap_out" | sort -u)
  if (( AVAHI_FALLBACK )); then
    avahi-browse -art | tee "$avahi_out" >/dev/null || true
    mapfile -t mdns_hosts < <(awk -F';' '/IPv4/ {print $8}' "$avahi_out" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u)
  fi
  local combined=($(printf "%s\n" "${nmap_hosts[@]}" "${mdns_hosts[@]:-}" | sort -u))
  local filtered=()
  for h in "${combined[@]}"; do [[ "$h" != "$local_ip" ]] && filtered+=("$h"); done
  printf '%s\n' "${filtered[@]}"
}

get_or_prompt_password() {
  local host="$1" pass_var="SSH_PASS_${host//./_}" password=""
  [[ -f "$ENV_FILE" ]] && source "$ENV_FILE"
  password="${!pass_var:-}"
  if [[ -z "$password" ]]; then
    read -rsp "Enter SSH password for ${CLIENT_USER}@${host}: " password; echo
    [[ -z "$password" ]] && { warn "Empty password for $host"; return 1; }
    mkdir -p "$(dirname "$ENV_FILE")"; chmod 600 "$ENV_FILE"
    echo "${pass_var}=\"${password}\"" >> "$ENV_FILE"
    pass "Password cached for $host"
  fi
  echo "$password"
}

bootstrap_ssh_key() {
  local host="$1" password
  password="$(get_or_prompt_password "$host")" || return 1
  sshpass -p "$password" ssh -o StrictHostKeyChecking=no "$CLIENT_USER@$host" "mkdir -p ~/.ssh && chmod 700 ~/.ssh"
  sshpass -p "$password" scp -o StrictHostKeyChecking=no "$TMP_PUB" "$CLIENT_USER@$host:~/.ssh/tmpkey.pub"
  sshpass -p "$password" ssh -o StrictHostKeyChecking=no "$CLIENT_USER@$host" "cat ~/.ssh/tmpkey.pub >> ~/.ssh/authorized_keys && rm -f ~/.ssh/tmpkey.pub && chmod 600 ~/.ssh/authorized_keys"
}

ensure_ssh_access() {
  local host="$1"
  ssh-keyscan -T 5 "$host" >> "${SSH_DIR}/known_hosts" 2>/dev/null || true
  export SSH_AUTH_SOCK="${SSH_AUTH_SOCK:-}"
  local ssh_cmd=(sudo -E -u "$CALLER_USER" ssh -o ConnectTimeout="$SSH_TIMEOUT" -o StrictHostKeyChecking=no -o UserKnownHostsFile="${SSH_DIR}/known_hosts" -o LogLevel=ERROR)
  if "${ssh_cmd[@]}" -o BatchMode=yes "$CLIENT_USER@$host" 'echo ok' 2>&1 | tee /tmp/ssh_test.log | grep -q ok; then
    pass "$host: SSH key access OK"
    return 0
  fi
  if grep -q "Permission denied" /tmp/ssh_test.log; then
    warn "$host: Key auth failed — attempting password bootstrap"
    bootstrap_ssh_key "$host"
    "${ssh_cmd[@]}" -o BatchMode=yes "$CLIENT_USER@$host" 'echo ok' && return 0
  fi
  warn "$host: SSH unreachable"
  return 1
}

sync_to_host() {
  local host="$1" dest_path
  local ssh_exec=(sudo -E -u "$CALLER_USER" ssh -o ConnectTimeout=$SSH_TIMEOUT -o StrictHostKeyChecking=no -o UserKnownHostsFile=${SSH_DIR}/known_hosts)
  if "${ssh_exec[@]}" "$CLIENT_USER@$host" "test -d ~/.var/app/com.rustdesk.RustDesk/config/rustdesk"; then
    dest_path="~/.var/app/com.rustdesk.RustDesk/config/rustdesk/server.pub"
  else
    "${ssh_exec[@]}" "$CLIENT_USER@$host" "mkdir -p ~/.config/rustdesk"
    dest_path="~/.config/rustdesk/server.pub"
  fi
  for ((i=1; i<=SCP_RETRIES; i++)); do
    sudo -E -u "$CALLER_USER" scp -o ConnectTimeout="$SSH_TIMEOUT" -o StrictHostKeyChecking=no "$TMP_PUB" "${CLIENT_USER}@${host}:${dest_path}" && pass "$host synced" && return 0
    sleep 2
  done
  warn "$host: SCP failed after $SCP_RETRIES attempts"
  return 1
}

# ------------------------------ MAIN -------------------------------------------
log "===== RustDesk Flatpak Key Sync START ====="
auto_install_deps
mkdir -p "$RUSTDIR"; [[ -f "$PRIV" ]] || ssh-keygen -t ed25519 -N "" -f "$PRIV"
export_rustdesk_pub_with_retries
cp "$PUB" "$TMP_PUB"; chmod 644 "$TMP_PUB"; chown "$CALLER_USER":"$CALLER_USER" "$TMP_PUB"
pass "Server key ready: $(key_fingerprint "$PUB")"

mapfile -t HOSTS < <(discover_hosts)
if (( ${#HOSTS[@]} == 0 )); then warn "No hosts found"; exit 0; fi

echo -e "\nDiscovered hosts:"; for i in "${!HOSTS[@]}"; do printf '[%d] %s\n' $((i+1)) "${HOSTS[$i]}"; done
read -rp $'\nSelect hosts to sync (comma-separated or "a" for all): ' selection

declare -a SELECTED
if [[ "$selection" =~ ^[Aa]$ ]]; then SELECTED=("${HOSTS[@]}")
else IFS=',' read -ra c <<< "$selection"; for x in "${c[@]}"; do (( x>=1 && x<=${#HOSTS[@]} )) && SELECTED+=("${HOSTS[$((x-1))]}"); done; fi

declare -A RESULT
for host in "${SELECTED[@]}"; do
  if ensure_ssh_access "$host"; then sync_to_host "$host" && RESULT["$host"]="ok" || RESULT["$host"]="fail"; else RESULT["$host"]="unreachable"; fi
done

rm -f "$TMP_PUB"
log "===== COMPLETE ====="
for h in "${!RESULT[@]}"; do case "${RESULT[$h]}" in ok) pass "$h synced";; fail) warn "$h failed";; unreachable) warn "$h unreachable";; esac; done
