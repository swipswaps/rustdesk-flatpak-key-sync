#!/usr/bin/env bash
# ==============================================================================
# rustdesk_key_sync.sh (v2025-11-07.1)
# ------------------------------------------------------------------------------
# Auto-syncs RustDesk server key to the client's TOML config.
# New: Verifies key fingerprints post-sync and restarts client RustDesk service.
# ==============================================================================

set -euo pipefail
shopt -s extglob

# --- CONFIGURATION ---
RUSTDIR="/var/lib/rustdesk-server"
PUB="${RUSTDIR}/id_ed25519.pub"
TMP_PUB="/tmp/rustdesk_sync_key.pub"
CALLER_USER="${SUDO_USER:-$USER}"
CALLER_HOME="$(getent passwd "$CALLER_USER" | cut -d: -f6)"
SSH_DIR="${CALLER_HOME}/.ssh"
CLIENT_USER="owner"
LAN_SUBNET="192.168.1.0/24"
LOG_FILE="/var/log/rustdesk_key_sync.log"
SSH_TIMEOUT=5

# --- SETUP & LOGGING ---
mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
touch "$LOG_FILE"; chmod 644 "$LOG_FILE"

RED="\e[31m"; GREEN="\e[32m"; YELLOW="\e[33m"; CYAN="\e[36m"; RESET="\e[0m"

log()  { printf -- '[%s] %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG_FILE" >&2; }
pass() { printf -- "%b[%s] ✅ %s%b\n" "$GREEN" "$(date '+%F %T')" "$*" "$RESET" | tee -a "$LOG_FILE" >&2; }
warn() { printf -- "%b[%s] ⚠️ %s%b\n" "$YELLOW" "$(date '+%F %T')" "$*" "$RESET" | tee -a "$LOG_FILE" >&2; }
info() { printf -- "%b[%s] ℹ️ %s%b\n" "$CYAN" "$(date '+%F %T')" "$*" "$RESET" | tee -a "$LOG_FILE" >&2; }
fatal(){ printf -- "%b[%s] ❌ %s%b\n" "$RED" "$(date '+%F %T')" "$*" "$RESET" | tee -a "$LOG_FILE" >&2; exit 1; }

# --- DEPENDENCY & KEY MANAGEMENT ---
auto_install_deps() {
  log "[INIT] Checking dependencies..."
  local missing_deps=()
  for dep in nmap ssh scp ssh-keygen ssh-copy-id awk sed; do
    command -v "$dep" >/dev/null 2>&1 || missing_deps+=("$dep")
  done

  if (( ${#missing_deps[@]} > 0 )); then
      fatal "Missing dependencies: ${missing_deps[*]}. Please install them."
  fi
  pass "Dependencies verified"
}

# --- HOST DISCOVERY & SELECTION (Simplified from flatpak version) ---
discover_hosts() {
  info "[DISCOVERY] Scanning LAN subnet $LAN_SUBNET..."
  local local_ips
  local_ips=$(hostname -I)
  mapfile -t hosts < <(sudo nmap -sn "$LAN_SUBNET" -oG - | awk '/Up$/{print $2}' | sort -u)
  
  local filtered=()
  for h in "${hosts[@]}"; do
    [[ ! "$local_ips" =~ $h ]] && filtered+=("$h")
  done
  printf '%s\n' "${filtered[@]}"
}

select_hosts() {
    mapfile -t hosts <&0
    if (( ${#hosts[@]} == 0 )); then warn "No hosts found"; return; fi
    info "Discovered hosts:"
    for i in "${!hosts[@]}"; do printf '[%d] %s\n' "$((i+1))" "${hosts[$i]}"; done
    read -rp $'Select hosts to sync (e.g., 1 3, or \'a\' for all): ' selection
    
    if [[ "$selection" =~ ^[Aa](ll)?$ ]]; then
        printf '%s\n' "${hosts[@]}"
    else
        for num in $selection; do
            (( num > 0 && num <= ${#hosts[@]} )) && echo "${hosts[$((num-1))]}"
        done
    fi
}

# --- SSH & SYNC LOGIC ---
ensure_ssh_access() {
  local host="$1"
  sudo -E -u "$CALLER_USER" ssh-keyscan -T "$SSH_TIMEOUT" "$host" >> "${SSH_DIR}/known_hosts" 2>/dev/null || true
  if sudo -E -u "$CALLER_USER" ssh -o BatchMode=yes "${CLIENT_USER}@${host}" 'echo ok' &>/dev/null; then
    pass "$host: SSH key access verified."
    return 0
  fi
  warn "$host: Key auth failed. Attempting password bootstrap..."
  if sudo -E -u "$CALLER_USER" ssh-copy-id "${CLIENT_USER}@${host}"; then
    pass "$host: SSH key successfully bootstrapped."
    return 0
  fi
  warn "$host: SSH key bootstrap failed."
  return 1
}

restart_rustdesk_client() {
    local host="$1"
    info "Attempting to restart RustDesk client on $host..."
    local ssh_cmd="sudo -E -u '$CALLER_USER' ssh '${CLIENT_USER}@${host}'"
    if eval "$ssh_cmd 'systemctl --user is-active --quiet rustdesk.service'"; then
        if eval "$ssh_cmd 'systemctl --user restart rustdesk.service'"; then
            pass "$host: RustDesk service restarted via systemd."
            return 0
        else
            warn "$host: Failed to restart systemd service."
            return 1
        fi
    fi
    warn "$host: Could not find a systemd service for RustDesk to restart."
    return 1
}

sync_to_host() {
    local host="$1"
    local remote_cfg="~/.config/rustdesk/RustDesk2.toml"
    local temp_cfg="/tmp/RustDesk2.toml.$$.$host"

    local ssh_exec="sudo -E -u '$CALLER_USER' ssh '${CLIENT_USER}@${host}'"
    local scp_get="sudo -E -u '$CALLER_USER' scp '${CLIENT_USER}@${host}:${remote_cfg}' '$temp_cfg'"
    local scp_put="sudo -E -u '$CALLER_USER' scp '$temp_cfg' '${CLIENT_USER}@${host}:${remote_cfg}'"

    info "Syncing key to TOML config on $host"
    eval "$ssh_exec 'mkdir -p ~/.config/rustdesk && touch ${remote_cfg}'"
    
    if ! eval "$scp_get"; then
        RESULT["$host"]="Sync Failed (SCP Download)"
        return
    fi

    local key_str
    key_str=$(<"$TMP_PUB")
    # Use sed to replace the key. It will replace the line if it exists, or append it if it doesn't.
    sed -i '/^key = /d' "$temp_cfg"
    echo "key = '${key_str}'" >> "$temp_cfg"
    
    if ! eval "$scp_put"; then
        RESULT["$host"]="Sync Failed (SCP Upload)"
        rm "$temp_cfg"
        return
    fi
    rm "$temp_cfg"

    info "Verifying key in TOML on $host..."
    local remote_key
    remote_key=$(eval "$ssh_exec 'grep "^key = " ${remote_cfg}'" | sed "s/key = '\(.*\)'/\1/")
    
    if [[ "$key_str" == "$remote_key" ]]; then
        pass "$host: Key verification successful."
        if restart_rustdesk_client "$host"; then
            RESULT["$host"]="Synced and Restarted"
        else
            RESULT["$host"]="Synced, Restart Failed"
        fi
    else
        warn "$host: KEY MISMATCH! TOML update failed."
        info "Sent: $key_str"
        info "Rcvd: $remote_key"
        RESULT["$host"]="Verification Failed"
    fi
}

# ------------------------------ MAIN ------------------------------------------
trap 'rm -f "$TMP_PUB" /tmp/RustDesk2.toml*' EXIT

log "===== RustDesk Key Sync (v2025-11-07.1) START ======"
auto_install_deps

mkdir -p "$RUSTDIR"
[[ -f "$PUB" ]] || ssh-keygen -y -f "${RUSTDIR}/id_ed25519" > "$PUB"
cp "$PUB" "$TMP_PUB"
chown "$CALLER_USER:$CALLER_USER" "$TMP_PUB"

# Display fingerprint from the temp file for consistency
pass "Server key ready: $(awk '{print $2}' "$TMP_PUB" | openssl base64 -d | sha256sum -b | awk '{print $1}')"

mapfile -t SELECTED_HOSTS < <(discover_hosts | select_hosts)

if (( ${#SELECTED_HOSTS[@]} == 0 )); then log "No hosts selected. Exiting."; exit 0; fi

info "Preparing to sync to: ${SELECTED_HOSTS[*]}"
declare -A RESULT
for host in "${SELECTED_HOSTS[@]}"; do
    if ensure_ssh_access "$host"; then
        sync_to_host "$host"
    else
        RESULT["$host"]="Unreachable (SSH)"
    fi
done

log "===== SYNC COMPLETE: FINAL REPORT ======"
for h in "${!RESULT[@]}"; do
    case "${RESULT[$h]}" in
        "Synced and Restarted") pass "$h: ${RESULT[$h]}";;
        *) warn "$h: ${RESULT[$h]}";;
    esac
done
log "=========================================="
