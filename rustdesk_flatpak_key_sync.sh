#!/usr/bin/env bash
# ==============================================================================
# rustdesk_flatpak_key_sync.sh (v2025-11-07.1)
# ------------------------------------------------------------------------------
# Auto-syncs RustDesk server.pub to LAN clients, with full SSH auto-bootstrap.
# Fixes: agent context loss under sudo; adds auto keyscan + password fallback.
# New: Verifies key fingerprints post-sync and restarts client RustDesk service.
# ==============================================================================

set -euo pipefail
shopt -s extglob

# --- CONFIGURATION ---
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
SSH_TIMEOUT=5
SCP_RETRIES=3
AVAHI_FALLBACK=1
ENV_FILE="${CALLER_HOME}/.rustdesk_sync_env"

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
require_cmd() { command -v "$1" >/dev/null 2>&1; }

auto_install_deps() {
  log "[INIT] Checking dependencies..."
  local id_like pkgmgr missing_deps=()
  for dep in nmap ssh scp ssh-keygen openssl flatpak avahi-browse nc sshpass ssh-keyscan sha256sum; do
    require_cmd "$dep" || missing_deps+=("$dep")
  done

  if (( ${#missing_deps[@]} > 0 )); then
    warn "Missing dependencies: ${missing_deps[*]}"
    id_like="$(. /etc/os-release && echo "${ID_LIKE:-$ID}")"
    if [[ "$id_like" =~ (debian|ubuntu) ]]; then pkgmgr="apt-get"
    elif [[ "$id_like" =~ (fedora|rhel|centos) ]]; then pkgmgr="dnf"
    elif [[ "$id_like" =~ (arch|manjaro) ]]; then pkgmgr="pacman"
    else fatal "Cannot auto-install on unknown distro: $id_like"; fi
    
    read -rp "Attempt to install them now? (y/N): " choice
    if [[ "$choice" =~ ^[yY]$ ]]; then
      case "$pkgmgr" in
        apt-get) sudo apt-get update && sudo apt-get install -y "${missing_deps[@]}" ;;
        dnf) sudo dnf install -y "${missing_deps[@]}" ;;
        pacman) sudo pacman -Sy --noconfirm "${missing_deps[@]}" ;;
      esac
    else
      fatal "Dependencies not met. Aborting."
    fi
  fi
  pass "Dependencies verified"
}

export_rustdesk_pub() {
  [[ -f "$PRIV" ]] || fatal "Private key missing: $PRIV"
  ssh-keygen -y -f "$PRIV" > "$PUB" || fatal "Failed to export RustDesk pubkey"
  pass "Public key exported from private key."
}

# --- HOST DISCOVERY & SELECTION ---
discover_hosts() {
  local nmap_out avahi_out
  info "[DISCOVERY] Scanning LAN subnet(s) $LAN_SUBNET..."
  mapfile -t nmap_hosts < <(sudo nmap -sn "$LAN_SUBNET" -oG - | awk '/Up$/{print $2}' | sort -u)
  
  if (( AVAHI_FALLBACK )); then
    mapfile -t mdns_hosts < <(avahi-browse -art | awk -F';' '/_ssh._tcp/ && /IPv4/ {print $8}' | sort -u)
  fi
  
  local local_ips
  local_ips=$(hostname -I)
  mapfile -t combined < <(printf "%s\n" "${nmap_hosts[@]}" "${mdns_hosts[@]:-}" | sort -u)
  
  local filtered=()
  for h in "${combined[@]}"; do
    [[ ! "$local_ips" =~ $h ]] && filtered+=("$h")
  done
  
  if (( ${#filtered[@]} == 0 )); then
    warn "No remote hosts discovered. Check network and ensure clients are on."
  fi
  printf '%s\n' "${filtered[@]}"
}

select_hosts() {
    mapfile -t hosts <&0
    if (( ${#hosts[@]} == 0 )); then echo ""; return; fi

    info "Discovered hosts:"
    for i in "${!hosts[@]}"; do
        printf '[%d] %s\n' "$((i+1))" "${hosts[$i]}"
    done
    
    read -rp $'Select hosts to sync (e.g., 1 3, or \'a\' for all): ' selection
    
    declare -a selected_indices
    if [[ "$selection" =~ ^[Aa](ll)?$ ]]; then
        selected_indices=("${!hosts[@]}")
    else
        for num in $selection; do
            (( num > 0 && num <= ${#hosts[@]} )) && selected_indices+=($((num-1)))
        done
    fi
    
    local selected_hosts=()
    for i in "${selected_indices[@]}"; do
        selected_hosts+=("${hosts[$i]}")
    done
    printf '%s\n' "${selected_hosts[@]}"
}


# --- SSH & SYNC LOGIC ---
ensure_ssh_access() {
  local host="$1"
  sudo -E -u "$CALLER_USER" ssh-keyscan -T "$SSH_TIMEOUT" "$host" >> "${SSH_DIR}/known_hosts" 2>/dev/null || true
  
  local ssh_opts=(-o ConnectTimeout="$SSH_TIMEOUT" -o StrictHostKeyChecking=no -o UserKnownHostsFile="${SSH_DIR}/known_hosts" -o LogLevel=ERROR -o BatchMode=yes)
  
  if sudo -E -u "$CALLER_USER" ssh "${ssh_opts[@]}" "${CLIENT_USER}@${host}" 'echo "Key auth OK"' 2>/dev/null | grep -q "Key auth OK"; then
    pass "$host: SSH key access verified."
    return 0
  fi
  
  warn "$host: Key auth failed. Attempting password bootstrap..."
  if sudo -E -u "$CALLER_USER" ssh-copy-id -o ConnectTimeout="$SSH_TIMEOUT" -o StrictHostKeyChecking=no "${CLIENT_USER}@${host}"; then
    pass "$host: SSH key successfully bootstrapped."
    return 0
  else
    warn "$host: SSH key bootstrap failed."
    return 1
  fi
}

verify_synced_key() {
    local host="$1" dest_path="$2"
    info "Verifying key fingerprint on $host..."
    
    local local_fp remote_fp
    local_fp=$(sha256sum "$TMP_PUB" | awk '{print $1}')
    info "Server Key Fingerprint: $local_fp"
    
    remote_fp=$(sudo -E -u "$CALLER_USER" ssh "${CLIENT_USER}@${host}" "sha256sum ${dest_path} 2>/dev/null | awk '{print \$1}'")
    info "Client Key Fingerprint: $remote_fp"

    if [[ "$local_fp" == "$remote_fp" ]]; then
        pass "$host: Key verification successful."
        return 0
    else
        warn "$host: KEY MISMATCH! Sync failed or read a different file."
        return 1
    fi
}

restart_rustdesk_client() {
    local host="$1"
    info "Attempting to restart RustDesk client on $host..."
    
    local ssh_cmd="sudo -E -u '$CALLER_USER' ssh '${CLIENT_USER}@${host}'"

    # Attempt standard systemd restart
    if eval "$ssh_cmd 'systemctl --user is-active --quiet rustdesk.service'"; then
        if eval "$ssh_cmd 'systemctl --user restart rustdesk.service'"; then
            pass "$host: RustDesk service restarted via systemd."
            return 0
        else
            warn "$host: Failed to restart systemd service."
        fi
    fi

    # Attempt Flatpak restart
    if eval "$ssh_cmd 'flatpak info com.rustdesk.RustDesk &>/dev/null'"; then
        if eval "$ssh_cmd 'flatpak kill com.rustdesk.RustDesk &>/dev/null'"; then
            pass "$host: RustDesk (Flatpak) process killed. It should auto-restart or can be launched manually."
            return 0
        else
            warn "$host: Failed to kill Flatpak process."
        fi
    fi

    warn "$host: Could not find a managed RustDesk service to restart."
    return 1
}

sync_to_host() {
    local host="$1" dest_path
    
    local ssh_exec="sudo -E -u '$CALLER_USER' ssh '${CLIENT_USER}@${host}'"
    
    if eval "$ssh_exec 'test -d ~/.var/app/com.rustdesk.RustDesk/config/rustdesk'"; then
        dest_path="~/.var/app/com.rustdesk.RustDesk/config/rustdesk/id_ed25519.pub"
    else
        eval "$ssh_exec 'mkdir -p ~/.config/rustdesk'"
        dest_path="~/.config/rustdesk/id_ed25519.pub"
    fi

    info "Syncing key to $host at $dest_path"
    for ((i=1; i<=SCP_RETRIES; i++)); do
        if sudo -E -u "$CALLER_USER" scp -o ConnectTimeout="$SSH_TIMEOUT" "$TMP_PUB" "${CLIENT_USER}@${host}:${dest_path}"; then
            if verify_synced_key "$host" "$dest_path"; then
                if restart_rustdesk_client "$host"; then
                    RESULT["$host"]="Synced and Restarted"
                else
                    RESULT["$host"]="Synced, Restart Failed"
                fi
            else
                RESULT["$host"]="Verification Failed"
            fi
            return
        fi
        warn "SCP attempt $i failed for $host. Retrying..."
        sleep 2
    done
    RESULT["$host"]="Sync Failed (SCP)"
}

# ------------------------------ MAIN ------------------------------------------
trap 'rm -f "$TMP_PUB"' EXIT

log "===== RustDesk Key Sync (v2025-11-07.1) START ======"
auto_install_deps

mkdir -p "$RUSTDIR"
[[ -f "$PUB" ]] || export_rustdesk_pub
cp "$PUB" "$TMP_PUB"
chown "$CALLER_USER:$CALLER_USER" "$TMP_PUB"
pass "Server key ready: $(sha256sum "$PUB" | awk '{print $1}')"

mapfile -t SELECTED_HOSTS < <(discover_hosts | select_hosts)

if (( ${#SELECTED_HOSTS[@]} == 0 )); then
    log "No hosts selected. Exiting."
    exit 0
fi

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
