#!/usr/bin/env bash
# ==============================================================================
# rustdesk_flatpak_key_sync.sh (STABLE)
# ------------------------------------------------------------------------------
# Auto-syncs RustDesk server key to LAN clients, handling Flatpak and standard
# configurations. Includes SSH bootstrapping, key verification, and client-side
# service restart.
# ==============================================================================

set -euo pipefail

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
LOG_FILE="/var/log/rustdesk_key_sync.log"
SSH_TIMEOUT=5

# --- SETUP & LOGGING ---
mkdir -p "$(dirname "$LOG_FILE")" &>/dev/null || true
touch "$LOG_FILE" &>/dev/null; chmod 644 "$LOG_FILE"

RED="\e[31m"; GREEN="\e[32m"; YELLOW="\e[33m"; CYAN="\e[36m"; RESET="\e[0m"

log()  { printf -- '[%s] %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG_FILE" >&2; }
pass() { printf -- "%b[%s] ✅ %s%b\n" "$GREEN" "$(date '+%F %T')" "$*" "$RESET" | tee -a "$LOG_FILE" >&2; }
warn() { printf -- "%b[%s] ⚠️ %s%b\n" "$YELLOW" "$(date '+%F %T')" "$*" "$RESET" | tee -a "$LOG_FILE" >&2; }
info() { printf -- "%b[%s] ℹ️ %s%b\n" "$CYAN" "$(date '+%F %T')" "$*" "$RESET" | tee -a "$LOG_FILE" >&2; }
fatal(){ printf -- "%b[%s] ❌ %s%b\n" "$RED" "$(date '+%F %T')" "$*" "$RESET" | tee -a "$LOG_FILE" >&2; exit 1; }

# --- DEPENDENCY & KEY MANAGEMENT ---
require_cmd() { command -v "$1" >/dev/null 2>&1 || return 1; }

auto_install_deps() {
    log "[INIT] Checking dependencies..."
    local id_like pkgmgr missing_deps=()
    for dep in nmap ssh scp ssh-keygen openssl flatpak ssh-copy-id ssh-keyscan sha256sum; do
        require_cmd "$dep" || missing_deps+=("$dep")
    done

    if (( ${#missing_deps[@]} > 0 )); then
        warn "Missing dependencies: ${missing_deps[*]}"
        id_like="$(. /etc/os-release && echo "${ID_LIKE:-$ID}")"
        pkgmgr=""
        if [[ "$id_like" =~ (debian|ubuntu) ]]; then pkgmgr="apt-get"
        elif [[ "$id_like" =~ (fedora|rhel|centos) ]]; then pkgmgr="dnf"
        elif [[ "$id_like" =~ (arch|manjaro) ]]; then pkgmgr="pacman"
        fi

        if [[ -n "$pkgmgr" ]]; then
            read -rp "Attempt to install them now? (y/N): " choice
            if [[ "$choice" =~ ^[yY]$ ]]; then
                sudo "$pkgmgr" install -y "${missing_deps[@]}"
            else fatal "Dependencies not met. Aborting."; fi
        else fatal "Cannot auto-install on unknown distro: $id_like"; fi
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
    info "[DISCOVERY] Scanning LAN for hosts..."
    local local_ips
    local_ips=$(hostname -I)
    mapfile -t hosts < <(sudo nmap -sn "$LAN_SUBNET" -oG - | awk '/Up$/{print $2}' | grep -vF "$local_ips" | sort -u)
    if (( ${#hosts[@]} == 0 )); then
        warn "No remote hosts discovered. Check network and ensure clients are on."
    fi
    printf '%s\n' "${hosts[@]}"
}

select_hosts() {
    mapfile -t hosts <&0
    if (( ${#hosts[@]} == 0 )); then echo ""; return; fi

    info "Discovered hosts:"
    for i in "${!hosts[@]}"; do
        printf '[\e[1;33m%d\e[0m] %s\n' "$((i+1))" "${hosts[$i]}" >&2
    done
    
    read -rp $'Select hosts to sync (e.g., 1 3, or \'a\' for all): ' selection
    
    local selected_hosts=()
    if [[ "$selection" =~ ^[aA](ll)?$ ]]; then
        selected_hosts=("${hosts[@]}")
    else
        for num in $selection; do
            if [[ "$num" =~ ^[0-9]+$ ]] && (( num > 0 && num <= ${#hosts[@]} )); then
                selected_hosts+=("${hosts[$((num-1))]}")
            fi
        done
    fi
    printf '%s\n' "${selected_hosts[@]}"
}

# --- SSH & SYNC LOGIC ---
ensure_ssh_access() {
    local host="$1"
    sudo -E -u "$CALLER_USER" ssh-keyscan -T "$SSH_TIMEOUT" "$host" >> "${SSH_DIR}/known_hosts" 2>/dev/null || true
    if sudo -E -u "$CALLER_USER" ssh -o ConnectTimeout="$SSH_TIMEOUT" -o BatchMode=yes "${CLIENT_USER}@${host}" 'echo ok' &>/dev/null; then
        pass "$host: SSH key access verified."
        return 0
    fi
    warn "$host: Key auth failed. Attempting password bootstrap..."
    if sudo -E -u "$CALLER_USER" ssh-copy-id -o ConnectTimeout="$SSH_TIMEOUT" "${CLIENT_USER}@${host}"; then
        pass "$host: SSH key successfully bootstrapped."
        return 0
    fi
    warn "$host: SSH key bootstrap failed."
    return 1
}

restart_rustdesk_client() {
    local host="$1"
    info "Attempting to restart RustDesk client on $host..."
    local ssh_cmd="sudo -E -u '$CALLER_USER' ssh -o ConnectTimeout='$SSH_TIMEOUT' '${CLIENT_USER}@${host}'"

    if eval "$ssh_cmd 'systemctl --user is-active --quiet rustdesk.service'" &>/dev/null; then
        if eval "$ssh_cmd 'systemctl --user restart rustdesk.service'"; then
            pass "$host: RustDesk service restarted via systemd."
            return 0
        fi
    fi
    if eval "$ssh_cmd 'flatpak info com.rustdesk.RustDesk &>/dev/null'" &>/dev/null; then
        if eval "$ssh_cmd 'flatpak kill com.rustdesk.RustDesk'" &>/dev/null; then
            pass "$host: RustDesk (Flatpak) process killed. It should auto-restart."
            return 0
        fi
    fi
    warn "$host: Could not find a managed RustDesk service to restart."
    return 1
}

sync_to_host() {
    local host="$1"
    local dest_path=""
    local is_flatpak=0
    local ssh_exec="sudo -E -u '$CALLER_USER' ssh -o ConnectTimeout='$SSH_TIMEOUT' '${CLIENT_USER}@${host}'"

    if eval "$ssh_exec 'test -d /home/${CLIENT_USER}/.var/app/com.rustdesk.RustDesk'"; then
        info "$host: Detected Flatpak installation."
        dest_path="/home/${CLIENT_USER}/.var/app/com.rustdesk.RustDesk/config/rustdesk/id_ed25519.pub"
        is_flatpak=1
    else
        info "$host: Detected standard installation."
        dest_path="/home/${CLIENT_USER}/.config/rustdesk/id_ed25519.pub"
        eval "$ssh_exec 'mkdir -p /home/${CLIENT_USER}/.config/rustdesk'"
    fi

    info "Syncing key to $host at $dest_path"
    declare -A RESULT
    if sudo -E -u "$CALLER_USER" scp -o ConnectTimeout="$SSH_TIMEOUT" "$TMP_PUB" "${CLIENT_USER}@${host}:${dest_path}" >/dev/null 2>&1; then
        local local_fp remote_fp
        local_fp=$(sha256sum "$TMP_PUB" | awk '{print $1}')
        remote_fp=$(eval "$ssh_exec 'sha256sum ${dest_path} 2>/dev/null | awk \'{print \$1}\'')"
        
        if [[ "$local_fp" == "$remote_fp" ]]; then
            pass "$host: Key verification successful."
            restart_rustdesk_client "$host" && RESULT["$host"]="Synced and Restarted" || RESULT["$host"]="Synced, Restart Failed"
        else
            warn "$host: KEY MISMATCH! Sync failed."
            RESULT["$host"]="Verification Failed"
        fi
    else
        RESULT["$host"]="Sync Failed (SCP)"
    fi
}

# --- MAIN ---
trap 'rm -f "$TMP_PUB"' EXIT

log "===== RustDesk Key Sync (STABLE) START ======"
auto_install_deps

mkdir -p "$RUSTDIR" &>/dev/null
[[ -f "$PUB" ]] || export_rustdesk_pub
cp "$PUB" "$TMP_PUB"
chown "$CALLER_USER:$CALLER_USER" "$TMP_PUB"

pass "Server key ready: $(sha256sum "$PUB" | awk '{print $1}')"

mapfile -t SELECTED_HOSTS < <(discover_hosts | select_hosts)

if (( ${#SELECTED_HOSTS[@]} == 0 )); then log "No hosts selected. Exiting."; exit 0; fi

info "Preparing to sync to: ${SELECTED_HOSTS[*]}"
declare -A RESULTS
for host in "${SELECTED_HOSTS[@]}"; do
    if ensure_ssh_access "$host"; then
        sync_to_host "$host"
    else
        RESULTS["$host"]="Unreachable (SSH)"
    fi
done

log "===== SYNC COMPLETE: FINAL REPORT ======"
for h in "${SELECTED_HOSTS[@]}"; do
    case "${RESULTS[$h]:-N/A}" in
        "Synced and Restarted") pass "$h: ${RESULTS[$h]}";;
        *) warn "$h: ${RESULTS[$h]:-Action Skipped}";;
    esac
done
log "=========================================="
