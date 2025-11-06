#!/usr/bin/env bash
# ==============================================================================
# rustdesk_key_sync.sh (v4 - Nmap Hotfix)
# ------------------------------------------------------------------------------
# Merges the robust SSH bootstrapping and discovery from the stable-v2 script
# with the multi-target (TOML, Flatpak, .pub) sync logic of the unified script.
# This version is feature-complete and resolves previous bugs.
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
LOG_FILE="/var/log/rustdesk_key_sync.log"
ENV_FILE="${CALLER_HOME}/.rustdesk_sync_env"
SSH_TIMEOUT=8
AVAHI_FALLBACK=1

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
require_cmd() { command -v "$1" >/dev/null 2>&1 || return 1; }

auto_install_deps() {
    log "[INIT] Checking dependencies..."
    local id_like pkgmgr missing_deps=()
    for dep in nmap ssh scp ssh-keygen openssl flatpak ssh-copy-id ssh-keyscan sha256sum sshpass avahi-browse; do
        require_cmd "$dep" || missing_deps+=("$dep")
    done

    if (( ${#missing_deps[@]} > 0 )); then
        warn "Missing dependencies: ${missing_deps[*]}"
        id_like="$(. /etc/os-release && echo "${ID_LIKE:-$ID}")"
        pkgmgr=""
        if [[ "$id_like" =~ (debian|ubuntu) ]]; then pkgmgr="apt-get"
        elif [[ "$id_like" =~ (fedora|rhel|centos|nobara) ]]; then pkgmgr="dnf"
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

# --- HOST DISCOVERY & SELECTION ---
discover_hosts() {
    info "[DISCOVERY] Scanning LAN subnet(s) $LAN_SUBNET for hosts with port 22 open..."
    local local_ips nmap_out
    local_ips=$(hostname -I)
    nmap_out=$(mktemp)
    # Correct Nmap command: -p22 filters for port 22, --open shows only open ports.
    # The contradictory -sn (no port scan) flag has been removed.
    sudo nmap -p22 --open "$LAN_SUBNET" -oG "$nmap_out"
    # Correct awk command to parse the output of a port scan, not a ping scan.
    mapfile -t nmap_hosts < <(awk '/\/open\// {print $2}' "$nmap_out" | grep -vF "$local_ips" | sort -u)
    
    if (( AVAHI_FALLBACK )); then
        info "[DISCOVERY] Using Avahi (mDNS) to supplement discovery..."
        mapfile -t mdns_hosts < <(avahi-browse -art | awk -F';' '/IPv4/ {print $8}' | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u || true)
    fi
    
    local combined_hosts=($(printf "%s\n" "${nmap_hosts[@]}" "${mdns_hosts[@]:-}" | sort -u))
    if (( ${#combined_hosts[@]} == 0 )); then
        warn "No remote hosts discovered. Check network and ensure clients are on."
    fi
    printf '%s\n' "${combined_hosts[@]}"
    rm "$nmap_out"
}

select_hosts() {
    mapfile -t hosts <&0
    if (( ${#hosts[@]} == 0 )); then echo ""; return; fi

    info "Discovered hosts:"
    for i in "${!hosts[@]}"; do
        printf '[\e[1;33m%d\e[0m] %s\n' "$((i+1))" "${hosts[$i]}" >&2
    done
    
    read -rp $'\nSelect hosts to sync (e.g., 1,3,5 or \'a\' for all): ' selection
    
    local selected_hosts=()
    if [[ "$selection" =~ ^[Aa](ll)?$ ]]; then
        selected_hosts=("${hosts[@]}")
    else
        IFS=',' read -ra indices <<< "$selection"
        for i in "${indices[@]}"; do
            i=$(echo "$i" | tr -d '[:space:]') # Trim whitespace
            if [[ "$i" =~ ^[0-9]+$ ]] && (( i > 0 && i <= ${#hosts[@]} )); then
                selected_hosts+=("${hosts[$((i-1))]}")
            fi
        done
    fi
    printf '%s\n' "${selected_hosts[@]}"
}


# --- SSH & SYNC LOGIC ---
get_or_prompt_password() {
    local host="$1" pass_var="SSH_PASS_${host//./_}"
    # Source the env file to get stored passwords
    [[ -f "$ENV_FILE" ]] && source "$ENV_FILE" >/dev/null 2>&1 || true
    local password="${!pass_var:-}"

    if [[ -z "$password" ]]; then
        read -rsp "Enter SSH password for ${CLIENT_USER}@${host}: " password; echo
        if [[ -z "$password" ]]; then warn "Empty password provided for $host"; return 1; fi
        
        # Save password for future runs
        mkdir -p "$(dirname "$ENV_FILE")"; chmod 700 "$(dirname "$ENV_FILE")";
        touch "$ENV_FILE"; chmod 600 "$ENV_FILE"
        echo "${pass_var}=\"${password}\"" >> "$ENV_FILE"
    fi
    echo "$password"
}

bootstrap_ssh_key() {
    local host="$1" password
    password="$(get_or_prompt_password "$host")" || return 1
    info "$host: Bootstrapping SSH key via password..."
    
    local ssh_opts="-o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no"
    
    # Use sshpass to provide the password for ssh-copy-id
    if sshpass -p "$password" ssh-copy-id -o ConnectTimeout="$SSH_TIMEOUT" $ssh_opts "${CLIENT_USER}@${host}"; then
        pass "$host: SSH key bootstrapped successfully."
        return 0
    else
        warn "$host: ssh-copy-id failed. This can happen on some systems. Trying manual bootstrap..."
        # Fallback to manual key copy
        local pub_key_string
        pub_key_string=$(sudo -u "$CALLER_USER" cat "${SSH_DIR}/id_ed25519.pub")
        if sshpass -p "$password" ssh $ssh_opts "${CLIENT_USER}@${host}" "mkdir -p ~/.ssh && echo \"$pub_key_string\" >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"; then
            pass "$host: Manual bootstrap successful."
            return 0
        fi
    fi
    warn "$host: All SSH key bootstrap methods failed."
    return 1
}

ensure_ssh_access() {
  local host="$1"
  sudo -E -u "$CALLER_USER" ssh-keyscan -T "$SSH_TIMEOUT" "$host" >> "${SSH_DIR}/known_hosts" 2>/dev/null || true

  if sudo -E -u "$CALLER_USER" ssh -o ConnectTimeout="$SSH_TIMEOUT" -o BatchMode=yes "${CLIENT_USER}@${host}" 'echo ok' &>/dev/null; then
    pass "$host: SSH key access verified."
    return 0
  fi
  
  warn "$host: Key auth failed. Attempting password bootstrap..."
  if bootstrap_ssh_key "$host"; then
      # Re-test connection after bootstrap
      if sudo -E -u "$CALLER_USER" ssh -o ConnectTimeout="$SSH_TIMEOUT" -o BatchMode=yes "${CLIENT_USER}@${host}" 'echo ok' &>/dev/null; then
          pass "$host: SSH connection now active."
          return 0
      fi
  fi

  warn "$host: Cannot establish SSH access."
  return 1
}

restart_rustdesk_client() {
    local host="$1" 
    info "$host: Attempting to restart RustDesk client..."
    local ssh_cmd="sudo -E -u '$CALLER_USER' ssh -o ConnectTimeout='$SSH_TIMEOUT' '${CLIENT_USER}@${host}'"

    if eval "$ssh_cmd 'systemctl --user is-active --quiet rustdesk.service'" &>/dev/null; then
        if eval "$ssh_cmd 'systemctl --user restart rustdesk.service'"; then pass "$host: RustDesk service restarted."; return 0; fi
    fi
    if eval "$ssh_cmd 'flatpak info com.rustdesk.RustDesk &>/dev/null'" &>/dev/null; then
        if eval "$ssh_cmd 'flatpak kill com.rustdesk.RustDesk'" &>/dev/null; then pass "$host: RustDesk (Flatpak) killed."; return 0; fi
    fi
    warn "$host: Could not find a managed RustDesk service to restart."
    return 1
}

sync_to_host() {
    local host="$1" key_str
    key_str=$(<"$TMP_PUB")
    local ssh_exec="sudo -E -u '$CALLER_USER' ssh -o ConnectTimeout='$SSH_TIMEOUT' '${CLIENT_USER}@${host}'"
    declare -gA FINAL_RESULTS # Use global associative array

    local sync_mode="" # Determine sync mode
    if eval "$ssh_exec 'test -d ~/.var/app/com.rustdesk.RustDesk/config/rustdesk'"; then sync_mode="flatpak_pub"
    elif eval "$ssh_exec 'test -f ~/.config/rustdesk/RustDesk2.toml'"; then sync_mode="toml"
    elif eval "$ssh_exec 'test -f ~/.config/rustdesk/id_ed25519.pub'"; then sync_mode="standard_pub"
    else sync_mode="standard_pub"; fi # Default to standard

    info "$host: Syncing key using mode: $sync_mode"

    case "$sync_mode" in
        flatpak_pub|standard_pub)
            local dest_path
            if [[ "$sync_mode" == "flatpak_pub" ]]; then dest_path="~/.var/app/com.rustdesk.RustDesk/config/rustdesk/id_ed25519.pub";
            else dest_path="~/.config/rustdesk/id_ed25519.pub"; eval "$ssh_exec 'mkdir -p ~/.config/rustdesk'"; fi

            if sudo -E -u "$CALLER_USER" scp -o ConnectTimeout="$SSH_TIMEOUT" "$TMP_PUB" "${CLIENT_USER}@${host}:${dest_path}" >/dev/null 2>&1; then
                pass "$host: Key file synced."
                restart_rustdesk_client "$host" && FINAL_RESULTS["$host"]="Synced and Restarted" || FINAL_RESULTS["$host"]="Synced, Restart Failed"
            else FINAL_RESULTS["$host"]="Sync Failed (SCP)" ; fi ;; 
        toml)
            local remote_cfg="~/.config/rustdesk/RustDesk2.toml" temp_cfg="/tmp/RustDesk2.toml.$$.$host"
            if sudo -E -u "$CALLER_USER" scp -o ConnectTimeout="$SSH_TIMEOUT" "${CLIENT_USER}@${host}:${remote_cfg}" "$temp_cfg" >/dev/null 2>&1; then
                sed -i "/^key =/d" "$temp_cfg" # Remove old key line
                echo "key = '${key_str}'" >> "$temp_cfg" # Add new key line

                if sudo -E -u "$CALLER_USER" scp -o ConnectTimeout="$SSH_TIMEOUT" "$temp_cfg" "${CLIENT_USER}@${host}:${remote_cfg}" >/dev/null 2>&1; then
                    pass "$host: TOML update successful."
                    restart_rustdesk_client "$host" && FINAL_RESULTS["$host"]="Synced and Restarted" || FINAL_RESULTS["$host"]="Synced, Restart Failed"
                else FINAL_RESULTS["$host"]="Sync Failed (TOML Upload)"; fi
                rm "$temp_cfg"
            else FINAL_RESULTS["$host"]="Sync Failed (TOML Download)"; fi ;; 
    esac
}

# --- MAIN ---
trap 'rm -f "$TMP_PUB" /tmp/RustDesk2.toml*' EXIT

log "===== RustDesk Key Sync (v4 - Nmap Hotfix) START ======"
[[ "$EUID" -ne 0 ]] && fatal "This script must be run with sudo."

auto_install_deps

mkdir -p "$RUSTDIR" "$SSH_DIR"
chown "$CALLER_USER:$CALLER_USER" "$SSH_DIR"

# Generate server keypair if it doesn't exist
[[ -f "$PRIV" ]] || sudo -u "$CALLER_USER" ssh-keygen -t ed25519 -f "$PRIV" -N ""

# Generate caller's SSH key if it doesn't exist, for ssh-copy-id
[[ -f "${SSH_DIR}/id_ed25519" ]] || sudo -u "$CALLER_USER" ssh-keygen -t ed25519 -f "${SSH_DIR}/id_ed25519" -N ""

# Export the public key
ssh-keygen -y -f "$PRIV" > "$PUB"
cp "$PUB" "$TMP_PUB"
chown "$CALLER_USER:$CALLER_USER" "$TMP_PUB"
pass "Server key ready: $(cut -d' ' -f2 "$PUB")"

mapfile -t SELECTED_HOSTS < <(discover_hosts | select_hosts)

if (( ${#SELECTED_HOSTS[@]} == 0 )); then log "No hosts selected. Exiting."; exit 0; fi

info "Preparing to sync to: ${SELECTED_HOSTS[*]}"
declare -gA FINAL_RESULTS
for host in "${SELECTED_HOSTS[@]}"; do
    if ensure_ssh_access "$host"; then
        sync_to_host "$host"
    else
        FINAL_RESULTS["$host"]="Unreachable (SSH)"
    fi
done

log "===== SYNC COMPLETE: FINAL REPORT ======"
for h in "${SELECTED_HOSTS[@]}"; do # Keep order
    status="${FINAL_RESULTS[$h]:-Action Skipped}"
    case "$status" in
        "Synced and Restarted") pass "$h: $status";;
        *) warn "$h: $status";;
    esac
done
log "=========================================="
