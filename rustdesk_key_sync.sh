#!/usr/bin/env bash
# ==============================================================================
# rustdesk_key_sync.sh (v4.0 Final)
# ------------------------------------------------------------------------------
# Author: Gemini
# Date: 2025-11-07
#
# Auto-syncs RustDesk server public key to LAN clients. Features include
# automatic dependency installation, robust SSH context handling under sudo,
# password-based SSH key bootstrapping, and an interactive host selection menu.
#
# ==============================================================================

set -euo pipefail
shopt -s extglob

# --- CONFIGURATION ---
# RustDesk server directory
RUSTDIR="/var/lib/rustdesk-server"
# Private and public key paths
PRIV="${RUSTDIR}/id_ed25519"
PUB="${RUSTDIR}/id_ed25519.pub"
# Temporary file for the public key
TMP_PUB="/tmp/rustdesk_sync_key.pub"

# Automatically determine the user who invoked sudo
CALLER_USER="${SUDO_USER:-$USER}"
# Get the home directory of the calling user
CALLER_HOME=$(getent passwd "$CALLER_USER" | cut -d: -f6)
# Path to the user's SSH directory
SSH_DIR="${CALLER_HOME}/.ssh"

# Username on the client machines to SSH into
CLIENT_USER="owner"
# Local network subnet to scan for hosts
LAN_SUBNET="192.168.1.0/24"
# Log file for script activity
LOG_FILE="/var/log/rustdesk_key_sync.log"
# Environment file to cache passwords (securely stored in user's home)
ENV_FILE="${CALLER_HOME}/.rustdesk_sync_env"

# --- LOGGING AND COLORS ---
# Ensure log file exists and has correct permissions
mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
touch "$LOG_FILE" && chmod 644 "$LOG_FILE"

# Color codes for terminal output
RED="\e[31m"; GREEN="\e[32m"; YELLOW="\e[33m"; CYAN="\e[36m"; RESET="\e[0m"

# Logging functions to provide timestamped and color-coded feedback
log()  { printf -- '[%s] %s\n' "$(date +'%F %T')" "$*" | tee -a "$LOG_FILE" >&2; }
pass() { printf -- "%b[%s] ✅ %s%b\n" "$GREEN" "$(date +'%F %T')" "$*" "$RESET" | tee -a "$LOG_FILE" >&2; }
warn() { printf -- "%b[%s] ⚠️ %s%b\n" "$YELLOW" "$(date +'%F %T')" "$*" "$RESET" | tee -a "$LOG_FILE" >&2; }
info() { printf -- "%b[%s] ℹ️ %s%b\n" "$CYAN" "$(date +'%F %T')" "$*" "$RESET" | tee -a "$LOG_FILE" >&2; }
fatal(){ printf -- "%b[%s] ❌ %s%b\n" "$RED" "$(date +'%F %T')" "$*" "$RESET" | tee -a "$LOG_FILE" >&2; exit 1; }

# --- CORE FUNCTIONS ---

# Checks if a command is available in the system's PATH.
require_cmd() {
    command -v "$1" >/dev/null 2>&1
}

# Automatically detects the Linux distribution and installs any missing dependencies.
auto_install_deps() {
    log "[INIT] Checking for required command dependencies..."
    local id_like pkgmgr install_cmd update_cmd query_cmd
    id_like=$(. /etc/os-release && echo "${ID_LIKE:-$ID}")

    case "$id_like" in
        debian|ubuntu)
            pkgmgr="apt-get"; update_cmd="$pkgmgr update"; install_cmd="$pkgmgr install -y"; query_cmd="dpkg-query -W -f='${Status}'"
            ;;
        fedora|rhel|centos|nobara)
            pkgmgr="dnf"; update_cmd=""; install_cmd="$pkgmgr install -y"; query_cmd="rpm -q"
            ;;
        arch|manjaro)
            pkgmgr="pacman"; update_cmd=""; install_cmd="$pkgmgr -Sy --noconfirm"; query_cmd="pacman -Q"
            ;;
        *)
            warn "Unsupported distro: $id_like. Please install dependencies (nmap, openssh, sshpass, avahi-utils) manually."
            return
            ;;
    esac

    local deps=("nmap" "ssh" "scp" "ssh-keygen" "sshpass" "avahi-browse")
    local to_install=()
    for cmd in "${deps[@]}"; do
        if ! require_cmd "$cmd"; then
            # A simple mapping from command to package name
            local pkg="$cmd"
            [[ "$cmd" == "avahi-browse" ]] && pkg="avahi-utils"
            [[ "$cmd" =~ (ssh|scp|ssh-keygen) ]] && pkg="openssh-clients"
            to_install+=("$pkg")
        fi
    done

    # Remove duplicates
    to_install=($(printf "%s\n" "${to_install[@]}" | sort -u))

    if (( ${#to_install[@]} > 0 )); then
        warn "Installing missing packages: ${to_install[*]}"
        [[ -n "$update_cmd" ]] && sudo $update_cmd
        sudo $install_cmd "${to_install[@]}"
    fi
    pass "Dependencies verified."
}

# Generates the RustDesk public key from the private key.
export_rustdesk_pub() {
  [[ -f "$PRIV" ]] || fatal "RustDesk private key not found at $PRIV"
  # Use ssh-keygen to derive the public key; quieter and more reliable
  ssh-keygen -y -f "$PRIV" > "$PUB" || fatal "Failed to export RustDesk public key."
  pass "RustDesk public key exported successfully."
}

# Discovers hosts on the local network that have the SSH port (22) open.
discover_hosts() {
    local local_ip
    local_ip=$(hostname -I | awk '{print $1}')
    info "[DISCOVERY] Scanning LAN ($LAN_SUBNET) for active SSH servers..."

    # Use nmap for primary discovery
    mapfile -t nmap_hosts < <(sudo nmap -p22 --open -oG - "$LAN_SUBNET" | awk '/Up$/{print $2}' | grep -v "$local_ip" | sort -u)

    # Use Avahi (mDNS) as a fallback discovery method
    mapfile -t avahi_hosts < <(avahi-browse -art | grep "IPv4" | awk -F';' '{print $8}' | grep -v "$local_ip" | sort -u || true)
    
    # Combine, sort, and unique the results
    local combined_hosts
    combined_hosts=($(printf "%s\n" "${nmap_hosts[@]}" "${avahi_hosts[@]}" | sort -u))
    
    printf '%s\n' "${combined_hosts[@]}"
}

# Retrieves a cached password or prompts the user for it if not found.
get_or_prompt_password() {
    local host="$1"
    # Sanitize host IP for use as a variable name
    local pass_var="SSH_PASS_${host//[.-]/_}"
    local password=""

    # Source the password from the secure environment file if it exists
    if [[ -f "$ENV_FILE" ]]; then
        # Check permissions before sourcing
        if [[ $(stat -c "%a" "$ENV_FILE") != "600" ]]; then
            warn "Permissions on $ENV_FILE are not 600. For security, please run 'chmod 600 $ENV_FILE'."
        fi
        source "$ENV_FILE"
        password="${!pass_var:-}"
    fi

    # If the password is still not found, prompt for it
    if [[ -z "$password" ]]; then
        read -rsp "Enter SSH password for ${CLIENT_USER}@${host}: " password; echo
        if [[ -z "$password" ]]; then
            warn "No password provided for $host."
            return 1
        fi
        # Cache the password for future runs
        mkdir -p "$(dirname "$ENV_FILE")"
        touch "$ENV_FILE" && chmod 600 "$ENV_FILE"
        echo "export ${pass_var}=\"${password}\"" >> "$ENV_FILE"
        pass "Password has been securely cached for this session."
    fi
    echo "$password"
}

# Uses sshpass to copy the user's SSH public key to a client machine.
bootstrap_ssh_key() {
    local host="$1"
    local password
    password=$(get_or_prompt_password "$host") || return 1
    info "Attempting to bootstrap SSH key for $host using password authentication..."

    local ssh_opts="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10"
    
    # Run the bootstrap commands as the original user ($CALLER_USER)
    # This ensures we use the correct SSH keys and home directory context.
    sudo -E -u "$CALLER_USER" sshpass -p "$password" ssh-copy-id -i "${SSH_DIR}/id_rsa.pub" ${ssh_opts} "${CLIENT_USER}@${host}"
    
    local rc=$?
    if (( rc == 0 )); then
        pass "SSH key successfully bootstrapped for $host."
    else
        warn "SSH key bootstrap failed for $host. Check password or SSH service on the client."
    fi
    return $rc
}

# Ensures SSH access to a host, attempting to bootstrap if key-based auth fails.
ensure_ssh_access() {
    local host="$1"
    info "Verifying SSH access to $host..."
    
    # Add host key to known_hosts to avoid prompts, running as the user.
    sudo -u "$CALLER_USER" ssh-keyscan -T 5 "$host" >> "${SSH_DIR}/known_hosts" 2>/dev/null || true

    # Define the SSH command to run in the user's context
    local ssh_cmd="sudo -E -u "$CALLER_USER" ssh -o BatchMode=yes -o ConnectTimeout=10"

    # Attempt key-based authentication
    if eval "$ssh_cmd ${CLIENT_USER}@${host} 'echo ACCESS_OK'" 2>/dev/null | grep -q ACCESS_OK; then
        pass "$host: SSH access verified (key-based)."
        return 0
    fi
    
    # If key-based auth fails, attempt password bootstrap
    warn "$host: Key-based auth failed. Attempting password bootstrap..."
    if ! [[ -f "${SSH_DIR}/id_rsa.pub" ]]; then
        warn "SSH public key not found for user $CALLER_USER at ${SSH_DIR}/id_rsa.pub. Cannot bootstrap."
        warn "Please generate one with: sudo -u $CALLER_USER ssh-keygen -t rsa"
        return 1
    fi

    if bootstrap_ssh_key "$host"; then
        # Re-verify access after bootstrap
        if eval "$ssh_cmd ${CLIENT_USER}@${host} 'echo ACCESS_OK'" 2>/dev/null | grep -q ACCESS_OK; then
            pass "$host: SSH access confirmed after bootstrap."
            return 0
        fi
    fi

    warn "$host: All SSH connection attempts failed."
    return 1
}

# Copies the RustDesk public key to the target host.
sync_to_host() {
    local host="$1"
    info "Syncing RustDesk key to $host..."
    # Define SSH and SCP commands to run in the user's context
    local ssh_exec="sudo -E -u "$CALLER_USER" ssh -o ConnectTimeout=10"
    local scp_exec="sudo -E -u "$CALLER_USER" scp -o ConnectTimeout=10"
    
    # Determine the correct destination path for Flatpak or standard installs
    local dest_path
    if $ssh_exec "${CLIENT_USER}@${host}" "test -d ~/.var/app/com.rustdesk.RustDesk"; then
        dest_path="~/.var/app/com.rustdesk.RustDesk/config/rustdesk/server.pub"
    else
        # Assume standard config path and create if it doesn't exist
        $ssh_exec "${CLIENT_USER}@${host}" "mkdir -p ~/.config/rustdesk"
        dest_path="~/.config/rustdesk/server.pub"
    fi

    # Copy the key
    if $scp_exec "$TMP_PUB" "${CLIENT_USER}@${host}:${dest_path}"; then
        pass "$host: RustDesk key synced successfully."
        return 0
    else
        warn "$host: Failed to copy RustDesk key."
        return 1
    fi
}

# --- MAIN EXECUTION ---
main() {
    # Ensure script is run with sudo
    if [[ $EUID -ne 0 ]]; then
       fatal "This script must be run with sudo."
    fi

    # Cleanup temporary file on exit
    trap 'rm -f "$TMP_PUB"' EXIT
    
    log "===== RustDesk Key Sync v4.0 START ====="
    
    auto_install_deps
    
    # Ensure RustDesk server keypair exists, creating if necessary
    mkdir -p "$RUSTDIR" && ( [[ -f "$PRIV" ]] || ssh-keygen -t ed25519 -N "" -f "$PRIV" )
    export_rustdesk_pub

    # Prepare temp file with correct user ownership for SCP
    cp "$PUB" "$TMP_PUB"
    chown "$CALLER_USER":"$(id -gn "$CALLER_USER")" "$TMP_PUB"
    pass "Server key ready to sync."

    mapfile -t HOSTS < <(discover_hosts)
    if (( ${#HOSTS[@]} == 0 )); then
        warn "No hosts discovered on the network. Check network connectivity or LAN_SUBNET setting."
        exit 0
    fi

    # Interactive host selection menu
    info "Discovered the following hosts on your network:"
    PS3=$'\nSelect a host to sync (or "All_Hosts"): '
    select host in "${HOSTS[@]}" "All_Hosts" "Quit"; do
        case $host in
            "Quit")
                info "User quit. No hosts were synced."
                exit 0
                ;;
            "All_Hosts")
                SELECTED_HOSTS=("${HOSTS[@]}")
                break
                ;;
            *) 
                if [[ -n "$host" ]]; then
                    SELECTED_HOSTS=($host)
                    break
                else
                    warn "Invalid selection. Please try again."
                fi
                ;;
        esac
    done

    info "Syncing to: ${SELECTED_HOSTS[*]}"
    
    declare -A results
    for host in "${SELECTED_HOSTS[@]}"; do
        if ensure_ssh_access "$host"; then
            sync_to_host "$host" && results[$host]="Synced" || results[$host]="Sync Failed"
        else
            results[$host]="Unreachable"
        fi
    done

    log "===== Sync COMPLETE ====="
    for host in "${!results[@]}"; do
        if [[ ${results[$host]} == "Synced" ]]; then
            pass "$host: ${results[$host]}"
        else
            warn "$host: ${results[$host]}"
        fi
    done
    log "=========================="
}

main "$@"
