#!/usr/bin/env bash
# ==============================================================================
# rustdesk_key_sync.sh (v5.0)
# ------------------------------------------------------------------------------
# Author: Gemini
# Date: 2025-11-08
#
# Auto-syncs RustDesk server public key to LAN clients. Features include
# automatic dependency installation, robust SSH context handling under sudo,
# password-based SSH key bootstrapping, and an interactive host selection menu.
#
# ==============================================================================

# --- Strict Mode & Options ---
set -euo pipefail
shopt -s extglob nullglob

# --- CONFIGURATION ---
# RustDesk server directory
readonly RUSTDIR="/var/lib/rustdesk-server"
# Private and public key paths
readonly PRIV="${RUSTDIR}/id_ed25519"
readonly PUB="${RUSTDIR}/id_ed25519.pub"
# Temporary file for the public key
readonly TMP_PUB="/tmp/rustdesk_sync_key.pub"

# --- LOGGING & COLORS ---
readonly NC='\033[0m'
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[0;33m'
readonly BLUE='\033[0;34m'

log() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" >&2
}

fail() {
    echo -e "${RED}[FAIL]${NC} $1" >&2
    exit 1
}

pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

# --- FUNCTION DEFINITIONS ---

# Graceful script exit
cleanup() {
    log "Cleaning up..."
    if [[ -f "${TMP_PUB}" ]]; then
        rm -f "${TMP_PUB}"
        log "Removed temporary key file."
    fi
}

# Check for required commands
check_dependencies() {
    local missing_deps=()
    for cmd in ssh scp sshpass nmap; do
        if ! command -v "$cmd" &>/dev/null; then
            missing_deps+=("$cmd")
        fi
    done

    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        warn "Missing dependencies: ${missing_deps[*]}."
        read -p "Attempt to install them? (y/N): " choice
        if [[ $choice =~ ^[Yy]$ ]]; then
            install_dependencies "${missing_deps[@]}"
        else
            fail "Aborted. Please install dependencies manually."
        fi
    fi
}

# Install missing dependencies
install_dependencies() {
    local -a deps_to_install=("$@")
    if command -v apt-get &>/dev/null; then
        log "Attempting installation via apt-get..."
        sudo apt-get update && sudo apt-get install -y "${deps_to_install[@]}"
    elif command -v dnf &>/dev/null; then
        log "Attempting installation via dnf..."
        sudo dnf install -y "${deps_to_install[@]}"
    elif command -v yum &>/dev/null; then
        log "Attempting installation via yum..."
        sudo yum install -y "${deps_to_install[@]}"
    else
        fail "Unsupported package manager. Please install dependencies manually: ${deps_to_install[*]}"
    fi
    log "Dependencies installed."
}

# Prepare RustDesk public key
prepare_key() {
    log "Preparing RustDesk public key..."
    if [[ ! -f "${PUB}" ]]; then
        fail "RustDesk public key not found at ${PUB}"
    fi

    # Handle sudo context for key access
    if [[ $EUID -ne 0 ]]; then
        log "Running with non-root privileges. Using sudo to access key."
        sudo cp "${PUB}" "${TMP_PUB}"
        sudo chown "$(whoami)" "${TMP_PUB}"
    else
        cp "${PUB}" "${TMP_PUB}"
    fi

    if [[ ! -s "${TMP_PUB}" ]]; then
        fail "Failed to create or access temporary key file."
    fi
    log "Public key ready for sync."
}

# Discover hosts on the local network
discover_hosts() {
    log "Discovering hosts on the local network (port 22)..."
    local lan_range
    lan_range=$(ip -o -f inet addr show | awk '/scope global/ {print $4}')
    
    if [[ -z "$lan_range" ]]; then
        fail "Could not determine local network range."
    fi
    
    nmap -p 22 --open "${lan_range}" -oG - | awk '/Up$/{print $2}'
}

# Display interactive host selection menu
select_hosts() {
    local -a hosts=("$@")
    if [[ ${#hosts[@]} -eq 0 ]]; then
        fail "No hosts found on the network. Check network connectivity and firewall settings."
    fi

    PS3="Select hosts to sync (e.g., 1 2 4, or 'all'): "
    select host in "${hosts[@]}" "all"; do
        if [[ "$host" == "all" ]]; then
            REPLY="${hosts[*]}"
            break
        fi
        if [[ -n "$host" ]]; then
            break
        fi
    done < /dev/tty
    
    # shellcheck disable=SC2206
    local selected_hosts=($REPLY)
    echo "${selected_hosts[@]}"
}

# Sync key to a single host
sync_to_host() {
    local host="$1"
    local user="$2"
    local pass="$3"
    
    local remote_config="/home/${user}/.config/RustDesk/RustDesk2.toml"
    local temp_config="/tmp/RustDesk2.toml.$$"

    log "Syncing to ${host}..."

    # Check for existing key and prompt for overwrite
    if sshpass -p "$pass" ssh -o StrictHostKeyChecking=no "${user}@${host}" "grep -q 'key = ' ${remote_config}"; then
        warn "Existing key found on ${host}."
        read -p "Overwrite? (y/N): " overwrite_choice
        if [[ ! $overwrite_choice =~ ^[Yy]$ ]]; then
            echo "Skipped"
            return
        fi
    fi

    # Fetch, update, and upload the config file
    if sshpass -p "$pass" scp -o StrictHostKeyChecking=no "${user}@${host}:${remote_config}" "${temp_config}"; then
        local pub_key
        pub_key=$(<"${TMP_PUB}")
        # Use awk for safer, more robust TOML updates
        awk -v key="$pub_key" '
            BEGIN { found=0 }
            /^key = / { print "key = \"" key "\""; found=1; next }
            { print }
            END { if (found==0) print "key = \"" key "\"" }
        ' "${temp_config}" > "${temp_config}.new" && mv "${temp_config}.new" "${temp_config}"
        
        if sshpass -p "$pass" scp -o StrictHostKeyChecking=no "${temp_config}" "${user}@${host}:${remote_config}"; then
            echo "Synced"
        else
            echo "Failed: SCP upload error"
        fi
    else
        echo "Failed: SCP download error"
    fi
    
    rm -f "${temp_config}"
}

# --- MAIN EXECUTION ---
main() {
    trap cleanup EXIT
    
    log "===== RustDesk Key Sync Initialized ====="
    
    check_dependencies
    prepare_key

    local hosts
    hosts=$(discover_hosts)
    
    local selected_hosts
    # shellcheck disable=SC2207
    selected_hosts=($(select_hosts "${hosts[@]}"))

    if [[ ${#selected_hosts[@]} -eq 0 ]]; then
        log "No hosts selected. Exiting."
        exit 0
    fi
    
    read -p "Enter SSH username for clients: " user
    read -s -p "Enter SSH password for clients: " pass
    echo

    declare -A results
    for host in "${selected_hosts[@]}"; do
        results["$host"]=$(sync_to_host "$host" "$user" "$pass")
    done
    
    # --- Report Results ---
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
