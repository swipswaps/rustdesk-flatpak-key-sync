#!/usr/bin/env bash
# ==============================================================================
# rustdesk_flatpak_key_sync.sh
# ------------------------------------------------------------------------------
# PURPOSE:
#   Automatically manage and deploy RustDesk server public keys to Flatpak clients
#   over SSH, including:
#     - Keypair validation/generation/backup
#     - Flatpak installation/update (interactive)
#     - LAN discovery via nmap
#     - Secure public key propagation
#     - Verification and logging
#     - Automatic dependency resolution per distro
#
# MODE: INTERACTIVE (prompts for install, confirmation, etc.)
# AUTHOR: Jose Melendez
# DATE: 2025-11-02
# ==============================================================================
set -euo pipefail

#### USER CONFIGURATION #########################################################
RUSTDIR="/var/lib/rustdesk-server"
PRIV="$RUSTDIR/id_ed25519"
PUB="$RUSTDIR/id_ed25519.pub"
FLATPAK_KEY_PATH=".var/app/com.rustdesk.RustDesk/config/rustdesk/server.pub"
CLIENT_USER="owner"
LAN_SUBNET="192.168.1.0/24"
LOG_FILE="/var/log/rustdesk_flatpak_key_sync.log"
LOCAL_SSH_KEY="${HOME}/.ssh/id_ed25519.pub"
[[ ! -f "$LOCAL_SSH_KEY" ]] && LOCAL_SSH_KEY="${HOME}/.ssh/id_rsa.pub"
SSH_TIMEOUT=6
VERIFY_RETRIES=2
VERIFY_RETRY_DELAY=2
#################################################################################

# ------------------------------------------------------------------------------
# LOGGING UTILITIES
# ------------------------------------------------------------------------------
log() { echo "[$(date '+%F %T')] $*" | tee -a "$LOG_FILE"; }
fatal() { echo "[$(date '+%F %T')] FATAL: $*" | tee -a "$LOG_FILE" >&2; exit 1; }

# ------------------------------------------------------------------------------
# DEPENDENCY DETECTOR + AUTO-INSTALLER
# ------------------------------------------------------------------------------
install_if_missing() {
  local cmd="$1"
  local pkgname="$2"
  local installer="$3"

  if ! command -v "$cmd" >/dev/null 2>&1; then
    log "Missing dependency: $cmd (package: $pkgname)"
    if prompt_yes_no "Install $pkgname now?"; then
      log "Installing $pkgname using $installer..."
      if sudo $installer install -y "$pkgname" &>>"$LOG_FILE"; then
        log "Installed $pkgname successfully."
      else
        fatal "Failed to install $pkgname. Please check network or repo availability."
      fi
    else
      fatal "User declined installation of $pkgname — cannot continue."
    fi
  fi
}

auto_install_deps() {
  # Detect distro via /etc/os-release
  local id_like installer
  id_like="$(. /etc/os-release && echo "${ID_LIKE:-$ID}")"
  if [[ "$id_like" =~ (debian|ubuntu) ]]; then
    installer="apt-get"
  elif [[ "$id_like" =~ (fedora|rhel|centos|nobara) ]]; then
    installer="dnf"
  elif [[ "$id_like" =~ (arch|manjaro) ]]; then
    installer="pacman"
  else
    fatal "Unsupported distro: $id_like. Add manual package map if needed."
  fi

  # Refresh repositories (safe)
  log "Refreshing repositories..."
  case "$installer" in
    apt-get) sudo apt-get update -y &>>"$LOG_FILE" ;;
    dnf) sudo dnf makecache &>>"$LOG_FILE" ;;
    pacman) sudo pacman -Sy --noconfirm &>>"$LOG_FILE" ;;
  esac

  # Define required packages per command
  install_if_missing "nmap" "nmap" "$installer"
  install_if_missing "ssh" "openssh-clients" "$installer"
  install_if_missing "scp" "openssh-clients" "$installer"
  install_if_missing "ssh-copy-id" "openssh-clients" "$installer"
  install_if_missing "sha256sum" "coreutils" "$installer"
  install_if_missing "ssh-keygen" "openssh" "$installer"
  install_if_missing "openssl" "openssl" "$installer"
  install_if_missing "flatpak" "flatpak" "$installer"

  log "All dependencies verified or installed successfully."
}

# ------------------------------------------------------------------------------
# GENERIC HELPERS
# ------------------------------------------------------------------------------
prompt_yes_no() {
  local prompt="$1"; local ans
  read -rp "$prompt [y/N]: " ans
  [[ "$ans" =~ ^[Yy]$ ]]
}

key_fingerprint() { sha256sum "$1" | awk '{print $1}'; }

# ------------------------------------------------------------------------------
# SERVER KEYPAIR HANDLING
# ------------------------------------------------------------------------------
ensure_rustdesk_pub_format() {
  require_cmd openssl
  [[ -f "$PRIV" ]] || fatal "Private key $PRIV missing."

  if ! openssl pkey -in "$PRIV" -pubout -outform DER 2>/dev/null | base64 -w0 >"$PUB.tmp"; then
    fatal "Unable to export Ed25519 public key from $PRIV."
  fi
  mv "$PUB.tmp" "$PUB"
  log "Created RustDesk-compatible public key ($PUB)."
}

ensure_server_keypair() {
  log "=== Checking server keypair ==="
  mkdir -p "$RUSTDIR"
  if [[ -f "$PRIV" || -f "$PUB" ]]; then
    local ts; ts=$(date +%Y%m%d_%H%M%S)
    mkdir -p "$RUSTDIR/backup_$ts"
    mv "$RUSTDIR"/id_ed25519* "$RUSTDIR/backup_$ts/" 2>/dev/null || true
    log "Existing keys backed up to $RUSTDIR/backup_$ts/"
  fi
  require_cmd ssh-keygen
  ssh-keygen -t ed25519 -N "" -f "$PRIV" <<<y >/dev/null 2>&1
  ensure_rustdesk_pub_format
  chmod 600 "$PRIV"; chmod 644 "$PUB"; chown root:root "$PRIV" "$PUB" || true
  log "Server fingerprint: $(key_fingerprint "$PUB")"
}

require_cmd() { command -v "$1" >/dev/null 2>&1 || fatal "Missing command: $1"; }

# ------------------------------------------------------------------------------
# NETWORK DISCOVERY + REMOTE OPS
# ------------------------------------------------------------------------------
discover_clients() {
  require_cmd nmap
  log "Scanning subnet $LAN_SUBNET for active hosts..."
  mapfile -t _hosts < <(nmap -sn "$LAN_SUBNET" 2>/dev/null | awk '/Nmap scan report for/{print $5}')
  echo "${_hosts[@]-}"
}

prompt_additional_hosts() {
  read -rp "Enter extra hosts (space/comma-separated), or ENTER to skip: " extra
  echo "${extra//,/ }"
}

deploy_ssh_key_if_needed() {
  local host="$1"
  if ssh -o ConnectTimeout="$SSH_TIMEOUT" -o BatchMode=yes "$CLIENT_USER@$host" "echo ok" &>/dev/null; then
    log "Passwordless SSH already works for $host."
    return 0
  fi
  [[ -f "$LOCAL_SSH_KEY" ]] || { log "No SSH pubkey found."; return 1; }
  log "Deploying SSH pubkey to $host..."
  ssh-copy-id -i "$LOCAL_SSH_KEY" "$CLIENT_USER@$host" &>>"$LOG_FILE" || return 1
}

remote_exec() { ssh -o ConnectTimeout="$SSH_TIMEOUT" "$CLIENT_USER@$1" "$2" &>>"$LOG_FILE"; }
remote_copy_pub() { scp -o ConnectTimeout="$SSH_TIMEOUT" "$PUB" "$CLIENT_USER@$1:/home/$CLIENT_USER/$FLATPAK_KEY_PATH" &>>"$LOG_FILE"; }

verify_remote_pub_matches() {
  local host="$1" tmp; tmp=$(mktemp)
  ssh -o ConnectTimeout="$SSH_TIMEOUT" "$CLIENT_USER@$host" "cat /home/$CLIENT_USER/$FLATPAK_KEY_PATH" >"$tmp" 2>/dev/null || return 1
  [[ "$(key_fingerprint "$tmp")" == "$(key_fingerprint "$PUB")" ]]
}

# ------------------------------------------------------------------------------
# MAIN
# ------------------------------------------------------------------------------
log "===== RustDesk Flatpak Key Sync START ====="
auto_install_deps
ensure_server_keypair

mapfile -t discovered_hosts < <(discover_clients)
log "Discovered hosts: ${discovered_hosts[*]:-none}"

extra_hosts=$(prompt_additional_hosts)
[[ -n "$extra_hosts" ]] && read -ra extra_list <<<"$extra_hosts" && discovered_hosts+=("${extra_list[@]}")

declare -A seen; final_hosts=()
for h in "${discovered_hosts[@]}"; do [[ -z "${seen[$h]:-}" ]] && seen[$h]=1 && final_hosts+=("$h"); done
log "Processing ${#final_hosts[@]} hosts: ${final_hosts[*]:-none}"

for host in "${final_hosts[@]}"; do
  log "---- Host: $host ----"
  ping -c1 -W2 "$host" &>/dev/null || { log "Host unreachable, skipping."; continue; }
  deploy_ssh_key_if_needed "$host" || { log "SSH setup failed for $host."; continue; }

  log "Ensuring RustDesk Flatpak present..."
  if ! remote_exec "$host" "flatpak list | grep -q com.rustdesk.RustDesk"; then
    if prompt_yes_no "Install RustDesk Flatpak on $host?"; then
      remote_exec "$host" "flatpak install -y flathub com.rustdesk.RustDesk" || { log "Install failed."; continue; }
    else
      log "User skipped install for $host."; continue
    fi
  fi

  log "Copying server.pub..."
  remote_exec "$host" "mkdir -p /home/$CLIENT_USER/$(dirname "$FLATPAK_KEY_PATH")"
  remote_copy_pub "$host" || { log "Copy failed for $host."; continue; }
  remote_exec "$host" "chmod 644 /home/$CLIENT_USER/$FLATPAK_KEY_PATH"

  if verify_remote_pub_matches "$host"; then
    log "Verification OK for $host."
  else
    log "Verification failed for $host."
  fi

  log "Restarting Flatpak RustDesk..."
  remote_exec "$host" "flatpak kill com.rustdesk.RustDesk || true; flatpak run -d com.rustdesk.RustDesk" || log "Restart failed on $host."
done

log "===== COMPLETE ====="
