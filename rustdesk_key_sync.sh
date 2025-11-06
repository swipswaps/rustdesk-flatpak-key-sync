#!/usr/bin/env bash
# ==============================================================================
# rustdesk_key_sync.sh (STABLE)
# ------------------------------------------------------------------------------
# Syncs the RustDesk public key to a single client.
# This is a basic script, for advanced features like host discovery and 
# dependency checks, see rustdesk_flatpak_key_sync.sh
# ==============================================================================

set -euo pipefail

# --- CONFIGURATION ---
# The user on the client machine that will receive the key.
CLIENT_USER="owner"

# The IP address of the client machine.
# If you leave this empty, the script will prompt you to enter it.
CLIENT_IP=""

# --- SCRIPT ---

# --- Colors for logging ---
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
CYAN="\e[36m"
RESET="\e[0m"

# --- Logging functions ---
log()   { printf -- "[%s] %s\n" "$(date '+%F %T')" "$*"; }
pass()  { printf -- "%b[%s] ✅ %s%b\n" "$GREEN" "$(date '+%F %T')" "$*" "$RESET"; }
warn()  { printf -- "%b[%s] ⚠️ %s%b\n" "$YELLOW" "$(date '+%F %T')" "$*" "$RESET"; }
info()  { printf -- "%b[%s] ℹ️ %s%b\n" "$CYAN" "$(date '+%F %T')" "$*" "$RESET"; }
fatal() { printf -- "%b[%s] ❌ %s%b\n" "$RED" "$(date '+%F %T')" "$*" "$RESET"; exit 1; }

# --- Ensure we are running as root ---
if [[ "$EUID" -ne 0 ]]; then
  fatal "This script must be run as root. Please use 'sudo'."
fi

# --- Check for public key ---
if [[ ! -f /var/lib/rustdesk-server/id_ed25519.pub ]]; then
  fatal "RustDesk public key not found at /var/lib/rustdesk-server/id_ed25519.pub"
fi

# --- Get client IP if not set ---
if [[ -z "$CLIENT_IP" ]]; then
  read -rp "Enter the client IP address: " CLIENT_IP
  if [[ -z "$CLIENT_IP" ]]; then
    fatal "Client IP address cannot be empty."
  fi
fi

info "Attempting to sync key to ${CLIENT_USER}@${CLIENT_IP}..."

# --- Create the remote directory and sync the key ---
if ssh "${CLIENT_USER}@${CLIENT_IP}" 'mkdir -p ~/.config/rustdesk'; then
  pass "Remote directory ~/.config/rustdesk ensured."
else
  warn "Could not create remote directory. It may already exist."
fi

if scp /var/lib/rustdesk-server/id_ed25519.pub "${CLIENT_USER}@${CLIENT_IP}:~/.config/rustdesk/id_ed25519.pub"; then
  pass "Public key successfully copied to ${CLIENT_IP}."
  info "Please restart the RustDesk client on the remote machine for the change to take effect."
else
  fatal "Failed to copy the public key. Check SSH connectivity and permissions."
fi

log "Sync process finished."
