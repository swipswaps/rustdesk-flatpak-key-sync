#!/usr/bin/env bash
# ==============================================================================
# rustdesk_flatpak_key_sync.sh
# ------------------------------------------------------------------------------
# PURPOSE:
#   Automate RustDesk Flatpak client/server key management across a LAN.
#   This script:
#     - Validates or generates the RustDesk server Ed25519 keypair
#     - Exports a RustDesk-compatible server.pub (base64-encoded DER)
#     - Installs missing dependencies automatically
#     - Discovers clients via nmap or manual input
#     - Deploys passwordless SSH where needed
#     - Syncs server.pub to Flatpak RustDesk clients
#     - Verifies integrity (prevents key mismatch)
#     - Supports cleanup/uninstall (--cleanup)
#
# DESIGN:
#   - Fully self-healing and idempotent
#   - All critical steps are logged with timestamps to $LOG_FILE
#   - Abstracts away complexity: user simply runs the script
#
# AUTHOR: Jose Melendez
# DATE: 2025-11-03
# ==============================================================================
set -euo pipefail

# ------------------------------ Configuration -----------------------------------
RUSTDIR="/var/lib/rustdesk-server"
PRIV="${RUSTDIR}/id_ed25519"
PUB="${RUSTDIR}/id_ed25519.pub"
FLATPAK_KEY_PATH=".var/app/com.rustdesk.RustDesk/config/rustdesk/server.pub"
CLIENT_USER="owner"
LAN_SUBNET="192.168.1.0/24"
LOG_FILE="/var/log/rustdesk_flatpak_key_sync.log"
LOCAL_SSH_KEY="${HOME}/.ssh/id_ed25519.pub"
[[ ! -f "$LOCAL_SSH_KEY" ]] && LOCAL_SSH_KEY="${HOME}/.ssh/id_rsa.pub"
SSH_TIMEOUT=6
VERIFY_RETRIES=2
VERIFY_RETRY_DELAY=2
# ------------------------------------------------------------------------------

# --------------------------- Exit Codes -----------------------------------------
EX_OK=0
EX_SERVER_KEY=1
EX_SSH_CONN=2
EX_SCP=3
EX_PERMISSION=4
EX_DEPEND=5
# ------------------------------------------------------------------------------

# ------------------------------ Logging -----------------------------------------
log() { printf '[%s] %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG_FILE"; }
fatal() { log "FATAL: $2"; exit "$1"; }
# ------------------------------------------------------------------------------

# ------------------------------ Utilities ---------------------------------------
key_fingerprint() { sha256sum "$1" | awk '{print $1}'; }
safe_mktemp() { mktemp "${TMPDIR:-/tmp}/rustdesk_key_sync.XXXXXX"; }
require_cmd() { command -v "$1" >/dev/null 2>&1; }
prompt_yes_no() { local p="$1" a; read -rp "$p [y/N]: " a; [[ "$a" =~ ^[Yy]$ ]]; }
# ------------------------------------------------------------------------------

# ----------------------- Dependency Installation --------------------------------
auto_install_deps() {
  log "Checking dependencies..."
  local id_like pkgmgr
  id_like="$(. /etc/os-release && echo "${ID_LIKE:-$ID}")"
  if [[ "$id_like" =~ (debian|ubuntu) ]]; then pkgmgr="apt-get"
  elif [[ "$id_like" =~ (fedora|rhel|centos|nobara) ]]; then pkgmgr="dnf"
  elif [[ "$id_like" =~ (arch|manjaro) ]]; then pkgmgr="pacman"
  else fatal "$EX_DEPEND" "Unsupported distro: $id_like"; fi

  install_pkg() {
    local cmd="$1" pkg="$2"
    if ! require_cmd "$cmd"; then
      log "Installing $pkg..."
      case "$pkgmgr" in
        apt-get) sudo apt-get update -y &>>"$LOG_FILE"; sudo apt-get install -y "$pkg" &>>"$LOG_FILE" ;;
        dnf) sudo dnf install -y "$pkg" &>>"$LOG_FILE" ;;
        pacman) sudo pacman -Sy --noconfirm "$pkg" &>>"$LOG_FILE" ;;
      esac
    fi
  }

  install_pkg "nmap" "nmap"
  install_pkg "ssh" "openssh-client"
  install_pkg "openssl" "openssl"
  install_pkg "flatpak" "flatpak"

  log "Dependencies verified/installed."
}
# ------------------------------------------------------------------------------

# ------------------------ Keypair Handling -------------------------------------
ensure_server_keypair() {
  mkdir -p "$RUSTDIR"; chmod 700 "$RUSTDIR"
  if [[ ! -f "$PRIV" ]]; then
    log "Generating Ed25519 server keypair..."
    ssh-keygen -t ed25519 -N "" -f "$PRIV" <<< y >/dev/null 2>&1 || fatal "$EX_SERVER_KEY" "ssh-keygen failed"
  fi

  # Export RustDesk-compatible format
  if ! openssl pkey -in "$PRIV" -pubout -outform DER 2>/dev/null | base64 -w0 > "$PUB" 2>/dev/null; then
    fatal "$EX_SERVER_KEY" "Failed to export RustDesk-compatible public key"
  fi

  chmod 600 "$PRIV"; chmod 644 "$PUB"; chown root:root "$PRIV" "$PUB" 2>/dev/null || true
  log "Keypair ready. Fingerprint: $(key_fingerprint "$PUB")"
}
# ------------------------------------------------------------------------------

# ------------------------ Remote & SSH Helpers ---------------------------------
deploy_ssh_key_if_needed() {
  local host="$1"
  if ssh -o ConnectTimeout="$SSH_TIMEOUT" -o BatchMode=yes "$CLIENT_USER@$host" "echo ok" &>/dev/null; then
    log "Passwordless SSH confirmed for $host"
    return 0
  fi
  log "Deploying SSH key to $host..."
  ssh-copy-id -i "$LOCAL_SSH_KEY" "$CLIENT_USER@$host" &>>"$LOG_FILE" || return 1
}

remote_exec() { ssh -o ConnectTimeout="$SSH_TIMEOUT" "$CLIENT_USER@$1" "${@:2}" &>>"$LOG_FILE"; }
remote_copy_pub() { scp -o ConnectTimeout="$SSH_TIMEOUT" "$PUB" "$CLIENT_USER@$1:/home/$CLIENT_USER/$FLATPAK_KEY_PATH" &>>"$LOG_FILE"; }
verify_remote_pub_matches() {
  local host="$1" tmp="$(safe_mktemp)"
  ssh -o ConnectTimeout="$SSH_TIMEOUT" "$CLIENT_USER@$host" "cat /home/$CLIENT_USER/$FLATPAK_KEY_PATH" >"$tmp" 2>/dev/null || return 1
  local remote_fp local_fp
  remote_fp="$(sha256sum "$tmp" | awk '{print $1}')"
  local_fp="$(key_fingerprint "$PUB")"
  rm -f "$tmp"
  [[ "$remote_fp" == "$local_fp" ]]
}
# ------------------------------------------------------------------------------

# --------------------------- Abstracted Test Flow ------------------------------
run_self_test() {
  log "Running self-test (abstracted from user)..."
  # Test keypair
  [[ -f "$PRIV" && -f "$PUB" ]] || fatal "$EX_SERVER_KEY" "Missing server keypair"

  # Quick OpenSSL validity test
  openssl pkey -in "$PRIV" -pubout -outform DER >/dev/null 2>&1 || fatal "$EX_SERVER_KEY" "OpenSSL key verification failed"

  # SSH sanity check
  require_cmd ssh || fatal "$EX_DEPEND" "SSH missing"
  log "Self-test passed."
}
# ------------------------------------------------------------------------------

# --------------------------- Main Logic ----------------------------------------
CLEANUP_MODE=0
[[ "${1:-}" == "--cleanup" ]] && CLEANUP_MODE=1
log "===== rustdesk_flatpak_key_sync START ====="

auto_install_deps
ensure_server_keypair
run_self_test

# LAN discovery
log "Scanning LAN subnet: $LAN_SUBNET"
mapfile -t discovered_hosts < <(nmap -sn "$LAN_SUBNET" 2>/dev/null | awk '/Nmap scan report for/ {print $5}')
read -rp "Enter additional hosts (space/comma-separated), or ENTER to skip: " extra
extra="${extra//,/ }"
for h in $extra; do discovered_hosts+=("$h"); done

declare -A _seen
hosts_to_process=()
for h in "${discovered_hosts[@]}"; do [[ -z "$h" ]] && continue; [[ ${_seen[$h]} ]] && continue; hosts_to_process+=("$h"); _seen[$h]=1; done

log "Hosts to process: ${hosts_to_process[*]:-none}"

for host in "${hosts_to_process[@]}"; do
  log "--- Processing $host ---"
  ping -c1 -W2 "$host" &>/dev/null || { log "Skipping $host (unreachable)"; continue; }

  deploy_ssh_key_if_needed "$host" || { log "SSH setup failed for $host"; continue; }

  if [[ "$CLEANUP_MODE" -eq 1 ]]; then
    log "Cleanup: removing server.pub from $host"
    remote_exec "$host" "rm -f /home/$CLIENT_USER/$FLATPAK_KEY_PATH" || log "Removal failed on $host"
    continue
  fi

  # Ensure dir exists, copy key, verify
  remote_exec "$host" "mkdir -p /home/$CLIENT_USER/$(dirname "$FLATPAK_KEY_PATH")"
  remote_copy_pub "$host" || { log "Failed to copy to $host"; continue; }

  for i in $(seq 1 $VERIFY_RETRIES); do
    if verify_remote_pub_matches "$host"; then
      log "Verification OK on $host"
      break
    else
      log "Retry $i: key mismatch on $host"
      sleep "$VERIFY_RETRY_DELAY"
    fi
  done
done

log "===== COMPLETE ====="
exit "$EX_OK"
