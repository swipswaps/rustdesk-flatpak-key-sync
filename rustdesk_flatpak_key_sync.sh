#!/usr/bin/env bash
# ==============================================================================
# rustdesk_flatpak_key_sync.sh
# ------------------------------------------------------------------------------
# PURPOSE:
#   - Automatically manage RustDesk server keypair and deploy its public key to
#     Flatpak clients over SSH for self-hosted setups.
#   - Auto-discovers clients via nmap, accepts manual IPs, validates connectivity,
#     and ensures Flatpak RustDesk install/update on each host.
#
#   Features:
#     ✅ Keypair generation / conversion (RustDesk-compatible)
#     ✅ LAN auto-discovery (nmap)
#     ✅ Interactive extra host entry (manual IP input)
#     ✅ SSH passwordless deployment (ssh-copy-id)
#     ✅ Flatpak install/update & key propagation
#     ✅ Verification of remote key integrity (hash match)
#     ✅ Detailed logging to /var/log/rustdesk_flatpak_key_sync.log
#     ✅ Auto dependency installer per distro
#
# MODE: INTERACTIVE (asks before install/update)
# AUTHOR: Jose Melendez
# UPDATED: 2025-11-02
# ==============================================================================
set -euo pipefail

# ------------------------------------------------------------------------------
# USER CONFIGURATION
# ------------------------------------------------------------------------------
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
#################################################################################

# ------------------------------------------------------------------------------
# LOGGING AND PROMPTS
# ------------------------------------------------------------------------------
log() { echo "[$(date '+%F %T')] $*" | tee -a "$LOG_FILE"; }
fatal() { echo "[$(date '+%F %T')] FATAL: $*" | tee -a "$LOG_FILE" >&2; exit 1; }
prompt_yes_no() { local p="$1" a; read -rp "$p [y/N]: " a; [[ "$a" =~ ^[Yy]$ ]]; }

# ------------------------------------------------------------------------------
# REQUIREMENT VALIDATION
# ------------------------------------------------------------------------------
require_cmd() { command -v "$1" >/dev/null 2>&1 || fatal "Missing required command: $1"; }

# ------------------------------------------------------------------------------
# DISTRO DETECTION AND DEPENDENCY INSTALLATION
# ------------------------------------------------------------------------------
auto_install_deps() {
  log "Detecting distro and verifying dependencies..."
  local id_like installer
  id_like="$(. /etc/os-release && echo "${ID_LIKE:-$ID}")"

  case "$id_like" in
    *debian*|*ubuntu*) installer="apt-get" ;;
    *fedora*|*rhel*|*centos*|*nobara*) installer="dnf" ;;
    *arch*|*manjaro*) installer="pacman" ;;
    *) fatal "Unsupported distro: $id_like. Please manually install required packages." ;;
  esac

  log "Using package manager: $installer"
  case "$installer" in
    apt-get) sudo apt-get update -y ;;
    dnf) sudo dnf makecache ;;
    pacman) sudo pacman -Sy --noconfirm ;;
  esac &>>"$LOG_FILE"

  declare -A pkgs=(
    [nmap]="nmap"
    [ssh]="openssh-clients"
    [scp]="openssh-clients"
    [ssh-copy-id]="openssh-clients"
    [ssh-keygen]="openssh"
    [flatpak]="flatpak"
    [openssl]="openssl"
    [sha256sum]="coreutils"
  )

  for cmd in "${!pkgs[@]}"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      if prompt_yes_no "Install ${pkgs[$cmd]} for missing $cmd?"; then
        sudo $installer install -y "${pkgs[$cmd]}" &>>"$LOG_FILE" || fatal "Failed installing ${pkgs[$cmd]}"
        log "Installed ${pkgs[$cmd]}"
      else
        fatal "User declined to install $cmd — aborting."
      fi
    fi
  done
  log "Dependencies verified or installed."
}

# ------------------------------------------------------------------------------
# KEYPAIR GENERATION AND VALIDATION
# ------------------------------------------------------------------------------
key_fingerprint() { sha256sum "$1" | awk '{print $1}'; }

ensure_rustdesk_pub_format() {
  # Converts OpenSSH pub key to base64-encoded format RustDesk expects.
  require_cmd openssl
  if ! openssl pkey -in "$PRIV" -pubout -outform DER 2>/dev/null | base64 -w0 >"$PUB.tmp"; then
    fatal "Failed exporting RustDesk-compatible public key from $PRIV"
  fi
  mv "$PUB.tmp" "$PUB"
  log "Generated RustDesk-compatible public key ($PUB)"
}

ensure_server_keypair() {
  log "=== Checking server keypair ==="
  mkdir -p "$RUSTDIR"
  if [[ -f "$PRIV" || -f "$PUB" ]]; then
    local ts; ts=$(date +%Y%m%d_%H%M%S)
    mkdir -p "$RUSTDIR/backup_$ts"
    mv "$RUSTDIR"/id_ed25519* "$RUSTDIR/backup_$ts/" 2>/dev/null || true
    log "Backed up existing keypair to $RUSTDIR/backup_$ts/"
  fi
  ssh-keygen -t ed25519 -N "" -f "$PRIV" <<<y >/dev/null 2>&1
  ensure_rustdesk_pub_format
  chmod 600 "$PRIV"; chmod 644 "$PUB"; chown root:root "$PRIV" "$PUB" || true
  log "Server key ready. Fingerprint: $(key_fingerprint "$PUB")"
}

# ------------------------------------------------------------------------------
# NETWORK DISCOVERY AND CLIENT HANDLING
# ------------------------------------------------------------------------------
discover_clients() {
  log "Scanning $LAN_SUBNET for live hosts..."
  mapfile -t found < <(nmap -sn "$LAN_SUBNET" 2>/dev/null | awk '/Nmap scan report for/{print $5}')
  echo "${found[@]-}"
}

prompt_additional_hosts() {
  read -rp "Enter extra hosts (IP/hostname, separated by space or comma), or press ENTER to skip: " extra
  echo "${extra//,/ }"
}

deploy_ssh_key_if_needed() {
  local host="$1"
  if ssh -o ConnectTimeout="$SSH_TIMEOUT" -o BatchMode=yes "$CLIENT_USER@$host" "echo ok" &>/dev/null; then
    log "SSH access already available for $host."
  else
    log "Deploying SSH pubkey to $host..."
    [[ -f "$LOCAL_SSH_KEY" ]] || fatal "Local SSH pubkey missing ($LOCAL_SSH_KEY)"
    ssh-copy-id -i "$LOCAL_SSH_KEY" "$CLIENT_USER@$host" &>>"$LOG_FILE" || fatal "Failed ssh-copy-id for $host"
  fi
}

remote_exec() {
  local host="$1" cmd="$2"
  ssh -o ConnectTimeout="$SSH_TIMEOUT" "$CLIENT_USER@$host" "$cmd" &>>"$LOG_FILE"
}

remote_copy_pub() {
  local host="$1"
  scp -o ConnectTimeout="$SSH_TIMEOUT" "$PUB" "$CLIENT_USER@$host:/home/$CLIENT_USER/$FLATPAK_KEY_PATH" &>>"$LOG_FILE"
}

verify_remote_pub_matches() {
  local host="$1" tmp
  tmp=$(mktemp)
  ssh -o ConnectTimeout="$SSH_TIMEOUT" "$CLIENT_USER@$host" "cat /home/$CLIENT_USER/$FLATPAK_KEY_PATH" >"$tmp" 2>/dev/null || return 1
  [[ "$(key_fingerprint "$tmp")" == "$(key_fingerprint "$PUB")" ]]
}

# ------------------------------------------------------------------------------
# MAIN EXECUTION LOGIC
# ------------------------------------------------------------------------------
log "===== RustDesk Flatpak Key Sync START ====="
auto_install_deps
ensure_server_keypair

mapfile -t hosts < <(discover_clients)
log "Discovered hosts: ${hosts[*]:-none}"

# Prompt user for manual host IPs (your requested feature)
extra_hosts=$(prompt_additional_hosts)
[[ -n "$extra_hosts" ]] && read -ra extra_list <<<"$extra_hosts" && hosts+=("${extra_list[@]}")

# Deduplicate
declare -A uniq; final_hosts=()
for h in "${hosts[@]}"; do [[ -z "${uniq[$h]:-}" ]] && uniq[$h]=1 && final_hosts+=("$h"); done
log "Final host list: ${final_hosts[*]:-none}"

for host in "${final_hosts[@]}"; do
  log "---- HOST: $host ----"
  if ! ping -c1 -W2 "$host" &>/dev/null; then
    log "Host $host unreachable — skipping."
    continue
  fi
  deploy_ssh_key_if_needed "$host"

  # Flatpak presence check and install/update
  log "Checking Flatpak RustDesk on $host..."
  if ! remote_exec "$host" "flatpak list | grep -q com.rustdesk.RustDesk"; then
    if prompt_yes_no "Install RustDesk Flatpak on $host?"; then
      remote_exec "$host" "flatpak install -y flathub com.rustdesk.RustDesk" || log "Install failed on $host"
    else
      log "Skipped RustDesk install for $host"
      continue
    fi
  else
    log "Updating RustDesk Flatpak on $host..."
    remote_exec "$host" "flatpak update -y com.rustdesk.RustDesk" || log "Update failed on $host"
  fi

  # Copy RustDesk server.pub to client
  log "Deploying server.pub to $host..."
  remote_exec "$host" "mkdir -p /home/$CLIENT_USER/$(dirname "$FLATPAK_KEY_PATH")"
  remote_copy_pub "$host" || log "Failed to copy key to $host"
  remote_exec "$host" "chmod 644 /home/$CLIENT_USER/$FLATPAK_KEY_PATH"

  if verify_remote_pub_matches "$host"; then
    log "✅ Key verified OK for $host."
  else
    log "⚠️  Key mismatch on $host — possible stale Flatpak sandbox path."
  fi

  # Restart Flatpak RustDesk (quiet mode)
  log "Restarting RustDesk Flatpak on $host..."
  remote_exec "$host" "flatpak kill com.rustdesk.RustDesk || true; flatpak run -d com.rustdesk.RustDesk" || log "Restart failed on $host"
done

log "===== RustDesk Flatpak Key Sync COMPLETE ====="
