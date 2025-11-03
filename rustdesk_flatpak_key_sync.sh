#!/usr/bin/env bash
# ==============================================================================
# rustdesk_flatpak_key_sync.sh
# ------------------------------------------------------------------------------
# PURPOSE:
#   Manage RustDesk server keypair and synchronize RustDesk-compatible server.pub
#   into Flatpak clients over SSH. Includes interactive dependency installation,
#   auto key generation/conversion, LAN discovery, manual host entry, verification,
#   and optional cleanup/uninstall mode.
#
# MODE: interactive (prompts for installs/confirmations). Use --cleanup to remove
# server.pub from clients and optionally uninstall Flatpak RustDesk (interactive).
#
# AUTHOR: Jose Melendez
# DATE: 2025-11-02 (finalized)
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

# Exit codes
EX_OK=0
EX_SERVER_KEY=1
EX_SSH_CONN=2
EX_SCP=3
EX_PERMISSION=4
EX_DEPEND=5

# ------------------------------ Helpers ---------------------------------------
log() { printf '[%s] %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG_FILE"; }
fatal() { printf '[%s] FATAL: %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG_FILE" >&2; exit "${1:-1}"; }
prompt_yes_no() { local prompt="$1" ans; read -rp "$prompt [y/N]: " ans; [[ "$ans" =~ ^[Yy]$ ]]; }

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    return 1
  fi
  return 0
}

key_fingerprint() { sha256sum "$1" | awk '{print $1}'; }

# Use mktemp safely
safe_mktemp() {
  mktemp "${TMPDIR:-/tmp}/rustdesk_key_sync.XXXXXX"
}

# ----------------------- Dependency installation -------------------------------
install_if_missing() {
  local cmd="$1" pkg="$2" pkgmgr="$3"
  if ! require_cmd "$cmd"; then
    log "Dependency missing: $cmd (package: $pkg)"
    if prompt_yes_no "Install $pkg (for $cmd) now?"; then
      case "$pkgmgr" in
        apt-get) sudo apt-get update -y &>>"$LOG_FILE"; sudo apt-get install -y "$pkg" &>>"$LOG_FILE" || return 1 ;;
        dnf) sudo dnf makecache &>>"$LOG_FILE"; sudo dnf install -y "$pkg" &>>"$LOG_FILE" || return 1 ;;
        pacman) sudo pacman -Sy --noconfirm "$pkg" &>>"$LOG_FILE" || return 1 ;;
        *) fatal "$EX_DEPEND" "Unsupported package manager: $pkgmgr"; ;;
      esac
      log "Installed $pkg"
    else
      fatal "$EX_DEPEND" "User declined to install $pkg (required)."
    fi
  fi
  return 0
}

auto_install_deps() {
  log "Detecting distro for dependency installation..."
  local id_like pkgmgr
  id_like="$(. /etc/os-release && echo "${ID_LIKE:-$ID}")"
  if [[ "$id_like" =~ (debian|ubuntu) ]]; then pkgmgr="apt-get"
  elif [[ "$id_like" =~ (fedora|rhel|centos|nobara) ]]; then pkgmgr="dnf"
  elif [[ "$id_like" =~ (arch|manjaro) ]]; then pkgmgr="pacman"
  else fatal "$EX_DEPEND" "Unsupported distro: $id_like"; fi

  log "Using package manager: $pkgmgr"

  # Map commands to packages (best-effort)
  install_if_missing "nmap" "nmap" "$pkgmgr"
  install_if_missing "ssh" "openssh-client" "$pkgmgr" || install_if_missing "ssh" "openssh" "$pkgmgr"
  install_if_missing "scp" "openssh-client" "$pkgmgr"
  install_if_missing "ssh-copy-id" "openssh-client" "$pkgmgr"
  install_if_missing "ssh-keygen" "openssh-client" "$pkgmgr"
  install_if_missing "openssl" "openssl" "$pkgmgr"
  install_if_missing "sha256sum" "coreutils" "$pkgmgr" || true
  install_if_missing "flatpak" "flatpak" "$pkgmgr" || true

  log "Dependency checks/install complete."
}

# ------------------------ Keypair handling -------------------------------------
ensure_rustdesk_pub_format() {
  # Create RustDesk-compatible public key: DER pubkey base64 on one line
  require_cmd openssl || fatal "$EX_DEPEND" "openssl required but missing"
  if [[ ! -f "$PRIV" ]]; then
    fatal "$EX_SERVER_KEY" "Private key $PRIV missing; cannot generate public key."
  fi

  if ! openssl pkey -in "$PRIV" -pubout -outform DER 2>/dev/null | base64 -w0 > "$PUB.tmp" 2>/dev/null; then
    # Some openssl builds differ; try alternative invocation
    if ! openssl ed25519 -in "$PRIV" -pubout -outform DER 2>/dev/null | base64 -w0 > "$PUB.tmp" 2>/dev/null; then
      fatal "$EX_SERVER_KEY" "Unable to export Ed25519 public key using openssl from $PRIV"
    fi
  fi
  mv "$PUB.tmp" "$PUB"
  log "Wrote RustDesk-compatible public key to $PUB"
}

ensure_server_keypair() {
  log "Ensuring server keypair exists..."
  mkdir -p "$RUSTDIR"
  chmod 700 "$RUSTDIR" || true

  # If keys already exist, back them up first (safer)
  if [[ -f "$PRIV" || -f "$PUB" ]]; then
    local ts backupdir
    ts="$(date '+%Y%m%d_%H%M%S')"
    backupdir="${RUSTDIR}/backup_${ts}"
    mkdir -p "$backupdir"
    mv "${RUSTDIR}"/id_ed25519* "$backupdir/" 2>/dev/null || true
    log "Existing keys moved to backup: $backupdir"
  fi

  # Generate private key if missing
  if [[ ! -f "$PRIV" ]]; then
    require_cmd ssh-keygen || fatal "$EX_DEPEND" "ssh-keygen missing"
    log "Generating new Ed25519 private key at $PRIV..."
    ssh-keygen -t ed25519 -N "" -f "$PRIV" <<< y >/dev/null 2>&1 || fatal "$EX_SERVER_KEY" "ssh-keygen failed"
    # At this point OpenSSH .pub exists too, but we will produce RustDesk format from the private key
  fi

  # Produce RustDesk public key format from private key
  ensure_rustdesk_pub_format

  # Permissions
  chmod 600 "$PRIV" || true
  chmod 644 "$PUB" || true
  chown root:root "$PRIV" "$PUB" 2>/dev/null || true

  log "Server keypair ready. Public key fingerprint: $(key_fingerprint "$PUB")"
}

# ------------------------ Remote helpers ---------------------------------------
deploy_ssh_key_if_needed() {
  local host="$1"
  # quick test
  if ssh -o ConnectTimeout="$SSH_TIMEOUT" -o BatchMode=yes "$CLIENT_USER@$host" "echo ok" &>/dev/null; then
    log "Passwordless SSH OK -> $host"
    return 0
  fi
  if [[ ! -f "$LOCAL_SSH_KEY" ]]; then
    log "Local SSH public key not found at $LOCAL_SSH_KEY; cannot deploy to $host"
    return 1
  fi
  log "Deploying SSH key to $host (you will be prompted for password)..."
  if ssh-copy-id -i "$LOCAL_SSH_KEY" "$CLIENT_USER@$host" &>>"$LOG_FILE"; then
    log "ssh-copy-id succeeded for $host"
    return 0
  fi
  log "ssh-copy-id failed for $host"
  return 1
}

remote_exec() {
  local host="$1"; shift
  ssh -o ConnectTimeout="$SSH_TIMEOUT" "$CLIENT_USER@$host" "$@" &>>"$LOG_FILE"
}

remote_copy_pub() {
  local host="$1"
  scp -o ConnectTimeout="$SSH_TIMEOUT" "$PUB" "$CLIENT_USER@$host:/home/$CLIENT_USER/$FLATPAK_KEY_PATH" &>>"$LOG_FILE"
}

remote_remove_pub() {
  local host="$1"
  ssh -o ConnectTimeout="$SSH_TIMEOUT" "$CLIENT_USER@$host" "rm -f '/home/$CLIENT_USER/$FLATPAK_KEY_PATH'" &>>"$LOG_FILE"
}

remote_uninstall_flatpak() {
  local host="$1"
  ssh -o ConnectTimeout="$SSH_TIMEOUT" "$CLIENT_USER@$host" "flatpak uninstall -y com.rustdesk.RustDesk" &>>"$LOG_FILE"
}

verify_remote_pub_matches() {
  local host="$1" tmp
  tmp="$(safe_mktemp)"
  if ! ssh -o ConnectTimeout="$SSH_TIMEOUT" "$CLIENT_USER@$host" "cat '/home/$CLIENT_USER/$FLATPAK_KEY_PATH'" >"$tmp" 2>/dev/null; then
    rm -f "$tmp"
    return 1
  fi
  local remote_fp local_fp
  remote_fp="$(sha256sum "$tmp" | awk '{print $1}')" || remote_fp="ERR"
  local_fp="$(key_fingerprint "$PUB")" || local_fp="ERR"
  rm -f "$tmp"
  [[ "$remote_fp" == "$local_fp" ]]
}

# --------------------------- Main flow -----------------------------------------
# Parse arguments (only --cleanup supported)
CLEANUP_MODE=0
if [[ "${1:-}" == "--cleanup" ]]; then
  CLEANUP_MODE=1
fi

log "===== rustdesk_flatpak_key_sync START ====="
log "Mode: $([[ $CLEANUP_MODE -eq 1 ]] && printf 'CLEANUP' || printf 'DEPLOY')"

# Ensure dependencies (interactive)
auto_install_deps

# Ensure server keys & public format
ensure_server_keypair

# Discover clients via nmap (interactive fallback to manual input)
require_cmd nmap || fatal "$EX_DEPEND" "nmap required but missing"
log "Scanning LAN subnet: $LAN_SUBNET ..."
mapfile -t discovered_hosts < <(nmap -sn "$LAN_SUBNET" 2>/dev/null | awk '/Nmap scan report for/ {print $5}')
log "Auto-discovered ${#discovered_hosts[@]} host(s)."

# Prompt for manual hosts (space/comma separated)
log "You may add extra hosts not discovered on the network."
read -rp "Enter additional hosts (space or comma-separated), or ENTER to skip: " extra_hosts
extra_hosts="${extra_hosts//,/ }"
if [[ -n "$extra_hosts" ]]; then
  read -ra _extra_arr <<< "$extra_hosts"
  for h in "${_extra_arr[@]}"; do discovered_hosts+=("$h"); done
  log "Added ${#_extra_arr[@]} manual host(s)."
fi

# Deduplicate and sanitize host list
declare -A _seen
hosts_to_process=()
for h in "${discovered_hosts[@]}"; do
  [[ -z "${h:-}" ]] && continue
  if [[ -z "${_seen[$h]:-}" ]]; then
    hosts_to_process+=("$h")
    _seen[$h]=1
  fi
done

log "Final host list contains ${#hosts_to_process[@]} host(s): ${hosts_to_process[*]:-none}"

# Per-host processing
for host in "${hosts_to_process[@]}"; do
  log "----------------------------------------"
  log "Processing host: $host"

  # Quick reachability
  if ! ping -c1 -W2 "$host" &>/dev/null; then
    log "Host $host did not respond to ping; skipping."
    continue
  fi

  # Ensure SSH connectivity / deploy key if needed
  if ! ssh -o ConnectTimeout="$SSH_TIMEOUT" -o BatchMode=yes "$CLIENT_USER@$host" "echo ok" &>/dev/null; then
    log "Passwordless SSH not configured for $host."
    if ! deploy_ssh_key_if_needed "$host"; then
      log "SSH key deployment failed for $host; skipping."
      continue
    fi
  fi

  if [[ "$CLEANUP_MODE" -eq 1 ]]; then
    # Interactive cleanup: remove server.pub and optionally uninstall Flatpak per host
    log "CLEANUP MODE: Will remove server.pub from $host"
    if prompt_yes_no "Confirm removal of server.pub on $host?"; then
      remote_remove_pub "$host" && log "Removed server.pub on $host" || log "Failed to remove server.pub on $host"
      if prompt_yes_no "Also uninstall Flatpak RustDesk on $host?"; then
        remote_uninstall_flatpak "$host" && log "Uninstalled Flatpak RustDesk on $host" || log "Uninstall failed on $host"
      fi
    else
      log "User skipped cleanup for $host"
    fi
    continue
  fi

  # Ensure remote Flatpak key directory exists
  remote_exec "$host" "mkdir -p '/home/$CLIENT_USER/$(dirname "$FLATPAK_KEY_PATH")'" || log "Warning: failed to ensure directory on $host"

  # Check/install/update Flatpak RustDesk on client
  if ! ssh -o ConnectTimeout="$SSH_TIMEOUT" "$CLIENT_USER@$host" "flatpak list | grep -q com.rustdesk.RustDesk" &>/dev/null; then
    log "RustDesk Flatpak not found on $host"
    if prompt_yes_no "Install RustDesk Flatpak on $host?"; then
      remote_exec "$host" "flatpak install -y flathub com.rustdesk.RustDesk" || log "Install failed on $host"
      log "Installed RustDesk Flatpak on $host (or attempted)"
    else
      log "User chose not to install RustDesk on $host; skipping host"
      continue
    fi
  else
    log "RustDesk Flatpak present on $host; attempting update..."
    remote_exec "$host" "flatpak update -y com.rustdesk.RustDesk" || log "Flatpak update failed on $host"
  fi

  # Copy server.pub with retries
  copy_ok=0
  for attempt in $(seq 1 3); do
    log "Copy attempt #$attempt to $host..."
    if remote_copy_pub "$host"; then
      copy_ok=1
      log "Copy succeeded to $host"
      break
    else
      log "Copy attempt #$attempt failed"
      sleep 2
    fi
  done
  if [[ "$copy_ok" -ne 1 ]]; then
    log "Failed to copy server.pub to $host after attempts; continuing to next host"
    continue
  fi

  # Set perms remotely (best effort)
  remote_exec "$host" "chmod 644 '/home/$CLIENT_USER/$FLATPAK_KEY_PATH' || true; chown $CLIENT_USER:$CLIENT_USER '/home/$CLIENT_USER/$FLATPAK_KEY_PATH' || true"

  # Restart Flatpak RustDesk to pick up new key
  remote_exec "$host" "flatpak kill com.rustdesk.RustDesk || true; flatpak run -d com.rustdesk.RustDesk" || log "Warning: failed to restart RustDesk on $host"

  # Verification with retries
  verified=0
  for attempt in $(seq 1 $VERIFY_RETRIES); do
    if verify_remote_pub_matches "$host"; then
      log "VERIFICATION OK: remote key matches local copy for $host"
      verified=1
      break
    else
      log "Verification attempt #$attempt failed for $host; retrying in $VERIFY_RETRY_DELAY s"
      sleep "$VERIFY_RETRY_DELAY"
    fi
  done
  if [[ "$verified" -ne 1 ]]; then
    log "VERIFICATION FAILED for $host — remote key differs from server.pub"
    # Helpful debug: show beginning of remote file
    tmpdbg="$(safe_mktemp)"
    if ssh -o ConnectTimeout="$SSH_TIMEOUT" "$CLIENT_USER@$host" "cat '/home/$CLIENT_USER/$FLATPAK_KEY_PATH'" >"$tmpdbg" 2>/dev/null; then
      log "Remote file sample (first 160 chars): $(head -c160 "$tmpdbg" | tr -d '\n')"
    else
      log "Unable to read remote file for debug on $host"
    fi
    rm -f "$tmpdbg" || true
  fi

  log "Finished processing $host"
done

log "===== rustdesk_flatpak_key_sync COMPLETE ====="
exit "$EX_OK"
