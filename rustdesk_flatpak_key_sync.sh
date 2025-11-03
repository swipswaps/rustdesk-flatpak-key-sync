#!/usr/bin/env bash
# ==============================================================================
# rustdesk_flatpak_key_sync.sh
# ------------------------------------------------------------------------------
# PURPOSE:
#   Manage RustDesk server keypair and synchronize RustDesk-compatible server.pub
#   into Flatpak clients over SSH. Includes interactive dependency installation,
#   auto key generation/conversion, LAN discovery, manual host entry, verification,
#   optional cleanup/uninstall mode, and automated self-test (--dry-run / --test).
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

# Exit codes
EX_OK=0
EX_SERVER_KEY=1
EX_SSH_CONN=2
EX_SCP=3
EX_PERMISSION=4
EX_DEPEND=5

# ------------------------------ Mode Flags -------------------------------------
CLEANUP_MODE=0
DRY_RUN_MODE=0

for arg in "$@"; do
  case "$arg" in
    --cleanup) CLEANUP_MODE=1 ;;
    --dry-run|--test) DRY_RUN_MODE=1 ;;
  esac
done

# ------------------------------ Helpers ---------------------------------------
log() { printf '[%s] %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG_FILE"; }
pass() { log "✅ PASS: $*"; }
fail() { log "❌ FAIL: $*"; }
fatal() { printf '[%s] FATAL: %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG_FILE" >&2; exit "${1:-1}"; }
prompt_yes_no() { local prompt="$1" ans; if [[ "$DRY_RUN_MODE" -eq 1 ]]; then ans="y"; else read -rp "$prompt [y/N]: " ans; fi; [[ "$ans" =~ ^[Yy]$ ]]; }

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    return 1
  fi
  return 0
}

key_fingerprint() { sha256sum "$1" | awk '{print $1}'; }

safe_mktemp() { mktemp "${TMPDIR:-/tmp}/rustdesk_key_sync.XXXXXX"; }

# ----------------------- Dependency installation -------------------------------
install_if_missing() {
  local cmd="$1" pkg="$2" pkgmgr="$3"
  if ! require_cmd "$cmd"; then
    log "Dependency missing: $cmd (package: $pkg)"
    if prompt_yes_no "Install $pkg (for $cmd) now?"; then
      if [[ "$DRY_RUN_MODE" -eq 1 ]]; then
        pass "DRY-RUN: Would install $pkg"
        return 0
      fi
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
  require_cmd openssl || fatal "$EX_DEPEND" "openssl required but missing"
  if [[ ! -f "$PRIV" ]]; then
    fatal "$EX_SERVER_KEY" "Private key $PRIV missing; cannot generate public key."
  fi

  if [[ "$DRY_RUN_MODE" -eq 1 ]]; then
    pass "DRY-RUN: Would convert $PRIV to RustDesk public key"
    return 0
  fi

  if ! openssl pkey -in "$PRIV" -pubout -outform DER 2>/dev/null | base64 -w0 > "$PUB.tmp" 2>/dev/null; then
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

  if [[ -f "$PRIV" || -f "$PUB" ]]; then
    local ts backupdir
    ts="$(date '+%Y%m%d_%H%M%S')"
    backupdir="${RUSTDIR}/backup_${ts}"
    mkdir -p "$backupdir"
    mv "${RUSTDIR}"/id_ed25519* "$backupdir/" 2>/dev/null || true
    log "Existing keys moved to backup: $backupdir"
  fi

  if [[ ! -f "$PRIV" ]]; then
    require_cmd ssh-keygen || fatal "$EX_DEPEND" "ssh-keygen missing"
    if [[ "$DRY_RUN_MODE" -eq 1 ]]; then
      pass "DRY-RUN: Would generate new Ed25519 private key at $PRIV"
    else
      log "Generating new Ed25519 private key at $PRIV..."
      ssh-keygen -t ed25519 -N "" -f "$PRIV" <<< y >/dev/null 2>&1 || fatal "$EX_SERVER_KEY" "ssh-keygen failed"
    fi
  fi

  [[ "$DRY_RUN_MODE" -eq 0 ]] && ensure_rustdesk_pub_format

  chmod 600 "$PRIV" || true
  chmod 644 "$PUB" || true
  chown root:root "$PRIV" "$PUB" 2>/dev/null || true
  [[ "$DRY_RUN_MODE" -eq 1 ]] && pass "DRY-RUN: Permissions set on $PRIV/$PUB"
}

# ------------------------ Remote helpers ---------------------------------------
deploy_ssh_key_if_needed() {
  local host="$1"
  if [[ "$DRY_RUN_MODE" -eq 1 ]]; then
    pass "DRY-RUN: Would deploy SSH key to $host"
    return 0
  fi
  if ssh -o ConnectTimeout="$SSH_TIMEOUT" -o BatchMode=yes "$CLIENT_USER@$host" "echo ok" &>/dev/null; then
    log "Passwordless SSH OK -> $host"
    return 0
  fi
  if [[ ! -f "$LOCAL_SSH_KEY" ]]; then
    log "Local SSH public key not found at $LOCAL_SSH_KEY; cannot deploy to $host"
    return 1
  fi
  log "Deploying SSH key to $host (you will be prompted for password)..."
  ssh-copy-id -i "$LOCAL_SSH_KEY" "$CLIENT_USER@$host" &>>"$LOG_FILE"
}

remote_exec() {
  local host="$1"; shift
  [[ "$DRY_RUN_MODE" -eq 1 ]] && { pass "DRY-RUN: Would execute on $host: $*"; return 0; }
  ssh -o ConnectTimeout="$SSH_TIMEOUT" "$CLIENT_USER@$host" "$@" &>>"$LOG_FILE"
}

remote_copy_pub() {
  local host="$1"
  [[ "$DRY_RUN_MODE" -eq 1 ]] && { pass "DRY-RUN: Would copy $PUB to $host:$FLATPAK_KEY_PATH"; return 0; }
  scp -o ConnectTimeout="$SSH_TIMEOUT" "$PUB" "$CLIENT_USER@$host:/home/$CLIENT_USER/$FLATPAK_KEY_PATH" &>>"$LOG_FILE"
}

remote_remove_pub() {
  local host="$1"
  [[ "$DRY_RUN_MODE" -eq 1 ]] && { pass "DRY-RUN: Would remove $FLATPAK_KEY_PATH on $host"; return 0; }
  ssh -o ConnectTimeout="$SSH_TIMEOUT" "$CLIENT_USER@$host" "rm -f '/home/$CLIENT_USER/$FLATPAK_KEY_PATH'" &>>"$LOG_FILE"
}

remote_uninstall_flatpak() {
  local host="$1"
  [[ "$DRY_RUN_MODE" -eq 1 ]] && { pass "DRY-RUN: Would uninstall Flatpak RustDesk on $host"; return 0; }
  ssh -o ConnectTimeout="$SSH_TIMEOUT" "$CLIENT_USER@$host" "flatpak uninstall -y com.rustdesk.RustDesk" &>>"$LOG_FILE"
}

# ------------------------- LAN Discovery --------------------------------------
discover_hosts() {
  log "Discovering hosts in LAN subnet $LAN_SUBNET..."
  if [[ "$DRY_RUN_MODE" -eq 1 ]]; then
    pass "DRY-RUN: Would scan LAN subnet"
    return 0
  fi
  mapfile -t hosts < <(nmap -sn "$LAN_SUBNET" | awk '/Nmap scan report/{print $NF}')
  echo "${hosts[@]}"
}

# ------------------------ Verification ----------------------------------------
verify_remote_pub() {
  local host="$1"
  if [[ "$DRY_RUN_MODE" -eq 1 ]]; then
    pass "DRY-RUN: Would verify $host:$FLATPAK_KEY_PATH"
    return 0
  fi
  local local_fp remote_fp tmp
  local_fp="$(key_fingerprint "$PUB")"
  tmp="$(safe_mktemp)"
  ssh -o ConnectTimeout="$SSH_TIMEOUT" "$CLIENT_USER@$host" "cat '$FLATPAK_KEY_PATH'" >"$tmp" 2>/dev/null || return 1
  remote_fp="$(key_fingerprint "$tmp")"
  rm -f "$tmp"
  [[ "$local_fp" == "$remote_fp" ]] && return 0 || return 1
}

# ------------------------- Main Flow ------------------------------------------
log "===== RustDesk Flatpak Key Sync START ====="

auto_install_deps
ensure_server_keypair

# Discover hosts
HOSTS=("${TEST_HOSTS[@]:-}")
if [[ "${#HOSTS[@]}" -eq 0 ]]; then
  mapfile -t HOSTS < <(discover_hosts)
fi
[[ "${#HOSTS[@]}" -eq 0 ]] && log "No hosts found; exiting..." && exit 0

# Deploy SSH keys
for host in "${HOSTS[@]}"; do
  deploy_ssh_key_if_needed "$host"
done

# Copy server.pub
for host in "${HOSTS[@]}"; do
  remote_copy_pub "$host"
done

# Verify
for host in "${HOSTS[@]}"; do
  local success=0
  for ((i=0;i<VERIFY_RETRIES;i++)); do
    if verify_remote_pub "$host"; then
      success=1
      break
    else
      log "Verification failed for $host; retrying in $VERIFY_RETRY_DELAY sec..."
      sleep "$VERIFY_RETRY_DELAY"
    fi
  done
  [[ "$success" -eq 1 ]] && pass "Remote key verified on $host" || fail "Remote key mismatch on $host"
done

# Cleanup / uninstall mode
if [[ "$CLEANUP_MODE" -eq 1 ]]; then
  for host in "${HOSTS[@]}"; do
    remote_remove_pub "$host"
    remote_uninstall_flatpak "$host"
  done
fi

log "===== RustDesk Flatpak Key Sync COMPLETE ====="
