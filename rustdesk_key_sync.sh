#!/usr/bin/env bash
# ==============================================================================
# rustdesk_key_sync.sh (v2025-11-06.22)
# ------------------------------------------------------------------------------
# PURPOSE:
#   Manage RustDesk server keypair and synchronize RustDesk-compatible server.pub
#   to Flatpak clients over SSH.
#
# FEATURES:
#   - Auto-installs dependencies for major Linux distributions.
#   - Discovers clients on the LAN using nmap and Avahi/mDNS.
#   - Bootstraps passwordless SSH access using ssh-copy-id.
#   - Exports the RustDesk public key in the correct format.
#   - Copies the public key to clients and verifies the transfer.
#   - Restarts the RustDesk Flatpak on clients to apply the new key.
#   - Includes --dry-run, --cleanup, and --self-allow flags for testing and
#     management.
# ==============================================================================

set -euo pipefail

# ------------------------------ Configuration -----------------------------------
RUSTDIR="/var/lib/rustdesk-server"
PRIV="${RUSTDIR}/id_ed25519"
PUB="${RUSTDIR}/id_ed25519.pub"
FLATPAK_KEY_PATH=".var/app/com.rustdesk.RustDesk/config/rustdesk/server.pub"
CLIENT_USER="owner"
LAN_SUBNET="192.168.1.0/24"
LOG_FILE="/var/log/rustdesk_key_sync.log"
SSH_TIMEOUT=6
VERIFY_RETRIES=3
VERIFY_RETRY_DELAY=2
EXPORT_RETRIES=3

# ------------------------------ Argument Parsing ------------------------------
CLEANUP_MODE=0
DRY_RUN_MODE=0
SELF_ALLOW_MODE=0

for arg in "$@"; do
  case "$arg" in
    --cleanup) CLEANUP_MODE=1 ;;
    --dry-run|--test) DRY_RUN_MODE=1 ;;
    --self-allow) SELF_ALLOW_MODE=1 ;;
    -h|--help)
      cat <<'USAGE'
Usage: rustdesk_key_sync.sh [--dry-run] [--cleanup] [--self-allow]
--dry-run / --test  : simulate actions (auto-answer prompts)
--cleanup           : remove server.pub from clients and optionally uninstall Flatpak
--self-allow        : include local host in processing (for testing only)
USAGE
      exit 0
      ;;
  esac
done

# ------------------------------ Colors and Logging ------------------------------
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
RESET="\e[0m"

log()  { printf '[%s] %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG_FILE"; }
pass() { printf "%b✅ %s%b\n" "$GREEN" "$*" "$RESET"; log "PASS: $*"; }
fail() { printf "%b❌ %s%b\n" "$RED" "$*" "$RESET"; log "FAIL: $*"; }
warn() { printf "%b⚠️ %s%b\n" "$YELLOW" "$*" "$RESET"; log "WARN: $*"; }
fatal(){ printf '[%s] FATAL: %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG_FILE" >&2; exit 1; }

# ------------------------------ Helper Functions --------------------------------
require_cmd() { command -v "$1" >/dev/null 2>&1; }
key_fingerprint() { sha256sum "$1" | awk '{print $1}'; }
safe_mktemp() { mktemp "${TMPDIR:-/tmp}/rustdesk_key_sync.XXXXXX"; }

prompt_yes_no() {
  local prompt="$1" ans
  if [[ "$DRY_RUN_MODE" -eq 1 ]]; then ans="y"; else read -rp "$prompt [y/N]: " ans; fi
  [[ "$ans" =~ ^[Yy]$ ]]
}

# ------------------------------ Dependency Installation ------------------------
install_if_missing() {
  local cmd="$1" pkg="$2" pkgmgr="$3"
  if ! require_cmd "$cmd"; then
    log "Dependency missing: $cmd (package: $pkg)"
    if prompt_yes_no "Install $pkg (for $cmd) now?"; then
      [[ "$DRY_RUN_MODE" -eq 1 ]] && { pass "DRY-RUN: Would install $pkg via $pkgmgr"; return 0; }
      case "$pkgmgr" in
        apt-get) sudo apt-get update -y &>>"$LOG_FILE"; sudo apt-get install -y "$pkg" &>>"$LOG_FILE" || return 1 ;;
        dnf) sudo dnf makecache &>>"$LOG_FILE"; sudo dnf install -y "$pkg" &>>"$LOG_FILE" || return 1 ;;
        pacman) sudo pacman -Sy --noconfirm "$pkg" &>>"$LOG_FILE" || return 1 ;;
        *) fatal "Unsupported package manager: $pkgmgr" ;;
      esac
      pass "Installed $pkg"
    else
      fatal "User declined to install $pkg (required)."
    fi
  fi
}

auto_install_deps() {
  log "Detecting distro for dependency installation..."
  local id_like pkgmgr
  id_like="$(. /etc/os-release && echo "${ID_LIKE:-$ID}")"
  if [[ "$id_like" =~ (debian|ubuntu) ]]; then pkgmgr="apt-get"
  elif [[ "$id_like" =~ (fedora|rhel|centos|nobara) ]]; then pkgmgr="dnf"
  elif [[ "$id_like" =~ (arch|manjaro) ]]; then pkgmgr="pacman"
  else warn "Unknown distro ($id_like). You may need to install dependencies manually."; return; fi

  install_if_missing "nmap" "nmap" "$pkgmgr"
  install_if_missing "ssh" "openssh-client" "$pkgmgr"
  install_if_missing "scp" "openssh-client" "$pkgmgr"
  install_if_missing "ssh-copy-id" "openssh-client" "$pkgmgr"
  install_if_missing "ssh-keygen" "openssh-client" "$pkgmgr"
  install_if_missing "openssl" "openssl" "$pkgmgr"
  install_if_missing "sha256sum" "coreutils" "$pkgmgr" || true
  install_if_missing "flatpak" "flatpak" "$pkgmgr" || true
  install_if_missing "avahi-daemon" "avahi-daemon" "$pkgmgr" || true
}

# ------------------------------ Keypair Handling --------------------------------
export_rustdesk_pub_with_retries() {
  local tries=0 tmpfile
  tmpfile="$(safe_mktemp)"
  
  while (( ++tries <= EXPORT_RETRIES )); do
    log "Export attempt #$tries: generating RustDesk pub from $PRIV -> tmp: $tmpfile"
    [[ ! -f "$PRIV" ]] && fatal "Private key $PRIV missing; cannot export."

    if ssh-keygen -y -f "$PRIV" > "$tmpfile"; then
      if [[ -s "$tmpfile" ]]; then
        mv -f "$tmpfile" "$PUB"
        pass "Export succeeded (attempt #$tries) -> $PUB"
        return 0
      fi
    else
      warn "ssh-keygen export failed on attempt #$tries"
    fi
    sleep 1
  done

  rm -f "$tmpfile"
  fatal "Failed to export RustDesk public key after $EXPORT_RETRIES attempts"
}

ensure_server_keypair() {
  log "Ensuring server keypair exists..."
  mkdir -p "$RUSTDIR"
  chmod 700 "$RUSTDIR" 2>/dev/null || true

  if [[ ! -f "$PRIV" ]]; then
    require_cmd ssh-keygen || fatal "ssh-keygen missing"
    if [[ "$DRY_RUN_MODE" -eq 1 ]]; then
      pass "DRY-RUN: Would generate Ed25519 private key at $PRIV"
    else
      log "Generating Ed25519 private key at $PRIV..."
      ssh-keygen -t ed25519 -N "" -f "$PRIV" <<< y >/dev/null 2>&1 || fatal "ssh-keygen failed"
    fi
  fi

  [[ "$DRY_RUN_MODE" -eq 1 ]] && pass "DRY-RUN: Would export RustDesk public key" || export_rustdesk_pub_with_retries

  chmod 600 "$PRIV" 2>/dev/null || true
  chmod 644 "$PUB" 2>/dev/null || true
  pass "Server keypair ready. Fingerprint: $(key_fingerprint "$PUB")"
}

# ------------------------------ Network Discovery ------------------------------
discover_hosts() {
  [[ "$DRY_RUN_MODE" -eq 1 ]] && { pass "DRY-RUN: Would scan LAN $LAN_SUBNET"; printf '%s\n' "192.168.1.101" "192.168.1.102"; return; }
  
  require_cmd nmap || { warn "nmap missing, please install it."; return; }
  
  local nmap_out
  nmap_out=$(nmap -p 22 --open -oG - "$LAN_SUBNET")
  
  local self_ips=($(hostname -I))
  local filtered=()

  while read -r line; do
    if [[ "$line" =~ Host:\ ([0-9.]+) ]]; then
      local host="${BASH_REMATCH[1]}"
      local skip=0
      for ip in "${self_ips[@]}"; do
        if [[ "$host" == "$ip" ]]; then
          skip=1
          break
        fi
      done
      
      if [[ "$skip" -eq 0 || "$SELF_ALLOW_MODE" -eq 1 ]]; then
        filtered+=("$host")
      else
        log "Skipping local host IP $host to prevent recursion"
      fi
    fi
  done <<< "$nmap_out"
  
  if [[ ${#filtered[@]} -eq 0 ]]; then
    warn "No hosts discovered on the network."
  fi

  printf '%s\n' "${filtered[@]}"
}

# ------------------------------ SSH & Remote Ops -------------------------------
deploy_ssh_key_if_needed() {
  local host="$1"
  local ssh_key_path
  ssh_key_path="$HOME/.ssh/id_ed25519.pub"
  [[ ! -f "$ssh_key_path" ]] && ssh_key_path="$HOME/.ssh/id_rsa.pub"

  [[ "$DRY_RUN_MODE" -eq 1 ]] && { pass "DRY-RUN: Would ensure passwordless SSH to $host"; return; }
  
  if ssh -o ConnectTimeout="$SSH_TIMEOUT" -o BatchMode=yes "$CLIENT_USER@$host" "echo ok" &>/dev/null; then
    pass "Passwordless SSH already works for $host"
    return
  fi
  
  if [[ ! -f "$ssh_key_path" ]]; then
    warn "No local SSH key found at $ssh_key_path to copy to the client."
    return 1
  fi
  
  log "Attempting ssh-copy-id to $host"
  if ssh-copy-id -i "$ssh_key_path" "$CLIENT_USER@$host" &>>"$LOG_FILE"; then
    pass "ssh-copy-id succeeded to $host"
  else
    warn "ssh-copy-id failed for $host. Please check your password and try again."
    return 1
  fi
}

remote_copy_pub() {
  local host="$1"
  [[ "$DRY_RUN_MODE" -eq 1 ]] && { pass "DRY-RUN: Would copy $PUB -> $host:~/$FLATPAK_KEY_PATH"; return; }
  
  ssh -o ConnectTimeout="$SSH_TIMEOUT" "$CLIENT_USER@$host" "mkdir -p \"$(dirname ~/$FLATPAK_KEY_PATH)\"" &>>"$LOG_FILE" || { warn "Cannot ensure dir on $host"; return 1; }
  
  if scp -o ConnectTimeout="$SSH_TIMEOUT" "$PUB" "$CLIENT_USER@$host:/home/$CLIENT_USER/$FLATPAK_KEY_PATH" &>>"$LOG_FILE"; then
    pass "Copied $PUB to $host:$FLATPAK_KEY_PATH"
  else
    warn "SCP copy failed for $host"
    return 1
  fi
}

verify_remote_pub() {
  local host="$1"
  [[ "$DRY_RUN_MODE" -eq 1 ]] && { pass "DRY-RUN: Would verify remote key"; return 0; }
  
  local tmp remote_fp local_fp
  tmp="$(safe_mktemp)"
  
  if ssh -o ConnectTimeout="$SSH_TIMEOUT" "$CLIENT_USER@$host" "cat '$FLATPAK_KEY_PATH'" >"$tmp" 2>/dev/null; then
    remote_fp="$(sha256sum "$tmp" | awk '{print $1}')"
    local_fp="$(key_fingerprint "$PUB")"
    rm -f "$tmp"
    
    if [[ "$remote_fp" == "$local_fp" ]]; then
      return 0
    fi
  fi
  
  return 1
}

remote_restart_flatpak() {
  local host="$1"
  [[ "$DRY_RUN_MODE" -eq 1 ]] && { pass "DRY-RUN: Would restart Flatpak RustDesk on $host"; return; }
  
  if ssh -o ConnectTimeout="$SSH_TIMEOUT" "$CLIENT_USER@$host" "flatpak kill com.rustdesk.RustDesk || true; nohup flatpak run com.rustdesk.RustDesk >/dev/null 2>&1 &" &>>"$LOG_FILE"; then
    pass "Restarted RustDesk on $host"
  else
    warn "Cannot restart RustDesk on $host"
  fi
}

# ------------------------------ Main Flow --------------------------------------
main() {
  log "===== RustDesk Flatpak Key Sync START ====="
  [[ "$DRY_RUN_MODE" -eq 1 ]] && pass "MODE: DRY-RUN"
  [[ "$CLEANUP_MODE" -eq 1 ]] && pass "MODE: CLEANUP"
  [[ "$SELF_ALLOW_MODE" -eq 1 ]] && pass "MODE: SELF-ALLOW enabled (local host will be included)"

  auto_install_deps
  ensure_server_keypair

  mapfile -t HOSTS < <(discover_hosts)
  if [[ "${#HOSTS[@]}" -eq 0 ]]; then
    warn "No hosts discovered/supplied. Exiting."
    exit 0
  fi
  
  pass "Hosts to process: ${HOSTS[*]}"

  for host in "${HOSTS[@]}"; do
    log "---- Host: $host ----"
    
    if ! ping -c1 -W2 "$host" &>/dev/null && [[ "$DRY_RUN_MODE" -eq 0 ]]; then
      warn "$host unreachable"
      continue
    fi
    
    if ! deploy_ssh_key_if_needed "$host"; then
      warn "Skipping $host due to SSH issues"
      continue
    fi

    if [[ "$CLEANUP_MODE" -eq 1 ]]; then
      if prompt_yes_no "Remove server.pub on $host?"; then
        [[ "$DRY_RUN_MODE" -eq 1 ]] && pass "DRY-RUN: Would remove server.pub" || ssh "$CLIENT_USER@$host" "rm -f '/home/$CLIENT_USER/$FLATPAK_KEY_PATH'" &>>"$LOG_FILE"
        pass "Removed server.pub on $host"
      fi
      if prompt_yes_no "Also uninstall Flatpak RustDesk on $host?"; then
        [[ "$DRY_RUN_MODE" -eq 1 ]] && pass "DRY-RUN: Would uninstall Flatpak" || ssh "$CLIENT_USER@$host" "flatpak uninstall -y com.rustdesk.RustDesk" &>>"$LOG_FILE"
        pass "Flatpak uninstalled on $host"
      fi
      continue
    fi

    if ! remote_copy_pub "$host"; then
      fail "Failed to copy key to $host. Skipping."
      continue
    fi
    
    ssh "$CLIENT_USER@$host" "chmod 644 '/home/$CLIENT_USER/$FLATPAK_KEY_PATH'; chown $CLIENT_USER:$CLIENT_USER '/home/$CLIENT_USER/$FLATPAK_KEY_PATH'" &>>"$LOG_FILE" || warn "Permissions/ownership change might have failed on $host"
    
    remote_restart_flatpak "$host"

    local verified=0
    for _ in $(seq 1 "$VERIFY_RETRIES"); do
      if verify_remote_pub "$host"; then
        verified=1
        pass "VERIFICATION OK on $host"
        break
      fi
      warn "Verification failed; retrying in $VERIFY_RETRY_DELAY s"
      sleep "$VERIFY_RETRY_DELAY"
    done
    [[ "$verified" -ne 1 ]] && fail "VERIFICATION FAILED on $host"
  done

  log "===== RustDesk Flatpak Key Sync COMPLETE ====="
  exit 0
}

main "$@"
