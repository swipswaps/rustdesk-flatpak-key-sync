# rustdesk_flatpak_key_sync.sh

## Overview

`rustdesk_flatpak_key_sync.sh` is a fully automated Bash script to manage RustDesk server keypairs and synchronize the RustDesk-compatible `server.pub` key to Flatpak clients across a LAN.  

It ensures:

- Server Ed25519 keypair exists and is RustDesk-compatible
- Dependencies (`ssh`, `nmap`, `openssl`, `flatpak`) are installed automatically
- LAN clients are discovered via `nmap` or manually entered
- Passwordless SSH setup is deployed if needed
- Remote `server.pub` is copied and verified with SHA256 fingerprints
- Optional cleanup and uninstallation mode

All steps are logged with timestamps to `/var/log/rustdesk_flatpak_key_sync.log`.

---

## Table of Contents

- [Prerequisites](#prerequisites)  
- [Installation](#installation)  
- [Usage](#usage)  
- [Modes](#modes)  
- [Structure](#structure)  
- [Troubleshooting](#troubleshooting)  
- [Cleanup Examples](#cleanup-examples)  
- [Logging](#logging)  

---

## Prerequisites

- Bash (≥4.0)  
- `ssh`, `ssh-keygen`, `ssh-copy-id`  
- `scp`  
- `openssl`  
- `nmap`  
- `flatpak` (client machines)  

The script auto-installs missing dependencies for Debian/Ubuntu, Fedora/RHEL, and Arch/Manjaro families.

---

## Installation

Clone or download the script and make it executable:

```bash
chmod +x rustdesk_flatpak_key_sync.sh

Run as a user with sudo privileges (for package installation and key generation):

./rustdesk_flatpak_key_sync.sh

Usage
Basic Deployment

./rustdesk_flatpak_key_sync.sh

    Auto-discovers LAN hosts on LAN_SUBNET (default 192.168.1.0/24)

    Prompts for manual hosts not discovered

    Ensures server keypair exists and is RustDesk-compatible

    Deploys server.pub to all reachable clients

    Verifies SHA256 fingerprints for each host

    Logs all events and errors

Cleanup / Uninstall Mode

./rustdesk_flatpak_key_sync.sh --cleanup

    Removes remote server.pub

    Optionally uninstalls Flatpak RustDesk on the client

    Interactive prompts ensure safe cleanup

Structure
Section	Purpose
Configuration	Set server directory, key paths, LAN subnet, SSH settings, log file
Logging	log() and fatal() functions write timestamped logs
Utilities	Fingerprint calculation, temporary files, SSH requirement checks
Dependency Installation	auto_install_deps() installs missing packages based on detected distro
Keypair Handling	ensure_server_keypair() generates private key and RustDesk-compatible public key
Remote Helpers	SSH key deployment, remote exec/copy, verification of remote keys
Abstracted Test Flow	run_self_test() validates environment without user intervention
Main Flow	LAN discovery, host deduplication, key deployment, verification, optional cleanup
Troubleshooting
Common Issues
Issue	Cause	Solution
Remote key mismatch	Remote server.pub differs from local DER format	Script retries copy; ensure server keypair is valid
SSH connection fails	Passwordless SSH not set	Deploy key automatically or manually copy $HOME/.ssh/id_ed25519.pub
Flatpak RustDesk missing	Client does not have RustDesk installed	Script prompts for installation; ensure Flathub repo is available
Dependency missing	Command not found	Script installs automatically if sudo is available; else install manually
Key Mismatch Handling

    Script calculates SHA256 fingerprints of local and remote server.pub.

    If mismatch occurs:

        Retry copy up to 2 times (configurable via VERIFY_RETRIES)

        Logs first 160 characters of remote key for debugging

    Persistent mismatch may indicate:

        Old/corrupted keys on client

        Incorrect file permissions (chmod 644 recommended)

        RustDesk not restarted after previous key update

Cleanup Examples
Remove server.pub from a single host

./rustdesk_flatpak_key_sync.sh --cleanup

    Prompts for confirmation per host

Remove key and uninstall RustDesk

    During --cleanup mode, the script asks:

Also uninstall Flatpak RustDesk on <host>?

    Answer y to uninstall

Logging

    All actions, warnings, errors, and events are logged to:

/var/log/rustdesk_flatpak_key_sync.log

    Each log entry is timestamped for audit and debugging purposes

Notes

    Script is idempotent: re-running does not break existing deployments

    Abstracted self-test ensures server key and environment are valid before deployment

    Supports Debian/Ubuntu, Fedora/RHEL, CentOS/Nobara, Arch/Manjaro

Author

Jose Melendez – 2025-11-03