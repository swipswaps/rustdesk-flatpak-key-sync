# RustDesk Flatpak Key Sync

**File:** `rustdesk_flatpak_key_sync.sh`  
**Author:** Jose Melendez  
**Version:** 2.0 (UX+Lint+Parallel)  
**Date:** 2025-11-02  

---

## 📘 Overview

This script automates **RustDesk server keypair generation** and **propagation of the server public key** to all LAN clients running RustDesk (Flatpak version).  

It detects clients automatically, establishes SSH connectivity, pushes the updated key, validates fingerprints, fixes permissions, and restarts the Flatpak app — all with real-time colored logs and robust fault-handling.

---

## 🚀 Features

✅ Auto-generates or replaces RustDesk server keypair  
✅ Converts to RustDesk’s Base64 public key format  
✅ Backs up previous keypairs safely  
✅ Discovers LAN clients automatically via `nmap`  
✅ Deploys SSH keys automatically with `ssh-copy-id`  
✅ Pushes new key to Flatpak path on each client  
✅ Restarts the RustDesk client cleanly  
✅ Verifies key fingerprints (multiple retries)  
✅ Logs all activity to `/var/log/rustdesk_flatpak_key_sync.log`  
✅ Supports parallel deployment (configurable threads)  

---

## 🧩 Prerequisites

### On the **server**
Ensure these commands exist:
```bash
sudo apt install -y nmap openssh-client openssl
# or Fedora/RHEL:
sudo dnf install -y nmap openssh openssl
