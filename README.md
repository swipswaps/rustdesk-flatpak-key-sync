# RustDesk Key Sync Scripts

Automated scripts for synchronizing a self-hosted RustDesk server's public key to LAN clients.

## Overview

This repository provides two Bash scripts to simplify the process of configuring RustDesk clients on a local network. Instead of manually copying the public key to each machine, these scripts discover clients on the network, handle authentication, and place the key in the correct location for both standard and Flatpak installations.

The primary goal is to make setting up and maintaining a self-hosted RustDesk environment as "hands-off" as possible.

### Key Problem Solved

If you've ever seen the "Connecting..." spinner time out in your RustDesk client when trying to connect to your self-hosted server, it's almost always because the client does not have the server's correct public key. These scripts fix that by automating the key distribution and, crucially, **restarting the client-side RustDesk service** to ensure the new key is loaded.

## Scripts in this Repository

1.  **`rustdesk_flatpak_key_sync.sh` (Recommended)**
    *   The more advanced script that supports both **standard and Flatpak** installations of RustDesk on client machines.
    *   Includes robust features like dependency auto-installation, SSH key bootstrapping, and network discovery.

2.  **`rustdesk_key_sync.sh`**
    *   A version that targets the standard `RustDesk2.toml` configuration file for non-Flatpak setups.

## Key Features

*   **Network Discovery:** Automatically scans the LAN to find active client machines.
*   **Interactive Menu:** Lets you select which discovered hosts to sync.
*   **Auto-Dependency Installation:** Checks for required tools (`nmap`, `sshpass`, etc.) and installs them on Debian, Fedora, or Arch-based systems.
*   **SSH Bootstrap:** If key-based SSH access isn't set up, it can use a password to configure it for future passwordless access.
*   **`sudo` Context-Awareness:** Correctly handles SSH authentication even when the script is run with `sudo`.
*   **Key Fingerprint Verification:** After syncing, the script double-checks the key on the client against the server's key to ensure the transfer was successful.
*   **Automatic Service Restart:** **(The Fix!)** After a successful sync, the script automatically restarts the RustDesk service on the client, forcing it to load the new key.
*   **Detailed Logging:** Provides clear, color-coded output and logs all operations to `/var/log/rustdesk_flatpak_key_sync.log`.

## Usage

1.  **Clone the repository** to your RustDesk server:
    ```bash
    git clone https://github.com/swipswaps/rustdesk-flatpak-key-sync.git
    cd rustdesk-flatpak-key-sync
    ```

2.  **Make the script executable**:
    ```bash
    chmod +x rustdesk_flatpak_key_sync.sh
    ```

3.  **Run the script with `sudo -E`**:
    The `-E` flag preserves your user environment, which is crucial for SSH authentication.
    ```bash
    sudo -E bash rustdesk_flatpak_key_sync.sh
    ```

4.  **Follow the prompts**:
    *   The script will discover hosts on your network.
    *   Select the hosts you want to sync from the menu.
    *   If prompted, enter the SSH password for the client user. The script will handle the rest.

## Configuration

You can edit the script to change the default configuration variables at the top of the file:
*   `CLIENT_USER`: The SSH username on the client machines (default: `"owner"`).
*   `LAN_SUBNET`: The network range to scan (default: `"192.168.1.0/24"`).

---
*This README has been updated by Gemini to reflect the latest script upgrades, including key verification and automatic service restarts.*
