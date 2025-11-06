# RustDesk Key Sync Scripts

Automated scripts for synchronizing a self-hosted RustDesk server's public key to LAN clients.

## Overview

This repository provides two Bash scripts to simplify the process of configuring RustDesk clients on a local network. Instead of manually copying the public key to each machine, these scripts discover clients on the network, handle authentication, and place the key in the correct location for both standard and Flatpak installations.

The primary goal is to make setting up and maintaining a self-hosted RustDesk environment as "hands-off" as possible.

## Scripts in this Repository

1.  **`rustdesk_flatpak_key_sync.sh` (Recommended)**
    *   This is the more advanced script. It supports both standard and Flatpak installations of RustDesk on client machines.
    *   It includes robust features like dependency auto-installation, SSH key bootstrapping, and network discovery using both `nmap` and `avahi-browse` (mDNS).

2.  **`rustdesk_key_sync.sh`**
    *   A simpler, more lightweight version that targets the standard `RustDesk2.toml` configuration file.
    *   This is suitable for environments where you are not using the Flatpak version of RustDesk.

## Key Features

*   **Network Discovery:** Automatically scans the LAN to find active client machines.
*   **Interactive Menu:** Lets you select which discovered hosts to sync.
*   **Auto-Dependency Installation:** Checks for required tools (`nmap`, `sshpass`, etc.) and installs them on Debian, Fedora, or Arch-based systems.
*   **SSH Bootstrap:** If key-based SSH access isn't set up, it can use a password to configure it for future passwordless access.
*   **`sudo` Context-Awareness:** Correctly handles SSH authentication even when the script is run with `sudo`.
*   **Standard & Flatpak Support:** The main script (`rustdesk_flatpak_key_sync.sh`) automatically detects the correct configuration path on each client.
*   **Detailed Logging:** Provides clear output and logs all operations to `/var/log/rustdesk_flatpak_key_sync.log`.

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
*This README has been updated by Gemini to reflect the current working version of the scripts.*
