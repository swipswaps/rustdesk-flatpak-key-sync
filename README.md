# RustDesk Flatpak Key Sync

This repository contains a powerful Bash script (`rustdesk_key_sync.sh`) designed to automate the synchronization of a self-hosted RustDesk server's public key to multiple clients on a local network (LAN). It simplifies the often tedious process of manually configuring clients to trust a new or existing self-hosted RustDesk server.

This script is particularly useful for users who run their own RustDesk server and want a seamless way to manage client connections, including those running the Flatpak version of RustDesk.

## Key Features

- **Automatic Host Discovery:** Scans the local network to find potential client machines running an SSH server.
- **Interactive Host Selection:** Presents a menu of discovered hosts, allowing you to choose which clients to sync.
- **Automatic SSH Key Bootstrapping:** If password-less (key-based) SSH access to a client is not already configured, the script will attempt to use `ssh-copy-id` to install the necessary SSH key, prompting for a password only once per client.
- **Secure Password Caching:** For convenience, client SSH passwords can be securely cached in an environment file (`~/.rustdesk_sync_env`) for the duration of the session. This file is created with secure permissions (600).
- **Context-Aware `sudo` Execution:** The script correctly handles being run with `sudo`, ensuring that all SSH and file operations are performed as the original user, not as root. This avoids common permission and context issues.
- **Cross-Platform Compatibility:** Automatically detects the Linux distribution (Debian/Ubuntu, Fedora/RHEL, Arch/Manjaro) and installs any missing dependencies like `nmap`, `sshpass`, and `avahi-utils`.
- **Flatpak and Standard Path Detection:** Intelligently determines whether the client is using the Flatpak version of RustDesk or a standard installation and places the server key in the correct directory.
- **Detailed Logging:** All actions are logged to both the console and a system log file (`/var/log/rustdesk_flatpak_key_sync.log`) for easy debugging and auditing.

## How to Use

### 1. Prerequisites

- A self-hosted RustDesk server running on a Linux machine.
- One or more Linux client machines on the same local network.
- SSH server installed and running on each client machine.
- Your user account on the server must have `sudo` privileges.

### 2. Installation

1.  **Clone this repository** to your RustDesk server machine:

    ```bash
    git clone https://github.com/swipswaps/rustdesk-flatpak-key-sync.git
    cd rustdesk-flatpak-key-sync
    ```

2.  **Make the script executable**:

    ```bash
    chmod +x rustdesk_key_sync.sh
    ```

### 3. Execution

Run the script with `sudo`. The `-E` flag is recommended to preserve the user environment, which helps the script identify the correct user home directory.

```bash
sudo -E bash rustdesk_key_sync.sh
```

**What the script will do:**

1.  **Check Dependencies:** It will first check if all required tools are installed and, if not, will attempt to install them using your system's package manager.
2.  **Generate/Verify Keys:** It ensures your RustDesk server has a valid keypair in `/var/lib/rustdesk-server`. If not, it will generate one.
3.  **Discover Hosts:** It will scan your network and list all the client machines it finds.
4.  **Interactive Menu:** It will present you with a menu of discovered hosts. You can choose to sync to a single host, all of them, or quit.
5.  **Sync Process:** For each selected host:
    *   It will try to connect via SSH using your existing SSH keys.
    *   If that fails, it will prompt you for the client's SSH password to set up key-based authentication for future runs.
    *   Once connected, it will copy the RustDesk server's public key to the correct location on the client.

## Configuration

The script includes a configuration section at the top where you can modify default settings:

- `CLIENT_USER`: The username on the client machines (default: `"owner"`).
- `LAN_SUBNET`: The network subnet to scan (default: `"192.168.1.0/24"`).

## Troubleshooting

- **SSH Connection Fails:**
    - Ensure the SSH server is running on the client machine (`sudo systemctl status sshd`).
    - Verify that the `CLIENT_USER` and password are correct.
    - Check your firewall settings on both the server and client to ensure port 22 is not blocked.

- **"Permissions on .rustdesk_sync_env are not 600" Warning:**
    - This is a security precaution. Run `chmod 600 ~/.rustdesk_sync_env` to secure the file where your temporary passwords may be cached.

- **"No hosts discovered" Message:**
    - Double-check that your `LAN_SUBNET` variable in the script is set correctly for your network.
    - Ensure the client machines are powered on and connected to the same network.

- **"Key-based auth failed" and Bootstrap Fails:**
    - This can happen if the client's SSH server is configured to disallow password authentication entirely (`PasswordAuthentication no` in `sshd_config`). In this case, you will need to manually copy your SSH key to the client first:
      ```bash
      # On your server, run this and follow the prompts
      ssh-copy-id owner@client-ip-address
      ```

## How It Works: The Technical Details

This script solves a common problem when running commands with `sudo`: **context loss**. When you run a script with `sudo`, it executes as the `root` user. If that script then tries to perform SSH operations, it will look for keys and configurations in `root`'s home directory (`/root/.ssh`), not your own user's (`/home/youruser/.ssh`).

The script cleverly works around this by:

1.  Using `SUDO_USER` to identify the original user who invoked `sudo`.
2.  Explicitly running all SSH and SCP commands within the context of that original user via `sudo -u $CALLER_USER ...`.
3.  Storing cached passwords in the user's home directory, not a system-wide location.

This ensures that your personal SSH keys and configuration are always used, allowing both key-based authentication and the one-time password bootstrap to function as expected.
