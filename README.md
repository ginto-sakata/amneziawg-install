# AmneziaWG Installer & Management Script

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A comprehensive Bash script for easily installing, migrating from WireGuard, and managing an **AmneziaWG** server on Linux.

AmneziaWG is a fork of WireGuard designed to enhance privacy and bypass Deep Packet Inspection (DPI) through advanced traffic obfuscation techniques. This script simplifies the setup and ongoing management process.

## Key Features

*   **Easy Installation:** Single command setup for popular Linux distributions (Debian, Ubuntu, CentOS, RHEL, Fedora).
*   **WireGuard Migration:** Detects existing WireGuard installations and offers an interactive migration process (server settings reuse, new client configs generated).
*   **Advanced Obfuscation:**
    *   Comes with sensible default presets (Mobile, Standard).
    *   Allows fine-tuning of AmneziaWG parameters (Jc, Jmin, Jmax, S1, S2, H1-H4, MTU) via a menu.
*   **Flexible Client Routing (AllowedIPs):**
    *   **All Traffic:** Route all client traffic through the VPN (Default).
    *   **Specific Services:** **(Interactive Web UI)** Select specific websites/services during setup or later using a temporary web server hosted by the script. No need to manually create IP lists!
    *   **Russia Blocked List:** Automatically fetch and use a curated list of IPs/CIDRs commonly blocked in Russia.
    *   **Custom:** Provide your own comma-separated list of CIDRs.
*   **Client Management:**
    *   Add new clients easily.
    *   List existing clients and their VPN IPs.
    *   Revoke client access.
    *   Regenerate configuration (new keys) for specific clients or all clients.
*   **QR Code Support:** Displays QR codes for easy import into AmneziaWG mobile apps (requires `qrencode` package).
*   **System Integration:** Configures system forwarding, firewall rules (`firewalld` or `iptables`), and systemd services.
*   **Uninstall Option:** Cleanly removes AmneziaWG packages and configurations.

## Quick Start

Run the following command on your server as **root**:

```bash
curl -fsSL https://raw.githubusercontent.com/ginto-sakata/amneziawg-install/master/amneziawg-install.sh -o amneziawg-install.sh && chmod +x amneziawg-install.sh && sudo ./amneziawg-install.sh
```

The script will guide you through the installation process, asking necessary questions about your network configuration, desired DNS servers, and default client traffic routing.

## Requirements / Dependencies

The script attempts to install dependencies automatically.

**Core Dependencies:**

*   `bash` (v4+)
*   `curl` or `wget` (for downloading the script itself and potentially IP lists)
*   `iproute2` (for `ip` command)
*   `grep`, `sed`, `awk`, `cut`, `tr` (standard core utilities)
*   `systemd` (for service management)
*   `openssl` (for random data generation)

**AmneziaWG & Build:**

*   `amneziawg` package (installed from Amnezia PPA/Repo)
*   `dkms`
*   `make`, `gcc`
*   `linux-headers` (matching your running kernel - script tries to install `linux-headers-$(uname -r)` or `linux-headers-generic`)

**Optional Features:**

*   **QR Codes:** `qrencode`
*   **Specific Service Routing (Web UI):**
    *   `git` (preferred for fetching data) OR `unzip` + (`curl` or `wget`)
    *   `jq` (for processing IP list data)
    *   `python3` or `python` or `php` (for running the temporary web server)

**Distribution Specific:**

*   **Debian/Ubuntu:** `software-properties-common`, `python3-launchpadlib`, `gnupg` (for PPA management)
*   **RHEL/CentOS/Fedora:** `epel-release`, `dnf-command(config-manager)` or `yum-utils` (potentially needed for repo management), `kernel-devel`

## Usage

1.  **Installation:** Run the Quick Start command. Follow the prompts.
2.  **Management:** Run the script again after installation:
    ```bash
    sudo ./amneziawg-install.sh
    ```
    This will present the management menu where you can add/list/revoke clients, change obfuscation settings, update default routing, or uninstall.

### Client Configuration Files

Client `.conf` files are typically saved in the home directory of the user who ran the script (or `/root` if run directly as root) inside an `amneziawg` subdirectory (e.g., `/root/amneziawg/` or `/home/your_user/amneziawg/`).

### Specific Service Routing (Web UI)

If you choose "Route only specific websites/services" during setup or via the management menu:

1.  The script will install necessary tools (`git`/`unzip`, `jq`, `python`/`php`).
2.  It will download website data and IP lists (`iplist` project).
3.  A temporary web server will start. The script will show you the URL (e.g., `http://YOUR_SERVER_IP:8080`).
4.  **Open the URL in your browser.**
5.  Select the desired services using the checkboxes.
6.  Click **"Generate IP List"** at the bottom.
7.  **Copy** the generated comma-separated list of CIDRs.
8.  **Paste** the list into the terminal where the script is waiting.
9.  Press **Ctrl+C** in the terminal to stop the web server and continue the script.

## Migration from WireGuard

If the script detects an existing WireGuard configuration (`/etc/wireguard/*.conf`):

1.  It will offer to migrate.
2.  **Server Settings:** It attempts to reuse the server's VPN IP addresses and listening port.
3.  **Private Key:**
    *   If `/etc/wireguard/params` (from `angristan/wireguard-install`) exists, it tries to read the key from there.
    *   Otherwise, it will ask for the **path** to the server's WireGuard private key file (more secure than pasting the key).
    *   If the key cannot be found or provided, a **new key pair** will be generated for AmneziaWG (existing clients will need new configs).
4.  **Clients:** Client private keys **cannot** be migrated. The script will generate **new** `.conf` files for each detected peer with new keys but using the original peer's public key and allowed IPs on the *server side*. Users will need to use these *new* configuration files.
5.  **Old Configs:** Original WireGuard files remain in `/etc/wireguard/` but the `wg-quick@...` service is stopped and disabled.

## Troubleshooting

*   **Service Fails to Start:** Check logs using `journalctl -u awg-quick@<interface_name>` (e.g., `journalctl -u awg-quick@awg0`). Also verify the configuration file (`/etc/amnezia/amneziawg/<interface_name>.conf`). Ensure kernel headers were correctly installed for DKMS module building.
*   **Web Server Fails:** Ensure dependencies (`git` or `unzip`+`curl`/`wget`, `jq`, `python`/`php`) are installed and that port `8080` is accessible from your browser (check server firewall if needed, although the server itself runs locally).
*   **Incorrect IPs:** If auto-detected IPs/interface are wrong, you can manually specify them during the initial questions.

## License

This project is distributed under the MIT License. See the LICENSE file for details.

## Credits

*   Based on the original [wireguard-install script](https://github.com/angristan/wireguard-install) by Stanislas Lange (@angristan).
*   Uses IP address data from the [iplist project](https://github.com/rekryt/iplist).
*   Uses the curated blocklist from [Antifilter.download](https://antifilter.download/list/allyouneed.lst).
*   AmneziaWG developed by the [AmneziaVPN team](https://github.com/amnezia-vpn).