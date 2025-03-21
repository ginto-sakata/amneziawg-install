# AmneziaWG Installer

A bash script for easy installation of AmneziaWG VPN on Linux servers. AmneziaWG is a WireGuard fork with advanced traffic obfuscation features to bypass DPI (Deep Packet Inspection).

> Note: This is a modified version of the original installer with enhanced features.

## Features

- **Traffic Obfuscation**: Advanced settings to bypass DPI and censorship
- **Automatic Migration**: Can detect and migrate existing WireGuard installations
- **Smart Routing**: Route all traffic or only specific websites through VPN
- **Easy Management**: Add/remove clients and manage settings through simple interface


## Quick Start

```bash
curl -fsSL https://raw.githubusercontent.com/ginto-sakata/amneziawg-install/refs/heads/master/amneziawg-install.sh -o amneziawg-install.sh && chmod +x amneziawg-install.sh && ./amneziawg-install.sh
```

## Website-Specific Routing

The installer includes a web interface for selecting which websites to route through the VPN:

- Uses [iplist](https://github.com/rekryt/iplist)

## License

This project is under the MIT License.

## Credits

Based on the [WireGuard installer](https://github.com/angristan/wireguard-install) by Stanislas Lange.
