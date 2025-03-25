#!/bin/bash

# AmneziaWG server installer
# Based on https://github.com/angristan/wireguard-install

RED='\033[0;31m'
ORANGE='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

function isRoot() {
	if [ "${EUID}" -ne 0 ]; then
		echo "You need to run this script as root"
		exit 1
	fi
}

function checkVirt() {
	function openvzErr() {
		echo "OpenVZ is not supported"
		exit 1
	}
	function lxcErr() {
		echo "LXC is not supported (yet)."
		echo "AmneziaWG can technically run in an LXC container,"
		echo "but the kernel module has to be installed on the host,"
		echo "the container has to be run with some specific parameters"
		echo "and only the tools need to be installed in the container."
		exit 1
	}
	if command -v virt-what &>/dev/null; then
		if [ "$(virt-what)" == "openvz" ]; then
			openvzErr
		fi
		if [ "$(virt-what)" == "lxc" ]; then
			lxcErr
		fi
	else
		if [ "$(systemd-detect-virt)" == "openvz" ]; then
			openvzErr
		fi
		if [ "$(systemd-detect-virt)" == "lxc" ]; then
			lxcErr
		fi
	fi
}

function checkOS() {
	source /etc/os-release
	OS="${ID}"
	
	# Debian-based
	if [[ ${OS} == "debian" || ${OS} == "raspbian" ]]; then
		if [[ ${VERSION_ID} -lt 10 ]]; then
			echo "Your version of Debian (${VERSION_ID}) is not supported. Please use Debian 10 Buster or later"
			exit 1
		fi
		OS=debian
	elif [[ ${OS} == "ubuntu" || ${OS} == "linuxmint" ]]; then
		RELEASE_YEAR=$(echo "${VERSION_ID}" | cut -d'.' -f1)
		if [[ ${RELEASE_YEAR} -lt 18 ]]; then
			echo "Your version (${VERSION_ID}) is not supported. Please use version 18.04 or later"
			exit 1
		fi
		OS=ubuntu
	# RHEL-based
	elif [[ ${OS} == "rhel" || ${OS} == "centos" || ${OS} == "fedora" || ${OS} == "opensuse-leap" ]]; then
		echo -e "${GREEN}Installing EPEL repository...${NC}"
		if [[ ${OS} == "fedora" ]]; then
			dnf install -y epel-release
		else
			yum install -y epel-release
		fi
		OS=rhel
	else
		echo "Unsupported operating system"
		exit 1
	fi
}

function setupDebSrc() {
    if [[ ${OS} == "ubuntu" ]]; then
        if ! grep -q "^Types:.*deb-src" /etc/apt/sources.list.d/ubuntu.sources; then
            echo "deb-src repositories are not enabled. They are required for AmneziaWG installation."
            read -rp "Would you like to enable deb-src repositories? [y/n]: " -i "y" ENABLE_SRC
            if [[ $ENABLE_SRC == 'y' ]]; then
                sed -i 's/^Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/ubuntu.sources
                apt-get update
            else
                echo "deb-src repositories are required. Installation cannot continue."
                exit 1
            fi
        fi
    elif [[ ${OS} == "debian" ]]; then
        if ! grep -q "^deb-src" /etc/apt/sources.list; then
            echo "deb-src repositories are not enabled. They are required for AmneziaWG installation."
            read -rp "Would you like to enable deb-src repositories? [y/n]: " -i "y" ENABLE_SRC
            if [[ $ENABLE_SRC == 'y' ]]; then
                sed -i 's/^#\s*deb-src/deb-src/' /etc/apt/sources.list
                apt-get update
            else
                echo "deb-src repositories are required. Installation cannot continue."
                exit 1
            fi
        fi
    fi
}

function getHomeDirForClient() {
	local CLIENT_NAME=$1

	if [ -z "${CLIENT_NAME}" ]; then
		echo "Error: getHomeDirForClient() requires a client name as argument"
		exit 1
	fi

	# Home directory of the user, where the client configuration will be written
	if [ -e "/home/${CLIENT_NAME}" ]; then
		# if $1 is a user name
		HOME_DIR="/home/${CLIENT_NAME}"
	elif [ "${SUDO_USER}" ]; then
		# if not, use SUDO_USER
		if [ "${SUDO_USER}" == "root" ]; then
			# If running sudo as root
			HOME_DIR="/root"
		else
			HOME_DIR="/home/${SUDO_USER}"
		fi
	else
		# if not SUDO_USER, use /root
		HOME_DIR="/root"
	fi

	echo "$HOME_DIR"
}

function detectExistingWireGuard() {
    # Check for WireGuard configuration files first
    if [[ -d /etc/wireguard ]] && [[ -n $(find /etc/wireguard -name "*.conf" 2>/dev/null) ]]; then
        echo -e "${ORANGE}WireGuard is already installed and configured on this system.${NC}"
        echo ""
        
        # Find configuration type
        if [[ -f /etc/wireguard/params ]]; then
            echo -e "Detected WireGuard installed using the wireguard-install script."
            WIREGUARD_TYPE="script"
        else
            echo -e "Detected standard WireGuard installation."
            WIREGUARD_TYPE="standard"
        fi
        
        echo -e "${RED}AmneziaWG will replace your existing WireGuard installation.${NC}"
        echo -e "${GREEN}Your client configurations will be copied to ~/amneziawg and renamed to use awg0 interface.${NC}"
        read -rp "Do you want to proceed with migration? [y/n]: " -i "y" CONFIRM
        if [[ $CONFIRM == 'y' ]]; then
            migrateWireGuard "${WIREGUARD_TYPE}"
        else
            echo "Installation cancelled."
                exit 0
        fi
    # Check if main wireguard package is installed
    elif dpkg -l 2>/dev/null | grep -q "^ii.*wireguard " || (command -v rpm &>/dev/null && rpm -qa | grep -q "^wireguard-[0-9]"); then
        echo -e "${ORANGE}WireGuard package is installed but no configurations found.${NC}"
        echo -e "${GREEN}Removing WireGuard before installing AmneziaWG...${NC}"
        
        # Remove WireGuard packages
        if [[ ${OS} == "ubuntu" || ${OS} == "debian" ]]; then
            apt-get remove -y wireguard
            apt-get autoremove -y  # This should remove wireguard-tools
        elif [[ ${OS} == "rhel" ]]; then
            dnf remove -y wireguard
            dnf autoremove -y
        fi
        
        echo -e "${GREEN}WireGuard packages removed. Proceeding with AmneziaWG installation...${NC}"
    fi
}

function migrateWireGuard() {
    local installation_type=$1
    echo -e "${GREEN}Starting WireGuard to AmneziaWG migration...${NC}"
    
    # Find WireGuard interface
    WG_INTERFACE=$(find /etc/wireguard -name "*.conf" -exec basename {} .conf \; | head -n 1)
    if [[ -z ${WG_INTERFACE} ]]; then
        echo -e "${RED}No WireGuard interface configuration found${NC}"
        exit 1
    fi
    
    # Extract common configuration regardless of installation type
        SERVER_PUB_NIC=$(ip -4 route ls | grep default | awk '/dev/ {for (i=1; i<=NF; i++) if ($i == "dev") print $(i+1)}' | head -1)
        SERVER_WG_IPV4=$(grep "Address" "/etc/wireguard/${WG_INTERFACE}.conf" | awk '{print $3}' | cut -d'/' -f1)
        SERVER_WG_IPV6=$(grep "Address" "/etc/wireguard/${WG_INTERFACE}.conf" | awk '{print $4}' | cut -d'/' -f1)
        SERVER_PORT=$(grep "ListenPort" "/etc/wireguard/${WG_INTERFACE}.conf" | awk '{print $3}')
    
    # Set default interface name if not specified
    SERVER_WG_NIC=${SERVER_WG_NIC:-awg0}
    
    # Get home directory for storing client configs
    HOME_DIR=$(getHomeDirForClient "${SUDO_USER:-root}")
    CLIENT_CONFIG_DIR="${HOME_DIR}/amneziawg"
    mkdir -p "${CLIENT_CONFIG_DIR}"
    chmod 700 "${CLIENT_CONFIG_DIR}"
    
    # Handle private key based on installation type
    if [[ ${installation_type} == "script" ]]; then
        # For wireguard-install script, we can load the params
        source /etc/wireguard/params
        # Get additional settings from params
        CLIENT_DNS_1=${CLIENT_DNS_1:-1.1.1.1}
        CLIENT_DNS_2=${CLIENT_DNS_2:-1.0.0.1}
        ALLOWED_IPS=${ALLOWED_IPS:-0.0.0.0/0}
        
        # Don't copy client configs - just read server config for settings
        echo -e "${GREEN}Reading WireGuard server configuration for migration...${NC}"
    else
        # For standard WireGuard, ask for the private key
        echo -e "${ORANGE}For full migration, the server's private key is required.${NC}"
        echo -e "${ORANGE}Without it, you won't be able to add new clients after migration.${NC}"
        read -rp "Do you have the server's private key? [y/n]: " -i "y" HAS_PRIVATE_KEY
        
        if [[ $HAS_PRIVATE_KEY == 'y' ]]; then
            read -rp "Enter the server's private key: " SERVER_PRIV_KEY
            # Validate the key
            if ! echo "${SERVER_PRIV_KEY}" | wg pubkey >/dev/null 2>&1; then
                echo -e "${RED}Invalid private key provided. Generating a new key pair.${NC}"
                SERVER_PRIV_KEY=$(wg genkey)
                SERVER_PUB_KEY=$(echo "${SERVER_PRIV_KEY}" | wg pubkey)
                echo -e "${ORANGE}New clients will need updated server public key: ${SERVER_PUB_KEY}${NC}"
            else
                SERVER_PUB_KEY=$(echo "${SERVER_PRIV_KEY}" | wg pubkey)
            fi
        else
            echo -e "${ORANGE}Generating new key pair for AmneziaWG server...${NC}"
            SERVER_PRIV_KEY=$(wg genkey)
            SERVER_PUB_KEY=$(echo "${SERVER_PRIV_KEY}" | wg pubkey)
            echo -e "${ORANGE}New clients will need updated server public key: ${SERVER_PUB_KEY}${NC}"
        fi
        
        # Set default values for other settings
        CLIENT_DNS_1=1.1.1.1
        CLIENT_DNS_2=1.0.0.1
        ALLOWED_IPS=0.0.0.0/0
    fi
    
    # Create AmneziaWG params file
    mkdir -p /etc/amnezia/amneziawg/
    echo "SERVER_PUB_IP=${SERVER_PUB_IP}
SERVER_PUB_NIC=${SERVER_PUB_NIC}
SERVER_WG_NIC=${SERVER_WG_NIC}
SERVER_WG_IPV4=${SERVER_WG_IPV4}
SERVER_WG_IPV6=${SERVER_WG_IPV6}
SERVER_PORT=${SERVER_PORT}
SERVER_PRIV_KEY=${SERVER_PRIV_KEY}
SERVER_PUB_KEY=${SERVER_PUB_KEY}
CLIENT_DNS_1=${CLIENT_DNS_1}
CLIENT_DNS_2=${CLIENT_DNS_2}
CLIENT_DNS_IPV6_1=${CLIENT_DNS_IPV6_1:-2606:4700:4700::1111}
CLIENT_DNS_IPV6_2=${CLIENT_DNS_IPV6_2:-2606:4700:4700::1001}
CLIENT_CONFIG_DIR=${CLIENT_CONFIG_DIR}
ALLOWED_IPS=${ALLOWED_IPS}" > /etc/amnezia/amneziawg/params
    
    # Secure the params file
    chmod 600 /etc/amnezia/amneziawg/params
    chmod 700 /etc/amnezia/amneziawg
    
    # Migrate peer configurations
    migratePeers "${installation_type}" "${WG_INTERFACE}"
    
    # Stop WireGuard services but don't remove configs
    echo -e "${GREEN}Stopping WireGuard services...${NC}"
    
    for interface in $(find /etc/wireguard -name "*.conf" -exec basename {} .conf \;); do
        echo -e "Stopping ${interface} service..."
        systemctl stop "wg-quick@${interface}" 2>/dev/null
        systemctl disable "wg-quick@${interface}" 2>/dev/null
    done
    
    echo -e "${GREEN}WireGuard services stopped. Original configuration files are preserved.${NC}"
    
    # Start and enable AmneziaWG service
    echo -e "${GREEN}Starting AmneziaWG service...${NC}"
    systemctl start "awg-quick@${SERVER_WG_NIC}"
    systemctl enable "awg-quick@${SERVER_WG_NIC}"
    
    # Verify service is running
    if systemctl is-active --quiet "awg-quick@${SERVER_WG_NIC}"; then
        echo -e "${GREEN}AmneziaWG service is running.${NC}"
    else
        echo -e "${RED}AmneziaWG service failed to start. Try running 'systemctl start awg-quick@${SERVER_WG_NIC}' manually.${NC}"
    fi
    
    echo -e "${GREEN}Migration completed successfully!${NC}"
    echo -e "${GREEN}Your AmneziaWG server is now running.${NC}"
    echo -e "${ORANGE}NOTE: Original WireGuard configurations remain at /etc/wireguard/${NC}"
}

function migratePeers() {
    local installation_type=$1
    local interface_name=$2
    
    if [[ ! -f "/etc/wireguard/${interface_name}.conf" ]]; then
        echo -e "${RED}Interface configuration file not found.${NC}"
        return
    fi
    
    echo -e "${GREEN}Migrating peer configurations...${NC}"
    
    # Create base server configuration
    echo "[Interface]
Address = ${SERVER_WG_IPV4}/24,${SERVER_WG_IPV6}/64
ListenPort = ${SERVER_PORT}
PrivateKey = ${SERVER_PRIV_KEY}
Jc = ${JC}
Jmin = ${JMIN}
Jmax = ${JMAX}
H1 = ${H1}
H2 = ${H2}
H3 = ${H3}
H4 = ${H4}
MTU = ${MTU}" >"/etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf"

    if pgrep firewalld; then
        FIREWALLD_IPV4_ADDRESS=$(echo "${SERVER_WG_IPV4}" | cut -d"." -f1-3)".0"
        FIREWALLD_IPV6_ADDRESS=$(echo "${SERVER_WG_IPV6}" | sed 's/:[^:]*$/:0/')
        echo "PostUp = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC} && firewall-cmd --add-port ${SERVER_PORT}/udp && firewall-cmd --add-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --add-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'
PostDown = firewall-cmd --zone=public --remove-interface=${SERVER_WG_NIC} && firewall-cmd --remove-port ${SERVER_PORT}/udp && firewall-cmd --remove-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --remove-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'" >>"/etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf"
    else
        echo "PostUp = iptables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostUp = ip6tables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostUp = ip6tables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = iptables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = ip6tables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostDown = ip6tables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE" >>"/etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf"
    fi
    
    # Track clients to prevent duplicates
    declare -A migrated_clients
    
    if [[ ${installation_type} == "script" ]]; then
        # For wireguard-install script, peer information includes client names
        awk '/^### Client/{client=$3; next} /^\[Peer\]/{peer=1; next} peer==1 && NF>0{print client";"$0}' "/etc/wireguard/${interface_name}.conf" > /tmp/peers.txt
        
        # Process each peer line
        client_name=""
        client_config=""
        while IFS=';' read -r name config_line; do
            if [[ -n ${name} ]]; then
                if [[ ${name} != ${client_name} ]]; then
                    # New client, save previous client if exists
                    if [[ -n ${client_name} && -n ${client_config} ]]; then
                        # Check if we already migrated this client
                        if [[ -z ${migrated_clients[${client_name}]} ]]; then
                            echo -e "${GREEN}Migrating client: ${client_name}${NC}"
                            saveClientConfig "${client_name}" "${client_config}"
                            migrated_clients[${client_name}]=1
                        else
                            echo -e "${ORANGE}Skipping duplicate client: ${client_name}${NC}"
                        fi
                    fi
                    # Start new client
                    client_name=${name}
                    client_config="PublicKey = $(echo "${config_line}" | grep -oP 'PublicKey = \K[a-zA-Z0-9+/]{43}=')"
                    if echo "${config_line}" | grep -q "PresharedKey"; then
                        client_config="${client_config}
PresharedKey = $(echo "${config_line}" | grep -oP 'PresharedKey = \K[a-zA-Z0-9+/]{43}=')"
                    fi
                    client_config="${client_config}
AllowedIPs = $(echo "${config_line}" | grep -oP 'AllowedIPs = \K[0-9\./,:]+')"
                else
                    # Continue existing client
                    if echo "${config_line}" | grep -q "PublicKey"; then
                        client_config="${client_config}
PublicKey = $(echo "${config_line}" | grep -oP 'PublicKey = \K[a-zA-Z0-9+/]{43}=')"
                    elif echo "${config_line}" | grep -q "PresharedKey"; then
                        client_config="${client_config}
PresharedKey = $(echo "${config_line}" | grep -oP 'PresharedKey = \K[a-zA-Z0-9+/]{43}=')"
                    elif echo "${config_line}" | grep -q "AllowedIPs"; then
                        client_config="${client_config}
AllowedIPs = $(echo "${config_line}" | grep -oP 'AllowedIPs = \K[0-9\./,:]+')"
                    fi
                fi
            fi
        done < /tmp/peers.txt
        
        # Save last client
        if [[ -n ${client_name} && -n ${client_config} ]]; then
            # Check if we already migrated this client
            if [[ -z ${migrated_clients[${client_name}]} ]]; then
                echo -e "${GREEN}Migrating client: ${client_name}${NC}"
                saveClientConfig "${client_name}" "${client_config}"
                migrated_clients[${client_name}]=1
            else
                echo -e "${ORANGE}Skipping duplicate client: ${client_name}${NC}"
            fi
        fi
    else
        # For standard WireGuard, we need to generate client names from public keys
        awk '/^\[Peer\]/{if(p) print s; s=""; p=1; next} p&&NF>0{s=s$0"\n"}END{if(p) print s}' "/etc/wireguard/${interface_name}.conf" > /tmp/peers.txt
        
        # Process each peer block
        client_counter=1
        while read -r peer_block; do
            peer_pub_key=$(echo "${peer_block}" | grep -oP 'PublicKey = \K[a-zA-Z0-9+/]{43}=' | head -1)
            base_name="client_$(echo "${peer_pub_key}" | cut -c1-8)"
            
            # Make sure we don't have duplicate client names
            client_name="${base_name}"
            while [[ -n ${migrated_clients[${client_name}]} ]]; do
                client_name="${base_name}_${client_counter}"
                ((client_counter++))
            done
            
            echo -e "${GREEN}Migrating client: ${client_name}${NC}"
            saveClientConfig "${client_name}" "${peer_block}"
            migrated_clients[${client_name}]=1
        done < /tmp/peers.txt
    fi
    
    rm -f /tmp/peers.txt
    
    echo -e "${GREEN}Migration complete. Migrated ${#migrated_clients[@]} unique peer configurations.${NC}"
}

function saveClientConfig() {
    local client_name=$1
    local peer_config=$2
    
    # Extract public key from peer config
    local peer_pub_key=$(echo "${peer_config}" | grep -oP 'PublicKey = \K[a-zA-Z0-9+/]{43}=' | head -1)
    
    echo -e "${GREEN}Converting client configuration for ${client_name} to AmneziaWG format...${NC}"
    
    # Create client config
    echo "[Interface]
PrivateKey = ${CLIENT_PRIV_KEY:-$(wg genkey)}
Address = ${CLIENT_WG_IPV4}/32,${CLIENT_WG_IPV6}/128
DNS = ${CLIENT_DNS_1},${CLIENT_DNS_2},${CLIENT_DNS_IPV6_1},${CLIENT_DNS_IPV6_2}
Jc = ${JC}
Jmin = ${JMIN}
Jmax = ${JMAX}
H1 = ${H1}
H2 = ${H2}
H3 = ${H3}
H4 = ${H4}
MTU = ${MTU}

[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
Endpoint = ${SERVER_PUB_IP}:${SERVER_PORT}
AllowedIPs = ${ALLOWED_IPS}" > "${CLIENT_CONFIG_DIR}/${client_name}.conf"
    
    # Add peer to server config
    echo -e "\n### Client ${client_name}
[Peer]
${peer_config}" >> "/etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf"
    
    echo -e "${GREEN}Migrated peer: ${client_name} to AmneziaWG format${NC}"
}

function initialCheck() {
	isRoot
	checkOS
	checkVirt
    
    # Check for existing WireGuard configurations
    detectExistingWireGuard
}

function installQuestions() {
	# Clear screen before welcome message
	clear
	echo ""
	echo "╔═══════════════════════════════════════════════╗"
	echo "║        Welcome to the AmneziaWG Installer     ║"
	echo "╚═══════════════════════════════════════════════╝"
	echo ""
	echo "I need to ask you a few questions before starting the setup."
	echo "You can keep the default options and just press enter if you are ok with them."
	echo ""

	# Ask about IPv6 support first
	echo -e "${GREEN}Do you want to enable IPv6 support?${NC}"
	while true; do
		read -rp "Enable IPv6? [y/n]: " -i "y" ENABLE_IPV6
		if [[ ${ENABLE_IPV6} =~ ^[yn]$ ]]; then
			break
		fi
	done
	echo ""

	# Try to get hostname
	SERVER_HOSTNAME=$(hostname -f 2>/dev/null)
	if [[ -n ${SERVER_HOSTNAME} ]]; then
		echo -e "${GREEN}Server domain/hostname detected: ${SERVER_HOSTNAME}${NC}"
		echo "This can be used as the endpoint URL for clients to connect."
		while true; do
			read -rp "Use domain/hostname instead of IP? [y/n]: " -i "y" USE_HOSTNAME
			if [[ ${USE_HOSTNAME} =~ ^[yn]$ ]]; then
				break
			fi
		done
		
		if [[ ${USE_HOSTNAME} == 'y' ]]; then
			read -rp "Domain/hostname for server endpoint: " -e -i "${SERVER_HOSTNAME}" SERVER_PUB_IP
		fi
	fi
	
	# Only ask for IP if we're not using a hostname
	if [[ ${USE_HOSTNAME} != 'y' ]]; then
		# Detect public IPv4 address and pre-fill for the user
		IPV4_ADDR=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | awk '{print $1}' | head -1)
		if [[ -n ${IPV4_ADDR} ]]; then
			read -rp "Public IPv4 address (for client connections): " -e -i "${IPV4_ADDR}" SERVER_PUB_IPV4
			SERVER_PUB_IP=${SERVER_PUB_IPV4}
		else
			read -rp "Public IPv4 address (for client connections): " SERVER_PUB_IPV4
			SERVER_PUB_IP=${SERVER_PUB_IPV4}
		fi
		
		# Only prompt for IPv6 public address if IPv6 is enabled
		if [[ ${ENABLE_IPV6} == 'y' ]]; then
			IPV6_ADDR=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
			if [[ -n ${IPV6_ADDR} ]]; then
				read -rp "Public IPv6 address (optional): " -e -i "${IPV6_ADDR}" SERVER_PUB_IPV6
			else
				read -rp "Public IPv6 address (optional): " SERVER_PUB_IPV6
			fi
		fi
	fi

	# Detect public interface and pre-fill for the user
	SERVER_NIC="$(ip -4 route ls | grep default | awk '/dev/ {for (i=1; i<=NF; i++) if ($i == "dev") print $(i+1)}' | head -1)"
	until [[ ${SERVER_PUB_NIC} =~ ^[a-zA-Z0-9_]+$ ]]; do
		read -rp "Public network interface: " -e -i "${SERVER_NIC}" SERVER_PUB_NIC
	done

	until [[ ${SERVER_WG_NIC} =~ ^[a-zA-Z0-9_]+$ && ${#SERVER_WG_NIC} -lt 16 ]]; do
		read -rp "AmneziaWG interface name: " -e -i awg0 SERVER_WG_NIC
	done

	until [[ ${SERVER_WG_IPV4} =~ ^([0-9]{1,3}\.){3} ]]; do
		read -rp "Internal VPN subnet IPv4 server address: " -e -i 10.0.0.1 SERVER_WG_IPV4
	done

	# Only ask for IPv6 address if IPv6 is enabled
	if [[ ${ENABLE_IPV6} == 'y' ]]; then
	until [[ ${SERVER_WG_IPV6} =~ ^([a-f0-9]{1,4}:){3,4}: ]]; do
			read -rp "Internal VPN subnet IPv6 server address: " -e -i fd42:42:42::1 SERVER_WG_IPV6
	done
	else
		# Set a default IPv6 address that won't be used
		SERVER_WG_IPV6="fd42:42:42::1"
	fi

	# Generate random number within private ports range
	RANDOM_PORT=$(shuf -i49152-65535 -n1)
	until [[ ${SERVER_PORT} =~ ^[0-9]+$ ]] && [ "${SERVER_PORT}" -ge 1 ] && [ "${SERVER_PORT}" -le 65535 ]; do
		read -rp "Server AmneziaWG port [1-65535]: " -e -i "${RANDOM_PORT}" SERVER_PORT
	done

	# Cloudflare DNS by default
	until [[ ${CLIENT_DNS_1} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
		read -rp "First DNS resolver to use for the clients (IPv4): " -e -i 1.1.1.1 CLIENT_DNS_1
	done
	until [[ ${CLIENT_DNS_2} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
		read -rp "Second DNS resolver to use for the clients (IPv4): " -e -i 1.0.0.1 CLIENT_DNS_2
		if [[ ${CLIENT_DNS_2} == "" ]]; then
			CLIENT_DNS_2="${CLIENT_DNS_1}"
		fi
	done

	# Cloudflare IPv6 DNS
	if [[ ${ENABLE_IPV6} == 'y' ]]; then
		read -rp "First DNS resolver to use for the clients (IPv6): " -e -i 2606:4700:4700::1111 CLIENT_DNS_IPV6_1
		read -rp "Second DNS resolver to use for the clients (IPv6): " -e -i 2606:4700:4700::1001 CLIENT_DNS_IPV6_2
	else
		CLIENT_DNS_IPV6_1=""
		CLIENT_DNS_IPV6_2=""
	fi

	echo ""
	echo -e "${GREEN}Configure default traffic routing for new clients${NC}"
	echo "1) Route all traffic (recommended)"
	echo "2) Route specific websites only"
    echo "3) Route websites blocked in Russia"
	read -rp "Select an option [1-3]: " ROUTE_OPTION
	
	if [[ ${ROUTE_OPTION} == "2" ]]; then
		startWebServer
		echo "Please paste the IP list generated from the website:"
		read -rp "IP List: " ALLOWED_IPS
		
		# Validate input format
		if [[ ! ${ALLOWED_IPS} =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}(,([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2})*$ ]]; then
			echo "Invalid format. Using default (all traffic)"
			ALLOWED_IPS="0.0.0.0/0"
		fi
	else
		ALLOWED_IPS="0.0.0.0/0"
	fi
	
	if [[ ${ENABLE_IPV6} == "y" ]]; then
		ALLOWED_IPS="${ALLOWED_IPS},::/0"
	fi
	
	echo ""
	echo -e "${GREEN}Okay, that was all I needed. We are ready to setup your AmneziaWG server now.${NC}"
	echo -e "${GREEN}You will be able to generate a client at the end of the installation.${NC}"
	read -n1 -r -p "Press any key to start the installation..."
	echo ""
	
	# Set default AmneziaWG advanced settings instead of asking
	setDefaultAmneziaSettings
	
	echo ""	
	# Choose server's port
	echo -e "${GREEN}What port do you want AmneziaWG to listen to?${NC}"
	read -rp "Port: " -e -i "51820" SERVER_PORT
	echo ""
	
	# Ask about traffic routing
	echo -e "${GREEN}By default, AmneziaWG will route all traffic through the VPN.${NC}"
	echo "You can specify different IP ranges if you want to exclude some traffic from the VPN."
	read -rp "Traffic to route through VPN (default is all traffic): " -e -i "0.0.0.0/0, ::/0" ALLOWED_IPS
	echo ""
	
	# Configure DNS for client devices
	echo -e "${GREEN}Select DNS servers for clients:${NC}"
	echo " 1) Google (Recommended)"
	echo " 2) Cloudflare"
	echo " 3) OpenDNS"
	echo " 4) AdGuard DNS (Blocks ads)"
	echo " 5) Custom"
	read -rp "DNS option [1-5]: " -e -i "1" DNS_CHOICE

	# Configure client DNS servers based on selection
	if [[ ${DNS_CHOICE} == "2" ]]; then
		CLIENT_DNS_1="1.1.1.1"
		CLIENT_DNS_2="1.0.0.1"
		CLIENT_DNS_IPV6_1="2606:4700:4700::1111"
		CLIENT_DNS_IPV6_2="2606:4700:4700::1001"
	elif [[ ${DNS_CHOICE} == "3" ]]; then
		CLIENT_DNS_1="208.67.222.222"
		CLIENT_DNS_2="208.67.220.220"
		CLIENT_DNS_IPV6_1="2620:119:35::35"
		CLIENT_DNS_IPV6_2="2620:119:53::53"
	elif [[ ${DNS_CHOICE} == "4" ]]; then
		CLIENT_DNS_1="94.140.14.14" 
		CLIENT_DNS_2="94.140.15.15"
		CLIENT_DNS_IPV6_1="2a10:50c0::ad1:ff"
		CLIENT_DNS_IPV6_2="2a10:50c0::ad2:ff"
	elif [[ ${DNS_CHOICE} == "5" ]]; then
		read -rp "Primary DNS IPv4: " CLIENT_DNS_1
		read -rp "Secondary DNS IPv4: " CLIENT_DNS_2
		if [[ ${ENABLE_IPV6} == 'y' ]]; then
			read -rp "Primary DNS IPv6: " CLIENT_DNS_IPV6_1
			read -rp "Secondary DNS IPv6: " CLIENT_DNS_IPV6_2
		fi
	else
		# Default to Google DNS
		CLIENT_DNS_1="8.8.8.8"
		CLIENT_DNS_2="8.8.4.4" 
		CLIENT_DNS_IPV6_1="2001:4860:4860::8888"
		CLIENT_DNS_IPV6_2="2001:4860:4860::8844"
        echo "net.ipv6.conf.all.forwarding = 1" >> /etc/sysctl.d/awg.conf
    fi
    sysctl --system
    
    # Configure the server interface
    if [[ ${ENABLE_IPV6} == 'y' ]]; then
        # Create config with both IPv4 and IPv6
	echo "[Interface]
Address = ${SERVER_WG_IPV4}/24,${SERVER_WG_IPV6}/64
ListenPort = ${SERVER_PORT}
PrivateKey = ${SERVER_PRIV_KEY}
Jc = ${JC}
Jmin = ${JMIN}
Jmax = ${JMAX}
H1 = ${H1}
H2 = ${H2}
H3 = ${H3}
H4 = ${H4}
MTU = ${MTU}" > /etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf
    else
        # IPv4 only config
        echo "[Interface]
Address = ${SERVER_WG_IPV4}/24
ListenPort = ${SERVER_PORT}
PrivateKey = ${SERVER_PRIV_KEY}
Jc = ${JC}
Jmin = ${JMIN}
Jmax = ${JMAX}
H1 = ${H1}
H2 = ${H2}
H3 = ${H3}
H4 = ${H4}
MTU = ${MTU}" > /etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf
    fi

    # Add firewall rules
	if pgrep firewalld; then
		FIREWALLD_IPV4_ADDRESS=$(echo "${SERVER_WG_IPV4}" | cut -d"." -f1-3)".0"
		FIREWALLD_IPV6_ADDRESS=$(echo "${SERVER_WG_IPV6}" | sed 's/:[^:]*$/:0/')
        echo "PostUp = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC}
PostUp = firewall-cmd --add-port ${SERVER_PORT}/udp
PostUp = firewall-cmd --add-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade'
PostDown = firewall-cmd --zone=public --remove-interface=${SERVER_WG_NIC}
PostDown = firewall-cmd --remove-port ${SERVER_PORT}/udp
PostDown = firewall-cmd --remove-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade'" >> /etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf
        if [[ ${ENABLE_IPV6} == 'y' ]]; then
            echo "PostUp = firewall-cmd --add-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/64 masquerade'
PostDown = firewall-cmd --remove-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/64 masquerade'" >> /etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf
        fi
	else
		echo "PostUp = iptables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = iptables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE" >> /etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf
        if [[ ${ENABLE_IPV6} == 'y' ]]; then
            echo "PostUp = ip6tables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostUp = ip6tables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = ip6tables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostDown = ip6tables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE" >> /etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf
        fi
    fi
    
    # Enable and start AmneziaWG service
	systemctl start "awg-quick@${SERVER_WG_NIC}"
	systemctl enable "awg-quick@${SERVER_WG_NIC}"

    # Verify service is running
    if systemctl is-active --quiet "awg-quick@${SERVER_WG_NIC}"; then
        echo -e "${GREEN}AmneziaWG service is running.${NC}"
    else
        echo -e "${RED}AmneziaWG service failed to start. Try running 'systemctl start awg-quick@${SERVER_WG_NIC}' manually.${NC}"
    fi
    
    # Create a new client
	newClient
    
    echo -e "${GREEN}AmneziaWG installation completed!${NC}"
    echo -e "${GREEN}You can add more clients using:${NC} $0"
}

function installAmneziaWGRHEL() {
    # RHEL/CentOS/Fedora specific installation
    # Install EPEL if not already installed
    if ! rpm -qa | grep -q epel-release; then
        yum install -y epel-release
    fi
    
    # Remove existing WireGuard packages
    yum remove -y wireguard wireguard-tools
    yum autoremove -y
    
    # Add AmneziaWG repo
    cat > /etc/yum.repos.d/amnezia.repo << 'EOF'
[amnezia]
name=Amnezia Repository
baseurl=https://rpm.amnezia.org/stable/
enabled=1
gpgcheck=0
EOF
    
    # Install AmneziaWG
    yum install -y amneziawg
    echo -e "${GREEN}WireGuard packages successfully removed. AmneziaWG installed.${NC}"
}

function newClient() {
			echo ""
    echo "+-----------------------------------------------+"
    echo "|               Add a New Client                |"
    echo "+-----------------------------------------------+"
			echo ""
    echo "Tell me a name for the client."
    echo "The name must consist of alphanumeric characters, underscores or dashes."
		echo ""

    until [[ ${CLIENT_NAME} =~ ^[a-zA-Z0-9_-]+$ ]]; do
        read -rp "Client name: " -e CLIENT_NAME
			echo ""
    done

    # Check if the client already exists
    CLIENT_EXISTS=$(grep -c "^### Client ${CLIENT_NAME}$" "/etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf")
    if [[ ${CLIENT_EXISTS} -eq 1 ]]; then
			echo ""
        echo "A client with the specified name was already created."
        read -rp "Do you want to regenerate the client key? [y/n]: " -i "y" REGEN_KEY
        if [[ ${REGEN_KEY} == 'y' ]]; then
            regenerateClientConfig "${CLIENT_NAME}"
			echo ""
            echo "Client ${CLIENT_NAME} regenerated!"
            exit 0
        else
            exit 0
		fi
    fi

    # Create client key pair
	CLIENT_PRIV_KEY=$(awg genkey)
	CLIENT_PUB_KEY=$(echo "${CLIENT_PRIV_KEY}" | awg pubkey)
	CLIENT_PRE_SHARED_KEY=$(awg genpsk)

    # Load current settings from params
    source /etc/amnezia/amneziawg/params

    # Get the next available IP
    IPV4_BASE=$(echo "$SERVER_WG_IPV4" | cut -d"." -f1-3)
    IPV6_BASE=$(echo "$SERVER_WG_IPV6" | cut -d":" -f1-3)

    # Count existing clients and add 2 (server is .1)
    LAST_INDEX=$(grep -c "^### Client" "/etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf")
    NEXT_IP_INDEX=$((LAST_INDEX + 2))
    CLIENT_WG_IPV4="${IPV4_BASE}.${NEXT_IP_INDEX}"
    CLIENT_WG_IPV6="${IPV6_BASE}::${NEXT_IP_INDEX}"

    # Create client config
    HOME_DIR=$(getHomeDirForClient "${SUDO_USER:-root}")
    CLIENT_CONFIG_DIR="${HOME_DIR}/amneziawg"
    mkdir -p "${CLIENT_CONFIG_DIR}"
    chmod 700 "${CLIENT_CONFIG_DIR}"

    # Create client config file
    cat > "${CLIENT_CONFIG_DIR}/${SERVER_WG_NIC}-${CLIENT_NAME}.conf" <<EOF
[Interface]
PrivateKey = ${CLIENT_PRIV_KEY}
Address = ${CLIENT_WG_IPV4}/32,${CLIENT_WG_IPV6}/128
DNS = ${CLIENT_DNS_1},${CLIENT_DNS_2},${CLIENT_DNS_IPV6_1},${CLIENT_DNS_IPV6_2}
Jc = ${JC}
Jmin = ${JMIN}
Jmax = ${JMAX}
H1 = ${H1}
H2 = ${H2}
H3 = ${H3}
H4 = ${H4}
MTU = ${MTU}

[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
Endpoint = ${SERVER_PUB_IP}:${SERVER_PORT}
AllowedIPs = ${ALLOWED_IPS}
EOF

    # Add the client to the server
    cat >> "/etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf" <<EOF

### Client ${CLIENT_NAME}
[Peer]
PublicKey = ${CLIENT_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
AllowedIPs = ${CLIENT_WG_IPV4}/32,${CLIENT_WG_IPV6}/128
EOF

    # Sync WireGuard with the new peer
    awg addconf "${SERVER_WG_NIC}" <(awg-quick strip "${SERVER_WG_NIC}")

    # QR code features
    echo -e "${GREEN}Client ${CLIENT_NAME} added. Configuration file is at ${CLIENT_CONFIG_DIR}/${SERVER_WG_NIC}-${CLIENT_NAME}.conf${NC}"
    
    # Check if qrencode is installed
    if command -v qrencode >/dev/null 2>&1; then
        echo -e "${GREEN}QR code for mobile clients:${NC}"
        qrencode -t ansiutf8 < "${CLIENT_CONFIG_DIR}/${SERVER_WG_NIC}-${CLIENT_NAME}.conf"
		echo ""
        echo -e "${GREEN}You can also scan this QR code with the AmneziaWG mobile app:${NC}"
    else
        echo -e "${ORANGE}QR code generation is unavailable. Install qrencode package to enable this feature.${NC}"
	fi

    echo ""
    echo -e "${GREEN}Client ${CLIENT_NAME} added successfully!${NC}"
}

function listClients() {
		echo ""
    echo "╔═══════════════════════════════════════════════╗"
    echo "║             AmneziaWG Client List             ║"
    echo "╚═══════════════════════════════════════════════╝"
    echo ""
    
    if [[ ! -f "/etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf" ]]; then
        echo -e "${RED}AmneziaWG configuration not found. Is AmneziaWG installed?${NC}"
		exit 1
	fi

    CLIENTS=$(grep -E "^### Client" "/etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3)
    
    if [[ -z "$CLIENTS" ]]; then
        echo -e "${ORANGE}No clients found. Add a client using option 1.${NC}"
        return
    fi
    
    # Display in table format
    echo "╭───────────────────────────╮"
    echo "│ Client Name               │"
    echo "├───────────────────────────┤"
    
    while read -r client; do
        # Pad or truncate the client name to fit the column
        printf "│ %-25s │\n" "${client}"
    done <<< "$CLIENTS"
    
    echo "╰───────────────────────────╯"
    echo ""
    
    # Find location of client config files
    HOME_DIR=$(getHomeDirForClient "${SUDO_USER:-root}")
    CLIENT_CONFIG_DIR="${HOME_DIR}/amneziawg"
    
    echo -e "${GREEN}Client configuration files are stored in: ${CLIENT_CONFIG_DIR}${NC}"
    echo ""
}

function revokeClient() {
		echo ""
    echo "╔═══════════════════════════════════════════════╗"
    echo "║               Revoke a Client                 ║"
    echo "╚═══════════════════════════════════════════════╝"
    echo ""
    
    if [[ ! -f "/etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf" ]]; then
        echo -e "${RED}AmneziaWG configuration not found. Is AmneziaWG installed?${NC}"
		exit 1
	fi

    CLIENTS=$(grep -E "^### Client" "/etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3)
    
    if [[ -z "$CLIENTS" ]]; then
        echo -e "${ORANGE}No clients found. Nothing to revoke.${NC}"
        return
    fi
    
    echo "Select the client to revoke:"
    
    # Create a numbered list of clients
    i=1
    while read -r client; do
        echo "${i}) ${client}"
        ((i++))
    done <<< "$CLIENTS"
    
    echo ""
    until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${i} ]]; do
        read -rp "Select client [1-$((i-1))]: " CLIENT_NUMBER
        echo ""
    done
    
    # Get the selected client name
    SELECTED_CLIENT=$(echo "$CLIENTS" | sed -n "${CLIENT_NUMBER}p")
    
    # Remove client from the server config
    echo -e "${ORANGE}Revoking access for client: ${SELECTED_CLIENT}${NC}"
    
    # Find the right section in the config file
    SECTION_START=$(grep -n "^### Client ${SELECTED_CLIENT}$" "/etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf" | cut -d: -f1)
    
    if [[ -z "$SECTION_START" ]]; then
        echo -e "${RED}Client section not found in configuration. Aborting.${NC}"
        exit 1
    fi
    
    # Find the next client section or end of file
    SECTION_END=$(tail -n +$SECTION_START "/etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf" | grep -n "^### Client" | head -1 | cut -d: -f1)
    
    if [[ -z "$SECTION_END" ]]; then
        # No more clients, so delete to the end of file
        LINES_TO_DELETE=$(wc -l "/etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf" | awk '{print $1}')
        LINES_TO_DELETE=$((LINES_TO_DELETE - SECTION_START + 1))
    else
        # Calculate lines to delete (section end - 1 is the actual end of the current section)
        SECTION_END=$((SECTION_START + SECTION_END - 1))
        LINES_TO_DELETE=$((SECTION_END - SECTION_START))
    fi
    
    # Delete the client section
    sed -i "${SECTION_START},+${LINES_TO_DELETE}d" "/etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf"
    
    # Delete the client config file
    HOME_DIR=$(getHomeDirForClient "${SUDO_USER:-root}")
    CLIENT_CONFIG_DIR="${HOME_DIR}/amneziawg"
    rm -f "${CLIENT_CONFIG_DIR}/${SERVER_WG_NIC}-${SELECTED_CLIENT}.conf"
    
    # Update the AmneziaWG interface
	awg syncconf "${SERVER_WG_NIC}" <(awg-quick strip "${SERVER_WG_NIC}")
    
    echo -e "${GREEN}Client ${SELECTED_CLIENT} revoked successfully!${NC}"
    echo ""
}

function regenerateClientConfig() {
    local CLIENT_NAME=$1
    
	echo ""
    echo "╔═══════════════════════════════════════════════╗"
    echo "║          Regenerate Client Configuration      ║"
    echo "╚═══════════════════════════════════════════════╝"
    echo ""
    
    # Check if client exists
    if ! grep -q "^### Client ${CLIENT_NAME}$" "/etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf"; then
        echo -e "${RED}Client ${CLIENT_NAME} not found.${NC}"
        return 1
    fi
    
    # Load current settings from params
    source /etc/amnezia/amneziawg/params
    
    # Extract client's IP addresses from the config
    CLIENT_WG_IPV4=$(grep -A2 "^### Client ${CLIENT_NAME}$" "/etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf" | grep -oP 'AllowedIPs = \K[0-9\./]+(?=,)' || echo "${SERVER_WG_IPV4%.*}.$((2 + $(grep -c '^### Client' /etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf)))")
    CLIENT_WG_IPV6=$(grep -A2 "^### Client ${CLIENT_NAME}$" "/etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf" | grep -oP 'AllowedIPs = [0-9\./]+,\K[a-f0-9:\/]+' || echo "${SERVER_WG_IPV6%::*}::$((2 + $(grep -c '^### Client' /etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf)))")
    
    # Get existing preshared key if available
    CLIENT_PRE_SHARED_KEY=$(grep -A3 "^### Client ${CLIENT_NAME}$" "/etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf" | grep -oP 'PresharedKey = \K[a-zA-Z0-9+/]{43}=' || awg genpsk)
    
    # Create new keys
    CLIENT_PRIV_KEY=$(awg genkey)
    CLIENT_PUB_KEY=$(echo "${CLIENT_PRIV_KEY}" | awg pubkey)
    
    # Update server config with new public key
    sed -i "/^### Client ${CLIENT_NAME}$/,/^###/ s/PublicKey = .*/PublicKey = ${CLIENT_PUB_KEY}/" "/etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf"
    
    # Create client config
    HOME_DIR=$(getHomeDirForClient "${SUDO_USER:-root}")
    CLIENT_CONFIG_DIR="${HOME_DIR}/amneziawg"
    mkdir -p "${CLIENT_CONFIG_DIR}"
    chmod 700 "${CLIENT_CONFIG_DIR}"
    
    # Create client config file
    cat > "${CLIENT_CONFIG_DIR}/${SERVER_WG_NIC}-${CLIENT_NAME}.conf" <<EOF
[Interface]
PrivateKey = ${CLIENT_PRIV_KEY}
Address = ${CLIENT_WG_IPV4}/32,${CLIENT_WG_IPV6}/128
DNS = ${CLIENT_DNS_1},${CLIENT_DNS_2},${CLIENT_DNS_IPV6_1},${CLIENT_DNS_IPV6_2}
Jc = ${JC}
Jmin = ${JMIN}
Jmax = ${JMAX}
H1 = ${H1}
H2 = ${H2}
H3 = ${H3}
H4 = ${H4}
MTU = ${MTU}

[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
Endpoint = ${SERVER_PUB_IP}:${SERVER_PORT}
AllowedIPs = ${ALLOWED_IPS}
EOF

    # Update the AmneziaWG interface
    awg syncconf "${SERVER_WG_NIC}" <(awg-quick strip "${SERVER_WG_NIC}")
    
    echo -e "${GREEN}Client ${CLIENT_NAME} configuration regenerated successfully!${NC}"
    echo -e "${GREEN}New configuration file is at ${CLIENT_CONFIG_DIR}/${SERVER_WG_NIC}-${CLIENT_NAME}.conf${NC}"
}

function configureObfuscationSettings() {
	echo ""
    echo "╔═══════════════════════════════════════════════╗"
    echo "║          Configure Obfuscation Settings       ║"
    echo "╚═══════════════════════════════════════════════╝"
	echo ""
    echo "These settings control how AmneziaWG traffic is obfuscated to avoid detection."
    echo ""
    
    echo "Select obfuscation preset:"
    echo "1) Mobile"
    echo "2) Standard"
    echo "3) Custom settings"
    read -rp "Select an option [1-3]: " OBFUSCATION_PRESET
    
    case "${OBFUSCATION_PRESET}" in
    1)
        # Mobile preset
        JC=4
        JMIN=40
        JMAX=70
        S1=50
        S2=100
        # Generate random magic headers
        H1=$((RANDOM * 100000 + 10000))
        H2=$((RANDOM * 100000 + 20000))
        H3=$((RANDOM * 100000 + 30000))
        H4=$((RANDOM * 100000 + 40000))
        MTU=1280
        echo -e "${GREEN}Using Mobile preset with random magic headers.${NC}"
        ;;
    2)
        # Desktop preset
        JC=2
        JMIN=100
        JMAX=200
        S1=100
        S2=200
        # Generate random magic headers
        H1=$((RANDOM * 100000 + 10000))
        H2=$((RANDOM * 100000 + 20000))
        H3=$((RANDOM * 100000 + 30000))
        H4=$((RANDOM * 100000 + 40000))
        MTU=1420
        echo -e "${GREEN}Using Standard preset with random magic headers.${NC}"
        ;;
    3)
        # Custom settings
        echo -e "${GREEN}Enter custom obfuscation settings:${NC}"
        read -rp "Junk coefficient (Jc) [1-10, default 4]: " -e CUSTOM_JC
        JC=${CUSTOM_JC:-4}
        
        read -rp "Minimum junk size (Jmin) [10-200, default 40]: " -e CUSTOM_JMIN
        JMIN=${CUSTOM_JMIN:-40}
        
        read -rp "Maximum junk size (Jmax) [${JMIN}-500, default 70]: " -e CUSTOM_JMAX
        JMAX=${CUSTOM_JMAX:-70}
        
        read -rp "Init packet junk size (S1) [10-1280, default 50]: " -e CUSTOM_S1
        S1=${CUSTOM_S1:-50}
        
        read -rp "Response packet junk size (S2) [10-1280, default 100]: " -e CUSTOM_S2
        S2=${CUSTOM_S2:-100}
        
        read -rp "Magic header 1 (H1) [5-999999, default random]: " -e CUSTOM_H1
        H1=${CUSTOM_H1:-$((RANDOM * 100000 + 10000))}
        
        read -rp "Magic header 2 (H2) [5-999999, default random]: " -e CUSTOM_H2
        H2=${CUSTOM_H2:-$((RANDOM * 100000 + 20000))}
        
        read -rp "Magic header 3 (H3) [5-999999, default random]: " -e CUSTOM_H3
        H3=${CUSTOM_H3:-$((RANDOM * 100000 + 30000))}
        
        read -rp "Magic header 4 (H4) [5-999999, default random]: " -e CUSTOM_H4
        H4=${CUSTOM_H4:-$((RANDOM * 100000 + 40000))}
        
        read -rp "MTU [500-1500, default 1280]: " -e CUSTOM_MTU
        MTU=${CUSTOM_MTU:-1280}
        
        echo -e "${GREEN}Using custom obfuscation settings.${NC}"
        ;;
    *)
        echo -e "${RED}Invalid option. Using Mobile preset.${NC}"
        JC=4
        JMIN=40
        JMAX=70
        S1=50
        S2=100
        H1=$((RANDOM * 100000 + 10000))
        H2=$((RANDOM * 100000 + 20000))
        H3=$((RANDOM * 100000 + 30000))
        H4=$((RANDOM * 100000 + 40000))
        MTU=1280
		;;
	esac
    
    # Ensure all headers are unique and within range
    while [[ ${H1} -lt 5 || ${H2} -lt 5 || ${H3} -lt 5 || ${H4} -lt 5 || 
            ${H1} -eq ${H2} || ${H1} -eq ${H3} || ${H1} -eq ${H4} || 
            ${H2} -eq ${H3} || ${H2} -eq ${H4} || ${H3} -eq ${H4} ]]; do
        echo -e "${ORANGE}Regenerating magic headers to ensure uniqueness...${NC}"
        H1=$((RANDOM * 100000 + 10000))
        H2=$((RANDOM * 100000 + 20000))
        H3=$((RANDOM * 100000 + 30000))
        H4=$((RANDOM * 100000 + 40000))
    done
    
    # Display the settings
	echo ""
    echo -e "${GREEN}AmneziaWG obfuscation settings:${NC}"
    echo "Junk coefficient (Jc): ${JC}"
    echo "Minimum junk size (Jmin): ${JMIN}"
    echo "Maximum junk size (Jmax): ${JMAX}"
    echo "Init packet junk size (S1): ${S1}"
    echo "Response packet junk size (S2): ${S2}"
    echo "Magic header 1 (H1): ${H1}"
    echo "Magic header 2 (H2): ${H2}"
    echo "Magic header 3 (H3): ${H3}"
    echo "Magic header 4 (H4): ${H4}"
    echo "MTU: ${MTU}"
    
    # Update server config
    updateServerConfig
    
    # Ask if regenerate all client configs
    read -rp "Regenerate all client configurations with these settings? [y/n]: " -i "y" REGEN_CLIENTS
    echo ""
    
    if [[ ${REGEN_CLIENTS} == 'y' ]]; then
        regenerateAllClientConfigs
    fi
}

function updateServerConfig() {
    echo -e "${GREEN}Updating server configuration with new settings...${NC}"
    
    # Update MTU in server config
    sed -i "s/MTU = .*/MTU = ${MTU}/" /etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf
    
    # Update obfuscation settings in server config
    sed -i "s/Jc = .*/Jc = ${JC}/" /etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf
    sed -i "s/Jmin = .*/Jmin = ${JMIN}/" /etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf
    sed -i "s/Jmax = .*/Jmax = ${JMAX}/" /etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf
    sed -i "s/H1 = .*/H1 = ${H1}/" /etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf
    sed -i "s/H2 = .*/H2 = ${H2}/" /etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf
    sed -i "s/H3 = .*/H3 = ${H3}/" /etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf
    sed -i "s/H4 = .*/H4 = ${H4}/" /etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf
    
    # Update ALLOWED_IPS in params
    sed -i "s/ALLOWED_IPS=.*/ALLOWED_IPS=${ALLOWED_IPS}/" /etc/amnezia/amneziawg/params
    
    # Update JC, JMIN, JMAX, S1, S2, H1-4, MTU in params
    sed -i "s/JC=.*/JC=${JC}/" /etc/amnezia/amneziawg/params 2>/dev/null || echo "JC=${JC}" >> /etc/amnezia/amneziawg/params
    sed -i "s/JMIN=.*/JMIN=${JMIN}/" /etc/amnezia/amneziawg/params 2>/dev/null || echo "JMIN=${JMIN}" >> /etc/amnezia/amneziawg/params
    sed -i "s/JMAX=.*/JMAX=${JMAX}/" /etc/amnezia/amneziawg/params 2>/dev/null || echo "JMAX=${JMAX}" >> /etc/amnezia/amneziawg/params
    sed -i "s/S1=.*/S1=${S1}/" /etc/amnezia/amneziawg/params 2>/dev/null || echo "S1=${S1}" >> /etc/amnezia/amneziawg/params
    sed -i "s/S2=.*/S2=${S2}/" /etc/amnezia/amneziawg/params 2>/dev/null || echo "S2=${S2}" >> /etc/amnezia/amneziawg/params
    sed -i "s/H1=.*/H1=${H1}/" /etc/amnezia/amneziawg/params 2>/dev/null || echo "H1=${H1}" >> /etc/amnezia/amneziawg/params
    sed -i "s/H2=.*/H2=${H2}/" /etc/amnezia/amneziawg/params 2>/dev/null || echo "H2=${H2}" >> /etc/amnezia/amneziawg/params
    sed -i "s/H3=.*/H3=${H3}/" /etc/amnezia/amneziawg/params 2>/dev/null || echo "H3=${H3}" >> /etc/amnezia/amneziawg/params
    sed -i "s/H4=.*/H4=${H4}/" /etc/amnezia/amneziawg/params 2>/dev/null || echo "H4=${H4}" >> /etc/amnezia/amneziawg/params
    sed -i "s/MTU=.*/MTU=${MTU}/" /etc/amnezia/amneziawg/params 2>/dev/null || echo "MTU=${MTU}" >> /etc/amnezia/amneziawg/params
    
    # Restart AmneziaWG service to apply changes
    systemctl restart "awg-quick@${SERVER_WG_NIC}"
    
    echo -e "${GREEN}Server configuration updated successfully!${NC}"
}

function regenerateAllClientConfigs() {
    echo -e "${GREEN}Regenerating all client configurations...${NC}"
    
    # Get list of clients
    CLIENTS=$(grep -E "^### Client" "/etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3)
    
    if [[ -z "$CLIENTS" ]]; then
        echo -e "${ORANGE}No clients found. Nothing to regenerate.${NC}"
        return
    fi
    
    # For each client, regenerate configuration
    while read -r client; do
        echo -e "${GREEN}Regenerating configuration for client: ${client}${NC}"
        regenerateClientConfig "${client}"
    done <<< "$CLIENTS"
    
    echo -e "${GREEN}All client configurations have been regenerated successfully!${NC}"
    echo -e "${GREEN}New configurations are available in ${CLIENT_CONFIG_DIR}${NC}"
}

function setDefaultAmneziaSettings() {
    # Set default values for AmneziaWG obfuscation
    # Mobile preset
    JC=4
    JMIN=40
    JMAX=70
    S1=50
    S2=100
    
    # Generate random magic headers
    H1=$((RANDOM * 100000 + 10000))
    H2=$((RANDOM * 100000 + 20000))
    H3=$((RANDOM * 100000 + 30000))
    H4=$((RANDOM * 100000 + 40000))
    
    # Default MTU
    MTU=1280
}

function uninstallWg() {
    echo ""
    echo "╔═══════════════════════════════════════════════╗"
    echo "║             Uninstall AmneziaWG               ║"
    echo "╚═══════════════════════════════════════════════╝"
    echo ""
    echo -e "${RED}WARNING: This will uninstall AmneziaWG and remove all configurations.${NC}"
    echo -e "${RED}All client configurations will be lost!${NC}"
    echo ""
    read -rp "Are you sure you want to uninstall AmneziaWG? [y/n]: " -i "y" CONFIRM
    
    if [[ $CONFIRM != 'y' ]]; then
        echo "Uninstall canceled."
        return
    fi
    
    # Stop the service
    echo "Stopping AmneziaWG service..."
    systemctl stop "awg-quick@${SERVER_WG_NIC}"
    systemctl disable "awg-quick@${SERVER_WG_NIC}"
    
    # Remove configs
    echo "Removing AmneziaWG configurations..."
    cleanup
    
    # Remove packages
    echo "Removing AmneziaWG packages..."
    if [[ ${OS} == "ubuntu" || ${OS} == "debian" ]]; then
        apt-get remove -y amneziawg
        apt-get autoremove -y
        rm -f /etc/apt/sources.list.d/amnezia.list
        rm -f /usr/share/keyrings/amnezia-archive-keyring.gpg
    elif [[ ${OS} == "rhel" ]]; then
        dnf remove -y amneziawg
        dnf autoremove -y
        rm -f /etc/yum.repos.d/amnezia.repo
    fi
    
    # Restore sysctl settings
    echo "Restoring system settings..."
    rm -f /etc/sysctl.d/awg.conf
    sysctl --system
    
    echo -e "${GREEN}AmneziaWG has been uninstalled successfully.${NC}"
    echo "If you want to reinstall in the future, just run this script again."
    
    exit 0
}

function configureAllowedIPs() {
	echo ""
	echo -e "${GREEN}Configure default traffic routing for new clients${NC}"
	echo "1) Route all traffic (recommended)"
	echo "2) Route specific websites only"
	read -rp "Select an option [1-2]: " ROUTE_OPTION
	
	if [[ ${ROUTE_OPTION} == "2" ]]; then
		startWebServer
		echo "Please paste the IP list generated from the website:"
		read -rp "IP List: " ALLOWED_IPS
		
		# Validate input format
		if [[ ! ${ALLOWED_IPS} =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}(,([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2})*$ ]]; then
			echo "Invalid format. Using default (all traffic)"
			ALLOWED_IPS="0.0.0.0/0"
		fi
	else
		ALLOWED_IPS="0.0.0.0/0"
	fi
	
	if [[ ${ENABLE_IPV6} == "y" ]]; then
		ALLOWED_IPS="${ALLOWED_IPS},::/0"
	fi
}

function startWebServer() {
    # Create a temporary directory for the website and data
    TEMP_DIR=$(mktemp -d)

    # Clone AWG-INSTALL repo (website, scripts, configs)
    cd "${TEMP_DIR}"
    git clone https://github.com/ginto-sakata/amneziawg-install

    AWG_INSTALL_TEMP_DIR="${TEMP_DIR}/amneziawg-install"
    IPLIST_DIR="${AWG_INSTALL_TEMP_DIR}/iplist"
    WEBSITE_DIR="${AWG_INSTALL_TEMP_DIR}/static_website"
    
    echo -e "${GREEN}Setting up website for service selection...${NC}"
    
    # Install necessary packages
    installWebServerDependencies

    # Download iplist repository using git with sparse checkout
        echo -e "${GREEN}Downloading IP lists data...${NC}"
    
    # Clone the iplist repository into temp directory with sparse checkout
    if command -v git &> /dev/null; then
        echo -e "${GREEN}Using git to clone the iplist repository...${NC}"
        cd "${AWG_INSTALL_TEMP_DIR}"
        #TODO: Can we remove check for existing directory "iplist" as we are using the temp directory? 
        if [ ! -d "${AWG_INSTALL_TEMP_DIR}/iplist" ]; then 
            git clone -n --depth=1 --filter=tree:0 https://github.com/rekryt/iplist
            cd iplist
            git sparse-checkout set --no-cone /config
            git checkout
        else
            echo -e "${GREEN}iplist directory already exists, updating...${NC}"
            cd "${AWG_INSTALL_TEMP_DIR}/iplist"
            git pull
        fi
    else
        echo -e "${ORANGE}Git not found, downloading zip file instead...${NC}"
        if command -v curl &> /dev/null; then
            curl -L "https://github.com/rekryt/iplist/archive/refs/heads/master.zip" -o "${AWG_INSTALL_TEMP_DIR}/iplist.zip"
        else
            wget -q "https://github.com/rekryt/iplist/archive/refs/heads/master.zip" -O "${AWG_INSTALL_TEMP_DIR}/iplist.zip"
        fi
        
        echo -e "${GREEN}Extracting data...${NC}"
        unzip -q "${AWG_INSTALL_TEMP_DIR}/iplist.zip" -d "${AWG_INSTALL_TEMP_DIR}"
        mv "${AWG_INSTALL_TEMP_DIR}/iplist-master" "${IPLIST_DIR}"
    fi
    
    # Make the script executable
    chmod +x "${AWG_INSTALL_TEMP_DIR}/generate_data.sh"
    
# Generate the cidrs.json file
    echo "Generating CIDR data..."
    "${AWG_INSTALL_TEMP_DIR}/generate_data.sh" "${IPLIST_DIR}/config" "${WEBSITE_DIR}"

    # Create a simple web server using Python 3
    echo -e "${GREEN}Starting web server...${NC}"

    # Try to get server's domain name, fallback to IP if not available
    WEBSERVER_ADDRESS=$(hostname -f 2>/dev/null || hostname)
    if [ -z "$WEBSERVER_ADDRESS" ] || [ "$WEBSERVER_ADDRESS" = "localhost" ]; then
        WEBSERVER_ADDRESS=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v 127.0.0.1 | head -1)
    fi

    WEBSERVER_ADDRESS=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v 127.0.0.1 | head -1)

    # Choose a port
    WEB_PORT=8080

    # Check if python3 is available
    if command -v python3 &> /dev/null; then
        echo -e "${GREEN}Starting web server using Python 3 at http://${WEBSERVER_ADDRESS}:${WEB_PORT}${NC}"
        echo -e "${GREEN}Please open this URL in your browser.${NC}"
        echo -e "${GREEN}After selecting services, click 'Generate IP List' and copy the result.${NC}"
        echo -e "${ORANGE}Press Ctrl+C when done to continue with the installation.${NC}"

        # Change to the website directory and start the server
        cd "${WEBSITE_DIR}"
        python3 -m http.server ${WEB_PORT} > /dev/null 2>&1 # Suppress "Serving HTTP..."
    else
        echo -e "${RED}Could not start a web server using Python 3. Please install Python 3.${NC}"
        echo -e "${RED}Continuing with default routing (all traffic).${NC}"
        ALLOWED_IPS="0.0.0.0/0"

        # Clean up
        rm -rf "${TEMP_DIR}"
        return 1
    fi

    # Clean up
    rm -rf "${TEMP_DIR}"
}

function installWebServerDependencies() {
    echo -e "${GREEN}Checking and installing necessary packages...${NC}"
    
    MISSING_PACKAGES=""
    
    # Check for unzip
    if ! command -v unzip &> /dev/null; then
        MISSING_PACKAGES="${MISSING_PACKAGES} unzip"
    fi
    
    # Check for curl or wget
    if ! command -v curl &> /dev/null && ! command -v wget &> /dev/null; then
        if [[ ${OS} == "ubuntu" || ${OS} == "debian" ]]; then
            MISSING_PACKAGES="${MISSING_PACKAGES} curl"
        else
            MISSING_PACKAGES="${MISSING_PACKAGES} wget"
        fi
    fi
    
    # Check for Python or PHP
    if ! command -v python3 &> /dev/null && ! command -v python &> /dev/null && ! command -v php &> /dev/null; then
        if [[ ${OS} == "ubuntu" || ${OS} == "debian" ]]; then
            MISSING_PACKAGES="${MISSING_PACKAGES} python3"
        else
            MISSING_PACKAGES="${MISSING_PACKAGES} python3"
        fi
    fi
    
    # Install missing packages if any
    if [[ ! -z "${MISSING_PACKAGES}" ]]; then
        echo -e "${GREEN}Installing missing packages: ${MISSING_PACKAGES}${NC}"
        
        if [[ ${OS} == "ubuntu" || ${OS} == "debian" ]]; then
            apt-get update
            apt-get install -y ${MISSING_PACKAGES}
        elif [[ ${OS} == "rhel" ]]; then
            if [[ ${OS} == "fedora" ]]; then
                dnf install -y ${MISSING_PACKAGES}
            else
                yum install -y ${MISSING_PACKAGES}
            fi
        fi
    else
        echo -e "${GREEN}All required packages are already installed.${NC}"
    fi
}

function installAmneziaWG() {
    # Start with welcome screen
    installQuestions
    
    echo ""
    echo "╔═══════════════════════════════════════════════╗"
    echo "║        AmneziaWG Installation Process         ║"
    echo "╚═══════════════════════════════════════════════╝"
    echo ""
    
    # Create necessary directories
    mkdir -p /etc/amnezia/amneziawg
    chmod 700 /etc/amnezia/amneziawg
    
    # Install dependencies
    echo -e "${GREEN}Installing required dependencies...${NC}"
    if [[ ${OS} == "ubuntu" || ${OS} == "debian" ]]; then
        setupDebSrc
        apt-get update
        apt-get install -y apt-transport-https ca-certificates curl gnupg lsb-release software-properties-common
        
        # Add Amnezia repositories
        echo -e "${GREEN}Adding AmneziaWG repository...${NC}"
        curl -fsSL https://dl.amnezia.org/key.pub | gpg --dearmor -o /usr/share/keyrings/amnezia-archive-keyring.gpg
        echo "deb [signed-by=/usr/share/keyrings/amnezia-archive-keyring.gpg] https://dl.amnezia.org/apt stable main" > /etc/apt/sources.list.d/amnezia.list
        
        # Update and install AmneziaWG
        apt-get update
        apt-get install -y amneziawg
    elif [[ ${OS} == "rhel" ]]; then
        installAmneziaWGRHEL
    fi
    
    # Generate server key pair
    echo -e "${GREEN}Generating AmneziaWG server keys...${NC}"
    SERVER_PRIV_KEY=$(awg genkey)
    SERVER_PUB_KEY=$(echo "${SERVER_PRIV_KEY}" | awg pubkey)
    
    # Run setupServer to configure the server
    setupServer
}

function manageMenu() {
    echo ""
    echo "╔═══════════════════════════════════════════════╗"
    echo "║           AmneziaWG Management Panel          ║"
    echo "╚═══════════════════════════════════════════════╝"
    echo ""
    echo "Welcome to AmneziaWG management menu"
    echo ""
    echo "What do you want to do?"
    echo "   1) Add a new client"
    echo "   2) List existing clients"
    echo "   3) Revoke a client"
    echo "   4) Configure obfuscation settings"
    echo "   5) Configure traffic routing"
    echo "   6) Uninstall AmneziaWG"
    echo "   7) Exit"
    echo ""
    
    until [[ ${MENU_OPTION} =~ ^[1-7]$ ]]; do
        read -rp "Select an option [1-7]: " MENU_OPTION
    done
    
    case "${MENU_OPTION}" in
    1)
        newClient
        ;;
    2)
        listClients
        ;;
    3)
        revokeClient
        ;;
    4)
        configureObfuscationSettings
        ;;
    5)
        configureAllowedIPs
        # Update server config
        updateServerConfig
        
        # Ask if regenerate all client configs
        read -rp "Regenerate all client configurations with these settings? [y/n]: " -i "y" REGEN_CLIENTS
        echo ""
        
        if [[ ${REGEN_CLIENTS} == 'y' ]]; then
            regenerateAllClientConfigs
        fi
        ;;
    6)
        uninstallWg
        ;;
    7)
        exit 0
        ;;
    esac
    
    echo ""
    read -n1 -r -p "Press any key to return to the menu..."
    echo ""
    manageMenu
}

# Check for root, virt, OS...
initialCheck

# Check if AmneziaWG is already installed and load params
if [[ -e /etc/amnezia/amneziawg/params ]]; then
	source /etc/amnezia/amneziawg/params
	manageMenu
else
	installAmneziaWG
fi

# Add error handling function
handle_error() {
    local exit_code=$?
    echo "Error occurred in script at line: ${BASH_LINENO[0]}"
    # Cleanup if needed
    exit $exit_code
}
trap 'handle_error' ERR

# Fix for potential syntax errors
set +e  # Continue execution even if there's an error

function setupServer() {
    echo -e "${GREEN}Setting up AmneziaWG server...${NC}"
    
    # Create server params file
    echo "SERVER_PUB_IP=${SERVER_PUB_IP}
SERVER_PUB_NIC=${SERVER_PUB_NIC}
SERVER_WG_NIC=${SERVER_WG_NIC}
SERVER_WG_IPV4=${SERVER_WG_IPV4}
SERVER_WG_IPV6=${SERVER_WG_IPV6}
SERVER_PORT=${SERVER_PORT}
SERVER_PRIV_KEY=${SERVER_PRIV_KEY}
SERVER_PUB_KEY=${SERVER_PUB_KEY}
CLIENT_DNS_1=${CLIENT_DNS_1}
CLIENT_DNS_2=${CLIENT_DNS_2}
CLIENT_DNS_IPV6_1=${CLIENT_DNS_IPV6_1}
CLIENT_DNS_IPV6_2=${CLIENT_DNS_IPV6_2}
JC=${JC}
JMIN=${JMIN}
JMAX=${JMAX}
S1=${S1}
S2=${S2}
H1=${H1}
H2=${H2}
H3=${H3}
H4=${H4}
MTU=${MTU}
ALLOWED_IPS=${ALLOWED_IPS}" > /etc/amnezia/amneziawg/params
    
    # Enable IP forwarding
    echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/awg.conf
    
    if [[ ${ENABLE_IPV6} == 'y' ]]; then
        echo "net.ipv6.conf.all.forwarding = 1" >> /etc/sysctl.d/awg.conf
    fi
    sysctl --system
    
    # Configure the server interface
    if [[ ${ENABLE_IPV6} == 'y' ]]; then
        # Create config with both IPv4 and IPv6
        echo "[Interface]
Address = ${SERVER_WG_IPV4}/24,${SERVER_WG_IPV6}/64
ListenPort = ${SERVER_PORT}
PrivateKey = ${SERVER_PRIV_KEY}
Jc = ${JC}
Jmin = ${JMIN}
Jmax = ${JMAX}
H1 = ${H1}
H2 = ${H2}
H3 = ${H3}
H4 = ${H4}
MTU = ${MTU}" > /etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf
    else
        # IPv4 only config
        echo "[Interface]
Address = ${SERVER_WG_IPV4}/24
ListenPort = ${SERVER_PORT}
PrivateKey = ${SERVER_PRIV_KEY}
Jc = ${JC}
Jmin = ${JMIN}
Jmax = ${JMAX}
H1 = ${H1}
H2 = ${H2}
H3 = ${H3}
H4 = ${H4}
MTU = ${MTU}" > /etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf
    fi

    # Add firewall rules
    if pgrep firewalld; then
        FIREWALLD_IPV4_ADDRESS=$(echo "${SERVER_WG_IPV4}" | cut -d"." -f1-3)".0"
        FIREWALLD_IPV6_ADDRESS=$(echo "${SERVER_WG_IPV6}" | sed 's/:[^:]*$/:0/')
        echo "PostUp = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC}
PostUp = firewall-cmd --add-port ${SERVER_PORT}/udp
PostUp = firewall-cmd --add-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade'
PostDown = firewall-cmd --zone=public --remove-interface=${SERVER_WG_NIC}
PostDown = firewall-cmd --remove-port ${SERVER_PORT}/udp
PostDown = firewall-cmd --remove-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade'" >> /etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf
        if [[ ${ENABLE_IPV6} == 'y' ]]; then
            echo "PostUp = firewall-cmd --add-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/64 masquerade'
PostDown = firewall-cmd --remove-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/64 masquerade'" >> /etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf
        fi
    else
        echo "PostUp = iptables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = iptables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE" >> /etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf
        if [[ ${ENABLE_IPV6} == 'y' ]]; then
            echo "PostUp = ip6tables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostUp = ip6tables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = ip6tables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostDown = ip6tables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE" >> /etc/amnezia/amneziawg/${SERVER_WG_NIC}.conf
        fi
    fi
    
    # Enable and start AmneziaWG service
    systemctl start "awg-quick@${SERVER_WG_NIC}"
    systemctl enable "awg-quick@${SERVER_WG_NIC}"

    # Verify service is running
    if systemctl is-active --quiet "awg-quick@${SERVER_WG_NIC}"; then
        echo -e "${GREEN}AmneziaWG service is running.${NC}"
    else
        echo -e "${RED}AmneziaWG service failed to start. Try running 'systemctl start awg-quick@${SERVER_WG_NIC}' manually.${NC}"
    fi
    
    # Create a new client
    newClient
    
    echo -e "${GREEN}AmneziaWG installation completed!${NC}"
    echo -e "${GREEN}You can add more clients using:${NC} $0"
}