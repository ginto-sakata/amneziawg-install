#!/bin/bash

# AmneziaWG server installer
# Based on https://github.com/angristan/wireguard-install
# Enhanced by ginto-sakata and reviewed/refactored

# --- Debug Mode Check ---
DEBUG_MODE="false"
if [[ "$1" == "--debug" ]]; then
    DEBUG_MODE="true"
    echo "DEBUG: Debug mode enabled. Command tracing activated."
    set -x
fi

set +e

RED='\033[0;31m'
ORANGE='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'
BOLD_GREEN='\033[1;32m'

OS=""
OS_VERSION=""
SERVER_PUB_IP=""
SERVER_PUB_NIC=""
SERVER_WG_NIC="awg0"
SERVER_WG_IPV4=""
SERVER_WG_IPV6=""
SERVER_PORT=""
SERVER_PRIV_KEY=""
SERVER_PUB_KEY=""
CLIENT_DNS_1=""
CLIENT_DNS_2=""
CLIENT_DNS_IPV6_1=""
CLIENT_DNS_IPV6_2=""
ALLOWED_IPS="0.0.0.0/0,::/0"
ENABLE_IPV6="y"
JC=4; JMIN=40; JMAX=70; S1=50; S2=100; MTU=1280
H1=$((RANDOM % 32767 * 1000 + RANDOM % 1000 + 10000))
H2=$((RANDOM % 32767 * 1000 + RANDOM % 1000 + 20000))
H3=$((RANDOM % 32767 * 1000 + RANDOM % 1000 + 30000))
H4=$((RANDOM % 32767 * 1000 + RANDOM % 1000 + 40000))
PARAMS_FILE="/etc/amnezia/amneziawg/params"
WG_CONF_DIR="/etc/wireguard"
AWG_CONF_DIR="/etc/amnezia/amneziawg"
MIGRATION_NEEDED="false"
MIGRATION_TYPE=""
MIGRATION_WG_INTERFACE=""

handle_error() {
    local exit_code=$?
    local line_no=$1
    echo -e "${RED}Error occurred in script at line: ${line_no}${NC}"
    echo -e "${RED}Exit code: ${exit_code}${NC}"
    [[ "$DEBUG_MODE" == "true" ]] && set +x
    exit "${exit_code}"
}
trap 'handle_error $LINENO' ERR

print_header() {
    local title="$1"
    local width=51
    printf "\n"
    printf "╔═══════════════════════════════════════════════════╗\n"
    printf "║ %-*s   ║\n" $((width-4)) "${title}"
    printf "╚═══════════════════════════════════════════════════╝\n"
    printf "\n"
}

isRoot() {
	if [ "${EUID}" -ne 0 ]; then
		echo -e "${RED}You need to run this script as root.${NC}"
		exit 1
	fi
}

checkVirt() {
    [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Entering function checkVirt"
	function openvzErr() { echo -e "${RED}OpenVZ is not supported.${NC}"; exit 1; }
	function lxcErr() { echo -e "${RED}LXC is not supported (yet).${NC}"; exit 1; }
	local virt_what=""; local systemd_virt=""
	if command -v virt-what &>/dev/null; then
		virt_what=$(virt-what)
		if [ "${virt_what}" == "openvz" ]; then openvzErr; fi
		if [ "${virt_what}" == "lxc" ]; then lxcErr; fi
	elif command -v systemd-detect-virt &>/dev/null; then
        systemd_virt=$(systemd-detect-virt)
		if [ "${systemd_virt}" == "openvz" ]; then openvzErr; fi
		if [ "${systemd_virt}" == "lxc" ]; then lxcErr; fi
	else
        echo -e "${ORANGE}Could not detect virtualization type. Proceeding with caution.${NC}"
    fi
}

checkOS() {
    [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Entering function checkOS"
    if [ -f /etc/os-release ]; then
	    source /etc/os-release
        OS="${ID}"
        OS_VERSION="${VERSION_ID}"
    elif [ -f /etc/debian_version ]; then
        OS="debian"
        OS_VERSION=$(cat /etc/debian_version)
    elif [ -f /etc/redhat-release ]; then
        OS="rhel"
        if grep -q "CentOS" /etc/redhat-release; then OS="centos"; fi
        if grep -q "Fedora" /etc/redhat-release; then OS="fedora"; fi
        OS_VERSION=$(grep -oP '[0-9]+(\.[0-9]+)?' /etc/redhat-release | head -1)
    else
        echo -e "${RED}Unsupported operating system.${NC}"; exit 1
    fi

	if [[ ${OS} == "debian" || ${OS} == "raspbian" ]]; then
		if [[ -z "$OS_VERSION" ]] || (( $(echo "$OS_VERSION" | cut -d'.' -f1) < 10 )); then echo -e "${RED}Debian ${OS_VERSION:-unknown} not supported. Need 10+.${NC}"; exit 1; fi
		OS=debian
	elif [[ ${OS} == "ubuntu" || ${OS} == "linuxmint" ]]; then
		local release_year=0; [[ -n "$OS_VERSION" ]] && release_year=$(echo "${OS_VERSION}" | cut -d'.' -f1)
		if (( release_year < 18 )); then echo -e "${RED}Ubuntu/Mint ${OS_VERSION:-unknown} not supported. Need 18.04+.${NC}"; exit 1; fi
		OS=ubuntu
	elif [[ ${OS} == "rhel" || ${OS} == "centos" || ${OS} == "fedora" || ${OS} == "rocky" || ${OS} == "almalinux" ]]; then
        local required_version=7; if [[ $OS == "fedora" ]]; then required_version=28; fi
        local major_version=0; if [[ -n "$OS_VERSION" ]]; then major_version=$(echo "$OS_VERSION" | cut -d'.' -f1); fi
		if (( major_version < required_version )); then echo -e "${RED}RHEL-based OS ${OS_VERSION:-unknown} not supported.${NC}"; exit 1; fi
        echo -e "${GREEN}Attempting EPEL setup...${NC}"
		if [[ ${OS} == "fedora" ]]; then
            dnf install -y 'dnf-command(config-manager)' || echo -e "${ORANGE}Could not install config-manager.${NC}"
            dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-$(rpm -E %fedora).noarch.rpm || echo -e "${ORANGE}Could not install EPEL.${NC}"
		else
            yum install -y epel-release || echo -e "${ORANGE}Could not install EPEL.${NC}"
            if [[ $OS == "rhel" && $major_version -ge 8 ]]; then
                 subscription-manager repos --enable codeready-builder-for-rhel-$(rpm -E %rhel)-$(arch)-rpms || echo -e "${ORANGE}Could not enable CodeReady Builder.${NC}"
            elif [[ ($OS == "centos" || $OS == "rocky" || $OS == "almalinux") && $major_version -ge 8 ]]; then
                 dnf config-manager --set-enabled crb || yum-config-manager --enable powertools || echo -e "${ORANGE}Could not enable CRB/PowerTools.${NC}"
            fi
		fi
		OS=rhel
	else
		echo -e "${RED}Unsupported OS: ${OS:-unknown}${NC}"; exit 1
	fi
}

setupDebSrc() {
    [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Entering function setupDebSrc"
    if [[ ${OS} != "debian" && ${OS} != "ubuntu" ]]; then return; fi
    local sources_file=""; local src_pattern=""; local sed_command=""; local needs_update=0
    echo -e "${GREEN}Checking deb-src repositories...${NC}"
    if [[ ${OS} == "ubuntu" ]]; then
        sources_file="/etc/apt/sources.list.d/ubuntu.sources"
        if [ -f "${sources_file}" ]; then
             if ! grep -q "^Types:.*deb-src" "${sources_file}"; then
                 echo -e "${ORANGE}deb-src repositories may not be enabled in ${sources_file}.${NC}"
                 read -rp "Attempt enabling deb-src? [y/n]: " -e -i "y" ENABLE_SRC
                 if [[ ${ENABLE_SRC,,} == 'y' ]]; then
                     sed -i.bak -E '/^Types: deb$/s/deb/deb deb-src/' "${sources_file}"
                     echo -e "${GREEN}Attempted enable. Backup: ${sources_file}.bak${NC}"
                     needs_update=1
                 else echo -e "${RED}deb-src required.${NC}"; exit 1; fi
             else echo -e "${GREEN}deb-src seems enabled in ${sources_file}.${NC}"; fi
        elif [ -f "/etc/apt/sources.list" ]; then
             sources_file="/etc/apt/sources.list"; src_pattern="^deb-src"; sed_command='s/^#\s*deb-src/deb-src/'
             if ! grep -qE "${src_pattern}" "${sources_file}"; then
                 echo -e "${ORANGE}deb-src repositories may not be enabled in ${sources_file}.${NC}"
                 read -rp "Attempt enabling deb-src (uncomment)? [y/n]: " -e -i "y" ENABLE_SRC
                 if [[ ${ENABLE_SRC,,} == 'y' ]]; then
                     sed -i.bak -E "${sed_command}" "${sources_file}"
                     echo -e "${GREEN}Attempted enable. Backup: ${sources_file}.bak${NC}"
                     needs_update=1
                 else echo -e "${RED}deb-src required.${NC}"; exit 1; fi
             else echo -e "${GREEN}deb-src seems enabled in ${sources_file}.${NC}"; fi
        else echo -e "${RED}Cannot find standard sources list.${NC}"; exit 1; fi
    elif [[ ${OS} == "debian" ]]; then
        sources_file="/etc/apt/sources.list"; src_pattern="^deb-src"; sed_command='s/^#\s*deb-src/deb-src/'
        if [ -f "${sources_file}" ]; then
             if ! grep -qE "${src_pattern}" "${sources_file}"; then
                 echo -e "${ORANGE}deb-src repositories may not be enabled in ${sources_file}.${NC}"
                 read -rp "Attempt enabling deb-src (uncomment)? [y/n]: " -e -i "y" ENABLE_SRC
                 if [[ ${ENABLE_SRC,,} == 'y' ]]; then
                     sed -i.bak -E "${sed_command}" "${sources_file}"
                     echo -e "${GREEN}Attempted enable. Backup: ${sources_file}.bak${NC}"
                     needs_update=1
                 else echo -e "${RED}deb-src required.${NC}"; exit 1; fi
             else echo -e "${GREEN}deb-src seems enabled in ${sources_file}.${NC}"; fi
        else echo -e "${RED}Cannot find /etc/apt/sources.list.${NC}"; exit 1; fi
    fi
    if [[ ${needs_update} -eq 1 ]]; then echo -e "${GREEN}Running apt-get update...${NC}"; apt-get update; fi
}

getHomeDirForClient() {
	local client_name="${1:-}"; local home_dir=""
	if [ -n "${client_name}" ] && [ -d "/home/${client_name}" ]; then home_dir="/home/${client_name}"
	elif [ -n "${SUDO_USER}" ] && [ "${SUDO_USER}" != "root" ] && [ -d "/home/${SUDO_USER}" ]; then home_dir="/home/${SUDO_USER}"
	elif [ -d "/root" ]; then home_dir="/root"
    else home_dir="/tmp"; echo -e "${ORANGE}Warn: Using ${home_dir} for client configs.${NC}"; fi
	echo "${home_dir}"
}

detectExistingWireGuard() {
    [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Entering function detectExistingWireGuard"
    MIGRATION_NEEDED="false"; MIGRATION_TYPE=""; MIGRATION_WG_INTERFACE=""

    [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Checking for AmneziaWG params file: ${PARAMS_FILE}"
    if [[ -f "${PARAMS_FILE}" ]]; then
        echo -e "${GREEN}Existing AmneziaWG installation detected (${PARAMS_FILE}).${NC}"
        [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Exiting detectExistingWireGuard with status 0"
        return 0
    fi

    [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Checking for WireGuard config directory: ${WG_CONF_DIR}"
    if [[ -d "${WG_CONF_DIR}" ]]; then
        if [[ ! -r "${WG_CONF_DIR}" || ! -x "${WG_CONF_DIR}" ]]; then
            echo -e "${RED}Error: Cannot access WireGuard directory: ${WG_CONF_DIR}${NC}"
            exit 1
        fi

        local wg_conf_file=""
        wg_conf_file=$(find "${WG_CONF_DIR}" -maxdepth 1 -name "*.conf" -print -quit)
        [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Found potential WG conf file: ${wg_conf_file}"

        if [[ -n "${wg_conf_file}" ]]; then
            print_header "Existing WireGuard Detected"
            MIGRATION_WG_INTERFACE=$(basename "${wg_conf_file}" .conf)
            echo -e "${ORANGE}WireGuard configuration files found in ${WG_CONF_DIR} (Interface: ${MIGRATION_WG_INTERFACE}).${NC}"
            echo ""

            if [[ -f "${WG_CONF_DIR}/params" ]]; then
                echo -e "${GREEN}Detected WireGuard likely installed using the 'angristan/wireguard-install' script.${NC}"
                MIGRATION_TYPE="script"
            else
                echo -e "${GREEN}Detected standard WireGuard installation.${NC}"
                MIGRATION_TYPE="standard"
            fi

            MIGRATION_NEEDED="true"
            echo -e "${ORANGE}Migration to AmneziaWG is required.${NC}"
            echo "The script will first install the necessary AmneziaWG packages."
            echo "Then, it will attempt to migrate your settings (IPs, Port, Server Key, Client Keys)."
            echo "New AmneziaWG-compatible client config files will be generated."
            echo -e "The original WireGuard service (${MIGRATION_WG_INTERFACE}) will be stopped and disabled.${NC}"
            echo ""
            read -n1 -r -p "Press any key to acknowledge and continue..."
            echo ""
            [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: After read, preparing to return 2"
            [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Exiting detectExistingWireGuard with status 2"
            return 2 # Migration needed
        fi
    fi

    [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: No WG conf files found. Checking for installed packages."
    if dpkg-query -W -f='${Status}' wireguard 2>/dev/null | grep -q "ok installed" || \
       dpkg-query -W -f='${Status}' wireguard-tools 2>/dev/null | grep -q "ok installed" || \
       (command -v rpm &>/dev/null && rpm -q wireguard-tools &>/dev/null); then
        echo -e "${ORANGE}WireGuard package (or tools) is installed but no config files found in ${WG_CONF_DIR}.${NC}"
        read -rp "Remove existing WireGuard package(s) before installing AmneziaWG? [y/n]: " -e -i "y" REMOVE_PKG
        if [[ ${REMOVE_PKG,,} == 'y' ]]; then
            echo -e "${GREEN}Removing WireGuard packages...${NC}"
            if [[ ${OS} == "ubuntu" || ${OS} == "debian" ]]; then
                apt-get purge -y wireguard wireguard-tools; apt-get autoremove -y
            elif [[ ${OS} == "rhel" ]]; then
                yum remove -y wireguard-tools || dnf remove -y wireguard-tools
                yum autoremove -y || dnf autoremove -y
            fi
            echo -e "${GREEN}WireGuard packages removed (if found).${NC}"
        else
            echo -e "${ORANGE}Proceeding without removing existing WireGuard packages. This might cause conflicts.${NC}"
        fi
    else
        echo -e "${GREEN}No existing WireGuard or AmneziaWG installation detected.${NC}"
    fi

    [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Exiting detectExistingWireGuard with status 1"
    return 1
}

initialCheck() {
    [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Entering function initialCheck"
	isRoot
	checkOS
	checkVirt
    detectExistingWireGuard
    local detect_status=$?
    [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Exiting function initialCheck with status ${detect_status}"
    return ${detect_status}
}

installQuestions() {
    [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Entering function installQuestions"
    print_header "AmneziaWG Installer - Configuration"
	echo "Gathering initial configuration preferences."
	echo "Some settings might be overridden if migrating an existing WireGuard setup."
	echo ""

	echo -e "${GREEN}Enable IPv6 support?${NC}"
	read -rp "[y/n]: " -e -i "${ENABLE_IPV6}" choice; ENABLE_IPV6=${choice,,}
	[[ "$ENABLE_IPV6" != "y" ]] && ENABLE_IPV6="n"
    echo ""

    SERVER_PUB_IP=""; auto_ipv4=""; auto_ipv6=""; use_hostname="n";
	SERVER_PUB_NIC="$(ip -4 route ls | grep default | awk '/dev/ {print $5}' | head -1)"
    if [[ -n "$SERVER_PUB_NIC" ]]; then
        auto_ipv4=$(ip -4 addr show "${SERVER_PUB_NIC}" | grep -oP 'inet \K[0-9\.]+' | head -1)
        [[ ${ENABLE_IPV6} == 'y' ]] && auto_ipv6=$(ip -6 addr show "${SERVER_PUB_NIC}" scope global | grep -oP 'inet6 \K[0-9a-fA-F:]+' | head -1)
        echo "Detected: NIC=${SERVER_PUB_NIC}, IPv4=${auto_ipv4:-N/A}, IPv6=${auto_ipv6:-N/A}"
    else echo -e "${ORANGE}Could not auto-detect public interface.${NC}"; fi

	server_hostname=$(hostname -f 2>/dev/null || hostname 2>/dev/null); if [[ -n "${server_hostname}" && "${server_hostname}" != "localhost" ]]; then
        read -rp "Use hostname (${server_hostname}) as endpoint? [y/n]: " -e -i "y" choice; use_hostname=${choice,,}
		[[ ${use_hostname} == 'y' ]] && SERVER_PUB_IP="${server_hostname}"; echo ""
    fi
	if [[ ${use_hostname} != 'y' ]]; then read -rp "Public IPv4 address or Hostname: " -e -i "${auto_ipv4:-}" SERVER_PUB_IP; fi
    [[ -z "${SERVER_PUB_IP}" ]] && { echo -e "${RED}Server IP/hostname empty.${NC}"; exit 1; }; echo ""

    local SERVER_PUB_NIC_INPUT=""; until [[ "${SERVER_PUB_NIC_INPUT}" =~ ^[a-zA-Z0-9_.-]+$ ]]; do read -rp "Public Network Interface: " -e -i "${SERVER_PUB_NIC:-eth0}" SERVER_PUB_NIC_INPUT; done; SERVER_PUB_NIC="${SERVER_PUB_NIC_INPUT}"; echo ""

	until [[ "${SERVER_WG_NIC}" =~ ^[a-zA-Z0-9_.-]+$ && ${#SERVER_WG_NIC} -lt 16 ]]; do read -rp "AmneziaWG Interface Name: " -e -i "${SERVER_WG_NIC}" SERVER_WG_NIC; done; echo ""

	until [[ "${SERVER_WG_IPV4}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; do read -rp "VPN Internal Subnet IPv4 (e.g., 10.0.0.1): " -e -i "10.0.0.1" SERVER_WG_IPV4; done
	if [[ ${ENABLE_IPV6} == 'y' ]]; then
        until [[ "${SERVER_WG_IPV6}" =~ ^([a-fA-F0-9]{1,4}:){1,7}[a-fA-F0-9]{1,4}$|^([a-fA-F0-9]{1,4}:){1,7}:([a-fA-F0-9]{1,4})?$|^::$ ]]; do
            local suggested_ipv6="fd$(openssl rand -hex 5)"; suggested_ipv6="fd${suggested_ipv6:0:2}:${suggested_ipv6:2:4}:${suggested_ipv6:6:4}::1"
			read -rp "VPN Internal Subnet IPv6 (e.g., ${suggested_ipv6}): " -e -i "${suggested_ipv6}" SERVER_WG_IPV6
		done
	else SERVER_WG_IPV6=""; fi; echo ""

	local random_port=$(shuf -i49152-65535 -n1); until [[ "${SERVER_PORT}" =~ ^[0-9]+$ ]] && [ "${SERVER_PORT}" -ge 1 ] && [ "${SERVER_PORT}" -le 65535 ]; do read -rp "AmneziaWG Listen Port [1-65535]: " -e -i "${random_port}" SERVER_PORT; done; echo ""

    if configureAllowedIPs "${ENABLE_IPV6}"; then
        mkdir -p "${AWG_CONF_DIR}"; echo "${ALLOWED_IPS}" > "${AWG_CONF_DIR}/default_routing"
		echo ""
	    echo -e "${GREEN}Default routing selection saved to ${AWG_CONF_DIR}/default_routing${NC}"; echo ""
    else
        echo -e "${RED}Failed to configure Allowed IPs. Exiting.${NC}"
        exit 1
    fi

    print_header "DNS Server Selection"; echo "Select DNS for clients:"; printf "   1) Google\n   2) Cloudflare\n   3) Comss.one DNS\n   4) OpenDNS\n   5) AdGuard DNS\n   6) Custom\n"
	local dns_choice=""; until [[ "${dns_choice}" =~ ^[1-6]$ ]]; do read -rp "[1-6]: " -e -i "3" dns_choice; done
	case "${dns_choice}" in
		1) CLIENT_DNS_1="8.8.8.8"; CLIENT_DNS_2="8.8.4.4"; CLIENT_DNS_IPV6_1="2001:4860:4860::8888"; CLIENT_DNS_IPV6_2="2001:4860:4860::8844";;
		2) CLIENT_DNS_1="1.1.1.1"; CLIENT_DNS_2="1.0.0.1"; CLIENT_DNS_IPV6_1="2606:4700:4700::1111"; CLIENT_DNS_IPV6_2="2606:4700:4700::1001";;
        3) CLIENT_DNS_1="83.220.169.155"; CLIENT_DNS_2="212.109.195.93"; CLIENT_DNS_IPV6_1="2606:4700:4700::1111"; CLIENT_DNS_IPV6_2="2606:4700:4700::1001";;
		4) CLIENT_DNS_1="208.67.222.222"; CLIENT_DNS_2="208.67.220.220"; CLIENT_DNS_IPV6_1="2620:119:35::35"; CLIENT_DNS_IPV6_2="2620:119:53::53";;
		5) CLIENT_DNS_1="94.140.14.14"; CLIENT_DNS_2="94.140.15.15"; CLIENT_DNS_IPV6_1="2a10:50c0::ad1:ff"; CLIENT_DNS_IPV6_2="2a10:50c0::ad2:ff";;
		6) read -rp "Primary DNS IPv4: " -e CLIENT_DNS_1; read -rp "Secondary DNS IPv4 (opt): " -e CLIENT_DNS_2;
			if [[ ${ENABLE_IPV6} == 'y' ]]; then read -rp "Primary DNS IPv6 (opt): " -e CLIENT_DNS_IPV6_1; read -rp "Secondary DNS IPv6 (opt): " -e CLIENT_DNS_IPV6_2; else CLIENT_DNS_IPV6_1=""; CLIENT_DNS_IPV6_2=""; fi
            [[ -z "$CLIENT_DNS_1" ]] && { echo -e "${RED}Primary DNS empty. Defaulting to Cloudflare.${NC}"; CLIENT_DNS_1="1.1.1.1"; CLIENT_DNS_2="1.0.0.1"; CLIENT_DNS_IPV6_1="2606:4700:4700::1111"; CLIENT_DNS_IPV6_2="2606:4700:4700::1001"; };;
	esac
    [[ "$ENABLE_IPV6" != "y" ]] && { CLIENT_DNS_IPV6_1=""; CLIENT_DNS_IPV6_2=""; }; echo ""

	setDefaultAmneziaSettings

	echo -e "${GREEN}Initial configuration gathered.${NC}"
    echo ""
	read -n1 -r -p "Press any key to start the installation..."
	echo ""
}

installAmneziaWGRHEL() {
    [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Entering function installAmneziaWGRHEL"
    echo -e "${GREEN}Installing AmneziaWG for RHEL-based systems...${NC}"
    local pkg_manager="yum"; if command -v dnf &>/dev/null; then pkg_manager="dnf"; fi
    if ! rpm -q epel-release &>/dev/null; then echo -e "${GREEN}Installing EPEL...${NC}"; $pkg_manager install -y epel-release || echo -e "${ORANGE}EPEL install failed.${NC}"; fi
    echo -e "${GREEN}Removing standard wireguard-tools if present...${NC}"; $pkg_manager remove -y wireguard-tools > /dev/null 2>&1
    echo -e "${GREEN}Adding Amnezia repository...${NC}"
    cat > /etc/yum.repos.d/amnezia.repo << 'EOF'
[amnezia]
name=Amnezia Repository
baseurl=https://rpm.amnezia.org/stable/
enabled=1
gpgcheck=0
EOF
    echo -e "${GREEN}Installing kernel headers/dev tools...${NC}"
    $pkg_manager install -y kernel-devel-$(uname -r) kernel-headers-$(uname -r) make gcc dkms || {
        echo -e "${ORANGE}Failed installing exact kernel headers. Trying generic...${NC}"
        $pkg_manager install -y kernel-devel kernel-headers make gcc dkms || {
             echo -e "${RED}Failed to install kernel headers or development tools.${NC}"; exit 1;
        }
    }
    echo -e "${GREEN}Installing AmneziaWG package...${NC}"
    if $pkg_manager install -y amneziawg; then echo -e "${GREEN}AmneziaWG installed successfully.${NC}"; else echo -e "${RED}Failed amneziawg install.${NC}"; exit 1; fi
}

installAmneziaWGPackagesOnly() {
    [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Entering function installAmneziaWGPackagesOnly"
    print_header "Installing AmneziaWG Packages"
    echo -e "${GREEN}Installing dependencies...${NC}"
    local kernel_headers_pkg=""
    if [[ ${OS} == "ubuntu" || ${OS} == "debian" ]]; then
        setupDebSrc; apt-get update
        kernel_headers_pkg="linux-headers-$(uname -r)"
        if ! apt-cache show "${kernel_headers_pkg}" > /dev/null 2>&1; then
            kernel_headers_pkg="linux-headers-generic"; if ! apt-cache show "${kernel_headers_pkg}" > /dev/null 2>&1; then
                 kernel_headers_pkg="linux-headers-$(echo "$(uname -r)" | cut -d'-' -f3-)"; if ! apt-cache show "${kernel_headers_pkg}" > /dev/null 2>&1; then
                    echo -e "${RED}Error: Cannot find suitable linux-headers package.${NC}"; exit 1;
                 fi
            fi
        fi
        apt-get install -y software-properties-common python3-launchpadlib gnupg "${kernel_headers_pkg}" make dkms qrencode || { echo -e "${RED}Failed to install dependencies.${NC}"; exit 1; }

        echo -e "${GREEN}Adding Amnezia PPA repository...${NC}"
        if ! command -v add-apt-repository &> /dev/null; then apt-get install -y software-properties-common; fi
        add-apt-repository -y ppa:amnezia/ppa || {
             echo -e "${RED}Failed PPA add. Trying manual GPG...${NC}"
             gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys E45A7054 && \
             gpg --export --armor E45A7054 | sudo tee /etc/apt/trusted.gpg.d/amnezia_ppa.gpg >/dev/null && \
             add-apt-repository -y ppa:amnezia/ppa && echo -e "${GREEN}Manual GPG OK.${NC}" || \
             { echo -e "${RED}Failed PPA add even with manual key.${NC}"; exit 1; }
        }
        apt-get update
        echo -e "${GREEN}Installing AmneziaWG package...${NC}"
        apt-get install -y amneziawg || { echo -e "${RED}Failed to install amneziawg package.${NC}"; exit 1; }

    elif [[ ${OS} == "rhel" ]]; then
        installAmneziaWGRHEL
        if ! command -v qrencode &>/dev/null; then
            yum install -y qrencode || dnf install -y qrencode || echo -e "${ORANGE}qrencode package not found, needed for QR codes.${NC}"
        fi
    fi
    echo -e "${GREEN}AmneziaWG core packages installed.${NC}"
}

setupFirewall() {
    [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Entering function setupFirewall"
    local interface_config_file="$1"
    if [[ ! -f "$interface_config_file" ]]; then
        echo -e "${RED}Cannot setup firewall, config file missing: ${interface_config_file}${NC}"
        return 1
    fi
    if [[ -z "$SERVER_WG_IPV4" || -z "$SERVER_PORT" || -z "$SERVER_PUB_NIC" || -z "$SERVER_WG_NIC" ]] && [[ -f "$PARAMS_FILE" ]]; then
         [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Sourcing params for firewall setup: ${PARAMS_FILE}"
         source "$PARAMS_FILE"
    fi
     if [[ -z "$SERVER_WG_IPV4" || -z "$SERVER_PORT" || -z "$SERVER_PUB_NIC" || -z "$SERVER_WG_NIC" ]]; then
        echo -e "${RED}Missing required variables (IPs, Port, NICs) for firewall setup.${NC}"
        return 1
    fi

    echo -e "${GREEN}Configuring firewall rules in ${interface_config_file}...${NC}"
    sed -i '/^PostUp *=/d' "${interface_config_file}"
    sed -i '/^PostDown *=/d' "${interface_config_file}"

    local ip_v4_base="${SERVER_WG_IPV4%.*}"
    if command -v firewall-cmd &> /dev/null && pgrep firewalld; then
        echo -e "${GREEN}Using firewall-cmd.${NC}"
        local FIREWALLD_IPV4_ADDRESS="${ip_v4_base}.0"
        cat >> "${interface_config_file}" <<EOF
PostUp = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC}
PostUp = firewall-cmd --add-port ${SERVER_PORT}/udp
PostUp = firewall-cmd --add-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade'
PostDown = firewall-cmd --zone=public --remove-interface=${SERVER_WG_NIC}
PostDown = firewall-cmd --remove-port ${SERVER_PORT}/udp
PostDown = firewall-cmd --remove-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade'
EOF
        if [[ ${ENABLE_IPV6} == 'y' && -n "${SERVER_WG_IPV6}" ]]; then
            local FIREWALLD_IPV6_ADDRESS=$(ip -6 route get "${SERVER_WG_IPV6}" 2>/dev/null | grep via | awk '{print $1}')/64
            [[ -z "$FIREWALLD_IPV6_ADDRESS" ]] || [[ "$FIREWALLD_IPV6_ADDRESS" == "/64" ]] && FIREWALLD_IPV6_ADDRESS=$(echo "${SERVER_WG_IPV6}" | sed 's/:[^:]*$/::/')"/64"
            [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: FirewallD IPv6 Address: ${FIREWALLD_IPV6_ADDRESS}"
            cat >> "${interface_config_file}" <<EOF
PostUp = firewall-cmd --add-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS} masquerade'
PostDown = firewall-cmd --remove-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS} masquerade'
EOF
        fi
        echo -e "${GREEN}Making firewall rules permanent (firewall-cmd)...${NC}"
        firewall-cmd --runtime-to-permanent || echo -e "${ORANGE}Warning: Failed to make firewall rules permanent.${NC}"

    elif command -v iptables &> /dev/null && command -v ip6tables &>/dev/null; then
        echo -e "${GREEN}Using iptables/ip6tables.${NC}"
        cat >> "${interface_config_file}" <<EOF
PostUp = iptables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = iptables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
EOF
        if [[ ${ENABLE_IPV6} == 'y' && -n "${SERVER_WG_IPV6}" ]]; then
            cat >> "${interface_config_file}" <<EOF
PostUp = ip6tables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostUp = ip6tables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = ip6tables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostDown = ip6tables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
EOF
        fi
        if command -v iptables-save &> /dev/null; then
            echo -e "${GREEN}Saving iptables rules for persistence...${NC}"
            mkdir -p /etc/iptables
            iptables-save > /etc/iptables/rules.v4
            [[ ${ENABLE_IPV6} == 'y' && -n "${SERVER_WG_IPV6}" ]] && command -v ip6tables-save &>/dev/null && ip6tables-save > /etc/iptables/rules.v6
            if [[ ${OS} == "debian" || ${OS} == "ubuntu" ]]; then
                 if ! command -v iptables-persistent &>/dev/null; then
                     echo -e "${ORANGE}Installing iptables-persistent for rule saving...${NC}"
                     DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent || echo -e "${RED}Failed to install iptables-persistent.${NC}"
                 fi
            elif [[ ${OS} == "rhel" ]]; then
                 if ! systemctl is-enabled --quiet iptables-services; then
                     echo -e "${ORANGE}Ensure iptables-services is installed and enabled for rules persistence on RHEL/CentOS.${NC}"
                 fi
            fi
        fi
    else
        echo -e "${ORANGE}Warning: No firewall detected (firewalld or iptables). Rules not added.${NC}"
    fi
}

applySysctl() {
  [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Entering function applySysctl"
  echo -e "${GREEN}Enabling IP forwarding...${NC}"
  local sysctl_conf="/etc/sysctl.d/99-amneziawg-forward.conf"
  touch "${sysctl_conf}"
  sed -i '/net.ipv4.ip_forward/d' "${sysctl_conf}"
  sed -i '/net.ipv6.conf.all.forwarding/d' "${sysctl_conf}"
  echo "net.ipv4.ip_forward = 1" >> "${sysctl_conf}"
  if [[ ${ENABLE_IPV6} == 'y' ]]; then echo "net.ipv6.conf.all.forwarding = 1" >> "${sysctl_conf}"; fi
  echo -e "${GREEN}Applying sysctl settings...${NC}"
  sysctl --system > /dev/null
}

startAmneziaWGService() {
    [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Entering function startAmneziaWGService"
    if [[ -z "${SERVER_WG_NIC}" ]] && [[ -f "${PARAMS_FILE}" ]]; then
        [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Sourcing params for service start: ${PARAMS_FILE}"
        source "${PARAMS_FILE}";
    fi
    if [[ -z "${SERVER_WG_NIC}" ]]; then echo -e "${RED}Cannot start service, SERVER_WG_NIC not set.${NC}"; return 1; fi

    local service_name="awg-quick@${SERVER_WG_NIC}"
    local config_file="${AWG_CONF_DIR}/${SERVER_WG_NIC}.conf"

    if [[ ! -f "${config_file}" ]]; then
        echo -e "${RED}Cannot start service, config file missing: ${config_file}${NC}"
        return 1
    fi

    echo -e "${GREEN}Enabling and starting AmneziaWG service (${service_name})...${NC}"
    systemctl enable "${service_name}"
    systemctl restart "${service_name}"

    sleep 2
    if systemctl is-active --quiet "${service_name}"; then
        echo -e "${GREEN}AmneziaWG service is running.${NC}"
         [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Exiting function startAmneziaWGService (Success)"
        return 0
    else
        echo -e "${RED}AmneziaWG service failed to start.${NC}"
        echo -e "${RED}Check logs: journalctl -u ${service_name}${NC}"
        echo -e "${RED}Check config: ${config_file}${NC}"
         [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Exiting function startAmneziaWGService (Failure)"
        return 1
    fi
}

migrateWireGuard() {
    [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Entering function migrateWireGuard (Type: $1, Original IF: $2)"
    local installation_type="$1"
    local original_wg_interface="$2"
    print_header "WireGuard Migration (Post-Install)"
    echo -e "${GREEN}Starting migration (Type: ${installation_type}, Original IF: ${original_wg_interface})...${NC}"
    echo -e "${ORANGE}AmneziaWG packages should already be installed.${NC}"

    local wg_conf_file="${WG_CONF_DIR}/${original_wg_interface}.conf"
    [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Checking original WG conf: ${wg_conf_file}"
    if [[ ! -f "${wg_conf_file}" ]]; then echo -e "${RED}Original WG conf not found: ${wg_conf_file}.${NC}"; exit 1; fi
    if [[ ! -r "${wg_conf_file}" ]]; then echo -e "${RED}Cannot read original config: ${wg_conf_file}${NC}"; exit 1; fi
    echo -e "${GREEN}Found original config: ${wg_conf_file}${NC}"

    local stripped_config=""; local config_for_address_parsing=""; local original_config_content=""
    echo -e "${GREEN}Parsing config using 'wg-quick strip'...${NC}"
    mkdir -p "${AWG_CONF_DIR}"; chmod 700 "${AWG_CONF_DIR}"
    if ! stripped_config=$(wg-quick strip "${original_wg_interface}" 2> "${AWG_CONF_DIR}/wg-quick-strip.err"); then
        echo -e "${ORANGE}Warn: 'wg-quick strip' failed. Reading directly.${NC}"
        [[ -s "${AWG_CONF_DIR}/wg-quick-strip.err" ]] && cat "${AWG_CONF_DIR}/wg-quick-strip.err"
        if ! original_config_content=$(cat "${wg_conf_file}"); then echo -e "${RED}Cannot read config file: ${wg_conf_file}${NC}"; exit 1; fi
        stripped_config="${original_config_content}"; config_for_address_parsing="${original_config_content}"
    else
         echo -e "${GREEN}Parsed via 'wg-quick strip'.${NC}"
         rm -f "${AWG_CONF_DIR}/wg-quick-strip.err"
         if ! echo "${stripped_config}" | grep -q "Address *="; then
            echo -e "${ORANGE}Warn: 'strip' removed Address. Reading original.${NC}"
            if ! original_config_content=$(cat "${wg_conf_file}"); then echo -e "${RED}Failed read original for Address.${NC}"; exit 1; fi
            config_for_address_parsing="${original_config_content}"
         else config_for_address_parsing="${stripped_config}"; fi
    fi

    local migrated_wg_ipv4="" migrated_wg_ipv6="" migrated_port="" migrated_priv_key=""
    local address_line=$(echo "${config_for_address_parsing}" | grep -m 1 -oP 'Address *= *\K.*')
    migrated_wg_ipv4=$(echo "$address_line" | grep -oP '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
    migrated_wg_ipv6=$(echo "$address_line" | grep -oP '([a-fA-F0-9:]+:+[a-fA-F0-9:/]*)' | grep ':' | head -1 | sed 's|/.*||')
    migrated_port=$(echo "${stripped_config}" | grep -m 1 -oP 'ListenPort *= *\K[0-9]+')
    local stripped_priv_key=$(echo "${stripped_config}" | grep -m 1 -oP 'PrivateKey *= *\K[A-Za-z0-9+/=]+')

    if [[ (-z "${migrated_wg_ipv4}" && -z "${migrated_wg_ipv6}") || -z "${migrated_port}" ]]; then echo -e "${RED}Could not extract IP/Port. Cannot migrate.${NC}"; exit 1; fi
    echo -e "${GREEN}Migrated Settings:${NC} IPv4=${migrated_wg_ipv4:-N/A}, IPv6=${migrated_wg_ipv6:-N/A}, Port=${migrated_port}"

    if [[ "${installation_type}" == "script" ]] && [[ -f "${WG_CONF_DIR}/params" ]] && [[ -r "${WG_CONF_DIR}/params" ]]; then
        echo -e "${GREEN}Reading private key from ${WG_CONF_DIR}/params...${NC}"
        local sourced_priv_key=$(source "${WG_CONF_DIR}/params" && echo "${SERVER_PRIV_KEY}")
        if [[ -n "${sourced_priv_key}" ]] && echo "${sourced_priv_key}" | grep -Eq '^[A-Za-z0-9+/]{43}=$'; then
             migrated_priv_key="${sourced_priv_key}"; echo -e "${GREEN}Key read from params file.${NC}"
        else echo -e "${ORANGE}Warn: Invalid/missing key in ${WG_CONF_DIR}/params.${NC}"; fi
    fi
    if [[ -z "${migrated_priv_key}" ]]; then
        if [[ -n "${stripped_priv_key}" ]] && echo "${stripped_priv_key}" | grep -Eq '^[A-Za-z0-9+/]{43}=$'; then
            echo -e "${GREEN}Using Key from stripped config.${NC}"; migrated_priv_key="${stripped_priv_key}"
        else
            echo -e "${ORANGE}Could not find server private key.${NC}"; echo -e "${ORANGE}Provide path or new key generated.${NC}"; echo -e "${RED}New key means ALL clients NEED new config.${NC}"
            read -rp "Path to server private key file (empty=generate new): " key_file_path
            if [[ -n "$key_file_path" ]] && [[ -f "${key_file_path}" ]] && [[ -r "${key_file_path}" ]]; then
                local key_content=$(cat "${key_file_path}")
                if echo "${key_content}" | grep -Eq '^[A-Za-z0-9+/]{43}=$'; then migrated_priv_key="${key_content}"; echo -e "${GREEN}Key read OK.${NC}";
                else echo -e "${RED}Invalid key format. Generating new.${NC}"; fi
            elif [[ -n "$key_file_path" ]]; then echo -e "${RED}File not found/readable. Generating new.${NC}";
            else echo -e "${GREEN}Generating new key pair...${NC}"; fi
            [[ -z "${migrated_priv_key}" ]] && migrated_priv_key=$(awg genkey)
        fi
    fi

    local migrated_pub_key=$(echo "${migrated_priv_key}" | awg pubkey)
    if [[ -z "${migrated_pub_key}" ]]; then echo -e "${RED}Failed derive public key. Invalid private key?${NC}"; exit 1; fi
    echo -e "${GREEN}Server Public Key: ${migrated_pub_key}${NC}"

    SERVER_WG_IPV4="${migrated_wg_ipv4:-$SERVER_WG_IPV4}"
    SERVER_WG_IPV6="${migrated_wg_ipv6:-$SERVER_WG_IPV6}"
    SERVER_PORT="${migrated_port:-$SERVER_PORT}"
    SERVER_PRIV_KEY="${migrated_priv_key}"
    SERVER_PUB_KEY="${migrated_pub_key}"

    if [ -f "${AWG_CONF_DIR}/default_routing" ]; then
        ALLOWED_IPS=$(cat "${AWG_CONF_DIR}/default_routing")
        echo -e "${GREEN}Using routing from ${AWG_CONF_DIR}/default_routing: ${ALLOWED_IPS}${NC}"
    else
        echo -e "${ORANGE}Default routing file not found. Fallback '0.0.0.0/0,::/0'.${NC}"
        ALLOWED_IPS="0.0.0.0/0,::/0"
    fi
    [[ -n "${SERVER_WG_IPV6}" ]] && ENABLE_IPV6="y" || ENABLE_IPV6="n"
    if echo "$ALLOWED_IPS" | grep -q "0.0.0.0/0"; then
        if [[ ${ENABLE_IPV6} == 'y' ]]; then [[ "$ALLOWED_IPS" != *"::/0"* ]] && ALLOWED_IPS="${ALLOWED_IPS},::/0"; else ALLOWED_IPS=$(echo "$ALLOWED_IPS" | sed 's/,::\/0//'); fi
         echo "${ALLOWED_IPS}" > "${AWG_CONF_DIR}/default_routing"
         echo -e "${GREEN}Adjusted routing: ${ALLOWED_IPS}${NC}"
    fi

    [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Writing final params to ${PARAMS_FILE}"
    mkdir -p "$(dirname "${PARAMS_FILE}")"; chmod 700 "$(dirname "${PARAMS_FILE}")"
    cat > "${PARAMS_FILE}" <<EOF
SERVER_PUB_IP=${SERVER_PUB_IP}
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
ALLOWED_IPS=${ALLOWED_IPS}
ENABLE_IPV6=${ENABLE_IPV6}
EOF
    chmod 600 "${PARAMS_FILE}"
    echo -e "${GREEN}Parameters saved.${NC}"

    local home_dir=$(getHomeDirForClient "${SUDO_USER:-root}")
    local client_config_dir="${home_dir}/amneziawg"
    mkdir -p "${client_config_dir}"; chmod 700 "${client_config_dir}"
    echo -e "${GREEN}Client config directory: ${client_config_dir}${NC}"

    migratePeers "${stripped_config}" "${client_config_dir}"

    echo -e "${GREEN}Stopping/disabling original WG service (wg-quick@${original_wg_interface})...${NC}"
    local wg_service_name="wg-quick@${original_wg_interface}"
    systemctl is-active --quiet "${wg_service_name}" && systemctl stop "${wg_service_name}"
    systemctl is-enabled --quiet "${wg_service_name}" && systemctl disable "${wg_service_name}"
    echo -e "${GREEN}Original WG service stopped/disabled.${NC}"
    echo -e "${ORANGE}Original config files remain at ${WG_CONF_DIR} as backup.${NC}"

    local server_conf_file="${AWG_CONF_DIR}/${SERVER_WG_NIC}.conf"
    setupFirewall "${server_conf_file}"

    applySysctl

    read -rp "Remove original wireguard package? [y/n]: " -e -i "n" REMOVE_OLD_PKG
    if [[ ${REMOVE_OLD_PKG,,} == 'y' ]]; then
        echo -e "${GREEN}Removing wireguard-tools package...${NC}"
        if [[ ${OS} == "ubuntu" || ${OS} == "debian" ]]; then apt-get purge -y wireguard-tools; apt-get autoremove -y;
        elif [[ ${OS} == "rhel" ]]; then yum remove -y wireguard-tools || dnf remove -y wireguard-tools; yum autoremove -y || dnf autoremove -y; fi
        echo -e "${GREEN}wireguard-tools package removed.${NC}"
    fi

    if startAmneziaWGService; then
        local management_script_path="${home_dir}/amneziawg/amneziawg-install.sh"
        echo -e "${GREEN}Copying management script to ${management_script_path}...${NC}"
        cp "$0" "${management_script_path}" && chmod +x "${management_script_path}" || echo -e "${RED}Failed to copy management script.${NC}"

        print_header "Migration Complete"
        echo -e "${GREEN}AmneziaWG service (${SERVER_WG_NIC}) running with migrated settings.${NC}"
        echo -e "${ORANGE}IMPORTANT: Distribute NEW client configs from ${client_config_dir}${NC}"
        echo -e "${ORANGE}Old client configs lack obfuscation.${NC}"
        echo -e "${GREEN}Run ${management_script_path} for future management.${NC}"
    else
        echo -e "${RED}Migration completed, but AWG service failed to start. Check logs.${NC}"
        exit 1
    fi
}

migratePeers() {
    [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Entering function migratePeers"
    local stripped_config="$1"
    local client_config_dir="$2"

    [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Checking for params file in migratePeers: ${PARAMS_FILE}"
    if [[ ! -f "${PARAMS_FILE}" ]]; then echo -e "${RED}Params file ${PARAMS_FILE} missing in migratePeers!${NC}"; return 1; fi
    source "${PARAMS_FILE}"

    local server_conf_file="${AWG_CONF_DIR}/${SERVER_WG_NIC}.conf"
    echo -e "${GREEN}Generating AWG server config: ${server_conf_file}${NC}"

    local address_line=""
    [[ -n "${SERVER_WG_IPV4}" ]] && address_line="${SERVER_WG_IPV4}/24"
    [[ ${ENABLE_IPV6} == 'y' && -n "${SERVER_WG_IPV6}" ]] && { [[ -n "$address_line" ]] && address_line+=","; address_line+="${SERVER_WG_IPV6}/64"; }

    cat > "${server_conf_file}" << EOF
[Interface]
Address = ${address_line}
ListenPort = ${SERVER_PORT}
PrivateKey = ${SERVER_PRIV_KEY}
Jc = ${JC}
Jmin = ${JMIN}
Jmax = ${JMAX}
S1 = ${S1}
S2 = ${S2}
H1 = ${H1}
H2 = ${H2}
H3 = ${H3}
H4 = ${H4}
MTU = ${MTU}
EOF

    echo -e "${GREEN}Migrating peer configs (generating NEW client files)...${NC}"
    echo -e "${ORANGE}Clients MUST use these new files.${NC}"

    local peer_block=""; local client_counter=0
    echo "${stripped_config}" | awk '/^\[Peer\]/{ if (peer_block) print peer_block; peer_block=""; next } NF > 0 { peer_block = peer_block $0 "\n" } END { if (peer_block) print peer_block }' | while IFS= read -r peer_block; do
        local peer_pub_key="" peer_allowed_ips="" peer_psk=""
        peer_pub_key=$(echo "${peer_block}" | grep -oP 'PublicKey *= *\K[A-Za-z0-9+/=]+')
        peer_allowed_ips=$(echo "${peer_block}" | grep -oP 'AllowedIPs *= *\K[0-9a-fA-F\.:/,]+')
        peer_psk=$(echo "${peer_block}" | grep -oP 'PresharedKey *= *\K[A-Za-z0-9+/=]+')

        if [[ -z "${peer_pub_key}" || -z "${peer_allowed_ips}" ]]; then echo -e "${ORANGE}Skipping invalid peer block:${NC}\n${peer_block}"; continue; fi
        ((client_counter++))
        local client_name="migrated_client_${client_counter}_$(echo "${peer_pub_key}" | cut -c1-6)"
        echo -e "  -> Migrating Peer: ${client_name} (PubKey: ${peer_pub_key})"

        local client_priv_key=$(awg genkey)
        local client_wg_ipv4_peer=$(echo "${peer_allowed_ips}" | tr ',' '\n' | grep -oP '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        local client_wg_ipv6_peer=$(echo "${peer_allowed_ips}" | tr ',' '\n' | grep -oP '^[a-fA-F0-9:]+' | grep ':' | head -1 | sed 's|/.*||')
        if [[ -z "${client_wg_ipv4_peer}" && -z "${client_wg_ipv6_peer}" ]]; then echo -e "${ORANGE}    Warn: No client IP found. Cannot gen client conf.${NC}"; continue; fi

        local client_address_line=""
        [[ -n "$client_wg_ipv4_peer" ]] && client_address_line="${client_wg_ipv4_peer}/32"
        [[ -n "$client_wg_ipv6_peer" ]] && { [[ -n "$client_address_line" ]] && client_address_line+=","; client_address_line+="${client_wg_ipv6_peer}/128"; }

        local client_dns_line="${CLIENT_DNS_1}"
        [[ -n "${CLIENT_DNS_2}" ]] && client_dns_line+=",${CLIENT_DNS_2}"
        [[ -n "${CLIENT_DNS_IPV6_1}" ]] && client_dns_line+=",${CLIENT_DNS_IPV6_1}"
        [[ -n "${CLIENT_DNS_IPV6_2}" ]] && client_dns_line+=",${CLIENT_DNS_IPV6_2}"

        local client_conf_path="${client_config_dir}/${client_name}.conf"
        cat > "${client_conf_path}" <<EOF
[Interface]
PrivateKey = ${client_priv_key}
Address = ${client_address_line}
DNS = ${client_dns_line}
Jc = ${JC}
Jmin = ${JMIN}
Jmax = ${JMAX}
S1 = ${S1}
S2 = ${S2}
H1 = ${H1}
H2 = ${H2}
H3 = ${H3}
H4 = ${H4}
MTU = ${MTU}

[Peer]
PublicKey = ${SERVER_PUB_KEY}
$( [[ -n "${peer_psk}" ]] && echo "PresharedKey = ${peer_psk}" )
Endpoint = ${SERVER_PUB_IP}:${SERVER_PORT}
AllowedIPs = ${ALLOWED_IPS}
EOF
        chmod 600 "${client_conf_path}"
        echo -e "${GREEN}    Generated new client config: ${client_conf_path}${NC}"

        cat >> "${server_conf_file}" <<EOF

### Client ${client_name} (Migrated)
[Peer]
PublicKey = ${peer_pub_key}
$( [[ -n "${peer_psk}" ]] && echo "PresharedKey = ${peer_psk}" )
AllowedIPs = ${peer_allowed_ips}
EOF
    done

    if [[ ${client_counter} -eq 0 ]]; then echo -e "${ORANGE}No valid [Peer] sections found.${NC}"; else echo -e "${GREEN}Processed ${client_counter} peer(s).${NC}"; fi
}

setupServer() {
  [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Entering function setupServer"
  print_header "Setting Up NEW AmneziaWG Server"
  mkdir -p "${AWG_CONF_DIR}"; chmod 700 "${AWG_CONF_DIR}"

  echo -e "${GREEN}Generating NEW AWG server keys...${NC}"
  SERVER_PRIV_KEY=$(awg genkey); SERVER_PUB_KEY=$(echo "${SERVER_PRIV_KEY}" | awg pubkey)
  if [[ -z "$SERVER_PRIV_KEY" || -z "$SERVER_PUB_KEY" ]]; then echo -e "${RED}Failed key generation.${NC}"; exit 1; fi
  echo -e "${GREEN}Server keys generated.${NC}"

  local allowed_ips_file="${AWG_CONF_DIR}/default_routing"
  if [ -f "$allowed_ips_file" ]; then
      ALLOWED_IPS=$(cat "$allowed_ips_file")
      echo -e "${GREEN}Using routing from ${allowed_ips_file}: ${ALLOWED_IPS}${NC}";
      if echo "$ALLOWED_IPS" | grep -q "0.0.0.0/0"; then
         if [[ ${ENABLE_IPV6} == 'y' ]]; then [[ "$ALLOWED_IPS" != *"::/0"* ]] && ALLOWED_IPS="${ALLOWED_IPS},::/0"; else ALLOWED_IPS=$(echo "$ALLOWED_IPS" | sed 's/,::\/0//'); fi
         echo "${ALLOWED_IPS}" > "$allowed_ips_file"
         echo -e "${GREEN}Adjusted routing: ${ALLOWED_IPS}${NC}"
      fi
  else
      ALLOWED_IPS="0.0.0.0/0"; [[ "$ENABLE_IPV6" == "y" ]] && ALLOWED_IPS="${ALLOWED_IPS},::/0";
      echo -e "${ORANGE}Routing file not found. Using default: ${ALLOWED_IPS}${NC}";
      echo "${ALLOWED_IPS}" > "$allowed_ips_file"
  fi

  [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Writing params to ${PARAMS_FILE}"
  mkdir -p "$(dirname "${PARAMS_FILE}")"; chmod 700 "$(dirname "${PARAMS_FILE}")"
  cat > "${PARAMS_FILE}" <<EOF
SERVER_PUB_IP=${SERVER_PUB_IP}
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
ALLOWED_IPS=${ALLOWED_IPS}
ENABLE_IPV6=${ENABLE_IPV6}
EOF
  chmod 600 "${PARAMS_FILE}"

  applySysctl

  local interface_config_file="${AWG_CONF_DIR}/${SERVER_WG_NIC}.conf"
  echo -e "${GREEN}Creating server interface config: ${interface_config_file}...${NC}"
  local address_line=""
  [[ -n "${SERVER_WG_IPV4}" ]] && address_line="${SERVER_WG_IPV4}/24"
  [[ ${ENABLE_IPV6} == 'y' && -n "${SERVER_WG_IPV6}" ]] && { [[ -n "$address_line" ]] && address_line+=","; address_line+="${SERVER_WG_IPV6}/64"; }

  cat > "${interface_config_file}" <<EOF
[Interface]
Address = ${address_line}
ListenPort = ${SERVER_PORT}
PrivateKey = ${SERVER_PRIV_KEY}
Jc = ${JC}
Jmin = ${JMIN}
Jmax = ${JMAX}
S1 = ${S1}
S2 = ${S2}
H1 = ${H1}
H2 = ${H2}
H3 = ${H3}
H4 = ${H4}
MTU = ${MTU}
EOF

  setupFirewall "${interface_config_file}"

  if startAmneziaWGService; then
      echo ""
      echo -e "${GREEN}Adding initial client...${NC}"
      newClient || echo -e "${RED}Failed to add initial client.${NC}"

      local home_dir=$(getHomeDirForClient "${SUDO_USER:-root}")
      local management_script_path="${home_dir}/amneziawg/amneziawg-install.sh"
      echo -e "${GREEN}Copying management script to ${management_script_path}...${NC}"
      cp "$0" "${management_script_path}" && chmod +x "${management_script_path}" || echo -e "${RED}Failed to copy management script.${NC}"

      print_header "AmneziaWG Installation Complete"
      echo -e "${GREEN}Config: ${interface_config_file}, Params: ${PARAMS_FILE}${NC}"
      echo -e "${GREEN}Run ${management_script_path} for management.${NC}"
  else
      echo -e "${RED}Server setup failed. Service did not start correctly.${NC}"
      exit 1
  fi
  echo ""
}

installAmneziaWG() {
    [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Entering function installAmneziaWG"
    installQuestions
    installAmneziaWGPackagesOnly
    setupServer
}

newClient() {
    [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Entering function newClient"
    print_header "Add New AmneziaWG Client"; if [[ ! -f "${PARAMS_FILE}" ]]; then echo -e "${RED}Params file missing: ${PARAMS_FILE}${NC}"; return 1; fi; source "${PARAMS_FILE}"
    local client_name=""; echo "Enter client name (alphanumeric, underscores, dashes):"; while true; do read -rp "Name: " -e client_name
        if [[ "${client_name}" =~ ^[a-zA-Z0-9_-]+$ ]]; then
            if grep -q "^### Client ${client_name}$" "${AWG_CONF_DIR}/${SERVER_WG_NIC}.conf"; then echo -e "${ORANGE}Client '${client_name}' exists.${NC}"; read -rp "Overwrite (regenerate keys)? [y/n]: " -e -i "n" ow; if [[ ${ow,,} == "y" ]]; then regenerateClientConfig "${client_name}"; return $?; else client_name=""; echo "Choose different name."; fi
            else break; fi
        else echo "Invalid name."; fi
    done
    local client_priv_key=$(awg genkey); local client_pub_key=$(echo "${client_priv_key}" | awg pubkey); local client_psk=$(awg genpsk)

    local last_ip_part=1; local ip_v4_base="${SERVER_WG_IPV4%.*}";
    local existing_ips=$(grep -oP "AllowedIPs *=.*\K${ip_v4_base}\.[0-9]+(?=/)" "${AWG_CONF_DIR}/${SERVER_WG_NIC}.conf")
    [[ -n "$existing_ips" ]] && while IFS= read -r ip; do local cip=$(echo "$ip"|cut -d'.' -f4); [[ "$cip" =~ ^[0-9]+$ && "$cip" -gt "$last_ip_part" ]] && last_ip_part=$cip; done <<< "$existing_ips"
    local next_ip_index=$((last_ip_part + 1)); local client_wg_ipv4="${ip_v4_base}.${next_ip_index}"

    local client_wg_ipv6=""; if [[ ${ENABLE_IPV6} == 'y' && -n "${SERVER_WG_IPV6}" ]]; then
        local ipv6_base=$(echo "${SERVER_WG_IPV6}" | sed 's/::.*//'); local last_ipv6_part=1;
        local existing_ipv6s=$(grep -oP "AllowedIPs *=.*\K${ipv6_base}::[0-9a-fA-F]+(?=/)" "${AWG_CONF_DIR}/${SERVER_WG_NIC}.conf")
        [[ -n "$existing_ipv6s" ]] && while IFS= read -r ip6; do local chiph=$(echo "$ip6"|sed 's/.*:://'); [[ "$chiph" =~ ^[0-9a-fA-F]+$ ]] && local chipd=$((16#${chiph})); [[ "$chipd" -gt "$last_ipv6_part" ]] && last_ipv6_part=$chipd; done <<< "$existing_ipv6s"
        local next_ipv6_index_dec=$((last_ipv6_part + 1)); client_wg_ipv6="${ipv6_base}::$(printf "%x" ${next_ipv6_index_dec})"
    fi

    local home_dir=$(getHomeDirForClient "${SUDO_USER:-root}"); local client_config_dir="${home_dir}/amneziawg"; mkdir -p "${client_config_dir}"; chmod 700 "${client_config_dir}"

    local client_address_line=""
    [[ -n "$client_wg_ipv4" ]] && client_address_line="${client_wg_ipv4}/32"
    [[ -n "$client_wg_ipv6" ]] && { [[ -n "$client_address_line" ]] && client_address_line+=","; client_address_line+="${client_wg_ipv6}/128"; }

    local client_dns_line="${CLIENT_DNS_1}"
    [[ -n "${CLIENT_DNS_2}" ]] && client_dns_line+=",${CLIENT_DNS_2}"
    [[ -n "${CLIENT_DNS_IPV6_1}" ]] && client_dns_line+=",${CLIENT_DNS_IPV6_1}"
    [[ -n "${CLIENT_DNS_IPV6_2}" ]] && client_dns_line+=",${CLIENT_DNS_IPV6_2}"

    local client_conf_path="${client_config_dir}/${client_name}.conf"; echo -e "${GREEN}Generating client config: ${client_conf_path}${NC}"
    cat > "${client_conf_path}" <<EOF
[Interface]
PrivateKey = ${client_priv_key}
Address = ${client_address_line}
DNS = ${client_dns_line}
Jc = ${JC}
Jmin = ${JMIN}
Jmax = ${JMAX}
S1 = ${S1}
S2 = ${S2}
H1 = ${H1}
H2 = ${H2}
H3 = ${H3}
H4 = ${H4}
MTU = ${MTU}

[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${client_psk}
Endpoint = ${SERVER_PUB_IP}:${SERVER_PORT}
AllowedIPs = ${ALLOWED_IPS}
EOF
    chmod 600 "${client_conf_path}"

    echo -e "${GREEN}Adding peer to server configuration...${NC}"
    cat >> "${AWG_CONF_DIR}/${SERVER_WG_NIC}.conf" <<EOF

### Client ${client_name}
[Peer]
PublicKey = ${client_pub_key}
PresharedKey = ${client_psk}
AllowedIPs = ${client_address_line}
EOF

    echo -e "${GREEN}Applying changes to running server...${NC}"
    if ! awg syncconf "${SERVER_WG_NIC}" <(awg-quick strip "${SERVER_WG_NIC}"); then
        echo -e "${RED}Failed 'awg syncconf'.${NC} ${ORANGE}A service restart might be needed: systemctl restart awg-quick@${SERVER_WG_NIC}${NC}"
    else
        echo -e "${GREEN}Server configuration updated live.${NC}"
    fi
    echo ""
    if [[ "$ALLOWED_IPS" == *"0.0.0.0/0"* ]]; then
        if command -v qrencode &>/dev/null; then
            echo -e "${GREEN}Scan QR code:${NC}"; qrencode -t ansiutf8 < "${client_conf_path}" || echo -e "${ORANGE}Warning: QR code generation failed (config might be too large).${NC}"; echo ""
        else
            echo -e "${ORANGE}Install 'qrencode' to generate QR codes.${NC}"
        fi
    else
         echo -e "${ORANGE}QR code not displayed for large blocklist configurations.${NC}"
    fi
    echo -e "${GREEN}Client '${client_name}' added: ${client_conf_path}${NC}"; echo ""
	echo ""
}

listClients() {
    [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Entering function listClients"
    print_header "List Existing Clients"; if [[ -z "${SERVER_WG_NIC}" && -f "${PARAMS_FILE}" ]]; then source "${PARAMS_FILE}"; fi; local server_conf_file="${AWG_CONF_DIR}/${SERVER_WG_NIC:-dummy}.conf"
    if [[ ! -f "${server_conf_file}" ]]; then echo -e "${RED}Server conf not found: ${server_conf_file}${NC}"; return 1; fi

    local clients=$(grep -E "^### Client" "${server_conf_file}" | cut -d ' ' -f 3-)
    if [[ -z "$clients" ]]; then echo -e "${ORANGE}No clients found.${NC}"; return 1; fi

    echo "Clients for '${SERVER_WG_NIC}':"; echo "──────────────────────────────────────────"
    printf "%-30s %-20s\n" "Client Name" "VPN IP Address(es)"; echo "──────────────────────────────────────────"
    local i=1
    while IFS= read -r client_name; do
        local client_ips=$(awk -v name="${client_name}" 'BEGIN{RS="";FS="\n"} $1=="### Client "name{for(i=1;i<=NF;i++){if($i~/AllowedIPs *=/){sub(/AllowedIPs *= */,"",$i);print $i;exit}}}' "${server_conf_file}")
        printf "%2d) %-27s %-20s\n" "$i" "${client_name}" "${client_ips:-N/A}"
        ((i++))
    done <<< "$clients"
    echo "──────────────────────────────────────────"; echo ""
    local home_dir=$(getHomeDirForClient "${SUDO_USER:-root}"); echo -e "Configs typically stored in: ${home_dir}/amneziawg"; echo ""
    [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Exiting function listClients"
    return 0
}

revokeClient() {
    [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Entering function revokeClient"
    print_header "Revoke AmneziaWG Client"; if [[ -z "${SERVER_WG_NIC}" && -f "${PARAMS_FILE}" ]]; then source "${PARAMS_FILE}"; fi; local server_conf_file="${AWG_CONF_DIR}/${SERVER_WG_NIC:-dummy}.conf"; if [[ ! -f "${server_conf_file}" ]]; then echo -e "${RED}Server conf not found.${NC}"; return 1; fi

    local clients=$(grep -E "^### Client" "${server_conf_file}" | cut -d ' ' -f 3-)
    if [[ -z "$clients" ]]; then echo -e "${ORANGE}No clients to revoke.${NC}"; return; fi

    echo "Select client to revoke:"; local client_list=(); local i=1
    while IFS= read -r client; do echo "   ${i}) ${client}"; client_list+=("${client}"); ((i++)); done <<< "$clients"
    local client_count=$((i - 1)); echo ""
    local client_number=""
    until [[ "${client_number}" =~ ^[1-9][0-9]*$ && ${client_number} -le ${client_count} ]]; do read -rp "Enter client number [1-${client_count}]: " client_number; done
    local selected_client="${client_list[$((client_number - 1))]}"; echo ""
    read -rp "Revoke '${selected_client}'? [y/n]: " -e -i "n" confirm_revoke
    if [[ ${confirm_revoke,,} != "y" ]]; then echo "Cancelled."; return; fi

    echo -e "${ORANGE}Revoking: ${selected_client}...${NC}"
    cp "${server_conf_file}" "${server_conf_file}.bak.$(date +%s)"

    awk -v name="${selected_client}" 'BEGIN{RS="";FS="\n";ORS="\n\n"} !/^### Client / {print;next} $1 != "### Client " name {print}' "${server_conf_file}" > "${server_conf_file}.tmp"

    if [[ $? -eq 0 ]] && [[ -s "${server_conf_file}.tmp" ]]; then
        grep -v '^$' "${server_conf_file}.tmp" | awk 'BEGIN{ORS="\n"}{print}' > "${server_conf_file}"; rm "${server_conf_file}.tmp"
        echo -e "${GREEN}Client removed from server config.${NC}"
    else
        echo -e "${RED}Error removing client using awk. Restoring backup.${NC}"; [[ -f "${server_conf_file}.bak.$(date +%s)" ]] && mv "${server_conf_file}.bak.$(date +%s)" "${server_conf_file}"; rm -f "${server_conf_file}.tmp"; return 1;
    fi

    local home_dir=$(getHomeDirForClient "${SUDO_USER:-root}"); local client_config_dir="${home_dir}/amneziawg"
    local safe_client_name=$(echo "${selected_client}" | sed 's/[^a-zA-Z0-9_-]/_/g')
    local client_conf_path="${client_config_dir}/${safe_client_name}.conf"
    if [[ -f "${client_conf_path}" ]]; then echo -e "${GREEN}Deleting client config file: ${client_conf_path}${NC}"; rm -f "${client_conf_path}";
    else echo -e "${ORANGE}Client config file not found: ${client_conf_path}${NC}"; fi

    echo -e "${GREEN}Applying updated server config...${NC}"
    if ! awg syncconf "${SERVER_WG_NIC}" <(awg-quick strip "${SERVER_WG_NIC}"); then
        echo -e "${RED}Failed 'awg syncconf'.${NC} ${ORANGE}A service restart might be needed: systemctl restart awg-quick@${SERVER_WG_NIC}${NC}"
    else
        echo -e "${GREEN}Server configuration updated live.${NC}"
    fi
    echo -e "${GREEN}Client '${selected_client}' revoked!${NC}"; echo ""
}

regenerateClientConfig() {
     [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Entering function regenerateClientConfig for client: $1"
     local client_name="$1"; print_header "Regenerate Client Config"; echo -e "${GREEN}Regenerating for: ${client_name}${NC}"; if [[ -z "${SERVER_WG_NIC}" && -f "${PARAMS_FILE}" ]]; then source "${PARAMS_FILE}"; fi; local server_conf_file="${AWG_CONF_DIR}/${SERVER_WG_NIC:-dummy}.conf"
     if [[ ! -f "${server_conf_file}" || ! -f "${PARAMS_FILE}" ]]; then echo -e "${RED}Server config or params file missing.${NC}"; return 1; fi; if ! grep -q "^### Client ${client_name}" "${server_conf_file}"; then echo -e "${RED}Client '${client_name}' not found.${NC}"; return 1; fi
     source "${PARAMS_FILE}"

     local client_ips=$(awk -v name="${client_name}" 'BEGIN{RS="";FS="\n"} $1=="### Client "name{for(i=1;i<=NF;i++){if($i~/AllowedIPs *=/){sub(/AllowedIPs *= */,"",$i);print $i;exit}}}' "${server_conf_file}"); if [[ -z "$client_ips" ]]; then echo -e "${RED}Could not find AllowedIPs for client.${NC}"; return 1; fi
     local client_wg_ipv4=$(echo "$client_ips" | tr ',' '\n' | grep -oP '^[0-9\.]+' | head -1)
     local client_wg_ipv6=$(echo "$client_ips" | tr ',' '\n' | grep -oP '^[a-fA-F0-9:]+' | grep ':' | head -1 | sed 's|/.*||')

     local client_psk=$(awk -v name="${client_name}" 'BEGIN{RS="";FS="\n"} $1=="### Client "name{for(i=1;i<=NF;i++){if($i~/PresharedKey *=/){sub(/PresharedKey *= */,"",$i);print $i;exit}}}' "${server_conf_file}")
     [[ -z "$client_psk" ]] && client_psk=$(awg genpsk) && echo -e "${ORANGE}Existing PSK not found, generated new one.${NC}"

     local client_priv_key=$(awg genkey); local client_pub_key=$(echo "${client_priv_key}" | awg pubkey); if [[ -z "$client_priv_key" || -z "$client_pub_key" ]]; then echo -e "${RED}Failed to generate new keys.${NC}"; return 1; fi

     echo -e "${GREEN}Updating server config with new public key and PSK (if generated)...${NC}"
     awk -v name="${client_name}" -v new_pub_key="${client_pub_key}" -v new_psk="${client_psk}" '
        BEGIN { RS=""; FS="\n"; ORS="\n\n"; seen_psk=0 }
        $1=="### Client "name {
            in_block=1
            print $1
            for(i=2; i<=NF; i++) {
                if ($i ~ /^PublicKey *=/) { $i = "PublicKey = " new_pub_key }
                else if ($i ~ /^PresharedKey *=/) { $i = "PresharedKey = " new_psk; seen_psk=1 }
                print $i
            }
            if (!seen_psk && new_psk) { print "PresharedKey = " new_psk }
            in_block=0; seen_psk=0
            next
        }
        { print }
     ' "${server_conf_file}" > "${server_conf_file}.tmp"

     if [[ $? -eq 0 ]] && [[ -s "${server_conf_file}.tmp" ]]; then
         grep -v '^$' "${server_conf_file}.tmp" | awk 'BEGIN{ORS="\n"}{print}' > "${server_conf_file}"; rm "${server_conf_file}.tmp"
     else
         echo -e "${RED}Error updating server config using awk.${NC}"; rm -f "${server_conf_file}.tmp"; return 1;
     fi

     local home_dir=$(getHomeDirForClient "${SUDO_USER:-root}"); local client_config_dir="${home_dir}/amneziawg"; mkdir -p "${client_config_dir}"; chmod 700 "${client_config_dir}"; local safe_client_name=$(echo "${client_name}" | sed 's/[^a-zA-Z0-9_-]/_/g'); local client_conf_path="${client_config_dir}/${safe_client_name}.conf"

     local client_address_line=""
     [[ -n "$client_wg_ipv4" ]] && client_address_line="${client_wg_ipv4}/32"
     [[ -n "$client_wg_ipv6" ]] && { [[ -n "$client_address_line" ]] && client_address_line+=","; client_address_line+="${client_wg_ipv6}/128"; }

     local client_dns_line="${CLIENT_DNS_1}"
     [[ -n "${CLIENT_DNS_2}" ]] && client_dns_line+=",${CLIENT_DNS_2}"
     [[ -n "${CLIENT_DNS_IPV6_1}" ]] && client_dns_line+=",${CLIENT_DNS_IPV6_1}"
     [[ -n "${CLIENT_DNS_IPV6_2}" ]] && client_dns_line+=",${CLIENT_DNS_IPV6_2}"

     echo -e "${GREEN}Generating new client config: ${client_conf_path}${NC}"
     cat > "${client_conf_path}" <<EOF
[Interface]
PrivateKey = ${client_priv_key}
Address = ${client_address_line}
DNS = ${client_dns_line}
Jc = ${JC}
Jmin = ${JMIN}
Jmax = ${JMAX}
S1 = ${S1}
S2 = ${S2}
H1 = ${H1}
H2 = ${H2}
H3 = ${H3}
H4 = ${H4}
MTU = ${MTU}

[Peer]
PublicKey = ${SERVER_PUB_KEY}
$( [[ -n "${client_psk}" ]] && echo "PresharedKey = ${client_psk}" )
Endpoint = ${SERVER_PUB_IP}:${SERVER_PORT}
AllowedIPs = ${ALLOWED_IPS}
EOF
     chmod 600 "${client_conf_path}"

     echo -e "${GREEN}Applying updated server config...${NC}"; if ! awg syncconf "${SERVER_WG_NIC}" <(awg-quick strip "${SERVER_WG_NIC}"); then echo -e "${RED}Failed 'awg syncconf'.${NC} ${ORANGE}A service restart might be needed: systemctl restart awg-quick@${SERVER_WG_NIC}${NC}"; else echo -e "${GREEN}Server updated live.${NC}"; fi
     echo ""; if [[ "$ALLOWED_IPS" == *"0.0.0.0/0"* ]]; then if command -v qrencode &>/dev/null; then echo -e "${GREEN}Scan QR code:${NC}"; qrencode -t ansiutf8 < "${client_conf_path}" || echo -e "${ORANGE}Warning: QR code generation failed (config might be too large).${NC}"; echo ""; fi; fi
     echo -e "${GREEN}Client '${client_name}' regenerated: ${client_conf_path}${NC}"; echo ""
     [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Exiting function regenerateClientConfig"
     return 0
}

regenerateAllClientConfigs() {
    [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Entering function regenerateAllClientConfigs"
    print_header "Regenerate All Client Configurations"; echo -e "${ORANGE}Generates NEW keys/configs for ALL clients.${NC}"; read -rp "Proceed? [y/n]: " -e -i "n" confirm; if [[ ${confirm,,} != "y" ]]; then echo "Cancelled."; return; fi
    if [[ -z "${SERVER_WG_NIC}" && -f "${PARAMS_FILE}" ]]; then source "${PARAMS_FILE}"; fi; local server_conf_file="${AWG_CONF_DIR}/${SERVER_WG_NIC:-dummy}.conf"; if [[ ! -f "${server_conf_file}" ]]; then echo -e "${RED}Server conf not found.${NC}"; return 1; fi

    local clients=$(grep -E "^### Client" "${server_conf_file}" | cut -d ' ' -f 3-)
    if [[ -z "$clients" ]]; then echo -e "${ORANGE}No clients found to regenerate.${NC}"; return; fi

    echo -e "${GREEN}Starting regeneration...${NC}"; local success=0; local fail=0
    while IFS= read -r name; do
        if regenerateClientConfig "${name}"; then ((success++)); else ((fail++)); echo -e "${RED}Failed regeneration for: ${name}${NC}"; fi
        echo "-------------------"; sleep 1;
    done <<< "$clients"

    echo ""; print_header "Summary"; echo -e "${GREEN}Success: ${success}${NC}"; [[ $fail -gt 0 ]] && echo -e "${RED}Failed: ${fail}${NC}"; local home_dir=$(getHomeDirForClient "${SUDO_USER:-root}"); echo -e "${GREEN}New configs are located in ${home_dir}/amneziawg${NC}"; echo ""
}

setDefaultAmneziaSettings() {
    [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Entering function setDefaultAmneziaSettings"
    JC=4; JMIN=40; JMAX=70; S1=50; S2=100; MTU=1280
    H1=${H1:-$((RANDOM % 32767 * 1000 + RANDOM % 1000 + 10000))}
    H2=${H2:-$((RANDOM % 32767 * 1000 + RANDOM % 1000 + 20000))}
    H3=${H3:-$((RANDOM % 32767 * 1000 + RANDOM % 1000 + 30000))}
    H4=${H4:-$((RANDOM % 32767 * 1000 + RANDOM % 1000 + 40000))}
    while [[ ${H1} -eq ${H2} || ${H1} -eq ${H3} || ${H1} -eq ${H4} || ${H2} -eq ${H3} || ${H2} -eq ${H4} || ${H3} -eq ${H4} || ${H1} -le 4 || ${H2} -le 4 || ${H3} -le 4 || ${H4} -le 4 ]]; do
        [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Regenerating H values for uniqueness in setDefaultAmneziaSettings"
        H1=$((RANDOM % 32767 * 1000 + RANDOM % 1000 + 10000)); H2=$((RANDOM % 32767 * 1000 + RANDOM % 1000 + 20000)); H3=$((RANDOM % 32767 * 1000 + RANDOM % 1000 + 30000)); H4=$((RANDOM % 32767 * 1000 + RANDOM % 1000 + 40000))
    done
}

configureObfuscationSettings() {
    [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Entering function configureObfuscationSettings"
    print_header "Configure Obfuscation Settings"; if [[ ! -f "${PARAMS_FILE}" ]]; then echo -e "${RED}Params file not found: ${PARAMS_FILE}${NC}"; return 1; fi; source "${PARAMS_FILE}"

    local orig_JC="${JC}" orig_JMIN="${JMIN}" orig_JMAX="${JMAX}" orig_S1="${S1}" orig_S2="${S2}"
    local orig_H1="${H1}" orig_H2="${H2}" orig_H3="${H3}" orig_H4="${H4}" orig_MTU="${MTU}"

    echo "Current:";
	printf "  %-10s: %s\n" Jc $JC
	printf "  %-10s: %s\n" Jmin $JMIN
	printf "  %-10s: %s\n" Jmax $JMAX
	printf "  %-10s: %s\n" S1 $S1
	printf "  %-10s: %s\n" S2 $S2
	echo ""
    printf "  %-10s: %s\n" H1 $H1;
	printf "  %-10s: %s\n" H2 $H2;
	printf "  %-10s: %s\n" H3 $H3;
	printf "  %-10s: %s\n" H4 $H4;
	echo ""
	printf "  %-10s: %s\n" MTU $MTU
	echo ""
    echo "Presets:"; echo " 1) Mobile (Default)"; echo " 2) Standard"; echo " 3) Custom"; echo " 4) Back"
    local preset_choice=""; until [[ "${preset_choice}" =~ ^[1-4]$ ]]; do read -rp "Select [1-4]: " -e -i "1" preset_choice; done

    local new_JC="${JC}" new_JMIN="${JMIN}" new_JMAX="${JMAX}" new_S1="${S1}" new_S2="${S2}"
    local new_H1="${H1}" new_H2="${H2}" new_H3="${H3}" new_H4="${H4}" new_MTU="${MTU}"

    case "${preset_choice}" in
    1) new_JC=4; new_JMIN=40; new_JMAX=70; new_S1=50; new_S2=100; new_MTU=1280; new_H1=$((RANDOM%32767*1000+RANDOM%1000+10000)); new_H2=$((RANDOM%32767*1000+RANDOM%1000+20000)); new_H3=$((RANDOM%32767*1000+RANDOM%1000+30000)); new_H4=$((RANDOM%32767*1000+RANDOM%1000+40000)); echo -e "${GREEN}Mobile preset selected.${NC}";;
    2) new_JC=2; new_JMIN=100; new_JMAX=200; new_S1=100; new_S2=200; new_MTU=1420; new_H1=$((RANDOM%32767*1000+RANDOM%1000+10000)); new_H2=$((RANDOM%32767*1000+RANDOM%1000+20000)); new_H3=$((RANDOM%32767*1000+RANDOM%1000+30000)); new_H4=$((RANDOM%32767*1000+RANDOM%1000+40000)); echo -e "${GREEN}Standard preset selected.${NC}";;
    3) echo ""; echo -e "${GREEN}Enter custom values (Enter=keep current):${NC}"; local custom_val="";
       read -rp "Jc [1-10, cur ${new_JC}]: " -e custom_val; new_JC=${custom_val:-$new_JC}; if ! [[ "${new_JC}" =~ ^[1-9]$|^10$ ]]; then echo -e "${RED}Invalid Jc. Keep ${orig_JC}.${NC}"; new_JC=$orig_JC; fi
       read -rp "Jmin [10-500, cur ${new_JMIN}]: " -e custom_val; new_JMIN=${custom_val:-$new_JMIN}; if ! [[ "${new_JMIN}" =~ ^([1-9][0-9]|[1-4][0-9]{2}|500)$ ]]; then echo -e "${RED}Invalid Jmin. Keep ${orig_JMIN}.${NC}"; new_JMIN=$orig_JMIN; fi
       read -rp "Jmax [${new_JMIN}-1000, cur ${new_JMAX}]: " -e custom_val; new_JMAX=${custom_val:-$new_JMAX}; if ! [[ "${new_JMAX}" =~ ^[0-9]+$ ]] || [[ "${new_JMAX}" -lt "${new_JMIN}" ]] || [[ "${new_JMAX}" -gt 1000 ]]; then echo -e "${RED}Invalid Jmax. Keep ${orig_JMAX}.${NC}"; new_JMAX=$orig_JMAX; fi
       read -rp "S1 [10-1280, cur ${new_S1}]: " -e custom_val; new_S1=${custom_val:-$new_S1}; if ! [[ "${new_S1}" =~ ^[0-9]+$ ]] || [[ "${new_S1}" -lt 10 ]] || [[ "${new_S1}" -gt 1280 ]]; then echo -e "${RED}Invalid S1. Keep ${orig_S1}.${NC}"; new_S1=$orig_S1; fi
       read -rp "S2 [10-1280, cur ${new_S2}]: " -e custom_val; new_S2=${custom_val:-$new_S2}; if ! [[ "${new_S2}" =~ ^[0-9]+$ ]] || [[ "${new_S2}" -lt 10 ]] || [[ "${new_S2}" -gt 1280 ]]; then echo -e "${RED}Invalid S2. Keep ${orig_S2}.${NC}"; new_S2=$orig_S2; fi
       read -rp "H1 [num > 4, cur ${new_H1}]: " -e custom_val; new_H1=${custom_val:-$new_H1}; if ! [[ "${new_H1}" =~ ^[0-9]+$ ]] || [[ "${new_H1}" -le 4 ]]; then echo -e "${RED}Invalid H1. Keep ${orig_H1}.${NC}"; new_H1=$orig_H1; fi
       read -rp "H2 [num > 4, cur ${new_H2}]: " -e custom_val; new_H2=${custom_val:-$new_H2}; if ! [[ "${new_H2}" =~ ^[0-9]+$ ]] || [[ "${new_H2}" -le 4 ]]; then echo -e "${RED}Invalid H2. Keep ${orig_H2}.${NC}"; new_H2=$orig_H2; fi
       read -rp "H3 [num > 4, cur ${new_H3}]: " -e custom_val; new_H3=${custom_val:-$new_H3}; if ! [[ "${new_H3}" =~ ^[0-9]+$ ]] || [[ "${new_H3}" -le 4 ]]; then echo -e "${RED}Invalid H3. Keep ${orig_H3}.${NC}"; new_H3=$orig_H3; fi
       read -rp "H4 [num > 4, cur ${new_H4}]: " -e custom_val; new_H4=${custom_val:-$new_H4}; if ! [[ "${new_H4}" =~ ^[0-9]+$ ]] || [[ "${new_H4}" -le 4 ]]; then echo -e "${RED}Invalid H4. Keep ${orig_H4}.${NC}"; new_H4=$orig_H4; fi
       read -rp "MTU [576-1500, cur ${new_MTU}]: " -e custom_val; new_MTU=${custom_val:-$new_MTU}; if ! [[ "${new_MTU}" =~ ^[0-9]+$ ]] || [[ "${new_MTU}" -lt 576 ]] || [[ "${new_MTU}" -gt 1500 ]]; then echo -e "${RED}Invalid MTU. Keep ${orig_MTU}.${NC}"; new_MTU=$orig_MTU; fi
       echo -e "${GREEN}Custom settings entered.${NC}";;
    4) echo -e "${GREEN}No changes made.${NC}"; return 0;;
    *) echo -e "${RED}Invalid selection.${NC}"; return 1;;
    esac

    if [[ "${new_H1}" != "${orig_H1}" || "${new_H2}" != "${orig_H2}" || "${new_H3}" != "${orig_H3}" || "${new_H4}" != "${orig_H4}" || "${preset_choice}" != "3" ]]; then
         while [[ ${new_H1} -eq ${H2} || ${new_H1} -eq ${H3} || ${new_H1} -eq ${H4} || ${new_H2} -eq ${H3} || ${new_H2} -eq ${H4} || ${new_H3} -eq ${H4} || ${new_H1} -le 4 || ${new_H2} -le 4 || ${new_H3} -le 4 || ${new_H4} -le 4 ]]; do
            [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Regenerating H values for uniqueness in configureObfuscationSettings"
            new_H1=$((RANDOM%32767*1000+RANDOM%1000+10000)); new_H2=$((RANDOM%32767*1000+RANDOM%1000+20000)); new_H3=$((RANDOM%32767*1000+RANDOM%1000+30000)); new_H4=$((RANDOM%32767*1000+RANDOM%1000+40000))
        done
    fi

    if [[ "${new_JC}" != "${orig_JC}" || "${new_JMIN}" != "${orig_JMIN}" || "${new_JMAX}" != "${orig_JMAX}" || \
          "${new_S1}" != "${orig_S1}" || "${new_S2}" != "${orig_S2}" || "${new_H1}" != "${orig_H1}" || \
          "${new_H2}" != "${orig_H2}" || "${new_H3}" != "${orig_H3}" || "${new_H4}" != "${orig_H4}" || \
          "${new_MTU}" != "${orig_MTU}" ]]; then
        echo -e "${GREEN}Obfuscation settings changed.${NC}"
        JC="${new_JC}"; JMIN="${new_JMIN}"; JMAX="${new_JMAX}"; S1="${new_S1}"; S2="${new_S2}"
        H1="${new_H1}"; H2="${new_H2}"; H3="${new_H3}"; H4="${new_H4}"; MTU="${new_MTU}"
        updateServerConfig
        echo ""
        read -rp "Regenerate ALL client configs with new settings? [y/n]: " -e -i "y" regen_clients
        if [[ ${regen_clients,,} == 'y' ]]; then regenerateAllClientConfigs;
        else echo -e "${ORANGE}Clients NOT regenerated.${NC}"; fi
    else
        echo -e "${GREEN}No changes made to obfuscation settings.${NC}"
    fi
    echo ""
}

updateServerConfig() {
    [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Entering function updateServerConfig"
    if [[ -z "${SERVER_WG_NIC}" && -f "${PARAMS_FILE}" ]]; then source "${PARAMS_FILE}"; fi
    local server_conf_file="${AWG_CONF_DIR}/${SERVER_WG_NIC:-dummy}.conf"
    if [[ ! -f "${server_conf_file}" || ! -f "${PARAMS_FILE}" ]]; then echo -e "${RED}Config/params files not found: ${server_conf_file} / ${PARAMS_FILE}${NC}"; return 1; fi

    echo -e "${GREEN}Updating server config files...${NC}"
    cp "${server_conf_file}" "${server_conf_file}.bak.$(date +%s)"
    cp "${PARAMS_FILE}" "${PARAMS_FILE}.bak.$(date +%s)"

    sed -i "s|^Jc *=.*|Jc = ${JC}|" "${server_conf_file}"
    sed -i "s|^Jmin *=.*|Jmin = ${JMIN}|" "${server_conf_file}"
    sed -i "s|^Jmax *=.*|Jmax = ${JMAX}|" "${server_conf_file}"
    sed -i "s|^S1 *=.*|S1 = ${S1}|" "${server_conf_file}"
    sed -i "s|^S2 *=.*|S2 = ${S2}|" "${server_conf_file}"
    sed -i "s|^MTU *=.*|MTU = ${MTU}|" "${server_conf_file}"
    sed -i "s|^H1 *=.*|H1 = ${H1}|" "${server_conf_file}"
    sed -i "s|^H2 *=.*|H2 = ${H2}|" "${server_conf_file}"
    sed -i "s|^H3 *=.*|H3 = ${H3}|" "${server_conf_file}"
    sed -i "s|^H4 *=.*|H4 = ${H4}|" "${server_conf_file}"

    local new_address_line=""
    [[ -n "${SERVER_WG_IPV4}" ]] && new_address_line="${SERVER_WG_IPV4}/24"
    [[ ${ENABLE_IPV6} == 'y' && -n "${SERVER_WG_IPV6}" ]] && { [[ -n "$new_address_line" ]] && new_address_line+=","; new_address_line+="${SERVER_WG_IPV6}/64"; }
    local escaped_new_address_line=$(echo "Address = ${new_address_line}" | sed -e 's/[\/&]/\\&/g')
    sed -i "s|^Address *=.*|${escaped_new_address_line}|" "${server_conf_file}"

    local keys_to_update=("JC" "JMIN" "JMAX" "S1" "S2" "H1" "H2" "H3" "H4" "MTU" "ALLOWED_IPS" "ENABLE_IPV6" "SERVER_WG_IPV4" "SERVER_WG_IPV6" "SERVER_PORT" "SERVER_PUB_IP" "SERVER_PUB_NIC" "CLIENT_DNS_1" "CLIENT_DNS_2" "CLIENT_DNS_IPV6_1" "CLIENT_DNS_IPV6_2")
    for key in "${keys_to_update[@]}"; do
        local value="${!key}"; local sed_value=$(echo "${value}" | sed -e 's/[\/&]/\\&/g')
        if grep -q "^${key}=" "${PARAMS_FILE}"; then sed -i "s|^${key}=.*|${key}=${sed_value}|" "${PARAMS_FILE}"; else echo "${key}=${value}" >> "${PARAMS_FILE}"; fi
    done

    echo -e "${GREEN}Config files updated.${NC}"
    echo -e "${GREEN}Restarting AWG service to apply interface changes...${NC}"
    if ! systemctl restart "awg-quick@${SERVER_WG_NIC}"; then
        echo -e "${RED}Service restart failed. Check logs: journalctl -u awg-quick@${SERVER_WG_NIC}${NC}"
        echo -e "${ORANGE}You may need to manually restart the service.${NC}"
        return 1
    else
        echo -e "${GREEN}Service restarted successfully.${NC}"
    fi
    [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Exiting function updateServerConfig"
    return 0
}

configureAllowedIPs() {
    [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Entering function configureAllowedIPs (IPv6 status: $1)"
    local current_enable_ipv6="${1:-y}"
    print_header "Configure Default Client Routing"; echo "Affects NEW clients or requires regeneration."
    echo " 1) Route ALL traffic (Recommended)"
    echo " 2) Route specific services via Web UI"
    echo " 3) Route Russia Blocked List (from antifilter.download)"
    echo " 4) Custom CIDR list"

    local route_option=""; local current_default_ips=""
    [[ -f "${AWG_CONF_DIR}/default_routing" ]] && current_default_ips=$(cat "${AWG_CONF_DIR}/default_routing")
    local default_choice=1
    if [[ -z "$current_default_ips" ]]; then default_choice=1;
    elif [[ "$current_default_ips" == "0.0.0.0/0"* ]]; then default_choice=1;
    elif echo "$current_default_ips" | grep -qE '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}'; then
         if [[ $(echo "$current_default_ips" | tr ',' '\n' | wc -l) -gt 10 ]]; then default_choice=3; else default_choice=4; fi
    fi
    until [[ "$route_option" =~ ^[1-4]$ ]]; do read -rp "Select option [1-4]: " -e -i "${default_choice}" route_option; done

    local temp_allowed_ips=""

    case "${route_option}" in
    1) temp_allowed_ips="0.0.0.0/0"; if [[ ${current_enable_ipv6,,} == "y" ]]; then temp_allowed_ips="${temp_allowed_ips},::/0"; fi; echo -e "${GREEN}Selected: All Traffic (${temp_allowed_ips})${NC}";;
    2) echo -e "${GREEN}Starting web server...${NC}"; local selected_ips="";
       if ! type generate_cidr_data &>/dev/null || ! type startWebServer &>/dev/null; then echo -e "${RED}Web server functions missing.${NC}"; return 1; fi
       if ! selected_ips=$(startWebServer); then echo -e "${RED}Failed web server.${NC}"; return 1; fi
       if [[ -z "$selected_ips" ]]; then echo -e "${ORANGE}No IPs selected.${NC}"; return 1; fi
       temp_allowed_ips="${selected_ips}";
       if [[ ${current_enable_ipv6,,} == "y" ]] && ! echo "${temp_allowed_ips}" | grep -q "::/"; then echo -e "${ORANGE}Warning: IPv6 enabled, but no IPv6 routes selected.${NC}"; fi
       echo -e "${GREEN}Selected: Specific Services (${temp_allowed_ips:0:60}...)${NC}";;
    3) echo -e "${GREEN}Fetching Russia blocked list...${NC}"; local list_url="https://antifilter.download/list/allyouneed.lst"; local raw_list="";
       if command -v curl &>/dev/null; then raw_list=$(curl -sS --fail "${list_url}"); elif command -v wget &>/dev/null; then raw_list=$(wget -qO- "${list_url}"); else echo -e "${RED}curl/wget not found.${NC}"; return 1; fi
       if [[ -z "$raw_list" ]]; then echo -e "${RED}Download failed or empty list.${NC}"; return 1; fi
       temp_allowed_ips=$(echo "${raw_list}" | grep -vE '^#|^$' | paste -sd ',');
       if [[ -z "$temp_allowed_ips" ]]; then echo -e "${RED}List processing failed.${NC}"; return 1; fi
       if [[ ${current_enable_ipv6,,} == "y" ]]; then [[ "$temp_allowed_ips" != *"::/0"* ]] && temp_allowed_ips="${temp_allowed_ips},::/0"; echo -e "${GREEN}Selected: Russia List + All IPv6${NC}";
       else echo -e "${GREEN}Selected: Russia List (IPv4 Only)${NC}"; fi;;
    4) echo "Enter comma-separated CIDRs:"; read -rp "Custom AllowedIPs: " -e temp_allowed_ips;
       if [[ -z "$temp_allowed_ips" ]] || ! echo "$temp_allowed_ips" | grep -q "/"; then echo -e "${RED}Invalid/empty list.${NC}"; return 1; fi
       echo -e "${GREEN}Selected: Custom List (${temp_allowed_ips})${NC}";;
    *) echo -e "${RED}Invalid option.${NC}"; return 1;;
    esac

    ALLOWED_IPS="${temp_allowed_ips}"
    [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Exiting function configureAllowedIPs (ALLOWED_IPS=${ALLOWED_IPS})"
    return 0
}

installWebServerDependencies() {
    [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Entering function installWebServerDependencies"
    echo -e "${GREEN}Checking web server dependencies...${NC}"; local missing_packages=""; local pkg_manager_update=""; local pkg_manager_install=""
    if [[ ${OS} == "ubuntu" || ${OS} == "debian" ]]; then pkg_manager_update="apt-get update"; pkg_manager_install="apt-get install -y";
    elif [[ ${OS} == "rhel" ]]; then pkg_manager_update=""; pkg_manager_install="yum install -y"; if command -v dnf &>/dev/null; then pkg_manager_install="dnf install -y"; fi
    else echo -e "${RED}Cannot determine pkg manager.${NC}"; return 1; fi

    if ! command -v jq &> /dev/null; then missing_packages="${missing_packages} jq"; fi
    if ! command -v git &>/dev/null; then
        echo -e "${ORANGE}git not found. Need curl/wget + unzip.${NC}"
        if ! command -v unzip &>/dev/null; then missing_packages="${missing_packages} unzip"; fi
        if ! command -v curl &>/dev/null && ! command -v wget &>/dev/null; then
             [[ ${OS} == "ubuntu" || ${OS} == "debian" ]] && missing_packages="${missing_packages} curl" || missing_packages="${missing_packages} wget";
        fi
    fi

    local python_cmd="python3";
    if ! command -v python3 &>/dev/null; then
        if command -v python &>/dev/null; then
             if python -m SimpleHTTPServer --help &>/dev/null; then python_cmd="python"; else if ! command -v php &> /dev/null; then missing_packages="${missing_packages} python3"; fi; fi
        elif ! command -v php &>/dev/null; then missing_packages="${missing_packages} python3"; fi
    fi

    if [[ -n "${missing_packages}" ]]; then
        echo -e "${GREEN}Installing missing dependencies: ${missing_packages}${NC}"; ${pkg_manager_update};
        if ! ${pkg_manager_install} ${missing_packages}; then echo -e "${RED}Failed install dependencies.${NC}"; return 1; fi
    else echo -e "${GREEN}Web server dependencies OK.${NC}"; fi;
    [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Exiting function installWebServerDependencies"
    return 0
}

generate_cidr_data() {
    [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Entering function generate_cidr_data"
    local iplist_config_dir="$1"; local output_dir="$2"; local cidrs_json_file="$output_dir/cidrs.json"
    echo -e "${BOLD_GREEN}Generating CIDR data: ${iplist_config_dir} -> ${output_dir}...${NC}"

    if ! command -v jq &> /dev/null; then echo -e "${RED}jq required.${NC}"; return 1; fi
    if [ ! -d "$iplist_config_dir" ]; then echo -e "${RED}IP list dir not found: ${iplist_config_dir}${NC}"; return 1; fi

    mkdir -p "$output_dir"; local jq_filter_parts=()

    while IFS= read -r -d $'\0' category_path; do
        local category_name=$(basename "$category_path"); [[ ! -d "$category_path" ]] && continue
        echo -e "\n${BOLD_GREEN}--- Category: ${category_name} ---${NC}"
        while IFS= read -r -d $'\0' service_file; do
            local service_id=$(basename "$service_file" .json); echo -e "${GREEN}  Processing: ${service_id}${NC}"
            local cidrs4="" cidrs6="" cidrs_combined=""
            cidrs4=$(jq -c '.cidr4 // []' "$service_file" 2>/dev/null) || cidrs4="[]"
            cidrs6=$(jq -c '.cidr6 // []' "$service_file" 2>/dev/null) || cidrs6="[]"
            if [[ "$cidrs4" == "[]" && "$cidrs6" == "[]" ]]; then echo -e "${ORANGE}    No CIDRs found, skipping.${NC}"; continue; fi
            cidrs_combined=$(jq -n --argjson a1 "$cidrs4" --argjson a2 "$cidrs6" '$a1 + $a2')
            local jq_service_id=$(jq -nr --arg str "$service_id" '$str')
            jq_filter_parts+=(".services[$jq_service_id] = {\"cidrs\": $cidrs_combined}")
        done < <(find "$category_path" -maxdepth 1 -name "*.json" -type f -print0)
    done < <(find "$iplist_config_dir" -mindepth 1 -maxdepth 1 -type d -print0)

    if [ ${#jq_filter_parts[@]} -eq 0 ]; then echo -e "${ORANGE}No valid service files found.${NC}"; echo '{ "services": {} }' > "$cidrs_json_file"; return 0; fi
    local final_jq_filter=$(printf "%s | " "${jq_filter_parts[@]}"); final_jq_filter=${final_jq_filter% | }
    echo -e "${GREEN}Writing ${cidrs_json_file}...${NC}"
    if ! jq -n "{ \"services\": {} } | ${final_jq_filter}" > "$cidrs_json_file"; then echo -e "${RED}Failed generating cidrs.json.${NC}"; return 1; fi
    echo -e "${BOLD_GREEN}CIDR data generation complete.${NC}";
    [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Exiting function generate_cidr_data"
    return 0
}

startWebServer() {
    [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Entering function startWebServer"
    local web_server_pid=""; local temp_dir=""; local selected_ips=""; local web_port=8080
    trap 'echo -e "\n${ORANGE}Stopping web server & cleaning up...${NC}"; [[ -n "$web_server_pid" ]] && kill "$web_server_pid" >/dev/null 2>&1; [[ -n "$temp_dir" ]] && rm -rf "$temp_dir"; trap - INT; return 1' INT
    if ! installWebServerDependencies; then trap - INT; return 1; fi
    temp_dir=$(mktemp -d); echo -e "${GREEN}Temp dir: ${temp_dir}${NC}"

    local awg_install_repo="https://github.com/ginto-sakata/amneziawg-install.git"; local iplist_repo="https://github.com/rekryt/iplist.git"
    local installer_temp_dir="${temp_dir}/amneziawg-install"; local website_source_dir="${installer_temp_dir}/static_website"
    local iplist_temp_dir="${temp_dir}/iplist"; local iplist_source_dir="${iplist_temp_dir}/config"

    echo -e "${GREEN}Cloning installer repo...${NC}"
    if ! git clone --depth=1 "${awg_install_repo}" "${installer_temp_dir}"; then echo -e "${RED}Failed clone.${NC}"; rm -rf "${temp_dir}"; trap - INT; return 1; fi
    if [[ ! -d "${website_source_dir}" || ! -f "${website_source_dir}/index.html" ]]; then echo -e "${RED}Website files not found: ${website_source_dir}${NC}"; rm -rf "${temp_dir}"; trap - INT; return 1; fi

    mkdir -p "${iplist_temp_dir}"; echo -e "${GREEN}Fetching IP list data...${NC}"
    if command -v git &>/dev/null; then
        echo -e "${GREEN}Using git...${NC}"
        if ! git clone -n --depth=1 --filter=tree:0 "${iplist_repo}" "${iplist_temp_dir}"; then echo -e "${RED}Failed iplist clone.${NC}"; rm -rf "${temp_dir}"; trap - INT; return 1; fi
        (cd "${iplist_temp_dir}" && git sparse-checkout set --no-cone config && git checkout); if [[ ! -d "${iplist_source_dir}" ]]; then echo -e "${RED}Failed iplist checkout.${NC}"; rm -rf "${temp_dir}"; trap - INT; return 1; fi
    else
        echo -e "${GREEN}Using curl/wget+unzip...${NC}"; local iplist_zip_url="https://github.com/rekryt/iplist/archive/refs/heads/master.zip"; local zip_file="${temp_dir}/iplist.zip"; local dl_cmd=""
        if command -v curl &>/dev/null; then dl_cmd="curl -sSL -o"; else dl_cmd="wget -q -O"; fi
        if ! $dl_cmd "${zip_file}" "${iplist_zip_url}"; then echo -e "${RED}Failed iplist download.${NC}"; rm -rf "${temp_dir}"; trap - INT; return 1; fi
        if ! unzip -q "${zip_file}" -d "${temp_dir}"; then echo -e "${RED}Failed iplist unzip.${NC}"; rm -rf "${temp_dir}"; trap - INT; return 1; fi
        if ! mv "${temp_dir}/iplist-master/config" "${iplist_source_dir}"; then echo -e "${RED}Failed move iplist config.${NC}"; rm -rf "${temp_dir}/iplist-master"; rm -f "${zip_file}"; trap - INT; return 1; fi
        rm -rf "${temp_dir}/iplist-master"; rm -f "${zip_file}"
    fi

    if ! generate_cidr_data "${iplist_source_dir}" "${website_source_dir}"; then echo -e "${RED}Failed generating data.${NC}"; rm -rf "${temp_dir}"; trap - INT; return 1; fi

    local webserver_bind_address="0.0.0.0"; local display_address=""
    display_address=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $7}' | head -n1); if [[ -z "$display_address" ]]; then display_address=$(hostname -I 2>/dev/null | awk '{print $1}'); fi; if [[ -z "$display_address" ]]; then display_address=$(ip -4 addr show 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v 127.0.0.1 | head -1); fi; if [[ -z "$display_address" ]]; then display_address="127.0.0.1"; fi
    local server_cmd=""
    while true; do
        if ss -tuln | grep -q ":${web_port}\s" ; then echo -e "${ORANGE}Port ${web_port} busy. Trying next...${NC}"; ((web_port++)); if [[ $web_port -gt 65535 ]]; then echo -e "${RED}No available port.${NC}"; rm -rf "${temp_dir}"; trap - INT; return 1; fi; continue; fi
        if command -v python3 &>/dev/null; then server_cmd="python3 -m http.server ${web_port} --bind ${webserver_bind_address}"; break;
        elif command -v python &>/dev/null && python -m SimpleHTTPServer --help &>/dev/null; then server_cmd="python -m SimpleHTTPServer ${web_port}"; webserver_bind_address="0.0.0.0"; break;
        elif command -v php &>/dev/null; then server_cmd="php -S ${webserver_bind_address}:${web_port} -t ."; break;
        else echo -e "${RED}No web server found.${NC}"; rm -rf "${temp_dir}"; trap - INT; return 1; fi
    done

    echo ""; print_header "Service Selection via Web Browser"; echo -e "${GREEN}Starting temp web server...${NC}"
    echo -e "Open URL: ${GREEN}http://${display_address}:${web_port}${NC}"; echo " 1. Select services"; echo " 2. Click 'Generate IP List'"; echo " 3. Copy list"; echo " 4. ${ORANGE}PASTE list here:${NC}"; echo " 5. ${ORANGE}Press Ctrl+C here.${NC}"; echo ""
    (cd "${website_source_dir}" && ${server_cmd} &> "${temp_dir}/webserver.log") & web_server_pid=$!; sleep 1
    if ! ps -p $web_server_pid > /dev/null; then echo -e "${RED}Server failed. Logs: ${temp_dir}/webserver.log${NC}"; rm -rf "${temp_dir}"; trap - INT; return 1; fi

    echo -n -e "${GREEN}Paste the generated IP list here: ${NC}"; read -r selected_ips
    if [[ -z "$selected_ips" ]]; then echo -e "\n${ORANGE}No list pasted. Aborting.${NC}"; kill "$web_server_pid" >/dev/null 2>&1; wait "$web_server_pid" 2>/dev/null; rm -rf "${temp_dir}"; trap - INT; return 1;
    elif ! echo "$selected_ips" | grep -q "/"; then echo -e "\n${ORANGE}Not a CIDR list? Aborting.${NC}"; kill "$web_server_pid" >/dev/null 2>&1; wait "$web_server_pid" 2>/dev/null; rm -rf "${temp_dir}"; trap - INT; return 1; fi

    echo -e "\n${GREEN}List received. Press Ctrl+C to stop server...${NC}"
    wait "$web_server_pid" 2>/dev/null; local exit_status=$?
    rm -rf "${temp_dir}"; trap - INT

    if [[ $exit_status -ne 0 ]]; then echo -e "\n${GREEN}Server stopped. Continuing...${NC}"; echo "${selected_ips}"; [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Exiting function startWebServer (Success)"; return 0;
    else echo -e "\n${ORANGE}Server exited unexpectedly. Continuing...${NC}"; echo "${selected_ips}"; [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Exiting function startWebServer (Unexpected Exit)"; return 0; fi
}

cleanup() {
    [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Entering function cleanup"
    echo -e "${GREEN}Removing AWG server configs...${NC}"; local nic="${SERVER_WG_NIC}"; if [[ -z "${nic}" && -f "${PARAMS_FILE}" ]]; then nic=$(source "${PARAMS_FILE}" && echo "${SERVER_WG_NIC}"); fi
    rm -f "${PARAMS_FILE}"; [[ -n "${nic}" ]] && rm -f "${AWG_CONF_DIR}/${nic}.conf"
    rm -f "${AWG_CONF_DIR}/default_routing" "${AWG_CONF_DIR}/wg-quick-strip.err"
    [[ -d "${AWG_CONF_DIR}" ]] && [ -z "$(ls -A "${AWG_CONF_DIR}")" ] && rmdir "${AWG_CONF_DIR}" && echo -e "${GREEN}Removed ${AWG_CONF_DIR}.${NC}" || { [[ -d "${AWG_CONF_DIR}" ]] && echo -e "${ORANGE}Warn: ${AWG_CONF_DIR} not empty.${NC}"; }
    rm -f "/etc/sysctl.d/99-amneziawg-forward.conf"; echo -e "${GREEN}Applying sysctl changes...${NC}"; sysctl --system > /dev/null
    if [[ ${OS} == "ubuntu" || ${OS} == "debian" ]]; then rm -f /etc/apt/sources.list.d/amnezia*.list /etc/apt/sources.list.d/amnezia*.sources /etc/apt/trusted.gpg.d/amnezia_ppa.gpg; apt-get update > /dev/null 2>&1 || echo -e "${ORANGE}apt update failed.${NC}";
    elif [[ ${OS} == "rhel" ]]; then rm -f /etc/yum.repos.d/amnezia.repo; fi
    echo -e "${GREEN}Cleanup done.${NC}"
}

uninstallWg() {
    [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Entering function uninstallWg"
    local home_dir=$(getHomeDirForClient "${SUDO_USER:-root}")
    print_header "Uninstall AmneziaWG"; echo -e "${RED}WARNING: Stops service, removes packages & configs in ${AWG_CONF_DIR}.${NC}"; echo -e "${RED}WARNING: This will also remove the client config directory ${home_dir}/amneziawg.${NC}"; echo ""
    read -rp "Uninstall AmneziaWG? [y/n]: " -e -i "n" confirm; if [[ ${confirm,,} != 'y' ]]; then echo "Cancelled."; return; fi

    local nic_to_stop=""; if [[ -f "${PARAMS_FILE}" ]]; then source "${PARAMS_FILE}"; nic_to_stop="${SERVER_WG_NIC}"; else read -rp "Params missing. Enter AWG interface name (e.g., awg0): " -e -i "${SERVER_WG_NIC:-awg0}" nic_to_stop; fi
    if [[ -n "$nic_to_stop" ]]; then
        local service="awg-quick@${nic_to_stop}"; echo -e "${GREEN}Stopping/disabling ${service}...${NC}"; systemctl is-active --quiet "${service}" && systemctl stop "${service}"; systemctl is-enabled --quiet "${service}" && systemctl disable "${service}"
    else echo -e "${ORANGE}Warn: Could not determine service name.${NC}"; fi
    cleanup
    echo -e "${GREEN}Removing AmneziaWG packages...${NC}"; if [[ ${OS} == "ubuntu" || ${OS} == "debian" ]]; then apt-get purge -y amneziawg amneziawg-tools; apt-get autoremove -y; elif [[ ${OS} == "rhel" ]]; then yum remove -y amneziawg amneziawg-tools || dnf remove -y amneziawg amneziawg-tools; yum autoremove -y || dnf autoremove -y; fi
    echo -e "${GREEN}Removing client config directory ${home_dir}/amneziawg...${NC}"; rm -rf "${home_dir}/amneziawg"
    echo ""; echo -e "${GREEN}AmneziaWG uninstalled.${NC}"; echo "";
    [[ "$DEBUG_MODE" == "true" ]] && { echo "DEBUG: Exiting function uninstallWg"; set +x; }
    exit 0
}

manageMenu() {
    [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Entering function manageMenu"
    [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Checking for params file: ${PARAMS_FILE}"
    if [[ ! -f "${PARAMS_FILE}" ]]; then echo -e "${RED}Params missing. (${PARAMS_FILE})${NC}"; exit 1; fi

    while true; do
        source "${PARAMS_FILE}"
        print_header "AmneziaWG Management";
        echo " Interface: ${SERVER_WG_NIC:-N/A}"; echo " Port: ${SERVER_PORT:-N/A}"; echo " Endpoint: ${SERVER_PUB_IP:-N/A}";
        local display_allowed_ips="${ALLOWED_IPS:-N/A}"
        [[ ${#display_allowed_ips} -gt 70 ]] && display_allowed_ips="${display_allowed_ips:0:70}..."
        echo " Def Route: ${display_allowed_ips}"; echo ""

        echo " Options:"; echo " 1) Add client"; echo " 2) List clients"; echo " 3) Revoke client"; echo " 4) Regenerate client config"; echo " 5) Obfuscation settings"; echo " 6) Default Routing (AllowedIPs)"; echo " 7) Uninstall AmneziaWG"; echo " 8) Exit"; echo ""
        local menu_option=""; until [[ ${menu_option} =~ ^[1-8]$ ]]; do read -rp "Enter option [1-8]: " menu_option; done

        case "${menu_option}" in
        1) newClient;;
        2) listClients;;
        3) revokeClient;;
        4) if listClients; then read -rp "Enter exact client name to regenerate: " c; if [[ -n "$c" ]]; then regenerateClientConfig "$c"; else echo -e "${ORANGE}No name entered.${NC}"; fi; fi;;
        5) configureObfuscationSettings;;
        6) if configureAllowedIPs "${ENABLE_IPV6}"; then
              echo -e "${GREEN}Updating params file...${NC}"
              local sed_allowed_ips=$(echo "${ALLOWED_IPS}" | sed -e 's/[\/&]/\\&/g')
              if grep -q "^ALLOWED_IPS=" "${PARAMS_FILE}"; then sed -i "s|^ALLOWED_IPS=.*|ALLOWED_IPS=${sed_allowed_ips}|" "${PARAMS_FILE}"; else echo "ALLOWED_IPS=${ALLOWED_IPS}" >> "${PARAMS_FILE}"; fi
              echo "${ALLOWED_IPS}" > "${AWG_CONF_DIR}/default_routing" # Also update the routing file
              echo -e "${GREEN}Params and routing file updated. ${ORANGE}Affects NEW clients.${NC}"
              read -rp "Regenerate ALL clients now with new routing? [y/n]: " -e -i "n" regen; [[ ${regen,,} == 'y' ]] && regenerateAllClientConfigs || echo -e "${ORANGE}Clients NOT regenerated.${NC}";
           else echo -e "${RED}Failed configuring routing.${NC}"; fi;;
        7) uninstallWg;;
        8) echo "Exiting."; [[ "$DEBUG_MODE" == "true" ]] && set +x; exit 0;;
        *) echo -e "${RED}Invalid option.${NC}";;
        esac
        if [[ "$menu_option" != "7" && "$menu_option" != "8" ]]; then echo ""; read -n1 -r -p "Press any key..." echo ""; fi
    done
}

# --- Main Script Logic ---
[[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: Starting main script logic"
trap - ERR
initialCheck
check_result=$?
trap 'handle_error $LINENO' ERR

case ${check_result} in
    0)
        [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: In case 0 (Manage Menu)"
        manageMenu
        ;;
    1)
        [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: In case 1 (Fresh Install)"
        installAmneziaWG
        ;;
    2)
        [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: In case 2 (Migration)"
        installQuestions
        installAmneziaWGPackagesOnly
        migrateWireGuard "${MIGRATION_TYPE}" "${MIGRATION_WG_INTERFACE}"
        ;;
    *)
        [[ "$DEBUG_MODE" == "true" ]] && echo "DEBUG: In unexpected case * (${check_result})"
        echo -e "${RED}Internal error: Unexpected status (${check_result}) from initial check. Exiting.${NC}"
        exit 1
        ;;
esac

exit 0