#!/bin/bash

# AmneziaWG server installer
# Based on https://github.com/angristan/wireguard-install
# Enhanced by ginto-sakata and reviewed/refactored

# Strict Mode
# set -euo pipefail # Exit on error, unset var, pipe fail
# shopt -s inherit_errexit # Ensure errors propagate in command substitutions/subshells (Bash >= 4.4)
# Commenting out strict mode for now as extensive changes might introduce subtle issues,
# but recommend enabling it after thorough testing. Add '|| true' to commands expected to fail sometimes.
set +e # Temporarily disable exit on error for broader compatibility during refactoring

# --- Colors ---
RED='\033[0;31m'
ORANGE='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color
BOLD_GREEN='\033[1;32m' # For generate_data.sh compatibility

# --- Global Variables ---
# These might be overwritten by functions or sourced from params file
OS=""
OS_VERSION=""
SERVER_PUB_IP=""
SERVER_PUB_NIC=""
SERVER_WG_NIC="awg0" # Default interface name
SERVER_WG_IPV4=""    # Will store IP WITHOUT CIDR
SERVER_WG_IPV6=""    # Will store IP WITHOUT CIDR
SERVER_PORT=""
SERVER_PRIV_KEY=""
SERVER_PUB_KEY=""
CLIENT_DNS_1=""
CLIENT_DNS_2=""
CLIENT_DNS_IPV6_1=""
CLIENT_DNS_IPV6_2=""
ALLOWED_IPS="0.0.0.0/0,::/0" # Default routing
ENABLE_IPV6="y" # Default
# AmneziaWG Obfuscation Defaults (Mobile Preset)
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
# Params file location
PARAMS_FILE="/etc/amnezia/amneziawg/params"
WG_CONF_DIR="/etc/wireguard"
AWG_CONF_DIR="/etc/amnezia/amneziawg"

# --- Error Handling ---
handle_error() {
    local exit_code=$?
    local line_no=$1
    echo -e "${RED}Error occurred in script at line: ${line_no}${NC}"
    echo -e "${RED}Exit code: ${exit_code}${NC}"
    # Consider adding cleanup steps here if necessary
    # cleanup # Call cleanup if defined and needed
    exit "${exit_code}"
}
trap 'handle_error $LINENO' ERR

# --- Utility Functions ---

function print_header() {
    local title="$1"
    local width=51 # Adjust width as needed
    printf "\n"
    printf "╔═══════════════════════════════════════════════════╗\n" # Fixed width border
    printf "║ %-*s ║\n" $((width-4)) "${title}" # Pad title
    printf "╚═══════════════════════════════════════════════════╝\n"
    printf "\n"
}

function isRoot() {
	if [ "${EUID}" -ne 0 ]; then
		echo -e "${RED}You need to run this script as root.${NC}"
		exit 1
	fi
}

function checkVirt() {
	function openvzErr() {
		echo -e "${RED}OpenVZ is not supported.${NC}"
		exit 1
	}
	function lxcErr() {
		echo -e "${RED}LXC is not supported (yet).${NC}"
		echo "AmneziaWG can technically run in an LXC container,"
		echo "but the kernel module has to be installed on the host,"
		echo "the container has to be run with specific parameters,"
		echo "and only the tools need to be installed in the container."
		exit 1
	}
	local virt_what=""
	local systemd_virt=""
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

function checkOS() {
    if [ -f /etc/os-release ]; then
	    source /etc/os-release
        OS="${ID}"
        OS_VERSION="${VERSION_ID}"
    elif [ -f /etc/debian_version ]; then
        OS="debian"
        OS_VERSION=$(cat /etc/debian_version)
    elif [ -f /etc/redhat-release ]; then
        # Crude RHEL family detection
        OS="rhel" # Generic RHEL family
        if grep -q "CentOS" /etc/redhat-release; then OS="centos"; fi
        if grep -q "Fedora" /etc/redhat-release; then OS="fedora"; fi
        # Extract version roughly
        OS_VERSION=$(grep -oP '[0-9]+(\.[0-9]+)?' /etc/redhat-release | head -1)
    else
        echo -e "${RED}Unsupported operating system.${NC}"
		exit 1
    fi

	# Debian-based
	if [[ ${OS} == "debian" || ${OS} == "raspbian" ]]; then
		if [[ -z "$OS_VERSION" ]] || (( $(echo "$OS_VERSION" | cut -d'.' -f1) < 10 )); then
			echo -e "${RED}Your version of Debian (${OS_VERSION:-unknown}) is not supported. Please use Debian 10 Buster or later.${NC}"
			exit 1
		fi
		OS=debian # Standardize internal name
	elif [[ ${OS} == "ubuntu" || ${OS} == "linuxmint" ]]; then
		local release_year=0
        if [[ -n "$OS_VERSION" ]]; then
            release_year=$(echo "${OS_VERSION}" | cut -d'.' -f1)
        fi
		if (( release_year < 18 )); then
			echo -e "${RED}Your Ubuntu/Mint version (${OS_VERSION:-unknown}) is not supported. Please use 18.04 or later.${NC}"
			exit 1
		fi
		OS=ubuntu # Standardize internal name
	# RHEL-based
	elif [[ ${OS} == "rhel" || ${OS} == "centos" || ${OS} == "fedora" || ${OS} == "rocky" || ${OS} == "almalinux" ]]; then
        local required_version=7
        if [[ $OS == "fedora" ]]; then required_version=28; fi # Adjust as needed for Fedora

        local major_version=0
        if [[ -n "$OS_VERSION" ]]; then
             major_version=$(echo "$OS_VERSION" | cut -d'.' -f1)
        fi

		if (( major_version < required_version )); then
            echo -e "${RED}Your RHEL-based OS version (${OS_VERSION:-unknown}) is not supported. Please use CentOS/RHEL 7+, Fedora 28+.${NC}"
            exit 1
        fi

        echo -e "${GREEN}Attempting to install EPEL repository (needed for some dependencies)...${NC}"
		if [[ ${OS} == "fedora" ]]; then
			# Fedora usually has EPEL equivalents in main repos or EPEL is less critical
            dnf install -y 'dnf-command(config-manager)' || echo -e "${ORANGE}Could not install config-manager. Continuing...${NC}"
            dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-$(rpm -E %fedora).noarch.rpm || echo -e "${ORANGE}Could not install EPEL repo. Dependencies might fail.${NC}"
		else
            # RHEL, CentOS, Rocky, AlmaLinux
            yum install -y epel-release || echo -e "${ORANGE}Could not install EPEL repo. Dependencies might fail.${NC}"
            # Enable CodeReady Builder (or equivalent) on RHEL 8+ if needed for kernel headers later
            if [[ $OS == "rhel" && $major_version -ge 8 ]]; then
                 subscription-manager repos --enable codeready-builder-for-rhel-8-$(arch)-rpms || \
                 subscription-manager repos --enable codeready-builder-for-rhel-9-$(arch)-rpms || \
                 echo -e "${ORANGE}Could not enable CodeReady Builder repo. Kernel header installation might fail.${NC}"
            elif [[ ($OS == "centos" || $OS == "rocky" || $OS == "almalinux") && $major_version -ge 8 ]]; then
                 dnf config-manager --set-enabled crb || yum-config-manager --enable powertools || echo -e "${ORANGE}Could not enable CRB/PowerTools repo. Kernel header installation might fail.${NC}"
            fi
		fi
		OS=rhel # Standardize internal name
	else
		echo -e "${RED}Unsupported operating system: ${OS:-unknown}${NC}"
		exit 1
	fi
}

function setupDebSrc() {
    # Only run on Debian/Ubuntu
    if [[ ${OS} != "debian" && ${OS} != "ubuntu" ]]; then
        return
    fi

    local sources_file=""
    local src_pattern=""
    local sed_command=""
    local needs_update=0

    echo -e "${GREEN}Checking if deb-src repositories are enabled (required for building modules)...${NC}"

    if [[ ${OS} == "ubuntu" ]]; then
        # Ubuntu 22.04+ uses /etc/apt/sources.list.d/ubuntu.sources by default
        sources_file="/etc/apt/sources.list.d/ubuntu.sources"
        if [ -f "${sources_file}" ]; then
             # Check if *any* line defining Types includes deb-src
             if ! grep -q "^Types:.*deb-src" "${sources_file}"; then
                 echo -e "${ORANGE}deb-src repositories may not be enabled in ${sources_file}.${NC}"
                 read -rp "Would you like to attempt enabling deb-src? [y/n]: " -e -i "y" ENABLE_SRC
                 if [[ ${ENABLE_SRC,,} == 'y' ]]; then
                     # This tries to add deb-src to existing deb lines, might not be perfect for all formats
                     sed -i.bak -E '/^Types: deb$/s/deb/deb deb-src/' "${sources_file}"
                     echo -e "${GREEN}Attempted to enable deb-src. Backup created: ${sources_file}.bak${NC}"
                     needs_update=1
                 else
                     echo -e "${RED}deb-src repositories are required. Installation cannot continue.${NC}"
                     exit 1
                 fi
             else
                 echo -e "${GREEN}deb-src seems enabled in ${sources_file}.${NC}"
             fi
        elif [ -f "/etc/apt/sources.list" ]; then
             # Fallback for older Ubuntu or non-standard configs
             sources_file="/etc/apt/sources.list"
             src_pattern="^deb-src"
             sed_command='s/^#\s*deb-src/deb-src/'
             if ! grep -qE "${src_pattern}" "${sources_file}"; then
                 echo -e "${ORANGE}deb-src repositories may not be enabled in ${sources_file}.${NC}"
                 read -rp "Would you like to attempt enabling deb-src by uncommenting lines? [y/n]: " -e -i "y" ENABLE_SRC
                 if [[ ${ENABLE_SRC,,} == 'y' ]]; then
                     sed -i.bak -E "${sed_command}" "${sources_file}"
                     echo -e "${GREEN}Attempted to enable deb-src. Backup created: ${sources_file}.bak${NC}"
                     needs_update=1
                 else
                     echo -e "${RED}deb-src repositories are required. Installation cannot continue.${NC}"
                     exit 1
                 fi
             else
                 echo -e "${GREEN}deb-src seems enabled in ${sources_file}.${NC}"
             fi
        else
            echo -e "${RED}Cannot find standard sources list file. Cannot verify deb-src.${NC}"
            exit 1
        fi
    elif [[ ${OS} == "debian" ]]; then
        sources_file="/etc/apt/sources.list"
        src_pattern="^deb-src"
        sed_command='s/^#\s*deb-src/deb-src/'
        if [ -f "${sources_file}" ]; then
             if ! grep -qE "${src_pattern}" "${sources_file}"; then
                 echo -e "${ORANGE}deb-src repositories may not be enabled in ${sources_file}.${NC}"
                 read -rp "Would you like to attempt enabling deb-src by uncommenting lines? [y/n]: " -e -i "y" ENABLE_SRC
                 if [[ ${ENABLE_SRC,,} == 'y' ]]; then
                     sed -i.bak -E "${sed_command}" "${sources_file}"
                     echo -e "${GREEN}Attempted to enable deb-src. Backup created: ${sources_file}.bak${NC}"
                     needs_update=1
                 else
                     echo -e "${RED}deb-src repositories are required. Installation cannot continue.${NC}"
                     exit 1
                 fi
             else
                 echo -e "${GREEN}deb-src seems enabled in ${sources_file}.${NC}"
             fi
        else
             echo -e "${RED}Cannot find standard sources list file (/etc/apt/sources.list). Cannot verify deb-src.${NC}"
             exit 1
        fi
    fi

    if [[ ${needs_update} -eq 1 ]]; then
        echo -e "${GREEN}Running apt-get update to refresh sources...${NC}"
        apt-get update
    fi
}

function getHomeDirForClient() {
	local client_name="${1:-}" # Use default empty string if no arg
	local home_dir=""

	# Determine the home directory to save client configs
	if [ -n "${client_name}" ] && [ -d "/home/${client_name}" ]; then
		# If client_name is a valid user with a home directory
		home_dir="/home/${client_name}"
	elif [ -n "${SUDO_USER}" ] && [ "${SUDO_USER}" != "root" ] && [ -d "/home/${SUDO_USER}" ]; then
		# If running via sudo by a non-root user
		home_dir="/home/${SUDO_USER}"
	elif [ -d "/root" ]; then
		# Fallback to /root if SUDO_USER is root or not set, or if home dir doesn't exist
		home_dir="/root"
    else
        # Absolute fallback (should rarely happen)
        home_dir="/tmp"
        echo -e "${ORANGE}Warning: Could not determine a standard home directory. Using ${home_dir} for client configs.${NC}"
	fi

	echo "${home_dir}"
}

function detectExistingWireGuard() {
    if [[ -d "${WG_CONF_DIR}" ]] && find "${WG_CONF_DIR}" -maxdepth 1 -name "*.conf" -print -quit | grep -q .; then
        print_header "Existing WireGuard Detected"
        echo -e "${ORANGE}WireGuard configuration files found in ${WG_CONF_DIR}.${NC}"
        echo ""

        local wg_type="standard" # Assume standard by default
        if [[ -f "${WG_CONF_DIR}/params" ]]; then
            echo -e "${GREEN}Detected WireGuard possibly installed using the 'angristan/wireguard-install' script.${NC}"
            wg_type="script"
        else
            echo -e "${GREEN}Detected standard WireGuard installation.${NC}"
        fi

        echo -e "${RED}AmneziaWG installation will attempt to migrate your existing WireGuard setup.${NC}"
        echo "- Existing WireGuard services will be stopped and disabled."
        echo "- Server settings (IPs, Port, Server Private Key) will be reused to maintain server identity."
        echo "- Client authorization (public keys) will be migrated to the new server config."
        echo -e "- ${ORANGE}NEW client config files (with AmneziaWG obfuscation settings) will be generated in ~/amneziawg/.${NC}"
        echo -e "- ${ORANGE}These NEW config files MUST be distributed to clients to enable obfuscation.${NC}"
        echo -e "- ${ORANGE}Existing client config files MAY still work for basic connectivity (without obfuscation), but using the new files is recommended.${NC}"
        echo "- Old WireGuard config files (`/etc/wireguard/*.conf`) will remain as backups but the service will be inactive."
        echo ""
        read -rp "Do you want to proceed with migration? [y/n]: " -e -i "y" CONFIRM
        if [[ ${CONFIRM,,} == 'y' ]]; then
            migrateWireGuard "${wg_type}" # Pass detected type
            # If migration is successful, exit the script? Or continue to management menu?
            echo -e "${GREEN}Migration completed. Please manage your AmneziaWG server using this script later.${NC}"
            exit 0 # Exit after successful migration
        else
            echo "Installation cancelled."
                exit 0
        fi
    elif dpkg-query -W -f='${Status}' wireguard 2>/dev/null | grep -q "ok installed" || \
         (command -v rpm &>/dev/null && rpm -q wireguard-tools &>/dev/null); then
        echo -e "${ORANGE}WireGuard package (or tools) is installed but no *.conf files found in ${WG_CONF_DIR}.${NC}"
        echo -e "${GREEN}Attempting to remove WireGuard packages before installing AmneziaWG...${NC}"

        if [[ ${OS} == "ubuntu" || ${OS} == "debian" ]]; then
            apt-get remove -y wireguard wireguard-tools
            apt-get autoremove -y
        elif [[ ${OS} == "rhel" ]]; then
            # dnf/yum remove wireguard-tools (main package is usually kernel mod or handled by AmneziaWG install)
            yum remove -y wireguard-tools || dnf remove -y wireguard-tools
            yum autoremove -y || dnf autoremove -y
        fi

        echo -e "${GREEN}WireGuard packages removed (if found). Proceeding with AmneziaWG installation...${NC}"
    else
        echo -e "${GREEN}No existing WireGuard installation detected.${NC}"
    fi
}

function migrateWireGuard() {
    local installation_type="$1" # "script" or "standard"
    print_header "WireGuard Migration"
    echo -e "${GREEN}Starting WireGuard to AmneziaWG migration (Type: ${installation_type})...${NC}"

    # Find the primary WireGuard interface config file
    # Heuristic: find first .conf file
    local wg_conf_file=""
    wg_conf_file=$(find "${WG_CONF_DIR}" -maxdepth 1 -name "*.conf" -print -quit)

    if [[ -z "${wg_conf_file}" ]]; then
        echo -e "${RED}No WireGuard configuration file (*.conf) found in ${WG_CONF_DIR}. Cannot migrate.${NC}"
        exit 1
    fi

    local wg_interface_name=""
    wg_interface_name=$(basename "${wg_conf_file}" .conf)
    echo -e "${GREEN}Found WireGuard interface: ${wg_interface_name}${NC}"

    # --- Extract Settings from Old Config ---
    # Use wg-quick strip for cleaner parsing
    local stripped_config=""
    if ! stripped_config=$(wg-quick strip "${wg_interface_name}" 2>/dev/null); then
        echo -e "${ORANGE}Warning: Failed to strip configuration using 'wg-quick strip ${wg_interface_name}'. Reading file directly.${NC}"
        # Fallback to reading file if strip fails
        if ! stripped_config=$(cat "${wg_conf_file}"); then
             echo -e "${RED}Failed to read configuration file: ${wg_conf_file}${NC}"
             exit 1
        fi
    fi

    # Extract Interface settings using improved method
    local address_line=$(echo "${stripped_config}" | grep -m 1 -oP 'Address *= *\K.*')
    SERVER_WG_IPV4=$(echo "$address_line" | grep -oP '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1) # Extract IPv4 (no CIDR)
    SERVER_WG_IPV6=$(echo "$address_line" | grep -oP '[a-fA-F0-9:]+:[a-fA-F0-9:/]+' | grep ':' | head -1 | sed 's|/.*||') # Extract IPv6 (no CIDR)
    SERVER_PORT=$(echo "${stripped_config}" | grep -m 1 -oP 'ListenPort *= *\K[0-9]+')

    # Validate extracted mandatory settings
    # Check if at least one IP (v4 or v6) and the port were found
    if [[ (-z "${SERVER_WG_IPV4}" && -z "${SERVER_WG_IPV6}") || -z "${SERVER_PORT}" ]]; then
        echo -e "${RED}Could not reliably extract server IP address (IPv4 or IPv6) or ListenPort from ${wg_conf_file}.${NC}"
        echo -e "${RED}Stripped Config Content:\n${stripped_config}${NC}" # Debug output
        echo -e "${RED}Extracted Address Line: ${address_line}${NC}"
        echo -e "${RED}Extracted IPv4: ${SERVER_WG_IPV4}${NC}"
        echo -e "${RED}Extracted IPv6: ${SERVER_WG_IPV6}${NC}"
        echo -e "${RED}Extracted Port: ${SERVER_PORT}${NC}"
        echo -e "${RED}Please ensure the [Interface] section has 'Address' and 'ListenPort'.${NC}"
        exit 1
    fi
    echo -e "${GREEN}Extracted Settings:${NC} IPv4=${SERVER_WG_IPV4:-N/A}, IPv6=${SERVER_WG_IPV6:-N/A}, Port=${SERVER_PORT}"

    # Determine Public IP/NIC (Use current system state as fallback)
    SERVER_PUB_NIC=$(ip -4 route ls | grep default | awk '/dev/ {print $5}' | head -1)
    SERVER_PUB_IP=$(ip -4 addr show "${SERVER_PUB_NIC}" | grep -oP 'inet \K[0-9\.]+' | head -1)
    echo -e "${GREEN}Using current system Public NIC:${SERVER_PUB_NIC} and Public IP:${SERVER_PUB_IP}${NC}" # User might need to adjust this later

    # --- Handle Private Key ---
    SERVER_PRIV_KEY="" # Initialize as empty
    SERVER_PUB_KEY=""

    # Check specifically for the angristan script's params file first
    if [[ -f "${WG_CONF_DIR}/params" ]]; then
        echo -e "${GREEN}Detected '${WG_CONF_DIR}/params' file (likely from angristan/wireguard-install).${NC}"
        echo -e "${GREEN}Attempting to read SERVER_PRIV_KEY automatically...${NC}"
        # Source the params file safely in a subshell and capture the specific variable
        local sourced_priv_key=""
        # Ensure the params file is readable
        if [[ -r "${WG_CONF_DIR}/params" ]]; then
             # The command substitution runs 'source' in a subshell
             sourced_priv_key=$(source "${WG_CONF_DIR}/params" && echo "${SERVER_PRIV_KEY}")

             if [[ -n "${sourced_priv_key}" ]] && echo "${sourced_priv_key}" | grep -Eq '^[A-Za-z0-9+/]{43}=$'; then
                 SERVER_PRIV_KEY="${sourced_priv_key}"
                 echo -e "${GREEN}Server private key successfully read and validated from params file.${NC}"
             elif [[ -n "${sourced_priv_key}" ]]; then
                 echo -e "${ORANGE}Warning: Value read for SERVER_PRIV_KEY from params file appears invalid. Ignoring.${NC}"
             else
                 echo -e "${ORANGE}Warning: Could not read SERVER_PRIV_KEY variable from params file, even though it exists.${NC}"
             fi
        else
             echo -e "${ORANGE}Warning: Params file '${WG_CONF_DIR}/params' exists but is not readable.${NC}"
        fi
        # Optionally read other useful params like DNS, but stick to Amnezia defaults for now unless specified
        # Example: sourced_dns1=$(source "${WG_CONF_DIR}/params" && echo "${CLIENT_DNS_1}")
        # if [[ -n $sourced_dns1 ]]; then CLIENT_DNS_1=$sourced_dns1; fi
    fi

    # If key wasn't found/read from params OR if it was a 'standard' installation type
    if [[ -z "${SERVER_PRIV_KEY}" ]]; then
        # Add a message clarifying why we are asking now
        if [[ -f "${WG_CONF_DIR}/params" ]]; then
             echo -e "${ORANGE}Could not automatically get a valid private key from the params file.${NC}"
        else
             echo -e "${ORANGE}This looks like a standard WireGuard setup or key couldn't be auto-detected.${NC}"
        fi

        echo -e "${ORANGE}The server's private key is required to allow existing clients to connect after migration.${NC}"
        echo -e "${ORANGE}Without it, a new key pair will be generated, and ALL clients will need new config files.${NC}"
        echo ""
        read -rp "Do you have the path to the server's private key file? [y/n]: " -e -i "n" HAS_KEY_PATH
        if [[ ${HAS_KEY_PATH,,} == 'y' ]]; then
            local key_file_path=""
            read -rp "Enter the full path to the server's private key file: " key_file_path
            if [[ -f "${key_file_path}" ]] && [[ -r "${key_file_path}" ]]; then
                SERVER_PRIV_KEY=$(cat "${key_file_path}")
                # Validate the key basic format (length/chars) - wg pubkey checks better later
                if echo "${SERVER_PRIV_KEY}" | grep -Eq '^[A-Za-z0-9+/]{43}=$'; then
                     echo -e "${GREEN}Private key read successfully from ${key_file_path}.${NC}"
                else
                     echo -e "${RED}Invalid key format read from ${key_file_path}. Ignoring.${NC}"
                     SERVER_PRIV_KEY="" # Reset if invalid
                fi
            else
                echo -e "${RED}File not found or not readable: ${key_file_path}${NC}"
            fi
        fi

        # If still no key after asking, generate a new one
        if [[ -z "${SERVER_PRIV_KEY}" ]]; then
            echo -e "${ORANGE}No valid private key obtained. Generating a new key pair for the AmneziaWG server...${NC}"
            SERVER_PRIV_KEY=$(awg genkey)
            echo -e "${RED}IMPORTANT: Existing clients will NOT connect with this new key.${NC}"
            echo -e "${RED}You MUST distribute the newly generated client config files.${NC}"
        fi
    fi

    # Derive public key
    SERVER_PUB_KEY=$(echo "${SERVER_PRIV_KEY}" | awg pubkey)
    if [[ -z "${SERVER_PUB_KEY}" ]]; then
        echo -e "${RED}Failed to generate public key from private key. The private key may be invalid.${NC}"
        exit 1
    fi
    echo -e "${GREEN}Server Public Key: ${SERVER_PUB_KEY}${NC}"


    # --- Set Defaults for AmneziaWG (can be changed later) ---
    # Use AmneziaWG defaults for DNS, Obfuscation
    CLIENT_DNS_1="8.8.8.8" # Google DNS as default
    CLIENT_DNS_2="8.8.4.4"
    CLIENT_DNS_IPV6_1="2001:4860:4860::8888"
    CLIENT_DNS_IPV6_2="2001:4860:4860::8844"
    setDefaultAmneziaSettings # Sets JC, JMIN, JMAX, S1, S2, H1-4, MTU
    # Use default routing unless a specific file exists
    if [ -f "${AWG_CONF_DIR}/default_routing" ]; then
        ALLOWED_IPS=$(cat "${AWG_CONF_DIR}/default_routing")
        echo -e "${GREEN}Using default routing from ${AWG_CONF_DIR}/default_routing: ${ALLOWED_IPS}${NC}"
    else
        echo -e "${GREEN}Using default routing (0.0.0.0/0, ::/0).${NC}"
        ALLOWED_IPS="0.0.0.0/0"
        if [[ -n "${SERVER_WG_IPV6}" ]]; then # Check if WG had IPv6
             ALLOWED_IPS="${ALLOWED_IPS},::/0"
             ENABLE_IPV6="y" # Ensure IPv6 is marked enabled
        else
             ENABLE_IPV6="n"
        fi
    fi
    # Ensure ENABLE_IPV6 reflects extracted IPv6
    [[ -n "${SERVER_WG_IPV6}" ]] && ENABLE_IPV6="y" || ENABLE_IPV6="n"


    # --- Create AmneziaWG directories and params file ---
    mkdir -p "${AWG_CONF_DIR}"
    chmod 700 "${AWG_CONF_DIR}"

    # Write the params file (IPs without CIDR)
    cat > "${PARAMS_FILE}" <<EOF
SERVER_PUB_IP=${SERVER_PUB_IP}
SERVER_PUB_NIC=${SERVER_PUB_NIC}
SERVER_WG_NIC=${SERVER_WG_NIC} # Use Amnezia default 'awg0'
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
    echo -e "${GREEN}AmneziaWG parameters saved to ${PARAMS_FILE}${NC}"

    # Create client config dir
    local home_dir=""
    home_dir=$(getHomeDirForClient "${SUDO_USER:-root}")
    local client_config_dir="${home_dir}/amneziawg"
    mkdir -p "${client_config_dir}"
    chmod 700 "${client_config_dir}"
    echo -e "${GREEN}Client config directory set to: ${client_config_dir}${NC}"


    # --- Migrate Peer Configurations ---
    # This function will create the server conf file and generate NEW client conf files
    migratePeers "${stripped_config}" "${client_config_dir}"

    # --- Stop and Disable Old WireGuard Services ---
    echo -e "${GREEN}Stopping and disabling original WireGuard services...${NC}"
    local wg_service_name="wg-quick@${wg_interface_name}"
    if systemctl is-active --quiet "${wg_service_name}"; then
        systemctl stop "${wg_service_name}"
    fi
    if systemctl is-enabled --quiet "${wg_service_name}"; then
        systemctl disable "${wg_service_name}"
    fi
    echo -e "${GREEN}Original WireGuard service (${wg_service_name}) stopped and disabled.${NC}"
    echo -e "${ORANGE}Original configuration files remain at ${WG_CONF_DIR}${NC}"

    # --- Install AmneziaWG Packages (if not already done by initial check) ---
    # Might be redundant if detectExistingWireGuard ran first, but safe to run again
    echo -e "${GREEN}Ensuring AmneziaWG packages are installed...${NC}"
    if [[ ${OS} == "ubuntu" || ${OS} == "debian" ]]; then
        # Assume PPA was added or repo exists if migration is running after initial checks
        apt-get update
        apt-get install -y amneziawg linux-headers-$(uname -r) || echo -e "${RED}Failed to install amneziawg package!${NC}"
    elif [[ ${OS} == "rhel" ]]; then
        installAmneziaWGRHEL # Function handles repo and installation
    fi

    # --- Enable and Start AmneziaWG Service ---
    echo -e "${GREEN}Enabling and starting AmneziaWG service (awg-quick@${SERVER_WG_NIC})...${NC}"
    systemctl enable "awg-quick@${SERVER_WG_NIC}"
    # Restart might be safer than start if it was somehow already running
    systemctl restart "awg-quick@${SERVER_WG_NIC}"

    # Verify service is running
    if systemctl is-active --quiet "awg-quick@${SERVER_WG_NIC}"; then
        echo -e "${GREEN}AmneziaWG service (awg-quick@${SERVER_WG_NIC}) is running.${NC}"
    else
        echo -e "${RED}AmneziaWG service failed to start.${NC}"
        echo -e "${RED}Check logs: journalctl -u awg-quick@${SERVER_WG_NIC}${NC}"
        echo -e "${RED}Also check config: ${AWG_CONF_DIR}/${SERVER_WG_NIC}.conf${NC}"
        # Don't exit, let user troubleshoot
    fi
}

function migratePeers() {
    local stripped_config="$1"
    local client_config_dir="$2" # Directory to save NEW client configs

    # Source params to get current server settings needed for client configs
    # Use default values if params file somehow doesn't exist yet
    if [[ -f "${PARAMS_FILE}" ]]; then
        source "${PARAMS_FILE}"
    else
        echo -e "${RED}Params file ${PARAMS_FILE} not found during peer migration. Using defaults.${NC}"
        # Rely on defaults set globally or within this function
        SERVER_WG_NIC=${SERVER_WG_NIC:-awg0}
        SERVER_PUB_KEY=${SERVER_PUB_KEY:-"UNKNOWN_SERVER_PUBKEY"}
        SERVER_PUB_IP=${SERVER_PUB_IP:-"UNKNOWN_SERVER_IP"}
        SERVER_PORT=${SERVER_PORT:-51820}
        SERVER_WG_IPV4=${SERVER_WG_IPV4:-"10.0.0.1"} # Need defaults for server IPs too
        SERVER_WG_IPV6=${SERVER_WG_IPV6:-""}
        ENABLE_IPV6=${ENABLE_IPV6:-"n"}
        CLIENT_DNS_1=${CLIENT_DNS_1:-"8.8.8.8"}
        CLIENT_DNS_2=${CLIENT_DNS_2:-"8.8.4.4"}
        CLIENT_DNS_IPV6_1=${CLIENT_DNS_IPV6_1:-"2001:4860:4860::8888"}
        CLIENT_DNS_IPV6_2=${CLIENT_DNS_IPV6_2:-"2001:4860:4860::8844"}
        ALLOWED_IPS=${ALLOWED_IPS:-"0.0.0.0/0,::/0"}
        # Obfuscation params should be set by setDefaultAmneziaSettings called before migrateWireGuard
    fi

    local server_conf_file="${AWG_CONF_DIR}/${SERVER_WG_NIC}.conf"

    echo -e "${GREEN}Generating AmneziaWG server configuration: ${server_conf_file}${NC}"

    # Create base server configuration file (Add CIDR back here)
    cat > "${server_conf_file}" << EOF
[Interface]
Address = ${SERVER_WG_IPV4}/24$( [[ ${ENABLE_IPV6} == 'y' && -n "${SERVER_WG_IPV6}" ]] && echo ",${SERVER_WG_IPV6}/64" )
ListenPort = ${SERVER_PORT}
PrivateKey = ${SERVER_PRIV_KEY}
# AmneziaWG Obfuscation Params
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

    # Append PostUp/PostDown rules based on firewall type
    local ip_v4_base="${SERVER_WG_IPV4%.*}" # Get e.g., 10.0.0 from 10.0.0.1
    if command -v firewall-cmd &> /dev/null && pgrep firewalld; then
        echo -e "${GREEN}Adding firewall-cmd rules...${NC}"
        local FIREWALLD_IPV4_ADDRESS="${ip_v4_base}.0" # Get subnet like 10.0.0.0
        # Add rules (consider adding --permanent and then --reload, but runtime is often preferred for wg-quick)
        echo "PostUp = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC}" >> "${server_conf_file}"
        echo "PostUp = firewall-cmd --add-port ${SERVER_PORT}/udp" >> "${server_conf_file}"
        echo "PostUp = firewall-cmd --add-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade'" >> "${server_conf_file}"
        echo "PostDown = firewall-cmd --zone=public --remove-interface=${SERVER_WG_NIC}" >> "${server_conf_file}"
        echo "PostDown = firewall-cmd --remove-port ${SERVER_PORT}/udp" >> "${server_conf_file}"
        echo "PostDown = firewall-cmd --remove-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade'" >> "${server_conf_file}"

        if [[ ${ENABLE_IPV6} == 'y' && -n "${SERVER_WG_IPV6}" ]]; then
          local FIREWALLD_IPV6_ADDRESS=$(echo "${SERVER_WG_IPV6}" | sed 's/:[^:]*$/::/')"/64" # Get subnet like fd42:42:42::/64
          echo "PostUp = firewall-cmd --add-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS} masquerade'" >> "${server_conf_file}"
          echo "PostDown = firewall-cmd --remove-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS} masquerade'" >> "${server_conf_file}"
        fi
    elif command -v iptables &> /dev/null; then
        echo -e "${GREEN}Adding iptables rules...${NC}"
        cat >> "${server_conf_file}" <<EOF
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
            echo -e "${GREEN}Adding ip6tables rules...${NC}"
            cat >> "${server_conf_file}" <<EOF
PostUp = ip6tables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostUp = ip6tables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = ip6tables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostDown = ip6tables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
EOF
        fi
    else
        echo -e "${ORANGE}Warning: No firewall detected (firewalld or iptables). Firewall rules not added.${NC}"
        echo -e "${ORANGE}You may need to configure firewall rules manually for UDP port ${SERVER_PORT} and NAT/Forwarding.${NC}"
    fi

    # --- Process Peers ---
    echo -e "${GREEN}Migrating peer configurations (generating NEW client files with obfuscation)...${NC}"
    echo -e "${ORANGE}Clients MUST use these new config files to benefit from AmneziaWG obfuscation.${NC}"

    local peer_block=""
    local client_counter=0
    # Process the stripped config, splitting by '[Peer]' sections
    # Use awk to handle multi-line Peer blocks
    echo "${stripped_config}" | awk '/^\[Peer\]/{ if (peer_block) print peer_block; peer_block=""; next } NF > 0 { peer_block = peer_block $0 "\n" } END { if (peer_block) print peer_block }' | while IFS= read -r peer_block; do

        local peer_pub_key=""
        local peer_allowed_ips=""
        local peer_psk=""

        # Extract details from the peer block
        peer_pub_key=$(echo "${peer_block}" | grep -oP 'PublicKey *= *\K[A-Za-z0-9+/=]+')
        peer_allowed_ips=$(echo "${peer_block}" | grep -oP 'AllowedIPs *= *\K[0-9a-fA-F\.:/,]+')
        peer_psk=$(echo "${peer_block}" | grep -oP 'PresharedKey *= *\K[A-Za-z0-9+/=]+')

        if [[ -z "${peer_pub_key}" || -z "${peer_allowed_ips}" ]]; then
            echo -e "${ORANGE}Skipping invalid peer block (missing PublicKey or AllowedIPs):${NC}\n${peer_block}"
            continue
        fi

        ((client_counter++))
        # Try to find a comment name, otherwise use counter
        local client_name=""
        # Look for a comment line immediately preceding the [Peer] block in the *original* file content (less reliable)
        # Or just use a generic name based on counter/pubkey
        client_name="migrated_client_${client_counter}_$(echo "${peer_pub_key}" | cut -c1-6)"

        echo -e "  -> Migrating Peer: ${client_name} (PubKey: ${peer_pub_key})"

        # --- Generate NEW Client Config ---
        local client_priv_key=""
        local client_wg_ipv4_peer="" # IP extracted from peer's allowed IPs
        local client_wg_ipv6_peer="" # IP extracted from peer's allowed IPs

        client_priv_key=$(awg genkey) # Generate NEW private key for client

        # Extract the *first* IPv4 and IPv6 from the peer's AllowedIPs for the client's Interface Address
        # Ensure we remove the CIDR suffix here for the Address line
        client_wg_ipv4_peer=$(echo "${peer_allowed_ips}" | tr ',' '\n' | grep -oP '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        client_wg_ipv6_peer=$(echo "${peer_allowed_ips}" | tr ',' '\n' | grep -oP '^[a-fA-F0-9:]+' | grep ':' | head -1 | sed 's|/.*||')

        if [[ -z "${client_wg_ipv4_peer}" ]]; then
            echo -e "${ORANGE}    Warning: Could not extract client IPv4 from AllowedIPs (${peer_allowed_ips}). Cannot generate client config.${NC}"
            continue
        fi

        local client_conf_path="${client_config_dir}/${SERVER_WG_NIC}-${client_name}.conf"
        # Create client config file (NEW KEYS, OLD AllowedIPs from server perspective)
        cat > "${client_conf_path}" <<EOF
[Interface]
# Client configuration for ${client_name} - Generated during migration
# Use this file to enable AmneziaWG obfuscation
PrivateKey = ${client_priv_key}
Address = ${client_wg_ipv4_peer}/32$( [[ -n "${client_wg_ipv6_peer}" ]] && echo ",${client_wg_ipv6_peer}/128" )
DNS = ${CLIENT_DNS_1}${CLIENT_DNS_2:+,${CLIENT_DNS_2}}${CLIENT_DNS_IPV6_1:+,${CLIENT_DNS_IPV6_1}}${CLIENT_DNS_IPV6_2:+,${CLIENT_DNS_IPV6_2}}
# AmneziaWG Obfuscation Params (match server)
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
# Server Info
PublicKey = ${SERVER_PUB_KEY}
$( [[ -n "${peer_psk}" ]] && echo "PresharedKey = ${peer_psk}" )
Endpoint = ${SERVER_PUB_IP}:${SERVER_PORT}
# AllowedIPs for client (controls routing ON THE CLIENT) - use global default
AllowedIPs = ${ALLOWED_IPS}
EOF
        chmod 600 "${client_conf_path}"
        echo -e "${GREEN}    Generated new client config: ${client_conf_path}${NC}"

        # --- Append Peer to Server Config ---
        # We use the *original* public key from the old config here
        cat >> "${server_conf_file}" <<EOF

### Client ${client_name} (Migrated)
[Peer]
PublicKey = ${peer_pub_key}
$( [[ -n "${peer_psk}" ]] && echo "PresharedKey = ${peer_psk}" )
AllowedIPs = ${peer_allowed_ips} # Use original AllowedIPs on server side
EOF
    done # End of peer processing loop

    if [[ ${client_counter} -eq 0 ]]; then
         echo -e "${ORANGE}No valid [Peer] sections found in the stripped configuration.${NC}"
    else
         echo -e "${GREEN}Processed ${client_counter} peer(s).${NC}"
    fi

    # Apply the final server configuration (peers added)
    # We don't use syncconf here as the service will be restarted later
    # awg syncconf "${SERVER_WG_NIC}" <(wg-quick strip "${SERVER_WG_NIC}") # Not needed before service start
}

function saveClientConfig() {
    # This function seems to be a remnant/duplicate of logic now inside migratePeers or newClient
    # It was used differently in the original script.
    # For clarity and to avoid confusion, let's remove it or ensure it's not called during migration.
    echo -e "${ORANGE}DEBUG: saveClientConfig called - this might be unexpected during migration.${NC}"
    # Keeping the structure just in case it was called from somewhere missed in refactoring
    local client_name="$1"
    local peer_config="$2" # This would be the [Peer] block string
    echo -e "${RED}Error: saveClientConfig should not be directly called during migration refactor.${NC}"
    # Add logic here if needed, but prefer migratePeers or newClient
}

# --- Installation Functions ---

function initialCheck() {
	isRoot
	checkOS # Sets $OS variable
	checkVirt
    # Check for existing WireGuard or AmneziaWG installations
    if [[ -f "${PARAMS_FILE}" ]]; then
        # AmneziaWG already installed, proceed to manage menu
        return 0 # Indicates existing install
    elif [[ -d "${WG_CONF_DIR}" ]] && find "${WG_CONF_DIR}" -maxdepth 1 -name "*.conf" -print -quit | grep -q .; then
        # WireGuard detected, run migration check (which might exit)
        detectExistingWireGuard
        # If detectExistingWireGuard proceeds without exiting, it means user chose NOT to migrate.
        echo -e "${RED}Existing WireGuard found, but user chose not to migrate. Aborting AmneziaWG installation.${NC}"
        exit 1
    else
        # No WireGuard or AmneziaWG params found, proceed with fresh install
        return 1 # Indicates fresh install needed
    fi
}

function installQuestions() {
	print_header "AmneziaWG Installer - Configuration"
	echo "I need to ask a few questions before starting the setup."
	echo "You can keep the default options and just press enter if you are okay with them."
	echo ""

	# Ask about IPv6 support first
	echo -e "${GREEN}Do you want to enable IPv6 support (recommended)?${NC}"
    # Default ENABLE_IPV6 is 'y'
	read -rp "Enable IPv6? [y/n]: " -e -i "${ENABLE_IPV6}" choice
	ENABLE_IPV6=${choice,,} # to lower case
	if [[ "$ENABLE_IPV6" != "y" ]]; then
        ENABLE_IPV6="n"
        ALLOWED_IPS="0.0.0.0/0" # Reset default routing if IPv6 disabled
    else
        ALLOWED_IPS="0.0.0.0/0,::/0" # Ensure default includes IPv6
    fi
	echo ""

    # Public IP / Hostname
    SERVER_PUB_IP=""
    local auto_ipv4=""
    local auto_ipv6=""
    local use_hostname="n"

    # Detect public interface and IP addresses
	SERVER_PUB_NIC="$(ip -4 route ls | grep default | awk '/dev/ {print $5}' | head -1)"
    if [[ -n "$SERVER_PUB_NIC" ]]; then
        auto_ipv4=$(ip -4 addr show "${SERVER_PUB_NIC}" | grep -oP 'inet \K[0-9\.]+' | head -1)
        if [[ ${ENABLE_IPV6} == 'y' ]]; then
            # Try to find a global scope IPv6 on the same NIC
            auto_ipv6=$(ip -6 addr show "${SERVER_PUB_NIC}" scope global | grep -oP 'inet6 \K[0-9a-fA-F:]+' | head -1)
        fi
        echo -e "${GREEN}Detected public interface: ${SERVER_PUB_NIC}${NC}"
        echo -e "${GREEN}Detected IPv4 address: ${auto_ipv4:-Not found}${NC}"
        [[ ${ENABLE_IPV6} == 'y' ]] && echo -e "${GREEN}Detected IPv6 address: ${auto_ipv6:-Not found}${NC}"
    else
        echo -e "${ORANGE}Could not automatically detect public interface.${NC}"
    fi

	# Try to get hostname
	local server_hostname=""
    server_hostname=$(hostname -f 2>/dev/null || hostname 2>/dev/null)
	if [[ -n "${server_hostname}" && "${server_hostname}" != "localhost" ]]; then
		echo ""
        echo -e "${GREEN}Server hostname detected: ${server_hostname}${NC}"
		echo "You can use this hostname instead of an IP address for client endpoints."
        echo -e "${ORANGE}Note: Ensure this hostname resolves correctly to your server's public IP.${NC}"
        read -rp "Use hostname (${server_hostname}) as endpoint? [y/n]: " -e -i "y" choice
        use_hostname=${choice,,}
		if [[ ${use_hostname} == 'y' ]]; then
            SERVER_PUB_IP="${server_hostname}"
        fi
    fi

	# Ask for IP only if hostname is not used
	if [[ ${use_hostname} != 'y' ]]; then
        read -rp "Public IPv4 address or Hostname: " -e -i "${auto_ipv4:-}" SERVER_PUB_IP
        # We only need one public endpoint (IP or hostname) for the client config.
        # If IPv6 is enabled, the server will listen, but client endpoint uses SERVER_PUB_IP.
	fi
    # Validate SERVER_PUB_IP is not empty
    if [[ -z "${SERVER_PUB_IP}" ]]; then
        echo -e "${RED}Server public IP or hostname cannot be empty.${NC}"
        exit 1
    fi
    echo ""

	# Network Interface Names
    local SERVER_PUB_NIC_INPUT="" # Define locally
	until [[ "${SERVER_PUB_NIC_INPUT}" =~ ^[a-zA-Z0-9_.-]+$ ]]; do
		read -rp "Public Network Interface: " -e -i "${SERVER_PUB_NIC:-eth0}" SERVER_PUB_NIC_INPUT
	done
    SERVER_PUB_NIC="${SERVER_PUB_NIC_INPUT}" # Use user input

	until [[ "${SERVER_WG_NIC}" =~ ^[a-zA-Z0-9_.-]+$ && ${#SERVER_WG_NIC} -lt 16 ]]; do
		read -rp "AmneziaWG Interface Name: " -e -i "${SERVER_WG_NIC}" SERVER_WG_NIC
	done
    echo ""

	# VPN Internal Subnet (IP only, no CIDR)
	until [[ "${SERVER_WG_IPV4}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; do
		read -rp "VPN Internal Subnet IPv4 (Server IP, e.g., 10.0.0.1): " -e -i "10.0.0.1" SERVER_WG_IPV4
	done

	if [[ ${ENABLE_IPV6} == 'y' ]]; then
		# Accept standard IPv6 formats, without requiring CIDR
        until [[ "${SERVER_WG_IPV6}" =~ ^([a-fA-F0-9]{1,4}:){1,7}[a-fA-F0-9]{1,4}$|^([a-fA-F0-9]{1,4}:){1,7}:([a-fA-F0-9]{1,4})?$|^::$ ]]; do
            # Suggest a unique local address
            local suggested_ipv6="fd$(openssl rand -hex 5)"
            suggested_ipv6="fd${suggested_ipv6:0:2}:${suggested_ipv6:2:4}:${suggested_ipv6:6:4}::1"
			read -rp "VPN Internal Subnet IPv6 (Server IP, e.g., ${suggested_ipv6}): " -e -i "${suggested_ipv6}" SERVER_WG_IPV6
		done
	else
		SERVER_WG_IPV6="" # Ensure it's empty if IPv6 disabled
	fi
    echo ""

	# VPN Port
	local random_port=""
    random_port=$(shuf -i49152-65535 -n1)
	until [[ "${SERVER_PORT}" =~ ^[0-9]+$ ]] && [ "${SERVER_PORT}" -ge 1 ] && [ "${SERVER_PORT}" -le 65535 ]; do
		read -rp "AmneziaWG Listen Port [1-65535]: " -e -i "${random_port}" SERVER_PORT
	done
    echo ""

    # --- Configure Default Routing ---
    # This function will set the global ALLOWED_IPS variable
    configureAllowedIPs
    # Save the chosen default routing to the dedicated file
	mkdir -p "${AWG_CONF_DIR}"
    echo "${ALLOWED_IPS}" > "${AWG_CONF_DIR}/default_routing"
	echo -e "${GREEN}Default routing saved to ${AWG_CONF_DIR}/default_routing${NC}"
    echo ""

	# --- DNS Selection ---
    print_header "DNS Server Selection"
	echo "Select DNS servers for clients:"
	echo "   1) Google"
	echo "   2) Cloudflare (Recommended)"
    echo "   3) Comss.dns (Russia - No log, Filters Ads/Trackers/Malware)" # New option
	echo "   4) OpenDNS"
	echo "   5) AdGuard DNS (Blocks ads)"
	echo "   6) Custom"
	local dns_choice=""
    until [[ "${dns_choice}" =~ ^[1-6]$ ]]; do
	    read -rp "Select DNS option [1-6]: " -e -i "2" dns_choice
    done

	case "${dns_choice}" in
		1) # Google
			CLIENT_DNS_1="8.8.8.8"
			CLIENT_DNS_2="8.8.4.4"
			CLIENT_DNS_IPV6_1="2001:4860:4860::8888"
			CLIENT_DNS_IPV6_2="2001:4860:4860::8844"
			;;
		2) # Cloudflare
			CLIENT_DNS_1="1.1.1.1"
			CLIENT_DNS_2="1.0.0.1"
			CLIENT_DNS_IPV6_1="2606:4700:4700::1111"
			CLIENT_DNS_IPV6_2="2606:4700:4700::1001"
			;;
        3) # Comss.dns (IPv4 only provided)
            CLIENT_DNS_1="83.220.169.155" # Primary DNS address
            CLIENT_DNS_2="212.109.195.93" # Secondary DNS address
            # Comss doesn't publish IPv6, use Cloudflare as fallback if IPv6 enabled
            CLIENT_DNS_IPV6_1="2606:4700:4700::1111"
			CLIENT_DNS_IPV6_2="2606:4700:4700::1001"
            ;;
		4) # OpenDNS
			CLIENT_DNS_1="208.67.222.222"
			CLIENT_DNS_2="208.67.220.220"
			CLIENT_DNS_IPV6_1="2620:119:35::35"
			CLIENT_DNS_IPV6_2="2620:119:53::53"
			;;
		5) # AdGuard DNS
			CLIENT_DNS_1="94.140.14.14"
			CLIENT_DNS_2="94.140.15.15"
			CLIENT_DNS_IPV6_1="2a10:50c0::ad1:ff"
			CLIENT_DNS_IPV6_2="2a10:50c0::ad2:ff"
			;;
		6) # Custom
			read -rp "Primary DNS IPv4: " -e CLIENT_DNS_1
			read -rp "Secondary DNS IPv4 (optional): " -e CLIENT_DNS_2
			if [[ ${ENABLE_IPV6} == 'y' ]]; then
				read -rp "Primary DNS IPv6 (optional): " -e CLIENT_DNS_IPV6_1
				read -rp "Secondary DNS IPv6 (optional): " -e CLIENT_DNS_IPV6_2
			else
                CLIENT_DNS_IPV6_1=""
                CLIENT_DNS_IPV6_2=""
            fi
			# Basic validation
            if [[ -z "$CLIENT_DNS_1" ]]; then
                echo -e "${RED}Primary DNS cannot be empty. Defaulting to Cloudflare.${NC}";
                CLIENT_DNS_1="1.1.1.1"; CLIENT_DNS_2="1.0.0.1"; CLIENT_DNS_IPV6_1="2606:4700:4700::1111"; CLIENT_DNS_IPV6_2="2606:4700:4700::1001"
            fi
			;;
	esac
     # Clear IPv6 DNS if IPv6 is disabled overall
    if [[ "$ENABLE_IPV6" != "y" ]]; then
        CLIENT_DNS_IPV6_1=""
        CLIENT_DNS_IPV6_2=""
    fi
    echo ""

    # AmneziaWG advanced settings (using defaults)
	setDefaultAmneziaSettings # Sets JC, JMIN, JMAX, S1, S2, H1-4, MTU globally

	echo -e "${GREEN}Configuration complete. Ready to install AmneziaWG.${NC}"
	echo -e "${GREEN}You will be able to generate a client config at the end.${NC}"
    echo ""
	read -n1 -r -p "Press any key to start the installation..."
	echo ""
}

function installAmneziaWGRHEL() {
    echo -e "${GREEN}Installing AmneziaWG for RHEL-based systems...${NC}"
    local pkg_manager="yum"
    if command -v dnf &>/dev/null; then pkg_manager="dnf"; fi

    # Ensure EPEL is installed (might have been done in checkOS)
    if ! rpm -q epel-release &>/dev/null; then
        echo -e "${GREEN}Installing EPEL repository...${NC}"
        $pkg_manager install -y epel-release || echo -e "${ORANGE}EPEL installation failed. Dependencies might be missing.${NC}"
    fi

    # Remove existing WireGuard tools (AmneziaWG provides its own 'awg')
    echo -e "${GREEN}Removing standard wireguard-tools if present...${NC}"
    $pkg_manager remove -y wireguard-tools > /dev/null 2>&1

    # Add AmneziaWG repo
    echo -e "${GREEN}Adding Amnezia repository...${NC}"
    cat > /etc/yum.repos.d/amnezia.repo << 'EOF'
[amnezia]
name=Amnezia Repository
baseurl=https://rpm.amnezia.org/stable/
enabled=1
gpgcheck=0
EOF

    # Install necessary build tools and kernel headers
    echo -e "${GREEN}Installing kernel headers and development tools...${NC}"
    # Required for DKMS module build
    $pkg_manager install -y kernel-devel-$(uname -r) kernel-headers-$(uname -r) make gcc dkms || {
        echo -e "${RED}Failed to install kernel headers or development tools.${NC}"
        echo -e "${RED}Please install them manually and try again.${NC}"
        echo -e "${RED}Example: ${pkg_manager} install kernel-devel-$(uname -r) make gcc dkms${NC}"
        exit 1
    }


    # Install AmneziaWG
    echo -e "${GREEN}Installing AmneziaWG package...${NC}"
    if $pkg_manager install -y amneziawg; then
         echo -e "${GREEN}AmneziaWG installed successfully.${NC}"
    else
         echo -e "${RED}Failed to install amneziawg package from repository.${NC}"
         exit 1
    fi
}

function setupServer() {
  print_header "Setting Up AmneziaWG Server"

  # --- 1. Ensure config directory exists ---
  mkdir -p "${AWG_CONF_DIR}"
  chmod 700 "${AWG_CONF_DIR}"

  # --- 2. Generate server keys ---
  echo -e "${GREEN}Generating AmneziaWG server keys...${NC}"
  SERVER_PRIV_KEY=$(awg genkey)
  SERVER_PUB_KEY=$(echo "${SERVER_PRIV_KEY}" | awg pubkey)
  if [[ -z "$SERVER_PRIV_KEY" || -z "$SERVER_PUB_KEY" ]]; then
      echo -e "${RED}Failed to generate server keys. Is 'awg' command working?${NC}"
      exit 1
  fi
  echo -e "${GREEN}Server keys generated.${NC}"

  # --- 3. Load ALLOWED_IPS from default file ---
  # This should have been created by installQuestions or configureAllowedIPs
  local allowed_ips_file="${AWG_CONF_DIR}/default_routing"
  if [ -f "$allowed_ips_file" ]; then
    ALLOWED_IPS=$(cat "$allowed_ips_file")
    echo -e "${GREEN}Using default routing from ${allowed_ips_file}: ${ALLOWED_IPS}${NC}"
  else
    echo -e "${ORANGE}Default routing file ${allowed_ips_file} not found. Using '0.0.0.0/0,::/0' (if IPv6 enabled).${NC}"
    ALLOWED_IPS="0.0.0.0/0"
    [[ "$ENABLE_IPV6" == "y" ]] && ALLOWED_IPS="${ALLOWED_IPS},::/0"
  fi

  # --- 4. Create server params file (IPs without CIDR) ---
  echo -e "${GREEN}Saving configuration parameters to ${PARAMS_FILE}...${NC}"
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

  # --- 5. Enable IP forwarding ---
  echo -e "${GREEN}Enabling IP forwarding...${NC}"
  local sysctl_conf="/etc/sysctl.d/99-amneziawg-forward.conf"
  echo "net.ipv4.ip_forward = 1" > "${sysctl_conf}"
  if [[ ${ENABLE_IPV6} == 'y' ]]; then
    echo "net.ipv6.conf.all.forwarding = 1" >> "${sysctl_conf}"
  fi
  # Apply sysctl settings
  sysctl --system

  # --- 6. Configure the server interface (Add CIDR back here) ---
  local interface_config_file="${AWG_CONF_DIR}/${SERVER_WG_NIC}.conf"
  echo -e "${GREEN}Creating server interface configuration: ${interface_config_file}...${NC}"
  cat > "${interface_config_file}" <<EOF
[Interface]
Address = ${SERVER_WG_IPV4}/24$( [[ ${ENABLE_IPV6} == 'y' && -n "${SERVER_WG_IPV6}" ]] && echo ",${SERVER_WG_IPV6}/64" )
ListenPort = ${SERVER_PORT}
PrivateKey = ${SERVER_PRIV_KEY}
# AmneziaWG Obfuscation Params
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

  # --- 7. Configure Firewall Rules ---
  echo -e "${GREEN}Configuring firewall rules...${NC}"
  local ip_v4_base="${SERVER_WG_IPV4%.*}" # Get e.g., 10.0.0 from 10.0.0.1
  # Append PostUp/PostDown rules based on firewall type
  if command -v firewall-cmd &> /dev/null && pgrep firewalld; then
    echo -e "${GREEN}Using firewall-cmd.${NC}"
    local FIREWALLD_IPV4_ADDRESS="${ip_v4_base}.0" # Get subnet like 10.0.0.0
    cat >> "${interface_config_file}" <<EOF
PostUp = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC}
PostUp = firewall-cmd --add-port ${SERVER_PORT}/udp
PostUp = firewall-cmd --add-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade'
PostDown = firewall-cmd --zone=public --remove-interface=${SERVER_WG_NIC}
PostDown = firewall-cmd --remove-port ${SERVER_PORT}/udp
PostDown = firewall-cmd --remove-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade'
EOF
    if [[ ${ENABLE_IPV6} == 'y' && -n "${SERVER_WG_IPV6}" ]]; then
      local FIREWALLD_IPV6_ADDRESS=$(echo "${SERVER_WG_IPV6}" | sed 's/:[^:]*$/::/')"/64" # Get subnet like fd42:42:42::/64
      cat >> "${interface_config_file}" <<EOF
PostUp = firewall-cmd --add-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS} masquerade'
PostDown = firewall-cmd --remove-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS} masquerade'
EOF
    fi
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
  else
      echo -e "${ORANGE}Warning: No firewall detected (firewalld or iptables). Firewall rules not added.${NC}"
      echo -e "${ORANGE}You may need to configure firewall rules manually for UDP port ${SERVER_PORT} and NAT/Forwarding.${NC}"
  fi

  # --- 8. Enable and start AmneziaWG service ---
  echo -e "${GREEN}Enabling and starting AmneziaWG service (awg-quick@${SERVER_WG_NIC})...${NC}"
  systemctl enable "awg-quick@${SERVER_WG_NIC}"
  # Use restart to ensure it applies new config even if somehow running
  systemctl restart "awg-quick@${SERVER_WG_NIC}"

  # --- 9. Verify service status ---
  sleep 2 # Give service a moment to start
  if systemctl is-active --quiet "awg-quick@${SERVER_WG_NIC}"; then
    echo -e "${GREEN}AmneziaWG service is running.${NC}"
  else
    echo -e "${RED}AmneziaWG service failed to start.${NC}"
    echo -e "${RED}Check logs: journalctl -u awg-quick@${SERVER_WG_NIC}${NC}"
    echo -e "${RED}Also check config: ${AWG_CONF_DIR}/${SERVER_WG_NIC}.conf${NC}"
    # Don't exit, user might fix it and want to add a client
  fi

  # --- 10. Add Initial Client ---
  echo ""
  read -rp "Do you want to add an initial client now? [y/n]: " -e -i "y" add_client_now
  if [[ ${add_client_now,,} == "y" ]]; then
     newClient # Call function to add a client
  else
     echo -e "${GREEN}You can add clients later using this script.${NC}"
  fi

  # --- 11. Completion message ---
  print_header "AmneziaWG Installation Complete"
  echo -e "${GREEN}Server configuration: ${interface_config_file}${NC}"
  echo -e "${GREEN}Server parameters: ${PARAMS_FILE}${NC}"
  echo -e "${GREEN}Run this script again to manage clients or settings.${NC}"
  echo ""
}

function installAmneziaWG() {
    # Start with configuration questions
    installQuestions

    print_header "Starting AmneziaWG Installation"

    # --- Install Dependencies ---
    echo -e "${GREEN}Installing dependencies...${NC}"
    local kernel_headers_pkg=""
    if [[ ${OS} == "ubuntu" || ${OS} == "debian" ]]; then
        # Enable deb-src if needed
        setupDebSrc
        apt-get update

        # Determine correct headers package name
        kernel_headers_pkg="linux-headers-$(uname -r)"
        # Check if the package exists, fallback if needed
        if ! apt-cache show "${kernel_headers_pkg}" > /dev/null 2>&1; then
            echo -e "${ORANGE}Warning: Package ${kernel_headers_pkg} not found. Trying generic headers.${NC}"
            # Try generic headers for the major version (e.g., linux-headers-generic on Ubuntu)
            kernel_headers_pkg="linux-headers-generic"
            if ! apt-cache show "${kernel_headers_pkg}" > /dev/null 2>&1; then
                 # Another common pattern, especially on Debian derivatives
                 kernel_headers_pkg="linux-headers-$(echo "$(uname -r)" | cut -d'-' -f3-)" # e.g. linux-headers-amd64
                 if ! apt-cache show "${kernel_headers_pkg}" > /dev/null 2>&1; then
                    echo -e "${RED}Error: Cannot find suitable linux-headers package.${NC}"
                    echo -e "${RED}Please install kernel headers for $(uname -r) manually and retry.${NC}"
                    exit 1
                 fi
            fi
        fi
        # Install base dependencies + specific headers
        apt-get install -y software-properties-common python3-launchpadlib gnupg "${kernel_headers_pkg}" make dkms qrencode || {
             echo -e "${RED}Failed to install dependencies via apt-get.${NC}"; exit 1;
        }

        # Add Amnezia PPA
        echo -e "${GREEN}Adding Amnezia PPA repository...${NC}"
        # Check if add-apt-repository is available
        if ! command -v add-apt-repository &> /dev/null; then
             echo -e "${ORANGE}add-apt-repository command not found. Installing software-properties-common.${NC}"
             apt-get install -y software-properties-common
        fi
        # Handle potential GPG key issues more gracefully
        add-apt-repository -y ppa:amnezia/ppa || {
             echo -e "${RED}Failed to add Amnezia PPA directly. Trying manual GPG key import...${NC}"
             # Attempt manual key import (adjust key ID/URL if needed based on PPA)
             gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys E45A7054 && \
             gpg --export --armor E45A7054 | sudo apt-key add - && \
             add-apt-repository -y ppa:amnezia/ppa && \
             echo -e "${GREEN}Manual GPG key import successful.${NC}" || \
             { echo -e "${RED}Failed to add Amnezia PPA even after manual GPG key attempt.${NC}"; exit 1; }
        }
        apt-get update

        # Install AmneziaWG
        echo -e "${GREEN}Installing AmneziaWG package...${NC}"
        apt-get install -y amneziawg || { echo -e "${RED}Failed to install amneziawg package.${NC}"; exit 1; }

    elif [[ ${OS} == "rhel" ]]; then
        # RHEL install function handles repo, headers, and amneziawg install
        installAmneziaWGRHEL
        # Install qrencode separately if needed
        if ! command -v qrencode &>/dev/null; then
            yum install -y qrencode || dnf install -y qrencode || echo -e "${ORANGE}qrencode package not found, QR codes will be unavailable.${NC}"
        fi
    fi

    # Run server setup (generates keys, configs, starts service)
    setupServer
}

# --- Client Management Functions ---

function newClient() {
    print_header "Add New AmneziaWG Client"

    # Source current server settings
    if [[ -f "${PARAMS_FILE}" ]]; then
        source "${PARAMS_FILE}"
    else
        echo -e "${RED}Server parameters file not found: ${PARAMS_FILE}${NC}"
        echo -e "${RED}Cannot add client without server configuration.${NC}"
        return 1
    fi

    local client_name=""
    echo "Enter a name for the new client."
    echo "Use only alphanumeric characters, underscores, or dashes."
    echo ""
    while true; do
        read -rp "Client name: " -e client_name
        if [[ "${client_name}" =~ ^[a-zA-Z0-9_-]+$ ]]; then
            # Check if client already exists
            if grep -q "^### Client ${client_name}$" "${AWG_CONF_DIR}/${SERVER_WG_NIC}.conf"; then
                echo -e "${ORANGE}Client '${client_name}' already exists.${NC}"
                read -rp "Do you want to overwrite (regenerate keys for) this client? [y/n]: " -e -i "n" overwrite_choice
                if [[ ${overwrite_choice,,} == "y" ]]; then
                    regenerateClientConfig "${client_name}" # Call regenerate function
                    return $? # Return status of regeneration
                else
                    client_name="" # Clear name to re-prompt
                    echo "Please choose a different name."
                fi
            else
                break # Name is valid and unique
            fi
        else
            echo "Invalid name. Please use only letters, numbers, underscores, or dashes."
        fi
    done

    # Generate client key pair
    local client_priv_key=""
    local client_pub_key=""
    local client_psk=""
    client_priv_key=$(awg genkey)
	client_pub_key=$(echo "${client_priv_key}" | awg pubkey)
	client_psk=$(awg genpsk) # Preshared key for extra security

    # Determine client's VPN IP address
    # Find the highest existing IP index and add 1
    local last_ip_part=1 # Start at .1 (server)
    # Extract last octet/part from existing client AllowedIPs in server config
    # Make sure to match only IPs in the expected subnet base
    local ip_v4_base="${SERVER_WG_IPV4%.*}" # Get e.g., 10.0.0 from 10.0.0.1
    local existing_ips=$(grep -oP "AllowedIPs *= *\K${ip_v4_base}\.[0-9]+(?=/)" "${AWG_CONF_DIR}/${SERVER_WG_NIC}.conf")
    if [[ -n "$existing_ips" ]]; then
        while IFS= read -r ip; do
            local current_last_part=$(echo "$ip" | cut -d'.' -f4)
            if [[ "$current_last_part" -gt "$last_ip_part" ]]; then
                last_ip_part=$current_last_part
            fi
        done <<< "$existing_ips"
    fi
    local next_ip_index=$((last_ip_part + 1))

    local client_wg_ipv4="${ip_v4_base}.${next_ip_index}"
    local client_wg_ipv6=""
    if [[ ${ENABLE_IPV6} == 'y' && -n "${SERVER_WG_IPV6}" ]]; then
        # Construct IPv6 address, e.g., fd42:42:42::2
        # More robustly handle existing indices if they don't start at ::1
        local ipv6_base=$(echo "${SERVER_WG_IPV6}" | sed 's/::.*//') # Get base like fd42:42:42
        # Find highest existing index for IPv6
        local last_ipv6_part=1
        local existing_ipv6s=$(grep -oP "AllowedIPs *=.*\K${ipv6_base}::[0-9a-fA-F]+(?=/)" "${AWG_CONF_DIR}/${SERVER_WG_NIC}.conf")
         if [[ -n "$existing_ipv6s" ]]; then
             while IFS= read -r ip6; do
                 local current_last_part_hex=$(echo "$ip6" | sed 's/.*:://') # Get hex index
                 local current_last_part_dec=$((16#${current_last_part_hex})) # Convert hex to decimal
                 if [[ "$current_last_part_dec" -gt "$last_ipv6_part" ]]; then
                     last_ipv6_part=$current_last_part_dec
                 fi
             done <<< "$existing_ipv6s"
         fi
        local next_ipv6_index_dec=$((last_ipv6_part + 1))
        # Convert back to hex if needed, or just use decimal for simplicity if supported
        client_wg_ipv6="${ipv6_base}::${next_ipv6_index_dec}" # Use decimal index directly
    fi

    # Client config directory
    local home_dir=""
    home_dir=$(getHomeDirForClient "${SUDO_USER:-root}")
    local client_config_dir="${home_dir}/amneziawg"
    mkdir -p "${client_config_dir}"
    chmod 700 "${client_config_dir}"

    # Create client config file
    local client_conf_path="${client_config_dir}/${SERVER_WG_NIC}-${client_name}.conf"
    echo -e "${GREEN}Generating client configuration: ${client_conf_path}${NC}"
    cat > "${client_conf_path}" <<EOF
[Interface]
# Client: ${client_name}
PrivateKey = ${client_priv_key}
Address = ${client_wg_ipv4}/32$( [[ -n "${client_wg_ipv6}" ]] && echo ",${client_wg_ipv6}/128" )
DNS = ${CLIENT_DNS_1}${CLIENT_DNS_2:+,${CLIENT_DNS_2}}${CLIENT_DNS_IPV6_1:+,${CLIENT_DNS_IPV6_1}}${CLIENT_DNS_IPV6_2:+,${CLIENT_DNS_IPV6_2}}
# AmneziaWG Obfuscation Params (match server)
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
# Server: ${SERVER_WG_NIC}
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${client_psk}
Endpoint = ${SERVER_PUB_IP}:${SERVER_PORT}
# AllowedIPs for client routing (use server default)
AllowedIPs = ${ALLOWED_IPS}
EOF
    chmod 600 "${client_conf_path}"

    # Add Peer to Server Configuration
    echo -e "${GREEN}Adding peer to server configuration...${NC}"
    cat >> "${AWG_CONF_DIR}/${SERVER_WG_NIC}.conf" <<EOF

### Client ${client_name}
[Peer]
PublicKey = ${client_pub_key}
PresharedKey = ${client_psk}
AllowedIPs = ${client_wg_ipv4}/32$( [[ -n "${client_wg_ipv6}" ]] && echo ",${client_wg_ipv6}/128" )
EOF

    # Apply the updated server configuration live
    # Use syncconf for adding peers without full restart
    if ! awg syncconf "${SERVER_WG_NIC}" <(wg-quick strip "${SERVER_WG_NIC}"); then
        echo -e "${RED}Failed to apply updated configuration using 'awg syncconf'.${NC}"
        echo -e "${ORANGE}A server restart might be needed: systemctl restart awg-quick@${SERVER_WG_NIC}${NC}"
    else
        echo -e "${GREEN}Server configuration updated live.${NC}"
    fi

    # Display QR code if qrencode is available
    echo ""
    if command -v qrencode &>/dev/null; then
        echo -e "${GREEN}Scan this QR code with the AmneziaWG mobile app:${NC}"
        qrencode -t ansiutf8 < "${client_conf_path}"
        echo ""
    else
        echo -e "${ORANGE}qrencode command not found. Cannot display QR code.${NC}"
        echo -e "${ORANGE}Install 'qrencode' package to enable QR codes.${NC}"
    fi

    echo -e "${GREEN}Client '${client_name}' added successfully.${NC}"
    echo -e "Configuration file: ${client_conf_path}"
    echo ""
}

function listClients() {
    print_header "List Existing Clients"

    # Source params if needed to ensure SERVER_WG_NIC is set
    if [[ -z "${SERVER_WG_NIC}" && -f "${PARAMS_FILE}" ]]; then
       source "${PARAMS_FILE}"
    fi
    local server_conf_file="${AWG_CONF_DIR}/${SERVER_WG_NIC}.conf"
    if [[ ! -f "${server_conf_file}" ]]; then
        echo -e "${RED}Server configuration file not found: ${server_conf_file}${NC}"
		return 1
	fi

    # Extract client names from comments
    local clients=$(grep -E "^### Client" "${server_conf_file}" | cut -d ' ' -f 3-) # Get full name even with spaces

    if [[ -z "$clients" ]]; then
        echo -e "${ORANGE}No clients found in the configuration.${NC}"
        return 1 # Indicate no clients found
    fi

    echo "Configured Clients for interface '${SERVER_WG_NIC}':"
    echo "──────────────────────────────────────────"
    printf "%-30s %-20s\n" "Client Name" "VPN IP Address(es)"
    echo "──────────────────────────────────────────"

    local i=1
    while IFS= read -r client_name; do
        # Extract AllowedIPs for this specific client
        # Use awk to find the block for the client and get AllowedIPs
        local client_ips=$(awk -v name="${client_name}" '
            BEGIN { RS = "" ; FS = "\n" } # Process paragraph mode
            $1 == "### Client " name {
                for (i=1; i<=NF; i++) {
                    if ($i ~ /AllowedIPs *=/) {
                        sub(/AllowedIPs *= */, "", $i)
                        print $i
                        exit
                    }
                }
            }
        ' "${server_conf_file}")

        # Pad or truncate the client name
        printf "%2d) %-27s %-20s\n" "$i" "${client_name}" "${client_ips:-Not Found}"
        ((i++))
    done <<< "$clients"
    echo "──────────────────────────────────────────"
    echo ""

    # Find location of client config files
    local home_dir=""
    home_dir=$(getHomeDirForClient "${SUDO_USER:-root}")
    local client_config_dir="${home_dir}/amneziawg"

    echo -e "Client configuration files are typically stored in: ${client_config_dir}"
    echo ""
    return 0 # Indicate success
}

function revokeClient() {
    print_header "Revoke AmneziaWG Client"

    # Source params if needed
    if [[ -z "${SERVER_WG_NIC}" && -f "${PARAMS_FILE}" ]]; then
       source "${PARAMS_FILE}"
    fi
    local server_conf_file="${AWG_CONF_DIR}/${SERVER_WG_NIC}.conf"
    if [[ ! -f "${server_conf_file}" ]]; then
        echo -e "${RED}Server configuration file not found: ${server_conf_file}${NC}"
		return 1
	fi

    local clients=$(grep -E "^### Client" "${server_conf_file}" | cut -d ' ' -f 3-)

    if [[ -z "$clients" ]]; then
        echo -e "${ORANGE}No clients found to revoke.${NC}"
        return
    fi

    echo "Select the client to revoke:"
    local client_list=()
    local i=1
    while IFS= read -r client; do
        echo "   ${i}) ${client}"
        client_list+=("${client}") # Store names in an array
        ((i++))
    done <<< "$clients"
    local client_count=$((i - 1))

    echo ""
    local client_number=""
    until [[ "${client_number}" =~ ^[1-9][0-9]*$ && ${client_number} -le ${client_count} ]]; do
        read -rp "Enter client number to revoke [1-${client_count}]: " client_number
    done

    local selected_client="${client_list[$((client_number - 1))]}" # Get name from array (0-based index)

    echo ""
    read -rp "Are you sure you want to revoke client '${selected_client}'? [y/n]: " -e -i "n" confirm_revoke
    if [[ ${confirm_revoke,,} != "y" ]]; then
        echo "Revocation cancelled."
        return
    fi

    echo -e "${ORANGE}Revoking access for client: ${selected_client}...${NC}"

    # Backup the config file before modifying
    cp "${server_conf_file}" "${server_conf_file}.bak.$(date +%s)"

    # Remove the client's [Peer] section from the server config
    # Use awk for more robust block removal based on the ### Client comment
    # Use paragraph mode (RS="")
    awk -v name="${selected_client}" '
        BEGIN { RS = ""; FS = "\n"; ORS = "\n\n" } # Process paragraph mode, ensure blank line separator
        !/^### Client / { print; next } # Print non-client blocks
        $1 != "### Client " name { print } # Print client blocks that don't match
    ' "${server_conf_file}" > "${server_conf_file}.tmp"


    if [[ $? -eq 0 ]] && [[ -s "${server_conf_file}.tmp" ]]; then
        # awk in paragraph mode might add extra newlines, clean them up
        grep -v '^$' "${server_conf_file}.tmp" | awk 'BEGIN{ORS="\n"}{print}' > "${server_conf_file}"
        rm "${server_conf_file}.tmp"
        echo -e "${GREEN}Client section removed from server configuration.${NC}"
    else
        echo -e "${RED}Error removing client section from configuration. Restoring backup.${NC}"
        # Restore backup if tmp file failed or is empty
        [[ -f "${server_conf_file}.bak.$(date +%s)" ]] && mv "${server_conf_file}.bak.$(date +%s)" "${server_conf_file}"
        rm -f "${server_conf_file}.tmp"
        return 1
    fi

    # Delete the client's configuration file
    local home_dir=""
    home_dir=$(getHomeDirForClient "${SUDO_USER:-root}")
    local client_config_dir="${home_dir}/amneziawg"
    # Sanitize client name for filename (replace spaces/special chars if needed, though validator should prevent them)
    local safe_client_name=$(echo "${selected_client}" | sed 's/[^a-zA-Z0-9_-]/_/g')
    local client_conf_path="${client_config_dir}/${SERVER_WG_NIC}-${safe_client_name}.conf"

    if [[ -f "${client_conf_path}" ]]; then
        echo -e "${GREEN}Deleting client configuration file: ${client_conf_path}${NC}"
        rm -f "${client_conf_path}"
    else
         echo -e "${ORANGE}Client configuration file not found or already deleted: ${client_conf_path}${NC}"
    fi

    # Apply the updated server configuration live
    echo -e "${GREEN}Applying updated server configuration...${NC}"
    if ! awg syncconf "${SERVER_WG_NIC}" <(wg-quick strip "${SERVER_WG_NIC}"); then
        echo -e "${RED}Failed to apply updated configuration using 'awg syncconf'.${NC}"
        echo -e "${ORANGE}A server restart might be needed: systemctl restart awg-quick@${SERVER_WG_NIC}${NC}"
    else
        echo -e "${GREEN}Server configuration updated live.${NC}"
    fi

    echo -e "${GREEN}Client '${selected_client}' revoked successfully!${NC}"
    echo ""
}

function regenerateClientConfig() {
    local client_name="$1"
    print_header "Regenerate Client Configuration"
    echo -e "${GREEN}Regenerating configuration for client: ${client_name}${NC}"

    # Source params if needed
    if [[ -z "${SERVER_WG_NIC}" && -f "${PARAMS_FILE}" ]]; then
       source "${PARAMS_FILE}"
    elif [[ ! -f "${PARAMS_FILE}" ]]; then
         echo -e "${RED}Server parameters file not found: ${PARAMS_FILE}${NC}"
        return 1
    fi
    local server_conf_file="${AWG_CONF_DIR}/${SERVER_WG_NIC}.conf"
    if [[ ! -f "${server_conf_file}" ]]; then
        echo -e "${RED}Server configuration file not found: ${server_conf_file}${NC}"
        return 1
    fi

    # Check if client exists
    if ! grep -q "^### Client ${client_name}" "${server_conf_file}"; then
        echo -e "${RED}Client '${client_name}' not found.${NC}"
        return 1
    fi

    # Extract client's existing VPN IP addresses from server config
    local client_ips=$(awk -v name="${client_name}" '
        BEGIN { RS = "" ; FS = "\n" }
        $1 == "### Client " name {
            for (i=1; i<=NF; i++) {
                if ($i ~ /AllowedIPs *=/) {
                    sub(/AllowedIPs *= */, "", $i)
                    print $i
                    exit
                }
            }
        }
    ' "${server_conf_file}")

    if [[ -z "$client_ips" ]]; then
         echo -e "${RED}Could not find AllowedIPs for client '${client_name}' in server config.${NC}"
         return 1
    fi
    local client_wg_ipv4=$(echo "$client_ips" | tr ',' '\n' | grep -oP '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1) # No CIDR needed here
    local client_wg_ipv6=$(echo "$client_ips" | tr ',' '\n' | grep -oP '^[a-fA-F0-9:]+' | grep ':' | head -1 | sed 's|/.*||') # No CIDR needed here

    # Extract existing PresharedKey from server config
    local client_psk=$(awk -v name="${client_name}" '
        BEGIN { RS = "" ; FS = "\n" }
        $1 == "### Client " name {
            for (i=1; i<=NF; i++) {
                if ($i ~ /PresharedKey *=/) {
                    sub(/PresharedKey *= */, "", $i)
                    print $i
                    exit
                }
            }
        }
    ' "${server_conf_file}")

    # Generate NEW keys for the client
    local client_priv_key=""
    local client_pub_key=""
    client_priv_key=$(awg genkey)
    client_pub_key=$(echo "${client_priv_key}" | awg pubkey)

    if [[ -z "$client_priv_key" || -z "$client_pub_key" ]]; then
        echo -e "${RED}Failed to generate new keys for client.${NC}"
        return 1
    fi

    # --- Update Server Config ---
    echo -e "${GREEN}Updating server configuration with new client public key...${NC}"
    # Use awk to replace PublicKey for the specific client (paragraph mode)
    awk -v name="${client_name}" -v new_pub_key="${client_pub_key}" '
        BEGIN { RS = ""; FS = "\n"; ORS = "\n\n" }
        $1 == "### Client " name {
            for (i=1; i<=NF; i++) {
                if ($i ~ /^PublicKey *=/) {
                    $i = "PublicKey = " new_pub_key # Replace line
                }
            }
        }
        { print } # Print the (potentially modified) block or other blocks
    ' "${server_conf_file}" > "${server_conf_file}.tmp"

    if [[ $? -eq 0 ]] && [[ -s "${server_conf_file}.tmp" ]]; then
        # Clean up extra newlines from awk processing
        grep -v '^$' "${server_conf_file}.tmp" | awk 'BEGIN{ORS="\n"}{print}' > "${server_conf_file}"
        rm "${server_conf_file}.tmp"
    else
        echo -e "${RED}Error updating server configuration with new public key.${NC}"
        rm -f "${server_conf_file}.tmp"
        return 1
    fi

    # --- Create New Client Config File ---
    local home_dir=""
    home_dir=$(getHomeDirForClient "${SUDO_USER:-root}")
    local client_config_dir="${home_dir}/amneziawg"
    mkdir -p "${client_config_dir}"
    chmod 700 "${client_config_dir}"
    local safe_client_name=$(echo "${client_name}" | sed 's/[^a-zA-Z0-9_-]/_/g')
    local client_conf_path="${client_config_dir}/${SERVER_WG_NIC}-${safe_client_name}.conf"

    echo -e "${GREEN}Generating new client configuration file: ${client_conf_path}${NC}"
    cat > "${client_conf_path}" <<EOF
[Interface]
# Client: ${client_name} (Regenerated $(date))
PrivateKey = ${client_priv_key}
Address = ${client_wg_ipv4}/32$( [[ -n "${client_wg_ipv6}" ]] && echo ",${client_wg_ipv6}/128" )
DNS = ${CLIENT_DNS_1}${CLIENT_DNS_2:+,${CLIENT_DNS_2}}${CLIENT_DNS_IPV6_1:+,${CLIENT_DNS_IPV6_1}}${CLIENT_DNS_IPV6_2:+,${CLIENT_DNS_IPV6_2}}
# AmneziaWG Obfuscation Params (match server)
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
# Server: ${SERVER_WG_NIC}
PublicKey = ${SERVER_PUB_KEY}
$( [[ -n "${client_psk}" ]] && echo "PresharedKey = ${client_psk}" ) # Keep existing PSK
Endpoint = ${SERVER_PUB_IP}:${SERVER_PORT}
AllowedIPs = ${ALLOWED_IPS} # Use current server default AllowedIPs
EOF
    chmod 600 "${client_conf_path}"

    # --- Apply Changes Live ---
    echo -e "${GREEN}Applying updated server configuration...${NC}"
    if ! awg syncconf "${SERVER_WG_NIC}" <(wg-quick strip "${SERVER_WG_NIC}"); then
        echo -e "${RED}Failed to apply updated configuration using 'awg syncconf'.${NC}"
        echo -e "${ORANGE}A server restart might be needed: systemctl restart awg-quick@${SERVER_WG_NIC}${NC}"
    else
        echo -e "${GREEN}Server configuration updated live.${NC}"
    fi

    echo ""
    # Display QR code if qrencode is available
    if command -v qrencode &>/dev/null; then
        echo -e "${GREEN}Scan this QR code with the AmneziaWG mobile app:${NC}"
        qrencode -t ansiutf8 < "${client_conf_path}"
        echo ""
    fi

    echo -e "${GREEN}Client '${client_name}' configuration regenerated successfully!${NC}"
    echo -e "New configuration file: ${client_conf_path}"
    echo ""
    return 0
}

function regenerateAllClientConfigs() {
    print_header "Regenerate All Client Configurations"
    echo -e "${ORANGE}This will generate NEW keys and config files for ALL clients.${NC}"
    echo -e "${ORANGE}You MUST distribute these new files to your clients.${NC}"
    read -rp "Are you sure you want to proceed? [y/n]: " -e -i "n" confirm_regen_all
    if [[ ${confirm_regen_all,,} != "y" ]]; then
        echo "Operation cancelled."
        return
    fi

    # Source params if needed
    if [[ -z "${SERVER_WG_NIC}" && -f "${PARAMS_FILE}" ]]; then
       source "${PARAMS_FILE}"
    fi
    local server_conf_file="${AWG_CONF_DIR}/${SERVER_WG_NIC}.conf"
    if [[ ! -f "${server_conf_file}" ]]; then
        echo -e "${RED}Server configuration file not found: ${server_conf_file}${NC}"
        return 1
    fi

    # Get list of clients
    local clients=$(grep -E "^### Client" "${server_conf_file}" | cut -d ' ' -f 3-)

    if [[ -z "$clients" ]]; then
        echo -e "${ORANGE}No clients found to regenerate.${NC}"
        return
    fi

    echo -e "${GREEN}Starting regeneration process...${NC}"
    local success_count=0
    local fail_count=0
    # Iterate through each client name
    while IFS= read -r client_name; do
        if regenerateClientConfig "${client_name}"; then
             ((success_count++))
        else
             ((fail_count++))
             echo -e "${RED}Failed to regenerate config for client: ${client_name}${NC}"
        fi
        echo "-----------------------------------------"
        sleep 1 # Small delay between clients
    done <<< "$clients"

    echo ""
    print_header "Regeneration Summary"
    echo -e "${GREEN}Successfully regenerated: ${success_count} client(s)${NC}"
    if [[ $fail_count -gt 0 ]]; then
        echo -e "${RED}Failed to regenerate: ${fail_count} client(s)${NC}"
    fi
    local home_dir=$(getHomeDirForClient "${SUDO_USER:-root}")
    local client_config_dir="${home_dir}/amneziawg"
    echo -e "${GREEN}New configuration files are available in ${client_config_dir}${NC}"
    echo ""
}

# --- Settings Management Functions ---

function setDefaultAmneziaSettings() {
    # Sets global vars for Mobile Preset
    JC=4
    JMIN=40
    JMAX=70
    S1=50
    S2=100
    # Generate random magic headers if not already set (e.g., during first install)
    # Keep existing random headers if function is called again (e.g. during migration)
    H1=${H1:-$((RANDOM % 32767 * 1000 + RANDOM % 1000 + 10000))}
    H2=${H2:-$((RANDOM % 32767 * 1000 + RANDOM % 1000 + 20000))}
    H3=${H3:-$((RANDOM % 32767 * 1000 + RANDOM % 1000 + 30000))}
    H4=${H4:-$((RANDOM % 32767 * 1000 + RANDOM % 1000 + 40000))}
    MTU=1280
    # Ensure uniqueness (simple check)
    while [[ ${H1} -eq ${H2} || ${H1} -eq ${H3} || ${H1} -eq ${H4} || ${H2} -eq ${H3} || ${H2} -eq ${H4} || ${H3} -eq ${H4} || ${H1} -lt 5 || ${H2} -lt 5 || ${H3} -lt 5 || ${H4} -lt 5 ]]; do
        echo -e "${ORANGE}Regenerating default magic headers to ensure uniqueness and minimum value...${NC}"
        H1=$((RANDOM % 32767 * 1000 + RANDOM % 1000 + 10000)); H2=$((RANDOM % 32767 * 1000 + RANDOM % 1000 + 20000)); H3=$((RANDOM % 32767 * 1000 + RANDOM % 1000 + 30000)); H4=$((RANDOM % 32767 * 1000 + RANDOM % 1000 + 40000))
    done
}

function configureObfuscationSettings() {
    print_header "Configure Obfuscation Settings"

    # Load current settings from params file
    if [[ -f "${PARAMS_FILE}" ]]; then
        source "${PARAMS_FILE}"
    else
        echo -e "${RED}Parameters file not found: ${PARAMS_FILE}${NC}"
        echo -e "${RED}Cannot configure settings.${NC}"
        return 1
    fi

    # Store original settings for comparison
    local orig_JC="${JC}" orig_JMIN="${JMIN}" orig_JMAX="${JMAX}"
    local orig_S1="${S1}" orig_S2="${S2}"
    local orig_H1="${H1}" orig_H2="${H2}" orig_H3="${H3}" orig_H4="${H4}"
    local orig_MTU="${MTU}"

    echo "These settings control AmneziaWG traffic obfuscation."
    echo -e "${ORANGE}Higher values might increase overhead but improve bypass capabilities.${NC}"
    echo ""
    echo -e "${GREEN}Current Settings:${NC}"
    printf "  %-25s: %s\n" "Junk coefficient (Jc)" "${JC}"
    printf "  %-25s: %s\n" "Min junk packet size (Jmin)" "${JMIN}"
    printf "  %-25s: %s\n" "Max junk packet size (Jmax)" "${JMAX}"
    printf "  %-25s: %s\n" "Init packet junk size (S1)" "${S1}"
    printf "  %-25s: %s\n" "Response packet junk size (S2)" "${S2}"
    printf "  %-25s: %s\n" "Magic Header 1 (H1)" "${H1}"
    printf "  %-25s: %s\n" "Magic Header 2 (H2)" "${H2}"
    printf "  %-25s: %s\n" "Magic Header 3 (H3)" "${H3}"
    printf "  %-25s: %s\n" "Magic Header 4 (H4)" "${H4}"
    printf "  %-25s: %s\n" "MTU" "${MTU}"
    echo ""

    # --- User Input ---
    echo "Select obfuscation preset or customize:"
    echo "   1) Mobile (Recommended Default: Balance performance & obfuscation)"
    echo "   2) Standard (Higher obfuscation, potentially more overhead)"
    echo "   3) Custom settings"
    echo "   4) Back (Discard changes)"
    local preset_choice=""
    until [[ "${preset_choice}" =~ ^[1-4]$ ]]; do
        read -rp "Select an option [1-4]: " -e -i "1" preset_choice
    done

    local new_JC="${JC}" new_JMIN="${JMIN}" new_JMAX="${JMAX}"
    local new_S1="${S1}" new_S2="${S2}"
    local new_H1="${H1}" new_H2="${H2}" new_H3="${H3}" new_H4="${H4}"
    local new_MTU="${MTU}"

    case "${preset_choice}" in
    1) # Mobile Preset
        new_JC=4; new_JMIN=40; new_JMAX=70; new_S1=50; new_S2=100; new_MTU=1280
        # Generate new random headers for preset change
        new_H1=$((RANDOM % 32767 * 1000 + RANDOM % 1000 + 10000)); new_H2=$((RANDOM % 32767 * 1000 + RANDOM % 1000 + 20000))
        new_H3=$((RANDOM % 32767 * 1000 + RANDOM % 1000 + 30000)); new_H4=$((RANDOM % 32767 * 1000 + RANDOM % 1000 + 40000))
        echo -e "${GREEN}Applying Mobile preset with new random magic headers.${NC}"
        ;;
    2) # Standard Preset
        new_JC=2; new_JMIN=100; new_JMAX=200; new_S1=100; new_S2=200; new_MTU=1420
        # Generate new random headers for preset change
        new_H1=$((RANDOM % 32767 * 1000 + RANDOM % 1000 + 10000)); new_H2=$((RANDOM % 32767 * 1000 + RANDOM % 1000 + 20000))
        new_H3=$((RANDOM % 32767 * 1000 + RANDOM % 1000 + 30000)); new_H4=$((RANDOM % 32767 * 1000 + RANDOM % 1000 + 40000))
        echo -e "${GREEN}Applying Standard preset with new random magic headers.${NC}"
        ;;
    3) # Custom Settings
        echo ""
        echo -e "${GREEN}Enter custom obfuscation settings (press Enter to keep current value):${NC}"
        local custom_val=""

        read -rp "Junk coefficient (Jc) [1-10, default ${new_JC}]: " -e custom_val
        new_JC=${custom_val:-$new_JC}
        if ! [[ "${new_JC}" =~ ^[1-9]$|^10$ ]]; then echo -e "${RED}Invalid Jc. Keeping ${orig_JC}.${NC}"; new_JC=$orig_JC; fi

        read -rp "Min junk size (Jmin) [10-500, default ${new_JMIN}]: " -e custom_val
        new_JMIN=${custom_val:-$new_JMIN}
        if ! [[ "${new_JMIN}" =~ ^[1-9][0-9]$|^[1-4][0-9]{2}$|^500$ ]]; then echo -e "${RED}Invalid Jmin. Keeping ${orig_JMIN}.${NC}"; new_JMIN=$orig_JMIN; fi

        read -rp "Max junk size (Jmax) [${new_JMIN}-1000, default ${new_JMAX}]: " -e custom_val
        new_JMAX=${custom_val:-$new_JMAX}
        if ! [[ "${new_JMAX}" =~ ^[0-9]+$ ]] || [[ "${new_JMAX}" -lt "${new_JMIN}" ]] || [[ "${new_JMAX}" -gt 1000 ]]; then echo -e "${RED}Invalid Jmax. Keeping ${orig_JMAX}.${NC}"; new_JMAX=$orig_JMAX; fi

        read -rp "Init packet junk (S1) [10-1280, default ${new_S1}]: " -e custom_val
        new_S1=${custom_val:-$new_S1}
        if ! [[ "${new_S1}" =~ ^[0-9]+$ ]] || [[ "${new_S1}" -lt 10 ]] || [[ "${new_S1}" -gt 1280 ]]; then echo -e "${RED}Invalid S1. Keeping ${orig_S1}.${NC}"; new_S1=$orig_S1; fi

        read -rp "Response packet junk (S2) [10-1280, default ${new_S2}]: " -e custom_val
        new_S2=${custom_val:-$new_S2}
        if ! [[ "${new_S2}" =~ ^[0-9]+$ ]] || [[ "${new_S2}" -lt 10 ]] || [[ "${new_S2}" -gt 1280 ]]; then echo -e "${RED}Invalid S2. Keeping ${orig_S2}.${NC}"; new_S2=$orig_S2; fi

        read -rp "Magic Header 1 (H1) [number > 4, default ${new_H1}]: " -e custom_val
        new_H1=${custom_val:-$new_H1}
        if ! [[ "${new_H1}" =~ ^[0-9]+$ ]] || [[ "${new_H1}" -le 4 ]]; then echo -e "${RED}Invalid H1. Keeping ${orig_H1}.${NC}"; new_H1=$orig_H1; fi

        read -rp "Magic Header 2 (H2) [number > 4, default ${new_H2}]: " -e custom_val
        new_H2=${custom_val:-$new_H2}
        if ! [[ "${new_H2}" =~ ^[0-9]+$ ]] || [[ "${new_H2}" -le 4 ]]; then echo -e "${RED}Invalid H2. Keeping ${orig_H2}.${NC}"; new_H2=$orig_H2; fi

        read -rp "Magic Header 3 (H3) [number > 4, default ${new_H3}]: " -e custom_val
        new_H3=${custom_val:-$new_H3}
        if ! [[ "${new_H3}" =~ ^[0-9]+$ ]] || [[ "${new_H3}" -le 4 ]]; then echo -e "${RED}Invalid H3. Keeping ${orig_H3}.${NC}"; new_H3=$orig_H3; fi

        read -rp "Magic Header 4 (H4) [number > 4, default ${new_H4}]: " -e custom_val
        new_H4=${custom_val:-$new_H4}
        if ! [[ "${new_H4}" =~ ^[0-9]+$ ]] || [[ "${new_H4}" -le 4 ]]; then echo -e "${RED}Invalid H4. Keeping ${orig_H4}.${NC}"; new_H4=$orig_H4; fi

        read -rp "MTU [576-1500, default ${new_MTU}]: " -e custom_val
        new_MTU=${custom_val:-$new_MTU}
        if ! [[ "${new_MTU}" =~ ^[0-9]+$ ]] || [[ "${new_MTU}" -lt 576 ]] || [[ "${new_MTU}" -gt 1500 ]]; then echo -e "${RED}Invalid MTU. Keeping ${orig_MTU}.${NC}"; new_MTU=$orig_MTU; fi
        echo -e "${GREEN}Using custom obfuscation settings.${NC}"
        ;;
    4)
        echo -e "${GREEN}No changes made to obfuscation settings.${NC}"
        return 0 # Exit function without applying changes
        ;;
    esac

    # Ensure Headers are unique (only if they were potentially changed)
    if [[ "${new_H1}" != "${orig_H1}" || "${new_H2}" != "${orig_H2}" || "${new_H3}" != "${orig_H3}" || "${new_H4}" != "${orig_H4}" ]]; then
         while [[ ${new_H1} -eq ${new_H2} || ${new_H1} -eq ${new_H3} || ${new_H1} -eq ${new_H4} || \
                  ${new_H2} -eq ${new_H3} || ${new_H2} -eq ${new_H4} || ${new_H3} -eq ${new_H4} || \
                  ${new_H1} -le 4 || ${new_H2} -le 4 || ${new_H3} -le 4 || ${new_H4} -le 4 ]]; do # Also check > 4 here
            echo -e "${ORANGE}Magic headers must be unique and greater than 4. Regenerating random headers...${NC}"
            new_H1=$((RANDOM % 32767 * 1000 + RANDOM % 1000 + 10000)); new_H2=$((RANDOM % 32767 * 1000 + RANDOM % 1000 + 20000))
            new_H3=$((RANDOM % 32767 * 1000 + RANDOM % 1000 + 30000)); new_H4=$((RANDOM % 32767 * 1000 + RANDOM % 1000 + 40000))
        done
    fi

    # --- Check if settings have changed ---
    if [[ "${new_JC}" != "${orig_JC}" || "${new_JMIN}" != "${orig_JMIN}" || "${new_JMAX}" != "${orig_JMAX}" || \
          "${new_S1}" != "${orig_S1}" || "${new_S2}" != "${orig_S2}" || \
          "${new_H1}" != "${orig_H1}" || "${new_H2}" != "${orig_H2}" || "${new_H3}" != "${orig_H3}" || "${new_H4}" != "${orig_H4}" || \
          "${new_MTU}" != "${orig_MTU}" ]]; then

        echo -e "${GREEN}Obfuscation settings have changed.${NC}"
        # Update global variables with new settings
        JC="${new_JC}"; JMIN="${new_JMIN}"; JMAX="${new_JMAX}"
        S1="${new_S1}"; S2="${new_S2}"
        H1="${new_H1}"; H2="${new_H2}"; H3="${new_H3}"; H4="${new_H4}"
        MTU="${new_MTU}"

        # Update server config file and params file
        updateServerConfig # This function updates files and restarts service

        # Ask to regenerate client configs
        echo ""
        read -rp "Do you want to regenerate ALL client configurations with these new settings? [y/n]: " -e -i "y" regen_clients
        if [[ ${regen_clients,,} == 'y' ]]; then
            regenerateAllClientConfigs
        else
            echo -e "${ORANGE}Client configurations were NOT regenerated.${NC}"
            echo -e "${ORANGE}Existing clients may need manual updates or regeneration later.${NC}"
        fi
    else
        echo -e "${GREEN}No changes were made to the obfuscation settings.${NC}"
    fi
    echo ""
}

function updateServerConfig() {
    # This function updates the server config file and params file with current global variable values
    # It should be called after global variables (JC, JMIN, ..., MTU, ALLOWED_IPS) have been updated.

    # Source params if needed
    if [[ -z "${SERVER_WG_NIC}" && -f "${PARAMS_FILE}" ]]; then
       source "${PARAMS_FILE}"
    elif [[ ! -f "${PARAMS_FILE}" ]]; then
        echo -e "${RED}Parameters file not found: ${PARAMS_FILE}${NC}"
        return 1
    fi
    local server_conf_file="${AWG_CONF_DIR}/${SERVER_WG_NIC}.conf"
    if [[ ! -f "${server_conf_file}" ]]; then
        echo -e "${RED}Server configuration file not found: ${server_conf_file}${NC}"
        return 1
    fi


    echo -e "${GREEN}Updating server configuration files with new settings...${NC}"

    # Backup files before modification
    cp "${server_conf_file}" "${server_conf_file}.bak.$(date +%s)"
    cp "${PARAMS_FILE}" "${PARAMS_FILE}.bak.$(date +%s)"

    # Update settings in server config file using sed
    # Use pipe as delimiter to avoid issues if values contain slashes
    sed -i "s|^Jc *=.*|Jc = ${JC}|" "${server_conf_file}"
    sed -i "s|^Jmin *=.*|Jmin = ${JMIN}|" "${server_conf_file}"
    sed -i "s|^Jmax *=.*|Jmax = ${JMAX}|" "${server_conf_file}"
    sed -i "s|^S1 *=.*|S1 = ${S1}|" "${server_conf_file}"
    sed -i "s|^S2 *=.*|S2 = ${S2}|" "${server_conf_file}"
    sed -i "s|^H1 *=.*|H1 = ${H1}|" "${server_conf_file}"
    sed -i "s|^H2 *=.*|H2 = ${H2}|" "${server_conf_file}"
    sed -i "s|^H3 *=.*|H3 = ${H3}|" "${server_conf_file}"
    sed -i "s|^H4 *=.*|H4 = ${H4}|" "${server_conf_file}"
    sed -i "s|^MTU *=.*|MTU = ${MTU}|" "${server_conf_file}"
    # Note: We don't typically change Address, ListenPort, PrivateKey here.

    # Update settings in params file
    # Use sed; if the line doesn't exist, append it (less robust than proper parsing but ok for this)
    local keys_to_update=("JC" "JMIN" "JMAX" "S1" "S2" "H1" "H2" "H3" "H4" "MTU" "ALLOWED_IPS" "ENABLE_IPV6" "SERVER_WG_IPV4" "SERVER_WG_IPV6") # Add other changeable params if needed
    for key in "${keys_to_update[@]}"; do
        local value="${!key}" # Indirect variable expansion
        # Escape characters for sed (specifically / and &)
        local sed_value=$(echo "${value}" | sed -e 's/[\/&]/\\&/g')
        # Check if key exists
        if grep -q "^${key}=" "${PARAMS_FILE}"; then
             sed -i "s|^${key}=.*|${key}=${sed_value}|" "${PARAMS_FILE}"
        else
             echo "${key}=${value}" >> "${PARAMS_FILE}" # Append if missing
        fi
    done

    echo -e "${GREEN}Configuration files updated.${NC}"

    # Restart AmneziaWG service to apply changes
    echo -e "${GREEN}Restarting AmneziaWG service (awg-quick@${SERVER_WG_NIC})...${NC}"
    if systemctl restart "awg-quick@${SERVER_WG_NIC}"; then
        echo -e "${GREEN}Service restarted successfully.${NC}"
    else
        echo -e "${RED}Failed to restart AmneziaWG service.${NC}"
        echo -e "${RED}Check logs: journalctl -u awg-quick@${SERVER_WG_NIC}${NC}"
    fi
}

function configureAllowedIPs() {
    print_header "Configure Default Client Routing"
    echo "Choose how traffic should be routed for NEWLY generated clients by default."
    echo "Existing clients will NOT be affected unless regenerated."
    echo ""
    echo "   1) Route ALL traffic through VPN (Recommended for privacy/security)"
    echo "   2) Route only specific websites/services (Requires web browser access during setup)"
    echo "   3) Route websites commonly blocked in Russia (Uses external list)"
    echo "   4) Custom comma-separated CIDR list"

    local route_option=""
    local current_default_ips=""
     # Read current default if available
    [[ -f "${AWG_CONF_DIR}/default_routing" ]] && current_default_ips=$(cat "${AWG_CONF_DIR}/default_routing")
    local default_choice=1 # Default to All Traffic
    # Try to guess current setting for better default prompt
    if [[ -z "$current_default_ips" ]]; then
        default_choice=1 # Default to All Traffic if file missing
    elif [[ "$current_default_ips" == "0.0.0.0/0"* ]]; then
        default_choice=1 # All Traffic
    elif echo "$current_default_ips" | grep -qE '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}'; then
        # Looks like specific CIDRs, guess Custom or maybe Web/Russia list
         if [[ $(echo "$current_default_ips" | tr ',' '\n' | wc -l) -gt 10 ]]; then
             default_choice=3 # Guess Russia list if many entries
         else
             default_choice=4 # Guess Custom otherwise
         fi
         # Web selection is transient, hard to guess
    fi


    until [[ "$route_option" =~ ^[1-4]$ ]]; do
        read -rp "Select default routing option [1-4]: " -e -i "${default_choice}" route_option
    done

    local temp_allowed_ips="" # Use a temporary variable

    # Source params to know if IPv6 is enabled
    local current_enable_ipv6="y" # Assume yes unless params says no
    if [[ -f "${PARAMS_FILE}" ]]; then
        source "${PARAMS_FILE}"
        current_enable_ipv6="${ENABLE_IPV6}"
    fi


    case "${route_option}" in
    1) # All Traffic
        temp_allowed_ips="0.0.0.0/0"
        if [[ ${current_enable_ipv6,,} == "y" ]]; then
             temp_allowed_ips="${temp_allowed_ips},::/0"
        fi
        echo -e "${GREEN}Default routing set to: All Traffic (${temp_allowed_ips})${NC}"
        ;;
    2) # Specific Websites (Web UI)
        echo -e "${GREEN}Starting web server for service selection...${NC}"
        # startWebServer function now handles setup, runs server, and returns the selected list
        local selected_ips=""
        if ! selected_ips=$(startWebServer); then
             echo -e "${RED}Failed to get IP list from web server. Aborting routing change.${NC}"
             return 1 # Indicate failure
        fi
        if [[ -z "$selected_ips" ]]; then
             echo -e "${ORANGE}No IPs selected or generated. Aborting routing change.${NC}"
             return 1
        fi
        temp_allowed_ips="${selected_ips}"
        # Decide whether to add ::/0 based on global IPv6 setting
        if [[ ${current_enable_ipv6,,} == "y" ]] && ! echo "${temp_allowed_ips}" | grep -q "::/"; then
             echo -e "${ORANGE}Warning: Global IPv6 is enabled, but selected services might not include IPv6 routes.${NC}"
             echo -e "${ORANGE}Consider adding '::/0' or selecting IPv6 services if needed.${NC}"
             # Optionally, automatically add it:
             # read -rp "Add '::/0' to route all IPv6 traffic? [y/n]: " -e -i "n" add_ipv6_all
             # if [[ ${add_ipv6_all,,} == 'y' ]]; then temp_allowed_ips="${temp_allowed_ips},::/0"; fi
        fi
        echo -e "${GREEN}Default routing set to: Selected Services (${temp_allowed_ips})${NC}"
        ;;
    3) # Russia Blocked List
        echo -e "${GREEN}Fetching list of IPs/CIDRs commonly blocked in Russia...${NC}"
        local list_url="https://antifilter.download/list/allyouneed.lst"
        local raw_list=""
        if command -v curl &>/dev/null; then
            raw_list=$(curl -sS --fail "${list_url}")
        elif command -v wget &>/dev/null; then
            raw_list=$(wget -qO- "${list_url}")
        else
            echo -e "${RED}Cannot download list: curl or wget not found.${NC}"
            return 1
        fi

        if [[ -z "$raw_list" ]]; then
             echo -e "${RED}Failed to download or list is empty: ${list_url}${NC}"
             return 1
        fi

        # Process list: remove comments, empty lines, join with comma
        temp_allowed_ips=$(echo "${raw_list}" | grep -vE '^#|^$' | paste -sd ',')

        if [[ -z "$temp_allowed_ips" ]]; then
            echo -e "${RED}Failed to process the downloaded list.${NC}"
            return 1
        fi

        # Decide whether to add ::/0 based on global IPv6 setting
        if [[ ${current_enable_ipv6,,} == "y" ]]; then
             temp_allowed_ips="${temp_allowed_ips},::/0" # Route all IPv6
             echo -e "${GREEN}Default routing set to: Russia Blocked List + All IPv6${NC}"
        else
             echo -e "${GREEN}Default routing set to: Russia Blocked List (IPv4 Only)${NC}"
        fi
        # echo "DEBUG: ${temp_allowed_ips}" # Optional: Show the long list
        ;;
    4) # Custom List
        echo "Enter the comma-separated list of IPv4/IPv6 CIDRs."
        echo "Example: 1.1.1.1/32,8.8.8.0/24,2606:4700::/32"
        read -rp "Custom AllowedIPs: " -e temp_allowed_ips
        # Basic validation: check for at least one slash
        if [[ -z "$temp_allowed_ips" ]] || ! echo "$temp_allowed_ips" | grep -q "/"; then
            echo -e "${RED}Invalid or empty list provided. Aborting routing change.${NC}"
            return 1
        fi
        echo -e "${GREEN}Default routing set to: Custom List (${temp_allowed_ips})${NC}"
        ;;
    *) # Should not happen due to until loop
        echo -e "${RED}Invalid option selected.${NC}"
        return 1
        ;;
    esac

    # --- Update Global Variable and File ---
    ALLOWED_IPS="${temp_allowed_ips}" # Update the global variable
    mkdir -p "${AWG_CONF_DIR}"
    echo "${ALLOWED_IPS}" > "${AWG_CONF_DIR}/default_routing"
	echo -e "${GREEN}Default routing saved to ${AWG_CONF_DIR}/default_routing${NC}"

    return 0 # Indicate success
}

# --- Web Server for IP Selection ---

function installWebServerDependencies() {
    echo -e "${GREEN}Checking web server dependencies...${NC}"
    local missing_packages=""
    local pkg_manager_update=""
    local pkg_manager_install=""

    if [[ ${OS} == "ubuntu" || ${OS} == "debian" ]]; then
        pkg_manager_update="apt-get update"
        pkg_manager_install="apt-get install -y"
    elif [[ ${OS} == "rhel" ]]; then
        pkg_manager_update="" # yum/dnf usually don't need explicit update first
        pkg_manager_install="yum install -y"
        if command -v dnf &>/dev/null; then pkg_manager_install="dnf install -y"; fi
    else
        echo -e "${RED}Cannot determine package manager for dependency check.${NC}"
        return 1
    fi

    # Need git or unzip+curl/wget
    if ! command -v git &>/dev/null; then
        echo -e "${ORANGE}git not found. Will try curl/wget + unzip.${NC}"
        if ! command -v unzip &>/dev/null; then missing_packages="${missing_packages} unzip"; fi
        if ! command -v curl &>/dev/null && ! command -v wget &>/dev/null; then
             # Install curl on Debian-based, wget elsewhere if neither exists
            [[ ${OS} == "ubuntu" || ${OS} == "debian" ]] && missing_packages="${missing_packages} curl" || missing_packages="${missing_packages} wget"
        fi
    fi

    # Need jq for data generation
    if ! command -v jq &> /dev/null; then
        missing_packages="${missing_packages} jq"
    fi

    # Need a web server: python3 preferred, then python, then php
    local python_cmd="python3" # Prefer python3
    if ! command -v python3 &>/dev/null; then
        if command -v python &>/dev/null; then
            python_cmd="python" # Fallback to python (could be python2)
        elif ! command -v php &>/dev/null; then
            # Only add python3 if NO web server found
             missing_packages="${missing_packages} python3"
        fi
    fi
    # If python fallback was chosen, check if it's python2 and if SimpleHTTPServer module exists
    if [[ "$python_cmd" == "python" ]] && ! $python_cmd -m SimpleHTTPServer --help &>/dev/null; then
         # If 'python' exists but doesn't have SimpleHTTPServer, try installing python3
         if ! command -v python3 &>/dev/null; then
            missing_packages="${missing_packages} python3"
         fi
         # If PHP exists, we might rely on that instead, otherwise error later
    fi


    if [[ -n "${missing_packages}" ]]; then
        echo -e "${GREEN}Installing missing dependencies: ${missing_packages}${NC}"
        ${pkg_manager_update}
        if ! ${pkg_manager_install} ${missing_packages}; then
            echo -e "${RED}Failed to install dependencies: ${missing_packages}${NC}"
            echo -e "${RED}Please install them manually and try again.${NC}"
            return 1
        fi
    else
        echo -e "${GREEN}Required dependencies seem to be installed.${NC}"
    fi
    return 0
}

function generate_cidr_data() {
    # This function replicates and optimizes generate_data.sh logic
    local iplist_config_dir="$1"
    local output_dir="$2"
    local cidrs_json_file="$output_dir/cidrs.json"

    echo -e "${GREEN}Generating CIDR data from ${iplist_config_dir} to ${output_dir}...${NC}"

    if ! command -v jq &> /dev/null; then
        echo -e "${RED}Error: jq is required for generating data.${NC}"
        return 1
    fi
    if [ ! -d "$iplist_config_dir" ]; then
        echo -e "${RED}Error: iplist config directory not found: ${iplist_config_dir}${NC}"
        return 1
    fi
     mkdir -p "$output_dir"

    # --- Efficient JSON Generation ---
    local jq_filter_parts=()

    # Find category directories
    while IFS= read -r -d $'\0' category_path; do
        local category_name=$(basename "$category_path")
        # Skip if not a directory (safety check)
        [[ ! -d "$category_path" ]] && continue

        echo -e "\n${BOLD_GREEN}--- Category: ${category_name} ---${NC}"

        # Find service files within category
        while IFS= read -r -d $'\0' service_file; do
            local service_id=$(basename "$service_file" .json)
            echo -e "${BOLD_GREEN}  Processing service: ${service_id}${NC}" # Use BOLD_GREEN for consistency

            # Extract CIDRs using jq (Combine IPv4 and IPv6)
            local cidrs4="" cidrs6="" cidrs_combined=""
            # Handle potential jq errors (e.g., invalid JSON file)
            cidrs4=$(jq -c '.cidr4 // []' "$service_file" 2>/dev/null) || cidrs4="[]"
            cidrs6=$(jq -c '.cidr6 // []' "$service_file" 2>/dev/null) || cidrs6="[]"


            # Skip if both are empty
            if [[ "$cidrs4" = "[]" && "$cidrs6" = "[]" ]]; then
                echo -e "${ORANGE}    No CIDRs (v4 or v6) found, skipping.${NC}"
                continue
            fi

            # Combine arrays using jq
            cidrs_combined=$(jq -n --argjson a1 "$cidrs4" --argjson a2 "$cidrs6" '$a1 + $a2')

            # Add a jq assignment part for this service (ensure service_id is quoted for jq)
            # Escape potential quotes in service_id although unlikely given file naming
            local jq_service_id=$(jq -nr --arg str "$service_id" '$str')
            jq_filter_parts+=(".services[$jq_service_id] = {\"cidrs\": $cidrs_combined}")

        done < <(find "$category_path" -maxdepth 1 -name "*.json" -type f -print0)
    done < <(find "$iplist_config_dir" -mindepth 1 -maxdepth 1 -type d -print0) # mindepth 1 avoids the top dir

    # Check if any services were found
    if [ ${#jq_filter_parts[@]} -eq 0 ]; then
        echo -e "${ORANGE}Warning: No services with CIDRs found in ${iplist_config_dir}.${NC}"
        # Create an empty services object
        echo '{ "services": {} }' > "$cidrs_json_file"
        return 0 # Not an error, but nothing to process
    fi

    # Construct the final jq filter by joining parts with ' | '
    local final_jq_filter
    final_jq_filter=$(printf "%s | " "${jq_filter_parts[@]}")
    final_jq_filter=${final_jq_filter% | } # Remove trailing ' | '

    # Apply all updates at once to an initial JSON structure
    echo -e "${GREEN}Writing final ${cidrs_json_file}...${NC}"
    if ! jq -n "{ \"services\": {} } | ${final_jq_filter}" > "$cidrs_json_file"; then
         echo -e "${RED}Error: Failed to generate final cidrs.json using jq.${NC}"
         return 1
    fi

    echo -e "${GREEN}Data generation complete.${NC}"
    return 0
}


function startWebServer() {
    # Returns the generated comma-separated IP list string on success, empty on failure/cancel
    local web_server_pid=""
    local temp_dir=""
    local selected_ips=""
    local web_port=8080 # Default port

    # Cleanup trap
    trap 'echo -e "\n${ORANGE}Stopping web server and cleaning up...${NC}"; [[ -n "$web_server_pid" ]] && kill "$web_server_pid" >/dev/null 2>&1; [[ -n "$temp_dir" ]] && rm -rf "$temp_dir"; trap - INT; return 1' INT

    if ! installWebServerDependencies; then
        trap - INT # Remove trap before returning
        return 1
    fi

    temp_dir=$(mktemp -d)
    echo -e "${GREEN}Using temporary directory: ${temp_dir}${NC}"

    local awg_install_repo="https://github.com/ginto-sakata/amneziawg-install.git"
    local iplist_repo="https://github.com/rekryt/iplist.git"
    local website_source_dir="${temp_dir}/amneziawg-install/static_website"
    local iplist_source_dir="${temp_dir}/iplist/config" # Target for iplist data

    # --- Get Website Files ---
    echo -e "${GREEN}Cloning AmneziaWG Installer repo for website files...${NC}"
    if ! git clone --depth=1 "${awg_install_repo}" "${temp_dir}/amneziawg-install"; then
        echo -e "${RED}Failed to clone repository: ${awg_install_repo}${NC}"
        rm -rf "${temp_dir}"; trap - INT; return 1
    fi
    if [[ ! -d "${website_source_dir}" || ! -f "${website_source_dir}/index.html" ]]; then
         echo -e "${RED}Website files (static_website/index.html) not found in cloned repo.${NC}"
         rm -rf "${temp_dir}"; trap - INT; return 1
    fi

    # --- Get iplist Data ---
    mkdir -p "${temp_dir}/iplist" # Create base iplist dir
    echo -e "${GREEN}Fetching IP list data...${NC}"
    if command -v git &>/dev/null; then
        echo -e "${GREEN}Using git sparse checkout for iplist config...${NC}"
        if ! git clone -n --depth=1 --filter=tree:0 "${iplist_repo}" "${temp_dir}/iplist"; then
             echo -e "${RED}Failed to clone iplist repository.${NC}"; rm -rf "${temp_dir}"; trap - INT; return 1
        fi
        (cd "${temp_dir}/iplist" && git sparse-checkout set --no-cone /config && git checkout)
        if [[ ! -d "${iplist_source_dir}" ]]; then
            echo -e "${RED}Failed to checkout iplist config directory.${NC}"; rm -rf "${temp_dir}"; trap - INT; return 1
        fi
    else
        echo -e "${GREEN}Using curl/wget + unzip for iplist data...${NC}"
        local iplist_zip_url="https://github.com/rekryt/iplist/archive/refs/heads/master.zip"
        local zip_file="${temp_dir}/iplist.zip"
        local dl_cmd=""
        if command -v curl &>/dev/null; then dl_cmd="curl -sSL -o"; else dl_cmd="wget -q -O"; fi # Added -sL to curl

        if ! $dl_cmd "${zip_file}" "${iplist_zip_url}"; then
             echo -e "${RED}Failed to download iplist zip file.${NC}"; rm -rf "${temp_dir}"; trap - INT; return 1
        fi
        if ! unzip -q "${zip_file}" -d "${temp_dir}"; then
             echo -e "${RED}Failed to unzip iplist data.${NC}"; rm -rf "${temp_dir}"; trap - INT; return 1
        fi
        # Move the config dir from the extracted folder
        if ! mv "${temp_dir}/iplist-master/config" "${iplist_source_dir}"; then
             echo -e "${RED}Failed to move iplist config directory.${NC}"; rm -rf "${temp_dir}"; trap - INT; return 1
        fi
        rm -rf "${temp_dir}/iplist-master" # Clean up rest of extracted files
        rm -f "${zip_file}"
    fi

    # --- Generate cidrs.json ---
    if ! generate_cidr_data "${iplist_source_dir}" "${website_source_dir}"; then
         echo -e "${RED}Failed to generate data for website.${NC}"
         rm -rf "${temp_dir}"; trap - INT; return 1
    fi

    # --- Start Web Server ---
    local webserver_address="0.0.0.0" # Listen on all interfaces
    local display_address=""
        # Try to get a usable display IP
    display_address=$(ip -4 route get 1.1.1.1 | awk '{print $7}' | head -n1) # More reliable way to get outbound IP
    if [[ -z "$display_address" ]]; then display_address=$(hostname -I | awk '{print $1}'); fi # Fallback 1
    if [[ -z "$display_address" ]]; then display_address=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v 127.0.0.1 | head -1); fi # Fallback 2
    if [[ -z "$display_address" ]]; then display_address="127.0.0.1"; fi # Last resort

    local server_cmd=""

    # Find available server command and check port availability
    while true; do
        if ss -tuln | grep -q ":${web_port}\s" ; then
            echo -e "${ORANGE}Port ${web_port} is already in use. Trying next port...${NC}"
            ((web_port++))
            if [[ $web_port -gt 65535 ]]; then # Should not happen, but safety check
                echo -e "${RED}Could not find an available port.${NC}"; rm -rf "${temp_dir}"; trap - INT; return 1
            fi
            continue # Retry check with new port
        fi

        # Port is free, determine command
        if command -v python3 &>/dev/null; then
            server_cmd="python3 -m http.server ${web_port} --bind ${webserver_address}"
            break # Found command
        elif command -v python &>/dev/null && python -m SimpleHTTPServer --help &>/dev/null; then
            # Python 2 SimpleHTTPServer doesn't have --bind, listens on 0.0.0.0 by default
            server_cmd="python -m SimpleHTTPServer ${web_port}"
            break # Found command
        elif command -v php &>/dev/null; then
            server_cmd="php -S ${webserver_address}:${web_port} -t ." # Need -t . for current dir
            break # Found command
        else
            echo -e "${RED}No suitable web server found (Python 3/2 or PHP). Cannot start selection interface.${NC}"
            rm -rf "${temp_dir}"; trap - INT; return 1
        fi
    done


    echo ""
    print_header "Service Selection via Web Browser"
    echo -e "${GREEN}Starting temporary web server...${NC}"
    echo -e "Please open this URL in your browser: ${GREEN}http://${display_address}:${web_port}${NC}"
    echo -e "1. Select the websites/services you want routed through the VPN."
    echo -e "2. Click ${GREEN}'Generate IP List'${NC} at the bottom of the page."
    echo -e "3. Copy the generated comma-separated IP list."
    echo -e "4. ${ORANGE}IMPORTANT: Paste the copied list here in the terminal when prompted below.${NC}"
    echo -e "5. ${ORANGE}Then, press Ctrl+C in THIS terminal window to stop the web server.${NC}"
    echo ""

    # Start server in background
    (cd "${website_source_dir}" && ${server_cmd} &> "${temp_dir}/webserver.log") &
    web_server_pid=$!
    sleep 1 # Give server a moment to start

    # Check if server started successfully
    if ! ps -p $web_server_pid > /dev/null; then
        echo -e "${RED}Web server failed to start. Check logs: ${temp_dir}/webserver.log${NC}"
        rm -rf "${temp_dir}"; trap - INT; return 1
    fi

    # Wait for user to paste the list
    echo -n -e "${GREEN}Paste the generated IP list here: ${NC}"
    read -r selected_ips

    # Check if something was pasted (basic check)
    if [[ -z "$selected_ips" ]]; then
        echo -e "\n${ORANGE}No IP list pasted. Aborting selection.${NC}"
        # Stop server and clean up (handled by trap)
        kill "$web_server_pid" >/dev/null 2>&1
        wait "$web_server_pid" 2>/dev/null # Wait for it to exit
        rm -rf "${temp_dir}"
        trap - INT # Remove trap
        return 1
    elif ! echo "$selected_ips" | grep -q "/"; then
        echo -e "\n${ORANGE}Pasted text doesn't look like a CIDR list. Aborting selection.${NC}"
        kill "$web_server_pid" >/dev/null 2>&1
        wait "$web_server_pid" 2>/dev/null
        rm -rf "${temp_dir}"
        trap - INT
        return 1
    fi

    # User pasted something, prompt to stop server
    echo -e "\n${GREEN}IP List received. Press Ctrl+C now to stop the web server and continue...${NC}"
    # The trap will handle cleanup and return 1, we need to return 0 with the value
    wait "$web_server_pid" 2>/dev/null # Wait for Ctrl+C kill or server exit
    local exit_status=$?

    # If we reach here, the server stopped (likely via Ctrl+C)
    rm -rf "${temp_dir}"
    trap - INT # Remove trap explicitly

    if [[ $exit_status -ne 0 ]]; then
         echo -e "\n${GREEN}Web server stopped. Continuing with selected IPs.${NC}"
         # Return the pasted IPs via stdout
         echo "${selected_ips}"
         return 0
    else
         # This case might happen if server exited unexpectedly before Ctrl+C
         echo -e "\n${ORANGE}Web server exited. Continuing with selected IPs.${NC}"
         echo "${selected_ips}"
         return 0
    fi
}

# --- Uninstall Function ---

function cleanup() {
    # Function to remove configuration files and directories
    echo -e "${GREEN}Removing AmneziaWG configuration files...${NC}"
    # Use -f to avoid errors if files/dirs don't exist
    rm -f "${PARAMS_FILE}"
    # Source SERVER_WG_NIC one last time if possible, just for the config file name
    if [[ -z "${SERVER_WG_NIC}" && -f "${PARAMS_FILE}" ]]; then
        source "${PARAMS_FILE}"
    fi
    [[ -n "${SERVER_WG_NIC}" ]] && rm -f "${AWG_CONF_DIR}/${SERVER_WG_NIC}.conf"
    rm -f "${AWG_CONF_DIR}/default_routing" # Remove the routing file (FIXED)

    # Remove potentially empty directory, check if empty first
    if [ -d "${AWG_CONF_DIR}" ] && [ -z "$(ls -A "${AWG_CONF_DIR}")" ]; then
         rmdir "${AWG_CONF_DIR}"
         echo -e "${GREEN}Removed directory ${AWG_CONF_DIR}.${NC}"
    elif [ -d "${AWG_CONF_DIR}" ]; then
         echo -e "${ORANGE}Warning: Directory ${AWG_CONF_DIR} is not empty. Not removing.${NC}"
         echo -e "${ORANGE}You may need to remove it manually if desired: rm -rf ${AWG_CONF_DIR}${NC}"
    fi

    # Remove sysctl config
    rm -f "/etc/sysctl.d/99-amneziawg-forward.conf"
    echo -e "${GREEN}Applying sysctl changes (disabling forwarding if no other rule enables it)...${NC}"
    sysctl --system

    # Remove repository configs
    if [[ ${OS} == "ubuntu" || ${OS} == "debian" ]]; then
        rm -f /etc/apt/sources.list.d/amnezia*.list # Remove amnezia PPA file
        rm -f /etc/apt/sources.list.d/amnezia*.sources # Also remove new format if present
        echo -e "${GREEN}Attempting apt update to refresh sources after PPA removal...${NC}"
        apt-get update > /dev/null 2>&1 || echo -e "${ORANGE}apt update failed, may need manual run.${NC}"
    elif [[ ${OS} == "rhel" ]]; then
        rm -f /etc/yum.repos.d/amnezia.repo
    fi

    echo -e "${GREEN}Cleanup completed.${NC}"
}

function uninstallWg() {
    print_header "Uninstall AmneziaWG"
    echo -e "${RED}WARNING: This will stop AmneziaWG, remove its packages,${NC}"
    echo -e "${RED}         and delete configuration files in ${AWG_CONF_DIR}.${NC}"
    echo -e "${ORANGE}Client configuration files in user home directories will NOT be deleted.${NC}"
    echo ""
    read -rp "Are you sure you want to uninstall AmneziaWG? [y/n]: " -e -i "n" confirm_uninstall

    if [[ ${confirm_uninstall,,} != 'y' ]]; then
        echo "Uninstall cancelled."
        return
    fi

    # Source params to get SERVER_WG_NIC if possible
    if [[ -f "${PARAMS_FILE}" ]]; then
        source "${PARAMS_FILE}"
    else
        # Prompt if params file missing
        read -rp "Enter the AmneziaWG interface name used (e.g., awg0): " -e -i "${SERVER_WG_NIC}" SERVER_WG_NIC_INPUT
        SERVER_WG_NIC="${SERVER_WG_NIC_INPUT}" # Use input if params missing
    fi

    # Stop the service
    local service_name="awg-quick@${SERVER_WG_NIC}"
    echo -e "${GREEN}Stopping and disabling AmneziaWG service (${service_name})...${NC}"
    if systemctl is-active --quiet "${service_name}"; then systemctl stop "${service_name}"; fi
    if systemctl is-enabled --quiet "${service_name}"; then systemctl disable "${service_name}"; fi

    # Run cleanup FIRST to remove configs that might prevent package removal
    cleanup # This function removes files and sysctl settings

    # Remove packages
    echo -e "${GREEN}Removing AmneziaWG packages...${NC}"
    if [[ ${OS} == "ubuntu" || ${OS} == "debian" ]]; then
        apt-get remove --purge -y amneziawg # Use purge to remove configs owned by package
        apt-get autoremove -y
    elif [[ ${OS} == "rhel" ]]; then
        yum remove -y amneziawg || dnf remove -y amneziawg
        yum autoremove -y || dnf autoremove -y
    fi


    echo ""
    echo -e "${GREEN}AmneziaWG has been uninstalled successfully.${NC}"
    echo "Run this script again if you want to reinstall."
    echo ""
    exit 0 # Exit script after successful uninstall
}


# --- Management Menu ---

function manageMenu() {
    # Source params file to get current settings
    if [[ -f "${PARAMS_FILE}" ]]; then
		source "${PARAMS_FILE}"
	else
        echo -e "${RED}AmneziaWG parameters file not found: ${PARAMS_FILE}${NC}"
        echo -e "${RED}Cannot manage the server. It might not be installed correctly.${NC}"
        exit 1
	fi

    while true; do
        # Re-source params each time in case they were changed by an option
        [[ -f "${PARAMS_FILE}" ]] && source "${PARAMS_FILE}"

        print_header "AmneziaWG Management Panel"
        echo "Server Interface: ${SERVER_WG_NIC}"
        echo "Listen Port: ${SERVER_PORT}"
        echo "Public Endpoint: ${SERVER_PUB_IP}"
        echo "Default Routing: ${ALLOWED_IPS}"
        echo ""
        echo "Select an option:"
        echo "   1) Add a new client"
        echo "   2) List existing clients"
        echo "   3) Revoke a client"
        echo "   4) Regenerate a specific client's config"
        echo "   5) Configure Obfuscation settings"
        echo "   6) Configure Default Client Routing (AllowedIPs)"
        echo "   7) Uninstall AmneziaWG"
        echo "   8) Exit"
        echo ""

        local menu_option=""
        until [[ ${menu_option} =~ ^[1-8]$ ]]; do
            read -rp "Enter option [1-8]: " menu_option
        done

        case "${menu_option}" in
        1)
            newClient
            ;;
        2)
            listClients
            ;;
        3)
            revokeClient
            ;;
        4) # Regenerate specific client
            if listClients; then # Only proceed if listClients succeeded (found clients)
                 read -rp "Enter the name of the client to regenerate: " client_to_regen
                 if [[ -n "$client_to_regen" ]]; then
                    regenerateClientConfig "$client_to_regen"
                 else
                    echo "No client name entered."
                 fi
            fi
            ;;
        5)
            configureObfuscationSettings
            ;;
        6)
             # Configure Allowed IPs (updates global var and file)
             if configureAllowedIPs; then
                 # Update server params file with new ALLOWED_IPS
                 # updateServerConfig is called within configureObfuscationSettings if changes are made
                 # Here we only changed AllowedIPs, so just need to update params and maybe restart
                 echo -e "${GREEN}Updating parameter file with new default routing...${NC}"
                 if grep -q "^ALLOWED_IPS=" "${PARAMS_FILE}"; then
                    local sed_allowed_ips=$(echo "${ALLOWED_IPS}" | sed -e 's/[\/&]/\\&/g')
                    sed -i "s|^ALLOWED_IPS=.*|ALLOWED_IPS=${sed_allowed_ips}|" "${PARAMS_FILE}"
                 else
                    echo "ALLOWED_IPS=${ALLOWED_IPS}" >> "${PARAMS_FILE}"
                 fi

                 echo -e "${GREEN}Parameter file updated. No service restart needed for default routing change.${NC}"
                 echo -e "${ORANGE}Remember: This only affects NEWLY generated clients.${NC}"

                 # Ask if regenerate all client configs
                 echo ""
                 read -rp "Regenerate ALL client configurations now to use the new default routing? [y/n]: " -e -i "n" regen_clients
                 if [[ ${regen_clients,,} == 'y' ]]; then
                     regenerateAllClientConfigs
                 else
                     echo -e "${ORANGE}Client configurations were NOT regenerated.${NC}"
                     echo -e "${ORANGE}Existing clients will keep their current AllowedIPs setting.${NC}"
                 fi
             else
                 echo -e "${RED}Failed to configure default routing.${NC}"
             fi
            ;;
        7)
            uninstallWg # This function exits the script if successful
            ;;
        8)
            echo "Exiting."
            exit 0
            ;;
        esac # End case

        echo ""
        read -n1 -r -p "Press any key to return to the menu..."
        echo ""
    done # End while loop
}

# --- Main Script Logic ---

# Perform initial checks (root, OS, virt, existing install)
if initialCheck; then
    # AmneziaWG seems installed, go to manage menu
    manageMenu
else
    # No existing install or WireGuard migration cancelled/failed, proceed with fresh install
    installAmneziaWG
fi

exit 0 # Explicitly exit with success if we reach here