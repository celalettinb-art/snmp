#!/usr/bin/env bash

# SNMPv3 setup for Debian
# Installs and configures snmpd (SNMPv3 only) on UDP/161
# Creates a read-only SNMPv3 user with the strongest supported auth/priv methods
# Restricts UDP/161 by source CIDR via nftables firewall rules
# Writes a summary to ~/snmpd.creds (for the invoking user)
# Run the script -> bash -c "$(curl -fsSL https://raw.githubusercontent.com/celalettinb-art/snmp/refs/heads/main/install-and-configure-snmpv3-on-debian-manuell.sh)"

set -euo pipefail

# ===== Color Output =====
RED="$(tput setaf 1 || true)"
GREEN="$(tput setaf 2 || true)"
YELLOW="$(tput setaf 3 || true)"
BLUE="$(tput setaf 4 || true)"
BOLD="$(tput bold || true)"
RESET="$(tput sgr0 || true)"

info()  { echo "${BLUE}[INFO]${RESET} $*"; }
ok()    { echo "${GREEN}[OK]${RESET} $*"; }
warn()  { echo "${YELLOW}[WARN]${RESET} $*"; }
fail()  { echo "${RED}[ERROR]${RESET} $*"; exit 1; }

prompt_yellow_bold() {
  # Usage: prompt_yellow_bold "question" VAR
  local q="$1" __var="$2"
  read -r -p "$(echo -e "${BOLD}${YELLOW}${q}${RESET}")" "$__var"
}

# ===== Root Check =====
if [[ "${EUID}" -ne 0 ]]; then
  fail "You must run this script as root (e.g., using sudo)."
fi

# ===== Setup Credentials File for Invoking User =====
TARGET_USER="${SUDO_USER:-root}"
TARGET_HOME="$(getent passwd "${TARGET_USER}" | cut -d: -f6 || true)"
[[ -z "${TARGET_HOME}" || ! -d "${TARGET_HOME}" ]] && TARGET_HOME="${HOME}"
CREDS_FILE="${TARGET_HOME}/snmpd.creds"

# ===== Ask: Allowed CIDR =====
prompt_yellow_bold "Allowed IP address range (CIDR) for SNMP queries (e.g., 192.168.1.0/24): " ALLOW_CIDR
ALLOW_CIDR="${ALLOW_CIDR//[[:space:]]/}"
[[ -z "${ALLOW_CIDR}" ]] && fail "No CIDR provided."

# Basic CIDR check
if ! [[ "${ALLOW_CIDR}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[12][0-9]|3[0-2])$ ]]; then
  warn "CIDR format looks unusual. Continuing anyway..."
fi

# ===== Ask: sysLocation =====
SYS_LOCATION=""
while [[ -z "${SYS_LOCATION}" ]]; do
  prompt_yellow_bold "Enter sysLocation (e.g., DC Server Room): " SYS_LOCATION
  SYS_LOCATION="${SYS_LOCATION//[[:space:]]/ }"
  SYS_LOCATION="${SYS_LOCATION#"${SYS_LOCATION%%[![:space:]]*}"}"
  SYS_LOCATION="${SYS_LOCATION%"${SYS_LOCATION##*[![:space:]]}"}"
  [[ -z "${SYS_LOCATION}" ]] && warn "sysLocation cannot be empty."
done

# ===== Ask: sysContact (valid email) =====
is_valid_email() { [[ "$1" =~ ^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$ ]]; }

SYS_CONTACT=""
while true; do
  prompt_yellow_bold "Enter sysContact email (e.g., admin@example.com): " SYS_CONTACT
  SYS_CONTACT="${SYS_CONTACT//[[:space:]]/}"
  if [[ -z "${SYS_CONTACT}" ]]; then
    warn "sysContact cannot be empty."
    continue
  fi
  if is_valid_email "${SYS_CONTACT}"; then
    ok "Valid email address."
    break
  else
    warn "Invalid email format, please retry."
  fi
done

# ===== Ask: SNMPv3 Username & Password =====
prompt_yellow_bold "Enter SNMPv3 username: " USERNAME
[[ -z "${USERNAME}" ]] && fail "Username cannot be empty."

prompt_yellow_bold "Enter SNMPv3 auth password (min 8 chars): " AUTH_PASS
[[ ${#AUTH_PASS} -lt 8 ]] && fail "Password too short."

prompt_yellow_bold "Enter SNMPv3 privacy password (min 8 chars): " PRIV_PASS
[[ ${#PRIV_PASS} -lt 8 ]] && fail "Privacy pass too short."

# ===== Install Required Packages =====
info "Installing SNMP packages if missing..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends snmpd snmp nftables openssl
ok "Required packages installed."

# ===== Stop SNMP Daemon =====
info "Stopping snmpd before configuration..."
systemctl stop snmpd >/dev/null 2>&1 || true

# ===== Create SNMPv3 User =====
info "Creating SNMPv3 user (authPriv, SHA, AES)..."
set +e
net-snmp-create-v3-user -ro -a SHA -A "${AUTH_PASS}" -x AES -X "${PRIV_PASS}" "${USERNAME}" >/dev/null 2>&1
RC=$?
set -e
if [[ $RC -ne 0 ]]; then
  fail "Failed to create SNMPv3 user."
else
  ok "SNMPv3 user '${USERNAME}' created."
fi

# ===== Write SNMPv3 Config =====
SNMPD_CONF="/etc/snmp/snmpd.conf"
info "Writing SNMPv3 only configuration to ${SNMPD_CONF}..."

cat >"${SNMPD_CONF}" <<EOF
# SNMPv3 only configuration
# Allowed IP range (enforced via firewall): ${ALLOW_CIDR}
agentAddress udp:161

# System metadata
sysLocation    ${SYS_LOCATION}
sysContact     ${SYS_CONTACT}

# SNMPv3 user with authPriv (SHA, AES)
rouser ${USERNAME} authpriv

# Disable SNMPv1/v2c
# no rocommunity or rwcommunity lines
EOF

ok "Configuration written."

# ===== Firewall: nftables =====
NFT_SNMP="/etc/nftables.d/snmpd.nft"
NFT_MAIN="/etc/nftables.conf"
info "Configuring nftables to restrict UDP/161 to ${ALLOW_CIDR}..."
mkdir -p /etc/nftables.d
cat >"${NFT_SNMP}" <<EOF
table inet snmpd_filter {
  chain input {
    type filter hook input priority 0;
    udp dport 161 ip saddr ${ALLOW_CIDR} counter accept
    udp dport 161 counter drop
  }
}
EOF

# Ensure include directive
if ! grep -q "include \"/etc/nftables.d/\"" "${NFT_MAIN}"; then
  echo "include \"/etc/nftables.d/*.nft\"" >> "${NFT_MAIN}"
fi

nft -f "${NFT_MAIN}" || warn "Failed loading nftables rules, please check manually."

ok "Firewall rules applied."

# ===== Enable & Start snmpd =====
info "Enabling and starting snmpd..."
systemctl enable snmpd
systemctl restart snmpd
ok "snmpd is running."

# ===== Write Credentials File =====
info "Saving relevant info to ${CREDS_FILE}..."
cat >"${CREDS_FILE}" <<EOF
SNMPv3 Username:       ${USERNAME}
Auth Protocol:        SHA
Auth Password:        ${AUTH_PASS}
Privacy Protocol:     AES
Privacy Password:     ${PRIV_PASS}
Allowed CIDR:         ${ALLOW_CIDR}
Config File:          ${SNMPD_CONF}
EOF

chmod 600 "${CREDS_FILE}"
chown "${TARGET_USER}:${TARGET_USER}" "${CREDS_FILE}" || true
ok "Credentials file created with restricted permissions."

# ===== Final Summary =====
echo
echo "${BOLD}${GREEN}===== SNMPv3 Setup Completed =====${RESET}"
echo "${BOLD}Allowed IP range:${RESET} ${YELLOW}${ALLOW_CIDR}${RESET} (enforced via firewall)"
echo "${BOLD}SNMP Version:${RESET} ${YELLOW}v3 only${RESET}"
echo "${BOLD}Port:${RESET} ${YELLOW}UDP/161${RESET}"
echo "${BOLD}sysLocation:${RESET} ${YELLOW}${SYS_LOCATION}${RESET}"
echo "${BOLD}sysContact:${RESET} ${YELLOW}${SYS_CONTACT}${RESET}"
echo "${BOLD}SNMPv3 username:${RESET} ${YELLOW}${USERNAME}${RESET}"
echo "${BOLD}Auth protocol:${RESET} ${YELLOW}SHA${RESET}"
echo "${BOLD}Privacy protocol:${RESET} ${YELLOW}AES${RESET}"
echo "${BOLD}Config file:${RESET} ${YELLOW}${SNMPD_CONF}${RESET}"
echo "${BOLD}Credentials file:${RESET} ${YELLOW}${CREDS_FILE}${RESET}"
echo
echo "${BOLD}${YELLOW}Hint:${RESET} Test SNMP access from allowed host using:"
echo "  snmpwalk -v3 -l authPriv -u ${USERNAME} -a SHA -A '${AUTH_PASS}' -x AES -X '${PRIV_PASS}' localhost .1.3.6.1.2.1.1"
echo
