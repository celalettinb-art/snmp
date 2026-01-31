#!/usr/bin/env bash
# Then run the script -> bash -c "$(curl -fsSL https://raw.githubusercontent.com/celalettinb-art/snmp/refs/heads/main/create-snmpv3.sh)"
set -euo pipefail

# ======= Colors =======
RED="$(tput setaf 1 || true)"
GREEN="$(tput setaf 2 || true)"
YELLOW="$(tput setaf 3 || true)"
BLUE="$(tput setaf 4 || true)"
BOLD="$(tput bold || true)"
RESET="$(tput sgr0 || true)"

info()  { echo "${BLUE}[i]${RESET} $*"; }
ok()    { echo "${GREEN}[✓]${RESET} $*"; }
warn()  { echo "${YELLOW}[!]${RESET} $*"; }
fail()  { echo "${RED}[x]${RESET} $*"; exit 1; }

# ======= Root check =======
if [[ "${EUID}" -ne 0 ]]; then
  fail "Please run this script as root (e.g. using sudo)."
fi

# ======= User input: allowed IP range =======
echo "${BOLD}SNMPv3 Setup (Debian)${RESET}"
echo
read -r -p "From which IP address range (CIDR) should SNMP requests be accepted? (e.g. 192.168.1.0/24): " ALLOW_CIDR
ALLOW_CIDR="${ALLOW_CIDR//[[:space:]]/}"

if [[ -z "${ALLOW_CIDR}" ]]; then
  fail "No IP address range provided."
fi

# Basic CIDR sanity check (not a full validator)
if ! [[ "${ALLOW_CIDR}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[12][0-9]|3[0-2])$ ]]; then
  warn "The CIDR value looks unusual: '${ALLOW_CIDR}'. Continuing anyway."
fi

# ======= Installation =======
info "Installing required packages (net-snmp, snmp, nftables, openssl)..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends snmpd snmp nftables openssl
ok "Packages installed."

# ======= Generate strong credentials =======
USERNAME="snmpv3_$(openssl rand -hex 4)"
AUTH_PASS="$(openssl rand -base64 32 | tr -d '\n' | tr '/+' 'Aa' | cut -c1-24)"
PRIV_PASS="$(openssl rand -base64 32 | tr -d '\n' | tr '/+' 'Bb' | cut -c1-28)"

# ======= Determine best available crypto (fallback logic) =======
AUTH_PROTO="SHA-256"
PRIV_PROTO="AES-256"

if ! net-snmp-create-v3-user -h 2>&1 | grep -qi "SHA-256"; then
  AUTH_PROTO="SHA"
  warn "SHA-256 does not seem to be supported by net-snmp-create-v3-user. Falling back to SHA."
fi

if ! net-snmp-create-v3-user -h 2>&1 | grep -qi "AES-256"; then
  PRIV_PROTO="AES"
  warn "AES-256 does not seem to be supported by net-snmp-create-v3-user. Falling back to AES."
fi

# ======= Stop snmpd before user creation =======
info "Stopping snmpd (if running)..."
systemctl stop snmpd >/dev/null 2>&1 || true

# ======= Create SNMPv3 user =======
info "Creating SNMPv3 user (authPriv, read-only)..."
set +e
CREATE_OUT="$(
  (echo "y" | net-snmp-create-v3-user -ro -a "${AUTH_PROTO}" -A "${AUTH_PASS}" -x "${PRIV_PROTO}" -X "${PRIV_PASS}" "${USERNAME}") 2>&1
)"
RC=$?
set -e

if [[ $RC -ne 0 ]]; then
  echo "${CREATE_OUT}"
  fail "Failed to create SNMPv3 user."
fi
ok "SNMPv3 user created: ${USERNAME}"

# ======= Configure snmpd (SNMPv3 only, port 161) =======
SNMPD_CONF="/etc/snmp/snmpd.conf"
BACKUP="${SNMPD_CONF}.$(date +%Y%m%d-%H%M%S).bak"

if [[ -f "${SNMPD_CONF}" ]]; then
  cp -a "${SNMPD_CONF}" "${BACKUP}"
  ok "Backup created: ${BACKUP}"
fi

info "Writing secure snmpd configuration (SNMPv3 only, UDP/161)..."
cat > "${SNMPD_CONF}" <<EOF
###############################################################################
# Managed by setup script
# Goal: SNMPv3 only (no v1/v2c), standard port UDP/161
###############################################################################

# Listen only on standard SNMP port
agentAddress udp:161

# System information (adjust if needed)
sysLocation  "Debian Server"
sysContact   "admin@example.local"

# No community strings defined -> SNMPv1/v2c effectively disabled
# (Do NOT add rocommunity or rwcommunity lines)

# SNMPv3 access: read-only, authPriv required
rouser ${USERNAME} authpriv

# Reduce unnecessary log noise
dontLogTCPWrappersConnects yes
EOF
ok "Configuration written: ${SNMPD_CONF}"

# ======= Firewall configuration (nftables) =======
NFT_DIR="/etc/nftables.d"
NFT_SNMP="${NFT_DIR}/snmpd.nft"
NFT_MAIN="/etc/nftables.conf"

info "Configuring nftables rules (only ${ALLOW_CIDR} allowed to access UDP/161)..."
mkdir -p "${NFT_DIR}"

cat > "${NFT_SNMP}" <<EOF
# Managed by setup script - SNMPd restriction
table inet snmpd_filter {
  chain input {
    type filter hook input priority -150; policy accept;

    # Allow SNMP (UDP/161) only from allowed source range
    udp dport 161 ip saddr ${ALLOW_CIDR} counter accept
    udp dport 161 counter drop
  }
}
EOF

if [[ -f "${NFT_MAIN}" ]]; then
  if ! grep -qE 'include\s+"/etc/nftables\.d/\*\.nft"' "${NFT_MAIN}"; then
    if ! grep -qE 'include\s+".*nftables\.d.*"' "${NFT_MAIN}"; then
      echo 'include "/etc/nftables.d/*.nft"' >> "${NFT_MAIN}"
      ok "Added include directive to ${NFT_MAIN}"
    else
      warn "An include directive for nftables.d already exists in ${NFT_MAIN}. Leaving it unchanged."
    fi
  fi
else
  cat > "${NFT_MAIN}" <<EOF
#!/usr/sbin/nft -f
flush ruleset
include "/etc/nftables.d/*.nft"
EOF
  warn "${NFT_MAIN} did not exist. A minimal config was created (flush ruleset!). Review carefully if you already had firewall rules."
fi

systemctl enable --now nftables >/dev/null 2>&1 || true
nft -f "${NFT_MAIN}" >/dev/null 2>&1 || true

if ! nft list ruleset >/dev/null 2>&1; then
  warn "Unable to verify nftables ruleset. Please check with 'nft -f /etc/nftables.conf'."
else
  ok "nftables rules are active."
fi

# ======= Enable and start snmpd =======
info "Enabling autostart and starting snmpd..."
systemctl enable snmpd >/dev/null 2>&1 || true
systemctl restart snmpd

if systemctl is-active --quiet snmpd; then
  ok "snmpd is running."
else
  warn "snmpd is not active. Check logs with 'journalctl -u snmpd --no-pager'."
fi

# ======= Summary =======
echo
echo "${BOLD}${GREEN}===== Setup completed – Relevant information =====${RESET}"
echo "${BOLD}Allowed IP range:${RESET} ${YELLOW}${ALLOW_CIDR}${RESET}"
echo "${BOLD}SNMP version:${RESET} ${YELLOW}v3 only (v1/v2c not configured)${RESET}"
echo "${BOLD}Port:${RESET} ${YELLOW}UDP/161${RESET}"
echo
echo "${BOLD}SNMPv3 username:${RESET} ${YELLOW}${USERNAME}${RESET}"
echo "${BOLD}Auth protocol:${RESET} ${YELLOW}${AUTH_PROTO}${RESET}"
echo "${BOLD}Auth password:${RESET} ${YELLOW}${AUTH_PASS}${RESET}"
echo "${BOLD}Privacy protocol:${RESET} ${YELLOW}${PRIV_PROTO}${RESET}"
echo "${BOLD}Privacy password:${RESET} ${YELLOW}${PRIV_PASS}${RESET}"
echo
echo "${BOLD}Configuration files:${RESET}"
echo "  ${YELLOW}/etc/snmp/snmpd.conf${RESET}  (daemon configuration)"
echo "  ${YELLOW}/var/lib/snmp/snmpd.conf${RESET}  (SNMPv3 USM users/keys – do not edit manually)"
echo
echo "${BOLD}Firewall rules:${RESET} ${YELLOW}${NFT_SNMP}${RESET} (included via /etc/nftables.conf)"
echo
echo "${BOLD}${YELLOW}Hint:${RESET} You can test from an allowed host using:"
echo "  snmpwalk -v3 -l authPriv -u ${USERNAME} -a ${AUTH_PROTO} -A '${AUTH_PASS}' -x ${PRIV_PROTO} -X '${PRIV_PASS}' <SERVER-IP> 1.3.6.1.2.1.1"
echo
