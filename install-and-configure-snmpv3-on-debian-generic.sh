#!/usr/bin/env bash

# SNMPv3 setup for Debian
# Installs and configures snmpd (SNMPv3 only) on UDP/161
# Creates a read-only SNMPv3 user with the strongest supported auth/priv methods
# Restricts UDP/161 by source CIDR via nftables firewall rules
# Writes a summary to ~/snmpd.creds (for the invoking user)
# Run the script -> bash -c "$(curl -fsSL https://raw.githubusercontent.com/celalettinb-art/snmp/refs/heads/main/install-and-configure-snmpv3-on-debian-generic.sh)"

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

prompt_yellow_bold() {
  # Usage: prompt_yellow_bold "Question: " VAR
  local q="$1"
  local __varname="$2"
  read -r -p "$(echo -e "${BOLD}${YELLOW}${q}${RESET}")" "$__varname"
}

# ======= Root check =======
if [[ "${EUID}" -ne 0 ]]; then
  fail "Please run this script as root (e.g. using sudo)."
fi

# ======= Determine target home for creds file =======
# If started via sudo, write creds to the invoking user's home (not /root).
TARGET_USER="${SUDO_USER:-root}"
TARGET_HOME="$(getent passwd "${TARGET_USER}" | cut -d: -f6 || true)"
if [[ -z "${TARGET_HOME}" || ! -d "${TARGET_HOME}" ]]; then
  TARGET_HOME="${HOME}"
fi
CREDS_FILE="${TARGET_HOME}/snmpd.creds"

# ======= Input: Allowed CIDR =======
prompt_yellow_bold "From which IP address range (CIDR) should SNMP requests be accepted? (e.g. 192.168.1.0/24): " ALLOW_CIDR
ALLOW_CIDR="${ALLOW_CIDR//[[:space:]]/}"
if [[ -z "${ALLOW_CIDR}" ]]; then
  fail "No IP address range provided."
fi

# Basic CIDR sanity check (not a full validator)
if ! [[ "${ALLOW_CIDR}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[12][0-9]|3[0-2])$ ]]; then
  warn "The CIDR value looks unusual: '${ALLOW_CIDR}'. Continuing anyway."
fi

# ======= Input: sysLocation (must not be empty) =======
SYS_LOCATION=""
while [[ -z "${SYS_LOCATION}" ]]; do
  prompt_yellow_bold "Enter sysLocation (e.g. DC Berlin Rack 3): " SYS_LOCATION
  SYS_LOCATION="${SYS_LOCATION//$'\r'/}"
  SYS_LOCATION="${SYS_LOCATION#"${SYS_LOCATION%%[![:space:]]*}"}"
  SYS_LOCATION="${SYS_LOCATION%"${SYS_LOCATION##*[![:space:]]}"}"
  if [[ -z "${SYS_LOCATION}" ]]; then
    warn "sysLocation must not be empty."
  fi
done

# ======= Input: sysContact email (must be valid and must not be empty) =======
is_valid_email() {
  local email="$1"
  [[ "$email" =~ ^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$ ]]
}

SYS_CONTACT=""
while true; do
  prompt_yellow_bold "Enter sysContact email address (e.g. admin@example.com): " SYS_CONTACT
  SYS_CONTACT="${SYS_CONTACT//[[:space:]]/}"
  if [[ -z "${SYS_CONTACT}" ]]; then
    warn "sysContact must not be empty."
    continue
  fi
  if is_valid_email "${SYS_CONTACT}"; then
    ok "sysContact email validated."
    break
  else
    warn "Invalid email format. Please enter a valid email address (e.g. admin@example.com)."
  fi
done

# ======= Install packages (if missing) =======
info "Installing required packages (snmpd, snmp, nftables, openssl) if not already installed..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends snmpd snmp nftables openssl
ok "Packages are installed."

# ======= Generate SNMPv3 credentials =======
USERNAME="snmpv3_$(openssl rand -hex 4)"

# SNMP passphrases must be at least 8 characters; use strong random strings.
AUTH_PASS="$(openssl rand -base64 36 | tr -d '\n' | tr '/+' 'Aa' | cut -c1-28)"
PRIV_PASS="$(openssl rand -base64 40 | tr -d '\n' | tr '/+' 'Bb' | cut -c1-32)"

# ======= Pick strongest supported auth/priv protocols (robust parsing) =======
# We parse from snmpwalk help because it usually prints supported -a/-x values consistently.
WALK_HELP="$(snmpwalk -h 2>&1 || true)"

extract_brace_values() {
  # Extracts the content inside {...} for a given option (e.g. -a or -x) from help text.
  # Returns a string like "SHA|SHA-256|SHA-512" or empty if not found.
  local opt="$1"
  echo "${WALK_HELP}" | sed -nE "s/.*${opt}[[:space:]]*\\{([^}]*)\\}.*/\\1/p" | head -n1
}

choose_best_from_list() {
  # Args: list_string (separated by | or ,), candidates...
  local list="$1"; shift
  local normalized
  # Normalize separators to newlines for easier matching
  normalized="$(echo "${list}" | tr '|' '\n' | tr ',' '\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  local c
  for c in "$@"; do
    if echo "${normalized}" | grep -qiE "^${c}$"; then
      echo "$c"
      return 0
    fi
  done
  return 1
}

AUTH_LIST="$(extract_brace_values "-a")"
PRIV_LIST="$(extract_brace_values "-x")"

# Prefer modern options, but only if supported by this installation.
AUTH_PROTO="$(choose_best_from_list "${AUTH_LIST}" "SHA-512" "SHA-384" "SHA-256" "SHA" || true)"
PRIV_PROTO="$(choose_best_from_list "${PRIV_LIST}" "AES-256" "AES-192" "AES" || true)"

# Last-resort fallback (some builds don't show braces in help, but still accept SHA/AES)
if [[ -z "${AUTH_PROTO}" ]]; then
  warn "Could not detect supported auth algorithms from snmpwalk help. Falling back to SHA."
  AUTH_PROTO="SHA"
fi
if [[ -z "${PRIV_PROTO}" ]]; then
  warn "Could not detect supported privacy algorithms from snmpwalk help. Falling back to AES."
  PRIV_PROTO="AES"
fi

info "Selected strongest supported SNMPv3 algorithms: auth='${AUTH_PROTO}', priv='${PRIV_PROTO}'."

# ======= Stop snmpd before creating user =======
info "Stopping snmpd (if running) before creating the SNMPv3 user..."
systemctl stop snmpd >/dev/null 2>&1 || true

# ======= Create SNMPv3 user (authPriv, read-only) =======
# net-snmp-create-v3-user stores USM keys in /var/lib/snmp/snmpd.conf
info "Creating SNMPv3 user (read-only, authPriv)..."
set +e
CREATE_OUT="$(
  (echo "y" | net-snmp-create-v3-user \
    -ro \
    -a "${AUTH_PROTO}" -A "${AUTH_PASS}" \
    -x "${PRIV_PROTO}" -X "${PRIV_PASS}" \
    "${USERNAME}") 2>&1
)"
RC=$?
set -e

if [[ $RC -ne 0 ]]; then
  echo "${CREATE_OUT}"
  fail "Failed to create SNMPv3 user."
fi
ok "SNMPv3 user created: ${USERNAME}"

# ======= Write snmpd.conf (SNMPv3 only, UDP/161) =======
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
#
# Allowed source CIDR: ${ALLOW_CIDR}
# NOTE: Source IP restriction is enforced by the firewall (nftables), not by snmpd.conf.
###############################################################################

# Listen on standard SNMP port
agentAddress udp:161

# System information (provided interactively)
sysLocation  "${SYS_LOCATION}"
sysContact   "${SYS_CONTACT}"

# No community strings defined -> SNMPv1/v2c effectively disabled.
# Do NOT add rocommunity or rwcommunity lines.

# SNMPv3 access: read-only, authPriv required
rouser ${USERNAME} authpriv

# Reduce unnecessary log noise
dontLogTCPWrappersConnects yes
EOF
ok "Configuration written: ${SNMPD_CONF}"

# ======= Firewall (nftables): allow CIDR to UDP/161, drop others =======
NFT_DIR="/etc/nftables.d"
NFT_SNMP="${NFT_DIR}/snmpd.nft"
NFT_MAIN="/etc/nftables.conf"

info "Configuring nftables rules to restrict UDP/161 to '${ALLOW_CIDR}'..."
mkdir -p "${NFT_DIR}"

# If our table already exists, remove it to avoid duplicates / load errors.
if nft list table inet snmpd_filter >/dev/null 2>&1; then
  nft delete table inet snmpd_filter >/dev/null 2>&1 || true
  warn "Existing nftables table 'inet snmpd_filter' was removed and will be recreated."
fi

cat > "${NFT_SNMP}" <<EOF
# Managed by setup script - SNMPd restriction
# This file enforces: UDP/161 allowed only from ${ALLOW_CIDR}, dropped otherwise.
table inet snmpd_filter {
  chain input {
    type filter hook input priority -150; policy accept;

    udp dport 161 ip saddr ${ALLOW_CIDR} counter accept
    udp dport 161 counter drop
  }
}
EOF

# Ensure /etc/nftables.conf includes /etc/nftables.d/*.nft
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
  # Create a minimal config WITHOUT flushing existing rulesets (safer default).
  cat > "${NFT_MAIN}" <<EOF
#!/usr/sbin/nft -f
# Minimal nftables config created by setup script
include "/etc/nftables.d/*.nft"
EOF
  warn "${NFT_MAIN} did not exist. A minimal config was created without flushing existing rulesets."
fi

systemctl enable --now nftables >/dev/null 2>&1 || true

# Load config (best effort)
if nft -f "${NFT_MAIN}" >/dev/null 2>&1; then
  ok "nftables configuration loaded."
else
  warn "Failed to load nftables configuration from ${NFT_MAIN}. Please review manually."
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

# ======= Write credentials file (for invoking user) =======
info "Writing relevant information to ${CREDS_FILE}..."
cat > "${CREDS_FILE}" <<EOF
# SNMPv3 credentials and configuration summary
# Generated on: $(date)
#
# IMPORTANT:
# - This file contains plaintext secrets. Keep it secure.
# - Recommended permissions: chmod 600 ${CREDS_FILE}

Allowed IP range : ${ALLOW_CIDR}
SNMP version     : v3 only
Port             : UDP/161

sysLocation      : ${SYS_LOCATION}
sysContact       : ${SYS_CONTACT}

SNMPv3 username  : ${USERNAME}

Authentication:
  Protocol       : ${AUTH_PROTO}
  Password       : ${AUTH_PASS}

Privacy (encryption):
  Protocol       : ${PRIV_PROTO}
  Password       : ${PRIV_PASS}

Configuration files:
  /etc/snmp/snmpd.conf        (daemon configuration)
  /var/lib/snmp/snmpd.conf    (SNMPv3 USM users/keys – do not edit manually)

Firewall rules:
  ${NFT_SNMP} (included via /etc/nftables.conf)

Test command example (run from an allowed host):
snmpwalk -v3 -l authPriv \\
  -u ${USERNAME} \\
  -a ${AUTH_PROTO} -A '${AUTH_PASS}' \\
  -x ${PRIV_PROTO} -X '${PRIV_PASS}' \\
  <SERVER-IP> 1.3.6.1.2.1.1
EOF

chmod 600 "${CREDS_FILE}" || true
chown "${TARGET_USER}:${TARGET_USER}" "${CREDS_FILE}" >/dev/null 2>&1 || true
ok "Credentials file written with permissions 600."

# ======= Final colored summary =======
echo
echo "${BOLD}${GREEN}===== Setup completed – Relevant information =====${RESET}"
echo "${BOLD}Allowed IP range:${RESET} ${YELLOW}${ALLOW_CIDR}${RESET} ${BLUE}(enforced via firewall)${RESET}"
echo "${BOLD}SNMP version:${RESET} ${YELLOW}v3 only${RESET}"
echo "${BOLD}Port:${RESET} ${YELLOW}UDP/161${RESET}"
echo
echo "${BOLD}sysLocation:${RESET} ${YELLOW}${SYS_LOCATION}${RESET}"
echo "${BOLD}sysContact:${RESET} ${YELLOW}${SYS_CONTACT}${RESET}"
echo
echo "${BOLD}SNMPv3 username:${RESET} ${YELLOW}${USERNAME}${RESET}"
echo "${BOLD}Auth protocol:${RESET} ${YELLOW}${AUTH_PROTO}${RESET}"
echo "${BOLD}Auth password:${RESET} ${YELLOW}${AUTH_PASS}${RESET}"
echo "${BOLD}Privacy protocol:${RESET} ${YELLOW}${PRIV_PROTO}${RESET}"
echo "${BOLD}Privacy password:${RESET} ${YELLOW}${PRIV_PASS}${RESET}"
echo
echo "${BOLD}Config file:${RESET} ${YELLOW}${SNMPD_CONF}${RESET}"
echo "${BOLD}Creds file:${RESET} ${YELLOW}${CREDS_FILE}${RESET}"
echo "${BOLD}Firewall rules:${RESET} ${YELLOW}${NFT_SNMP}${RESET}"
echo
echo "${BOLD}${YELLOW}Hint:${RESET} Test from an allowed host using:"
echo "  snmpwalk -v3 -l authPriv -u ${USERNAME} -a ${AUTH_PROTO} -A '${AUTH_PASS}' -x ${PRIV_PROTO} -X '${PRIV_PASS}' <SERVER-IP> 1.3.6.1.2.1.1"
echo
