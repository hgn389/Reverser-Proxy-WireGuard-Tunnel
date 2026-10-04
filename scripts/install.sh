#!/usr/bin/env bash
set -Eeuo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

repo="${RPCTL_REPO:-hgn389/Reverser-Proxy-WireGuard-Tunnel}"
release="${RPCTL_VERSION:-latest}"
acme_version="3.1.6"
acme_sha256="0d3f9000ac44a6331314742a88c475f79134e24fc991997883652adc59efc486"
wireguard="ask"
wireguard_mode="ask"
tailscale="no"
vpn_backend="ask"
acme="ask"
web="ask"
web_existing="no"
firewall="ask"
wireguard_option_seen=no
acme_option_seen=no
web_option_seen=no
firewall_option_seen=no

wg_network_env_set=no
wg_server_address_env_set=no
wg_client_address_env_set=no
[[ -n ${RPCTL_WG_NETWORK+x} ]] && wg_network_env_set=yes
[[ -n ${RPCTL_WG_SERVER_ADDRESS+x} ]] && wg_server_address_env_set=yes
[[ -n ${RPCTL_WG_CLIENT_ADDRESS+x} ]] && wg_client_address_env_set=yes
wg_address_override=no
if [[ $wg_network_env_set == yes || $wg_server_address_env_set == yes || $wg_client_address_env_set == yes ]]; then
  wg_address_override=yes
fi

wg_interface="${RPCTL_WG_INTERFACE:-wg0}"
default_wg_network="10.10.10.0/24"
default_wg_server_address="10.10.10.1/24"
default_wg_client_address="10.10.10.2/32"
wg_server_address="${RPCTL_WG_SERVER_ADDRESS:-$default_wg_server_address}"
wg_network="${RPCTL_WG_NETWORK:-$default_wg_network}"
wg_client_address="${RPCTL_WG_CLIENT_ADDRESS:-$default_wg_client_address}"
wg_port="${RPCTL_WG_PORT:-51820}"
wg_peer_name="${RPCTL_WG_PEER_NAME:-client1}"
wg_endpoint="${RPCTL_WG_ENDPOINT:-}"
tailscale_auth_key_file="${RPCTL_TS_AUTH_KEY_FILE:-}"

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
info() { printf '%s\n' "$*"; }

wait_for_web_panel() {
  local attempt
  for ((attempt = 1; attempt <= 20; attempt++)); do
    if curl --fail --silent --noproxy '*' --max-time 2 http://127.0.0.1:9080/login >/dev/null; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

valid_ipv4() {
  local address=$1 octet
  local -a octets
  IFS=. read -r -a octets <<< "$address"
  [[ ${#octets[@]} -eq 4 ]] || return 1
  for octet in "${octets[@]}"; do
    [[ $octet =~ ^[0-9]{1,3}$ ]] && ((10#$octet <= 255)) || return 1
  done
}

valid_ipv4_cidr() {
  local value=$1 address prefix
  [[ $value == */* ]] || return 1
  address=${value%/*}
  prefix=${value##*/}
  valid_ipv4 "$address" && [[ $prefix =~ ^[0-9]{1,2}$ ]] && ((10#$prefix <= 32))
}

valid_endpoint_host() {
  local host=$1 label
  local -a labels
  if valid_ipv4 "$host"; then
    return 0
  fi
  ((${#host} >= 1 && ${#host} <= 253)) || return 1
  [[ $host != .* && $host != *. && $host != *..* ]] || return 1
  IFS=. read -r -a labels <<< "$host"
  for label in "${labels[@]}"; do
    ((${#label} >= 1 && ${#label} <= 63)) || return 1
    [[ $label =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$ ]] || return 1
  done
}

ipv4_to_int() {
  local address=$1
  local -a octets
  IFS=. read -r -a octets <<< "$address"
  printf '%u\n' "$(( (10#${octets[0]} << 24) | (10#${octets[1]} << 16) | (10#${octets[2]} << 8) | 10#${octets[3]} ))"
}

int_to_ipv4() {
  local value=$1
  printf '%d.%d.%d.%d\n' \
    "$(( (value >> 24) & 255 ))" \
    "$(( (value >> 16) & 255 ))" \
    "$(( (value >> 8) & 255 ))" \
    "$(( value & 255 ))"
}

cidr_contains() {
  local network=$1 candidate=$2 prefix network_int candidate_int mask
  prefix=${network##*/}
  network_int=$(ipv4_to_int "${network%/*}")
  candidate_int=$(ipv4_to_int "${candidate%/*}")
  if ((10#$prefix == 0)); then
    mask=0
  else
    mask=$(( (0xFFFFFFFF << (32 - 10#$prefix)) & 0xFFFFFFFF ))
  fi
  (( (network_int & mask) == (candidate_int & mask) ))
}

cidr_is_canonical_network() {
  local network=$1 prefix network_int mask
  prefix=${network##*/}
  network_int=$(ipv4_to_int "${network%/*}")
  if ((10#$prefix == 0)); then
    mask=0
  else
    mask=$(( (0xFFFFFFFF << (32 - 10#$prefix)) & 0xFFFFFFFF ))
  fi
  (( (network_int & mask) == network_int ))
}

cidrs_overlap() {
  local left=$1 right=$2
  cidr_contains "$left" "$right" || cidr_contains "$right" "$left"
}

network_conflicts_with_routes() {
  local route_type destination remainder
  while read -r route_type destination remainder; do
    case "$route_type" in
      default) continue ;;
      local|broadcast|unreachable|prohibit|blackhole|throw) ;;
      *)
        destination=$route_type
        ;;
    esac
    if valid_ipv4 "$destination"; then
      destination="${destination}/32"
    fi
    valid_ipv4_cidr "$destination" || continue
    if cidrs_overlap "$wg_network" "$destination"; then
      return 0
    fi
  done < <(/usr/sbin/ip -4 route show table all)
  return 1
}

valid_wireguard_network() {
  local network=$1 prefix private_network private_prefix
  valid_ipv4_cidr "$network" || return 1
  prefix=${network##*/}
  ((10#$prefix >= 16 && 10#$prefix <= 30)) || return 1
  cidr_is_canonical_network "$network" || return 1
  for private_network in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do
    private_prefix=${private_network##*/}
    if ((10#$prefix >= 10#$private_prefix)) && cidr_contains "$private_network" "$network"; then
      return 0
    fi
  done
  return 1
}

derive_wireguard_addresses() {
  local network_int prefix
  network_int=$(ipv4_to_int "${wg_network%/*}")
  prefix=${wg_network##*/}
  wg_server_address="$(int_to_ipv4 "$((network_int + 1))")/${prefix}"
  wg_client_address="$(int_to_ipv4 "$((network_int + 2))")/32"
}

prompt_custom_wireguard_network() {
  local candidate
  while true; do
    printf 'Custom subnet in CIDR notation (for example, 10.79.0.0/24): ' > /dev/tty
    IFS= read -r candidate < /dev/tty || die 'Could not read terminal input.'
    if ! valid_wireguard_network "$candidate"; then
      printf 'Invalid subnet. Use a canonical private IPv4 subnet between /16 and /30, such as 10.79.0.0/24.\n' > /dev/tty
      continue
    fi
    wg_network=$candidate
    if network_conflicts_with_routes; then
      printf 'Subnet %s overlaps an existing route. Enter a different private subnet.\n' "$wg_network" > /dev/tty
      continue
    fi
    derive_wireguard_addresses
    return
  done
}

select_wireguard_network() {
  local answer
  if [[ $wg_address_override == yes ]]; then
    if [[ $wg_network_env_set == yes && $wg_server_address_env_set == no && $wg_client_address_env_set == no ]]; then
      valid_wireguard_network "$wg_network" || die 'RPCTL_WG_NETWORK must be a canonical private IPv4 subnet between /16 and /30.'
      derive_wireguard_addresses
    fi
    return
  fi
  if [[ $wireguard_option_seen == yes || $has_tty != yes ]]; then
    return
  fi

  printf '\nWireGuard subnet:\n' > /dev/tty
  printf '  1) Use default subnet: %s\n' "$default_wg_network" > /dev/tty
  printf '  2) Enter a custom private IPv4 subnet\n' > /dev/tty
  printf 'Select [1]: ' > /dev/tty
  IFS= read -r answer < /dev/tty || die 'Could not read terminal input.'
  case "$answer" in
    2)
      prompt_custom_wireguard_network
      ;;
    *)
      wg_network=$default_wg_network
      wg_server_address=$default_wg_server_address
      wg_client_address=$default_wg_client_address
      if network_conflicts_with_routes; then
        printf 'Default subnet %s overlaps an existing route. Enter a custom subnet instead.\n' "$wg_network" > /dev/tty
        prompt_custom_wireguard_network
      fi
      ;;
  esac
  info "WireGuard network: ${wg_network} (server ${wg_server_address}, initial peer ${wg_client_address})"
}

validate_wireguard_settings() {
  [[ $wg_interface =~ ^[A-Za-z0-9_.-]{1,15}$ ]] || die 'RPCTL_WG_INTERFACE is invalid.'
  valid_ipv4_cidr "$wg_server_address" || die 'RPCTL_WG_SERVER_ADDRESS must be a valid IPv4 CIDR.'
  valid_wireguard_network "$wg_network" || die 'RPCTL_WG_NETWORK must be a canonical private IPv4 subnet between /16 and /30.'
  valid_ipv4_cidr "$wg_client_address" || die 'RPCTL_WG_CLIENT_ADDRESS must be a valid IPv4 CIDR.'
  cidr_is_canonical_network "$wg_network" || die 'RPCTL_WG_NETWORK must use the canonical network address.'
  [[ ${wg_server_address##*/} == "${wg_network##*/}" ]] || die 'RPCTL_WG_SERVER_ADDRESS prefix must match RPCTL_WG_NETWORK.'
  [[ ${wg_client_address##*/} == 32 ]] || die 'RPCTL_WG_CLIENT_ADDRESS must identify one client with a /32 prefix.'
  cidr_contains "$wg_network" "$wg_server_address" || die 'RPCTL_WG_SERVER_ADDRESS must belong to RPCTL_WG_NETWORK.'
  cidr_contains "$wg_network" "$wg_client_address" || die 'RPCTL_WG_CLIENT_ADDRESS must belong to RPCTL_WG_NETWORK.'
  [[ ${wg_server_address%/*} != "${wg_client_address%/*}" ]] || die 'WireGuard server and client addresses must differ.'
  if [[ ! $wg_port =~ ^[0-9]{1,5}$ ]] || ((10#$wg_port < 1 || 10#$wg_port > 65535)); then
    die 'RPCTL_WG_PORT must be 1-65535.'
  fi
  [[ $wg_peer_name =~ ^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$ ]] || die 'RPCTL_WG_PEER_NAME is invalid.'
  if [[ -n $wg_endpoint ]]; then
    valid_endpoint_host "$wg_endpoint" || die 'RPCTL_WG_ENDPOINT must be an IPv4 address or DNS hostname.'
  fi
}

configure_wireguard() (
  umask 077
  validate_wireguard_settings
  local server_config="/etc/wireguard/${wg_interface}.conf"
  local peer_dir="/etc/rpctl/wireguard/peers"
  local client_config="${peer_dir}/${wg_peer_name}.conf"
  local staged_server="${workdir}/wg-server/${wg_interface}.conf"
  local staged_client="${workdir}/wg-client/rpclient.conf"
  local route public_interface detected_endpoint
  local server_private server_public client_private client_public preshared_key client_allowed_ips
  local completed=no previous_ip_forward="" sysctl_changed=no

  if [[ -e $server_config || -L $server_config ]]; then
    info "Existing WireGuard config ${server_config} was preserved; automatic configuration was skipped."
    return 0
  fi
  if [[ -e $client_config || -L $client_config ]]; then
    die "Refusing to overwrite existing WireGuard client config ${client_config}."
  fi
  if [[ $wireguard_mode == full && ( -e /etc/sysctl.d/99-rpctl-wireguard.conf || -L /etc/sysctl.d/99-rpctl-wireguard.conf ) ]]; then
    die 'Refusing to overwrite existing /etc/sysctl.d/99-rpctl-wireguard.conf.'
  fi
  route=$(/usr/sbin/ip -4 route get 1.1.1.1 2>/dev/null || true)
  public_interface=$(awk '{ for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i+1); exit } }' <<< "$route")
  detected_endpoint=$(awk '{ for (i = 1; i <= NF; i++) if ($i == "src") { print $(i+1); exit } }' <<< "$route")
  if [[ -z $wg_endpoint ]]; then
    wg_endpoint=$detected_endpoint
  fi
  valid_endpoint_host "$wg_endpoint" || die 'Could not detect a safe WireGuard endpoint; set RPCTL_WG_ENDPOINT.'
  if [[ $wireguard_mode == full ]]; then
    [[ $public_interface =~ ^[A-Za-z0-9_.-]{1,15}$ ]] || die 'Could not detect the public network interface.'
    [[ -x /usr/sbin/iptables ]] || die 'iptables is required for full-tunnel WireGuard.'
  fi
  if network_conflicts_with_routes; then
    die "WireGuard network ${wg_network} conflicts with an existing route. Override RPCTL_WG_* addresses."
  fi

  cleanup_wireguard_setup() {
    if [[ $completed == yes ]]; then
      return
    fi
    /usr/bin/systemctl disable --now "wg-quick@${wg_interface}" >/dev/null 2>&1 || true
    if [[ -e $server_config ]]; then /usr/bin/unlink "$server_config"; fi
    if [[ -e $client_config ]]; then /usr/bin/unlink "$client_config"; fi
    if [[ $sysctl_changed == yes ]]; then
      if [[ -e /etc/sysctl.d/99-rpctl-wireguard.conf ]]; then /usr/bin/unlink /etc/sysctl.d/99-rpctl-wireguard.conf; fi
      /usr/sbin/sysctl -w "net.ipv4.ip_forward=${previous_ip_forward}" >/dev/null 2>&1 || true
    fi
  }
  trap cleanup_wireguard_setup EXIT

  install -d -m 0700 /etc/wireguard /etc/rpctl/wireguard "$peer_dir" "${workdir}/wg-server" "${workdir}/wg-client"
  server_private=$(/usr/bin/wg genkey)
  server_public=$(printf '%s' "$server_private" | /usr/bin/wg pubkey)
  client_private=$(/usr/bin/wg genkey)
  client_public=$(printf '%s' "$client_private" | /usr/bin/wg pubkey)
  preshared_key=$(/usr/bin/wg genpsk)
  client_allowed_ips=$wg_network
  if [[ $wireguard_mode == full ]]; then
    client_allowed_ips="0.0.0.0/0"
  fi

  {
    printf '[Interface]\n'
    printf 'Address = %s\n' "$wg_server_address"
    printf 'ListenPort = %s\n' "$wg_port"
    printf 'PrivateKey = %s\n' "$server_private"
    if [[ $wireguard_mode == full ]]; then
      printf 'PostUp = /usr/sbin/iptables -A FORWARD -i %%i -j ACCEPT; /usr/sbin/iptables -A FORWARD -o %%i -j ACCEPT; /usr/sbin/iptables -t nat -A POSTROUTING -o %s -j MASQUERADE\n' "$public_interface"
      printf 'PostDown = /usr/sbin/iptables -D FORWARD -i %%i -j ACCEPT; /usr/sbin/iptables -D FORWARD -o %%i -j ACCEPT; /usr/sbin/iptables -t nat -D POSTROUTING -o %s -j MASQUERADE\n' "$public_interface"
    fi
    printf '\n[Peer]\n'
    printf '# %s\n' "$wg_peer_name"
    printf 'PublicKey = %s\n' "$client_public"
    printf 'PresharedKey = %s\n' "$preshared_key"
    printf 'AllowedIPs = %s\n' "$wg_client_address"
  } > "$staged_server"

  {
    printf '[Interface]\n'
    printf 'Address = %s\n' "$wg_client_address"
    printf 'PrivateKey = %s\n' "$client_private"
    printf '\n[Peer]\n'
    printf 'PublicKey = %s\n' "$server_public"
    printf 'PresharedKey = %s\n' "$preshared_key"
    printf 'Endpoint = %s:%s\n' "$wg_endpoint" "$wg_port"
    printf 'AllowedIPs = %s\n' "$client_allowed_ips"
    printf 'PersistentKeepalive = 25\n'
  } > "$staged_client"

  /usr/bin/wg-quick strip "$staged_server" >/dev/null || die 'Generated WireGuard server configuration is invalid.'
  /usr/bin/wg-quick strip "$staged_client" >/dev/null || die 'Generated WireGuard client configuration is invalid.'
  install -m 0600 "$staged_client" "$client_config"
  install -m 0600 "$staged_server" "$server_config"
  if [[ $wireguard_mode == full ]]; then
    previous_ip_forward=$(/usr/sbin/sysctl -n net.ipv4.ip_forward)
    cat > "$workdir/99-rpctl-wireguard.conf" <<'SYSCTL'
# Managed by rpctl.
net.ipv4.ip_forward=1
SYSCTL
    install -m 0644 "$workdir/99-rpctl-wireguard.conf" /etc/sysctl.d/99-rpctl-wireguard.conf
    sysctl_changed=yes
    /usr/sbin/sysctl -w net.ipv4.ip_forward=1 >/dev/null
  fi
  if ! /usr/bin/systemctl enable --now "wg-quick@${wg_interface}"; then
    /usr/bin/systemctl disable --now "wg-quick@${wg_interface}" >/dev/null 2>&1 || true
    /usr/bin/unlink "$server_config" 2>/dev/null || true
    /usr/bin/unlink "$client_config" 2>/dev/null || true
    if [[ $wireguard_mode == full ]]; then
      /usr/bin/unlink /etc/sysctl.d/99-rpctl-wireguard.conf 2>/dev/null || true
    fi
    die 'WireGuard failed to start; generated server and client configs were removed.'
  fi
  : > "$workdir/wireguard-configured"
  completed=yes
  cleanup_wireguard_setup
  info "WireGuard ${wireguard_mode} mode is active on ${wg_interface} (${wg_server_address}, UDP ${wg_port})."
  info "Initial client configuration: ${client_config}"
)

write_vpn_mode() {
  local mode=$1 temporary
  [[ $mode == wireguard || $mode == tailscale || $mode == none ]] || die 'Internal VPN mode is invalid.'
  if [[ -e /etc/rpctl/vpn-mode || -L /etc/rpctl/vpn-mode ]]; then
    [[ -f /etc/rpctl/vpn-mode && ! -L /etc/rpctl/vpn-mode ]] || die 'Refusing to replace non-regular /etc/rpctl/vpn-mode.'
  fi
  temporary="/etc/rpctl/.vpn-mode.$$"
  (umask 022; printf '%s\n' "$mode" > "$temporary")
  chmod 0644 "$temporary"
  mv -f "$temporary" /etc/rpctl/vpn-mode
}

configure_tailscale() {
  /usr/bin/systemctl enable --now tailscaled
  if /usr/bin/tailscale ip -4 >/dev/null 2>&1; then
    info 'Existing Tailscale login was preserved.'
  elif [[ -n $tailscale_auth_key_file ]]; then
    [[ $tailscale_auth_key_file == /* ]] || die 'RPCTL_TS_AUTH_KEY_FILE must be an absolute path.'
    [[ -f $tailscale_auth_key_file && ! -L $tailscale_auth_key_file ]] || die 'RPCTL_TS_AUTH_KEY_FILE must be a regular file and not a symbolic link.'
    [[ $(stat -c '%u' "$tailscale_auth_key_file") == 0 ]] || die 'RPCTL_TS_AUTH_KEY_FILE must be owned by root.'
    tailscale_key_mode=$(stat -c '%a' "$tailscale_auth_key_file")
    (( (8#$tailscale_key_mode & 077) == 0 )) || die 'RPCTL_TS_AUTH_KEY_FILE permissions must be 0600 or stricter.'
    /usr/bin/tailscale up --auth-key="file:${tailscale_auth_key_file}"
  elif [[ $has_tty == yes ]]; then
    info 'Tailscale will display a secure login URL. Complete the login to continue.'
    /usr/bin/tailscale up
  else
    die 'Noninteractive Tailscale setup requires RPCTL_TS_AUTH_KEY_FILE unless this VPS is already logged in.'
  fi
  tailscale_ip=$(/usr/bin/tailscale ip -4 2>/dev/null | head -n 1)
  [[ -n $tailscale_ip ]] || die 'Tailscale was installed but did not receive an IPv4 address.'
  info "Tailscale is connected (${tailscale_ip})."
}

for arg in "$@"; do
  case "$arg" in
    --wireguard|--wireguard-private|--wireguard-full|--no-wireguard|--tailscale|--no-vpn)
      [[ $wireguard_option_seen == no ]] || die 'Choose exactly one VPN option.'
      wireguard_option_seen=yes
      case "$arg" in
        --wireguard) wireguard="yes"; wireguard_mode="none"; vpn_backend="none" ;;
        --wireguard-private) wireguard="yes"; wireguard_mode="private"; vpn_backend="wireguard" ;;
        --wireguard-full) wireguard="yes"; wireguard_mode="full"; vpn_backend="wireguard" ;;
        --tailscale) wireguard="no"; wireguard_mode="none"; tailscale="yes"; vpn_backend="tailscale" ;;
        --no-wireguard|--no-vpn) wireguard="no"; wireguard_mode="none"; vpn_backend="none" ;;
      esac
      ;;
    --acme|--no-acme)
      [[ $acme_option_seen == no ]] || die 'Choose exactly one SSL option.'
      acme_option_seen=yes
      [[ $arg == --acme ]] && acme="yes" || acme="no"
      ;;
    --web|--no-web)
      [[ $web_option_seen == no ]] || die 'Choose exactly one Web Panel option.'
      web_option_seen=yes
      [[ $arg == --web ]] && web="yes" || web="no"
      ;;
    --open-firewall|--no-firewall)
      [[ $firewall_option_seen == no ]] || die 'Choose exactly one firewall option.'
      firewall_option_seen=yes
      [[ $arg == --open-firewall ]] && firewall="yes" || firewall="no"
      ;;
    --help)
      cat <<'HELP'
Usage: install.sh [VPN] [--acme | --no-acme] [--web | --no-web] [--open-firewall | --no-firewall]

VPN choices:
  --wireguard           Install tools only
  --wireguard-private   Configure private VPN (default interactive mode)
  --wireguard-full      Configure full-tunnel VPN
  --tailscale           Install and connect Tailscale
  --no-vpn              Do not install a VPN
  --no-wireguard        Legacy alias for --no-vpn

SSL choices:
  --acme                Install acme.sh and the certificate renewal timer
  --no-acme             Do not install acme.sh

Web Panel choices:
  --web                 Install the optional Web Panel
  --no-web              Do not install the Web Panel (minimal default)

Installs Nginx and rpctl. The web service is installed only with --web.
When UFW is active, --open-firewall allows HTTP, selected optional component ports,
and preserves SSH rules. HTTPS is opened when acme.sh is selected.
Set RPCTL_REPO=owner/repo to select your GitHub repository.
Set RPCTL_VERSION=vX.Y.Z to install a specific release.
Set RPCTL_WG_NETWORK to a canonical private IPv4 CIDR to derive the server and
initial peer addresses automatically. Advanced RPCTL_WG_* overrides remain available.
For noninteractive --tailscale, set RPCTL_TS_AUTH_KEY_FILE to a root-owned regular
file with permissions 0600 or stricter. The file is read directly by Tailscale.
For noninteractive --web, set RPCTL_WEB_USERNAME and RPCTL_WEB_PASSWORD_FILE
(a regular file with permissions 0600 or stricter). RPCTL_WEB_DOMAIN is optional;
without it, the panel listens on public port 9080.
HELP
      exit 0 ;;
    *) die "Unknown option: $arg" ;;
  esac
done

[[ $EUID -eq 0 ]] || die 'Run as root (for example, curl ... | sudo bash).'
install -d -m 0755 /run/rpctl
exec 9>/run/rpctl/install.lock
flock -n 9 || die 'Another rpctl installer is running.'
[[ $repo =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die 'RPCTL_REPO must be owner/repo.'
[[ $release == latest || $release =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die 'RPCTL_VERSION must be latest or vX.Y.Z.'

# shellcheck disable=SC1091
. /etc/os-release
case "${ID:-}:${VERSION_ID:-}" in
  ubuntu:22.04|ubuntu:24.04) ;;
  *) die 'Only Ubuntu Server 22.04 LTS and 24.04 LTS are supported.' ;;
esac

motd_path=/etc/update-motd.d/99-rpctl
if [[ -e $motd_path || -L $motd_path ]]; then
  [[ -f $motd_path && ! -L $motd_path && $(sed -n '2p' "$motd_path") == '# Managed by rpctl.' ]] || \
    die "Refusing to replace unmanaged MOTD file ${motd_path}."
fi

case "$(uname -m)" in
  x86_64) arch=amd64 ;;
  aarch64) arch=arm64 ;;
  *) die "Unsupported architecture: $(uname -m)" ;;
esac
info "Detected supported system: Ubuntu ${VERSION_ID} (${arch})."

has_tty=no
if /usr/bin/tty -s </dev/tty 2>/dev/null; then
  has_tty=yes
fi

web_path_count=0
for web_path in \
  /etc/rpctl/web/config.json \
  /etc/systemd/system/rpctl-web.service \
  /etc/systemd/system/rpctl-web-helper.socket \
  /etc/systemd/system/rpctl-web-helper@.service; do
  if [[ -e $web_path || -L $web_path ]]; then
    ((web_path_count += 1))
  fi
done
if ((web_path_count != 0 && web_path_count != 4)); then
  die 'An incomplete Web Panel installation exists. Inspect /etc/rpctl/web and the rpctl-web systemd units before rerunning.'
fi
if ((web_path_count == 4)); then
  web_existing=yes
  web=no
  info 'Existing Web Panel installation detected; its configuration will be preserved.'
fi

existing_vpn_backend=''
if [[ -e /etc/rpctl/vpn-mode || -L /etc/rpctl/vpn-mode ]]; then
  [[ -f /etc/rpctl/vpn-mode && ! -L /etc/rpctl/vpn-mode ]] || die 'Existing /etc/rpctl/vpn-mode is not a regular file.'
  existing_vpn_backend=$(tr -d '[:space:]' < /etc/rpctl/vpn-mode)
  [[ $existing_vpn_backend == wireguard || $existing_vpn_backend == tailscale || $existing_vpn_backend == none ]] || \
    die 'Existing /etc/rpctl/vpn-mode contains an invalid value.'
elif [[ -f "/etc/wireguard/${wg_interface}.conf" && ! -L "/etc/wireguard/${wg_interface}.conf" ]]; then
  existing_vpn_backend=wireguard
elif [[ -f /var/lib/tailscale/tailscaled.state && ! -L /var/lib/tailscale/tailscaled.state ]]; then
  existing_vpn_backend=tailscale
fi

if [[ $vpn_backend != ask && -n $existing_vpn_backend && $existing_vpn_backend != none && $vpn_backend != "$existing_vpn_backend" ]]; then
  die "This VPS already uses ${existing_vpn_backend}. The installer will not switch an active VPN backend automatically."
fi
if [[ $vpn_backend == ask && -n $existing_vpn_backend ]]; then
  vpn_backend=$existing_vpn_backend
  wireguard=no
  wireguard_mode=none
  tailscale=no
  if [[ $vpn_backend == wireguard ]]; then
    wireguard=yes
  fi
  info "Existing ${vpn_backend} VPN selection detected; it will be preserved."
elif [[ $vpn_backend == ask ]]; then
  if [[ $has_tty != yes ]]; then
    die 'No terminal detected. Pass --wireguard-private, --wireguard-full, --tailscale, or --no-vpn.'
  fi
  printf '\nSelect VPN backend:\n' > /dev/tty
  printf '  1) WireGuard (default)\n' > /dev/tty
  printf '  2) Tailscale\n' > /dev/tty
  printf '  3) No VPN\n' > /dev/tty
  printf 'Select [1]: ' > /dev/tty
  IFS= read -r answer < /dev/tty || die 'Could not read terminal input.'
  case "$answer" in
    2) vpn_backend=tailscale; tailscale=yes; wireguard=no; wireguard_mode=none ;;
    3) vpn_backend=none; tailscale=no; wireguard=no; wireguard_mode=none ;;
    *) vpn_backend=wireguard; tailscale=no; wireguard=yes ;;
  esac
fi
if [[ $wireguard == yes && $wireguard_mode == ask ]]; then
  if [[ $has_tty == yes ]]; then
    printf 'Configure WireGuard server and initial client now? [Y/n] ' > /dev/tty
    IFS= read -r answer < /dev/tty || die 'Could not read terminal input.'
    case "$answer" in
      n|N|no|NO) wireguard_mode=none ;;
      *)
        printf 'WireGuard mode: 1) private network  2) full tunnel [1]: ' > /dev/tty
        IFS= read -r answer < /dev/tty || die 'Could not read terminal input.'
        case "$answer" in 2) wireguard_mode=full ;; *) wireguard_mode=private ;; esac
        ;;
    esac
  else
    die 'No terminal detected. Pass --wireguard, --wireguard-private, or --wireguard-full.'
  fi
fi
if [[ $vpn_backend == wireguard && $wireguard_mode == none && $existing_vpn_backend != wireguard ]]; then
  vpn_backend=none
fi
if [[ $wireguard_mode == private || $wireguard_mode == full ]]; then
  select_wireguard_network
  validate_wireguard_settings
fi
if [[ $web == ask ]]; then
  if [[ $has_tty == yes ]]; then
    printf 'Install the optional Web Panel now? [y/N] ' > /dev/tty
    IFS= read -r answer < /dev/tty || die 'Could not read terminal input.'
    case "$answer" in y|Y|yes|YES) web=yes ;; *) web=no ;; esac
  else
    die 'No terminal detected. Pass --web or --no-web.'
  fi
fi
if [[ $acme == ask ]]; then
  if [[ $has_tty == yes ]]; then
    if [[ $web == yes ]]; then
      printf 'Install acme.sh for Web Panel HTTPS certificates and automatic renewal? [Y/n] ' > /dev/tty
    else
      printf 'Install acme.sh for HTTPS certificates and automatic renewal? [y/N] ' > /dev/tty
    fi
    IFS= read -r answer < /dev/tty || die 'Could not read terminal input.'
    if [[ $web == yes ]]; then
      case "$answer" in n|N|no|NO) acme=no ;; *) acme=yes ;; esac
    else
      case "$answer" in y|Y|yes|YES) acme=yes ;; *) acme=no ;; esac
    fi
  else
    die 'No terminal detected. Pass --acme or --no-acme.'
  fi
fi
if [[ $acme == yes && -e /opt/acme.sh && ! -e /opt/acme.sh/.rpctl-managed ]]; then
  die 'Existing /opt/acme.sh is not managed by rpctl; refusing to overwrite it.'
fi
ufw_active=no
if [[ -x /usr/sbin/ufw ]] && /usr/sbin/ufw status | /usr/bin/grep -qx 'Status: active'; then
  ufw_active=yes
fi
if [[ $ufw_active == yes && $firewall == ask ]]; then
  if [[ $has_tty == yes ]]; then
    firewall_ports='80/tcp'
    if [[ $acme == yes ]]; then firewall_ports+=', 443/tcp'; fi
    if [[ $web == yes ]]; then firewall_ports+=', 9080/tcp'; fi
    if [[ $wireguard_mode == private || $wireguard_mode == full ]]; then firewall_ports+=", ${wg_port}/udp"; fi
    printf 'UFW is active. Allow %s for the selected rpctl services? [Y/n] ' "$firewall_ports" > /dev/tty
    IFS= read -r answer < /dev/tty || die 'Could not read terminal input.'
    case "$answer" in n|N|no|NO) firewall=no ;; *) firewall=yes ;; esac
  else
    die 'UFW is active and no terminal was detected. Pass --open-firewall or --no-firewall.'
  fi
fi

asset="rpctl-linux-${arch}"
if [[ $release == latest ]]; then
  base="https://github.com/${repo}/releases/latest/download"
else
  base="https://github.com/${repo}/releases/download/${release}"
fi

workdir=$(mktemp -d)
new_binary=""
trap 'rm -rf -- "$workdir"; if [[ -n $new_binary ]]; then rm -f -- "$new_binary"; fi' EXIT
info "Downloading ${asset} from ${repo}..."
curl_flags=(--fail --location --silent --show-error --retry 3 --connect-timeout 15 --proto '=https' --proto-redir '=https' --tlsv1.2)
tailscale_repo_new=no
tailscale_package_needed=no
if [[ $tailscale == yes && ! -x /usr/bin/tailscale ]]; then
  tailscale_package_needed=yes
  tailscale_keyring=/usr/share/keyrings/tailscale-archive-keyring.gpg
  tailscale_list=/etc/apt/sources.list.d/tailscale.list
  if [[ ! -e $tailscale_keyring && ! -L $tailscale_keyring && ! -e $tailscale_list && ! -L $tailscale_list ]]; then
    info 'Downloading the official Tailscale APT repository configuration...'
    curl "${curl_flags[@]}" --max-time 60 --max-filesize 1048576 \
      -o "$workdir/tailscale-archive-keyring.gpg" "https://pkgs.tailscale.com/stable/ubuntu/${VERSION_CODENAME}.noarmor.gpg" || \
      die 'Tailscale repository key download failed.'
    curl "${curl_flags[@]}" --max-time 60 --max-filesize 1048576 \
      -o "$workdir/tailscale.list" "https://pkgs.tailscale.com/stable/ubuntu/${VERSION_CODENAME}.tailscale-keyring.list" || \
      die 'Tailscale repository configuration download failed.'
    [[ -s $workdir/tailscale-archive-keyring.gpg && -s $workdir/tailscale.list ]] || die 'Downloaded Tailscale repository files are empty.'
    tailscale_repo_new=yes
  elif [[ -f $tailscale_keyring && ! -L $tailscale_keyring && -f $tailscale_list && ! -L $tailscale_list ]]; then
    info 'Existing Tailscale APT repository configuration was preserved.'
  else
    die 'Incomplete or unsafe Tailscale APT repository configuration exists; inspect /usr/share/keyrings and /etc/apt/sources.list.d.'
  fi
fi
curl "${curl_flags[@]}" --max-time 180 --max-filesize 52428800 -o "$workdir/$asset" "$base/$asset" || die 'Binary download failed.'
curl "${curl_flags[@]}" --max-time 60 --max-filesize 1048576 -o "$workdir/SHA256SUMS" "$base/SHA256SUMS" || die 'Checksum download failed.'
expected=$(awk -v file="$asset" '$2 == file { print $1 }' "$workdir/SHA256SUMS")
[[ $expected =~ ^[a-fA-F0-9]{64}$ ]] || die 'Release checksum is missing or malformed.'
actual=$(sha256sum "$workdir/$asset")
actual=${actual%% *}
[[ ${actual,,} == "${expected,,}" ]] || die 'Checksum mismatch; refusing to install binary.'

if [[ $acme == yes ]]; then
  info "Downloading acme.sh ${acme_version} for SSL support..."
  acme_archive="$workdir/acme.sh-${acme_version}.tar.gz"
  curl "${curl_flags[@]}" --max-time 120 --max-filesize 5242880 \
    -o "$acme_archive" "https://github.com/acmesh-official/acme.sh/archive/refs/tags/${acme_version}.tar.gz" || die 'acme.sh download failed.'
  acme_actual=$(sha256sum "$acme_archive")
  acme_actual=${acme_actual%% *}
  [[ $acme_actual == "$acme_sha256" ]] || die 'acme.sh checksum mismatch; refusing to install it.'
  tar -xzf "$acme_archive" -C "$workdir"
  [[ -x "$workdir/acme.sh-${acme_version}/acme.sh" ]] || die 'Downloaded acme.sh archive is malformed.'
fi
chmod 0755 "$workdir/$asset"
reported_version=$("$workdir/$asset" version) || die 'Downloaded binary cannot run on this VPS.'
[[ $reported_version =~ ^rpctl\ v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die 'Downloaded binary does not report a release version.'
if [[ $release != latest && $reported_version != "rpctl $release" ]]; then
  die "Downloaded binary reports ${reported_version}; expected rpctl ${release}."
fi

if [[ -e /usr/local/bin/rp || -L /usr/local/bin/rp ]]; then
  [[ -L /usr/local/bin/rp && $(readlink /usr/local/bin/rp) == /usr/local/bin/rpctl ]] || die '/usr/local/bin/rp is already used by another program.'
fi
[[ ! -e /usr/local/bin/.rpctl-new && ! -L /usr/local/bin/.rpctl-new ]] || die 'Temporary install path already exists.'
if [[ -e /usr/local/bin/rpctl || -L /usr/local/bin/rpctl ]]; then
  [[ -f /usr/local/bin/rpctl && ! -L /usr/local/bin/rpctl ]] || die 'Refusing to replace non-regular rpctl path.'
fi

info 'Installing Nginx and required tools...'
export DEBIAN_FRONTEND=noninteractive
if [[ $tailscale_repo_new == yes ]]; then
  install -d -m 0755 /usr/share/keyrings /etc/apt/sources.list.d
  install -m 0644 "$workdir/tailscale-archive-keyring.gpg" /usr/share/keyrings/tailscale-archive-keyring.gpg
  install -m 0644 "$workdir/tailscale.list" /etc/apt/sources.list.d/tailscale.list
fi
apt-get update
packages=(nginx ca-certificates)
if [[ $wireguard == yes ]]; then packages+=(wireguard-tools); fi
if [[ $wireguard_mode == full ]]; then packages+=(iptables); fi
if [[ $tailscale_package_needed == yes ]]; then packages+=(tailscale); fi
apt-get install -y --no-install-recommends "${packages[@]}"

install -d -m 0755 /etc/rpctl/sites
install -d -m 0700 /var/lib/rpctl/rollback
if [[ $acme == yes ]]; then
  install -d -m 0700 /etc/rpctl/acme /etc/rpctl/acme/certs /etc/rpctl/certs
  install -d -m 0755 /var/lib/rpctl/acme-webroot
fi
find /etc/rpctl/sites -mindepth 1 -maxdepth 1 -type f -name '*.json' -exec chmod 0644 -- {} +
/usr/sbin/nginx -t || die 'Nginx configuration test failed; no rpctl binary was installed.'
/usr/bin/systemctl enable --now nginx

if [[ $acme == yes ]]; then
  install -d -m 0755 /opt/acme.sh
  cp -a "$workdir/acme.sh-${acme_version}/." /opt/acme.sh/
  touch /opt/acme.sh/.rpctl-managed
  chmod 0755 /opt/acme.sh/acme.sh

  cat > "$workdir/rpctl-ssl-renew.service" <<'SERVICE'
[Unit]
Description=Renew rpctl TLS certificates
After=network-online.target nginx.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/rpctl ssl renew-all
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectHome=true
ProtectSystem=strict
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
ReadWritePaths=/etc/rpctl /var/lib/rpctl /run/rpctl
ReadWritePaths=-/var/log/nginx -/run/nginx.pid
SERVICE
  cat > "$workdir/rpctl-ssl-renew.timer" <<'TIMER'
[Unit]
Description=Daily rpctl TLS certificate renewal check

[Timer]
OnCalendar=daily
RandomizedDelaySec=6h
Persistent=true

[Install]
WantedBy=timers.target
TIMER
  install -m 0644 "$workdir/rpctl-ssl-renew.service" /etc/systemd/system/rpctl-ssl-renew.service
  install -m 0644 "$workdir/rpctl-ssl-renew.timer" /etc/systemd/system/rpctl-ssl-renew.timer
fi
new_binary=/usr/local/bin/.rpctl-new
install -m 0755 "$workdir/$asset" "$new_binary"
had_binary=no
if [[ -e /usr/local/bin/rpctl ]]; then
  cp -p /usr/local/bin/rpctl /usr/local/bin/rpctl.previous
  had_binary=yes
fi
mv -f "$new_binary" /usr/local/bin/rpctl
new_binary=""
ln -sfn /usr/local/bin/rpctl /usr/local/bin/rp
if ! /usr/local/bin/rpctl system recover; then
  if [[ $had_binary == yes ]]; then
    mv -f /usr/local/bin/rpctl.previous /usr/local/bin/rpctl
  else
    rm -f -- /usr/local/bin/rpctl /usr/local/bin/rp
  fi
  die 'Interrupted proxy transaction recovery failed; restored the previous installation.'
fi
if [[ -f /etc/rpctl/web/config.json ]]; then
  if ! /usr/local/bin/rpctl web refresh; then
    if [[ $had_binary == yes ]]; then
      mv -f /usr/local/bin/rpctl.previous /usr/local/bin/rpctl
    else
      rm -f -- /usr/local/bin/rpctl /usr/local/bin/rp
    fi
    die 'Could not refresh the installed Web Panel service units; restored the previous binary.'
  fi
fi
if /usr/bin/systemctl is-active --quiet rpctl-web.service; then
  if ! /usr/bin/systemctl restart rpctl-web.service || ! wait_for_web_panel; then
    if [[ $had_binary == yes ]]; then
      mv -f /usr/local/bin/rpctl.previous /usr/local/bin/rpctl
      if ! /usr/bin/systemctl restart rpctl-web.service || ! wait_for_web_panel; then
        die 'Updated Web Panel failed its health check and the previous binary could not be restored to a healthy state.'
      fi
    else
      /usr/bin/systemctl stop rpctl-web.service || true
      rm -f -- /usr/local/bin/rpctl /usr/local/bin/rp
    fi
    die 'Updated Web Panel failed its health check; restored the previous binary.'
  fi
fi
if [[ $acme == yes ]]; then
  /usr/bin/systemctl daemon-reload
  /usr/bin/systemctl enable --now rpctl-ssl-renew.timer
fi
if [[ $wireguard_mode == private || $wireguard_mode == full ]]; then
  configure_wireguard
fi
if [[ $tailscale == yes ]]; then
  configure_tailscale
fi
write_vpn_mode "$vpn_backend"

if [[ $ufw_active == yes && $firewall == yes ]]; then
  info 'Applying firewall rule: ufw allow 80/tcp'
  /usr/sbin/ufw allow 80/tcp
  if [[ $acme == yes ]]; then
    info 'Applying firewall rule: ufw allow 443/tcp'
    /usr/sbin/ufw allow 443/tcp
  fi
  if [[ -e $workdir/wireguard-configured ]]; then
    info "Applying firewall rule: ufw allow ${wg_port}/udp"
    /usr/sbin/ufw allow "${wg_port}/udp"
  fi
elif [[ $ufw_active == yes ]]; then
  info 'UFW is active; rpctl service firewall rules were not changed.'
fi

web_domain=''
web_username=''
web_password_display=''
if [[ $web == yes ]]; then
  web_firewall_args=()
  if [[ $firewall == no ]]; then
    web_firewall_args+=(--no-open-firewall)
  fi
  if [[ $has_tty == yes ]]; then
    printf 'Web Panel domain (press Enter to use IP:9080 only): ' > /dev/tty
    IFS= read -r web_domain < /dev/tty || die 'Could not read the Web Panel domain.'
    printf 'Admin username: ' > /dev/tty
    IFS= read -r web_username < /dev/tty || die 'Could not read the Web Panel username.'
    printf 'Admin password (12-72 characters): ' > /dev/tty
    IFS= read -r -s web_password < /dev/tty || die 'Could not read the Web Panel password.'
    printf '\nConfirm password: ' > /dev/tty
    IFS= read -r -s web_password_confirmation < /dev/tty || die 'Could not confirm the Web Panel password.'
    printf '\n' > /dev/tty
    [[ $web_password == "$web_password_confirmation" ]] || die 'Web Panel password confirmation does not match.'
    if LC_ALL=C /usr/bin/grep -q '[^ -~]' <<< "$web_password"; then
      die 'The interactive Web Panel password must contain printable ASCII characters only.'
    fi
    web_password_file="$workdir/web-password"
    (umask 077; printf '%s' "$web_password" > "$web_password_file")
    web_password_display=$web_password
    unset web_password web_password_confirmation
    /usr/local/bin/rpctl web install \
      --domain "$web_domain" \
      --username "$web_username" \
      --password-file "$web_password_file" \
      "${web_firewall_args[@]}" || \
      die 'Web Panel installation failed; the core CLI remains installed.'
    rm -f -- "$web_password_file"
  else
    [[ -n ${RPCTL_WEB_USERNAME:-} && -n ${RPCTL_WEB_PASSWORD_FILE:-} ]] || \
      die 'Noninteractive --web requires RPCTL_WEB_USERNAME and RPCTL_WEB_PASSWORD_FILE. RPCTL_WEB_DOMAIN is optional.'
    web_domain=${RPCTL_WEB_DOMAIN:-}
    web_username=$RPCTL_WEB_USERNAME
    web_password_display='(the password supplied in RPCTL_WEB_PASSWORD_FILE)'
    /usr/local/bin/rpctl web install \
      --domain "$web_domain" \
      --username "$web_username" \
      --password-file "$RPCTL_WEB_PASSWORD_FILE" \
      "${web_firewall_args[@]}" || \
      die 'Web Panel installation failed; the core CLI remains installed.'
  fi
fi

cat > "$workdir/99-rpctl" <<'MOTD'
#!/bin/sh
# Managed by rpctl.
if [ -x /usr/local/bin/rpctl ]; then
  /usr/local/bin/rpctl motd 2>/dev/null || true
fi
MOTD
install -m 0755 "$workdir/99-rpctl" "$motd_path"

if [[ $web == yes ]]; then
  server_ip=$(/usr/sbin/ip -4 route get 1.1.1.1 2>/dev/null | /usr/bin/awk '{ for (i = 1; i <= NF; i++) if ($i == "src") { print $(i+1); exit } }')
  [[ -n $server_ip ]] || server_ip='SERVER_IP'
  web_ssl_ready=no
  if [[ -n $web_domain ]] && /usr/local/bin/rpctl ssl status "$web_domain" | /usr/bin/awk '$2 == "enabled" { found=1 } END { exit !found }'; then
    web_ssl_ready=yes
  fi
  info ''
  info '############################################################'
  info '#             rpctl installation completed                 #'
  info '############################################################'
  if [[ -n $web_domain ]]; then
    if [[ $web_ssl_ready == yes ]]; then
      info "Web Panel domain: https://${web_domain} (SSL ready)"
    else
      info "Web Panel domain: https://${web_domain} (SSL pending)"
    fi
  fi
  info "Direct access:    http://${server_ip}:9080"
  info "Username:         ${web_username}"
  info "Password:         ${web_password_display}"
  if [[ -f /etc/rpctl/wireguard/peers/client1.conf ]]; then
    info 'Client configuration: /etc/rpctl/wireguard/peers/client1.conf'
  fi
  if [[ $vpn_backend == tailscale && -x /usr/bin/tailscale ]]; then
    info "Tailscale address: $(/usr/bin/tailscale ip -4 2>/dev/null | head -n 1)"
  fi
  info 'Terminal menu:    rp'
  info '############################################################'
  if [[ -n $web_domain && $web_ssl_ready == no ]]; then
    info 'SSL is not ready yet. Use direct access now.'
    info "After DNS points to this VPS, run: rp -> 9. SSL certificates -> 2. Issue certificate -> ${web_domain}"
  fi
  if [[ $ufw_active == yes && $firewall == no ]]; then
    info 'WARNING: UFW is active and its rules were not changed. Allow 9080/tcp before using direct access.'
  fi
elif [[ $web_existing == yes ]]; then
  info 'rpctl update completed. Existing Web Panel settings were preserved. Open the terminal menu with: rp'
else
  info 'rpctl installation completed. Open the terminal menu with: rp'
  info 'Install the optional Web Panel later from menu item 10.'
fi
