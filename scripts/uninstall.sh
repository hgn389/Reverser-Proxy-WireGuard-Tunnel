#!/usr/bin/env bash
set -Eeuo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

[[ $# -eq 0 ]] || { printf 'Usage: uninstall.sh\n' >&2; exit 2; }
[[ $EUID -eq 0 ]] || { printf 'Run as root.\n' >&2; exit 1; }
[[ -x /usr/local/bin/rpctl ]] || { printf 'rpctl is not installed.\n' >&2; exit 1; }

# Restore any transaction interrupted before its state file was committed. This
# must happen before listing sites or the list could reflect a partial update.
/usr/local/bin/rpctl system recover

/usr/bin/systemctl disable --now rpctl-ssl-renew.timer 2>/dev/null || true
/usr/bin/systemctl disable --now rpctl-web.service rpctl-web-helper.socket 2>/dev/null || true
if [[ -f /var/lib/rpctl/web-ufw-9080-managed && ! -L /var/lib/rpctl/web-ufw-9080-managed ]]; then
  if [[ -x /usr/sbin/ufw ]]; then
    /usr/sbin/ufw --force delete allow 9080/tcp || true
  fi
  rm -- /var/lib/rpctl/web-ufw-9080-managed
fi

# Delete only sites returned from canonical rpctl state. Each deletion checks
# nginx -t, reloads, and restores the prior site on failure.
site_output=$(/usr/local/bin/rpctl proxy list --quiet)
while IFS= read -r domain; do
  [[ -n $domain ]] || continue
  /usr/local/bin/rpctl proxy delete "$domain"
done <<< "$site_output"

if [[ -L /usr/local/bin/rp && $(readlink /usr/local/bin/rp) == /usr/local/bin/rpctl ]]; then
  rm -- /usr/local/bin/rp
fi
rm -- /usr/local/bin/rpctl
rm -f -- /usr/local/bin/rpctl.previous
rm -f -- /etc/systemd/system/rpctl-ssl-renew.service /etc/systemd/system/rpctl-ssl-renew.timer
renew_dropin=/etc/systemd/system/rpctl-ssl-renew.service.d/rpctl-nginx-runtime.conf
if [[ -f $renew_dropin && ! -L $renew_dropin ]] && \
   [[ $(sed -n '1p' "$renew_dropin") == '# Managed by rpctl.' ]]; then
  rm -- "$renew_dropin"
  rmdir --ignore-fail-on-non-empty -- /etc/systemd/system/rpctl-ssl-renew.service.d
fi
rm -f -- /etc/systemd/system/rpctl-web.service /etc/systemd/system/rpctl-web-helper.socket /etc/systemd/system/rpctl-web-helper@.service
rm -rf -- /etc/rpctl/web
rm -rf -- /var/lib/rpctl/web
if [[ -f /etc/rpctl/vpn-mode && ! -L /etc/rpctl/vpn-mode ]] && \
   [[ $(tr -d '[:space:]' < /etc/rpctl/vpn-mode) =~ ^(wireguard|tailscale|none)$ ]]; then
  rm -- /etc/rpctl/vpn-mode
fi
rm -f -- /run/rpctl/web-helper.sock
rm -f -- /run/rpctl/update.lock
if [[ -f /etc/update-motd.d/99-rpctl && ! -L /etc/update-motd.d/99-rpctl ]] && \
   [[ $(sed -n '2p' /etc/update-motd.d/99-rpctl) == '# Managed by rpctl.' ]]; then
  rm -- /etc/update-motd.d/99-rpctl
fi
/usr/bin/systemctl daemon-reload
if /usr/bin/id rpweb >/dev/null 2>&1; then
  /usr/sbin/userdel rpweb
fi
if /usr/bin/getent group rpweb >/dev/null 2>&1; then
  /usr/sbin/groupdel rpweb
fi
printf 'rpctl uninstalled. Nginx, WireGuard, Tailscale, certificates, acme.sh account data, and rollback copies were kept.\n'
