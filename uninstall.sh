#!/bin/sh
# Remove the cold-chain decoy.  Keeps the log (the evidence) unless --purge is given.
set -eu
systemctl disable --now coldstore.service 2>/dev/null || true
rm -f /etc/systemd/system/coldstore.service
systemctl daemon-reload 2>/dev/null || true
rm -rf /opt/coldstore
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "^Status: active"; then
  ufw delete allow 502/tcp  >/dev/null 2>&1 || true
  ufw delete allow 8443/tcp >/dev/null 2>&1 || true
  ufw delete allow 5136/udp >/dev/null 2>&1 || true
  ufw delete allow 1041/tcp >/dev/null 2>&1 || true
  ufw delete allow 1041/udp >/dev/null 2>&1 || true
fi
echo "removed: service, code, firewall rules"
if [ "${1:-}" = "--purge" ]; then
  rm -rf /etc/coldstore /var/log/coldstore
  userdel coldstore 2>/dev/null || true
  echo "purged: cert, logs, user"
else
  echo "kept: /etc/coldstore (cert), /var/log/coldstore (log), user coldstore  (use --purge to remove)"
fi
