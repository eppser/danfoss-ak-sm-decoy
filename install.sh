#!/bin/sh
# Install or update the cold-chain decoy on an edge host.  Idempotent.  Run as root from this
# directory.  It adds the external listeners of a real Danfoss AK-SM 800A beside your lure:
# Modbus/TCP 502, StoreView-Web (HTTPS) 8443, SNMP 5136/udp, Service Tool 1041/tcp and PI200
# 1041/udp.  Nothing it serves is real; every interaction is logged to
# /var/log/coldstore/coldstore.jsonl.
set -eu
D=$(cd "$(dirname "$0")" && pwd)

id coldstore >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin coldstore
echo "user: coldstore"

install -d -m 0755 /opt/coldstore
rm -rf /opt/coldstore/coldstore            # drop the old package layout on upgrade
install -m 0755 "$D/coldstore.py" /opt/coldstore/coldstore.py
find /opt/coldstore -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
echo "code: /opt/coldstore/coldstore.py"

install -d -m 0750 /etc/coldstore
if [ ! -f /etc/coldstore/cert.pem ]; then
  # Reproduce the real AK-SM 800A certificate chain (subjects verified against the
  # Danux firmware's /opt/create_ssl_cert.sh): a self-signed CA signs the web cert, so
  # an attacker inspecting the TLS cert sees the device's true issuer and subject.
  t=$(mktemp -d)
  CA_SUBJ="/C=US/ST=MD/L=Baltimore/O=Danfoss/OU=Certificate_Authority/CN=SelfSigned-DanfossSM800A"
  SRV_SUBJ="/C=US/ST=MD/L=Baltimore/O=Danfoss/OU=SM800A/CN=DanfossSM800A"
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$t/cakey.pem" >/dev/null 2>&1
  openssl req -new -x509 -key "$t/cakey.pem" -out "$t/cacert.pem" -days 3650 \
    -subj "$CA_SUBJ" >/dev/null 2>&1
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /etc/coldstore/key.pem >/dev/null 2>&1
  openssl req -new -key /etc/coldstore/key.pem -out "$t/req.csr" -subj "$SRV_SUBJ" >/dev/null 2>&1
  openssl x509 -req -in "$t/req.csr" -CA "$t/cacert.pem" -CAkey "$t/cakey.pem" \
    -CAcreateserial -days 3650 -out /etc/coldstore/cert.pem >/dev/null 2>&1
  # The real device uses a SEPARATE cert on the Service Tool port (/danfoss/certs/st_cert.pem);
  # reproduce that with a distinct key+cert under the same CA and subject.
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /etc/coldstore/st_key.pem >/dev/null 2>&1
  openssl req -new -key /etc/coldstore/st_key.pem -out "$t/st_req.csr" -subj "$SRV_SUBJ" >/dev/null 2>&1
  openssl x509 -req -in "$t/st_req.csr" -CA "$t/cacert.pem" -CAkey "$t/cakey.pem" \
    -CAcreateserial -days 3650 -out /etc/coldstore/st_cert.pem >/dev/null 2>&1
  # ship the CA alongside so a client that validates sees the real chain
  cp "$t/cacert.pem" /etc/coldstore/cacert.pem
  rm -rf "$t"
  echo "cert: /etc/coldstore/{cert,key}.pem + {st_cert,st_key}.pem (CN=DanfossSM800A, issuer SelfSigned-DanfossSM800A)"
fi
chown -R coldstore:coldstore /etc/coldstore
chmod 0640 /etc/coldstore/*.pem 2>/dev/null || true

install -m 0644 "$D/coldstore.service" /etc/systemd/system/coldstore.service
systemctl daemon-reload
systemctl enable --now coldstore.service
systemctl restart coldstore.service
echo "service: coldstore.service (Modbus 502, StoreView 8443, SNMP 5136/udp, Service Tool 1041, PI200 1041/udp)"

if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "^Status: active"; then
  ufw allow 502/tcp   comment 'coldstore modbus decoy'      >/dev/null || true
  ufw allow 8443/tcp  comment 'coldstore storeview decoy'   >/dev/null || true
  ufw allow 5136/udp  comment 'coldstore snmp decoy'        >/dev/null || true
  ufw allow 1041/tcp  comment 'coldstore service-tool decoy' >/dev/null || true
  ufw allow 1041/udp  comment 'coldstore pi200 decoy'       >/dev/null || true
  echo "ufw: allowed 502/tcp, 8443/tcp, 5136/udp, 1041/tcp, 1041/udp"
fi

sleep 1
printf "modbus device-id: "
python3 - <<'PY'
import socket, struct, sys
try:
    s = socket.create_connection(("127.0.0.1", 502), timeout=5)
    pdu = struct.pack(">BBBB", 0x2B, 0x0E, 0x01, 0x00)
    s.sendall(struct.pack(">HHHB", 1, 0, len(pdu) + 1, 1) + pdu)
    data = s.recv(512); s.close()
    print("OK" if b"Danfoss" in data else "unexpected response")
except Exception as e:
    print("FAILED:", e); sys.exit(1)
PY
curl -sk -o /dev/null -w "storeview https: HTTP %{http_code}\n" https://127.0.0.1:8443/
if command -v snmpget >/dev/null 2>&1; then
  printf "snmp sysDescr: "
  snmpget -v2c -c public -r1 -t2 -Ovq 127.0.0.1:5136 1.3.6.1.2.1.1.1.0 2>/dev/null || echo "(no response)"
fi
printf "listeners: "; ss -lntup 2>/dev/null | grep -Eo ':(502|8443|5136|1041)\b' | sort -u | tr '\n' ' '; echo
echo "log: /var/log/coldstore/coldstore.jsonl   (journalctl -u coldstore)"
