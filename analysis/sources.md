# Sources

## Binary / firmware (ground truth)

- `sm_app` — the AK-SM 800A application binary (ARM EABI5, full DWARF, 1617 `TFN_*` symbols),
  extracted from the publicly downloadable Danfoss firmware package.
- `firewall1.sh`, `create_ssl_cert.sh`, `nginx-auth-proxy/nginx.conf` — plaintext scripts/config
  shipped in the same firmware.
- Tooling: `pahole`, `nm`, `readelf`, `arm-linux-gnueabihf-objdump`, `strings`, `openssl`.

## Public documentation

- **AK-SM 800A series User Guide** `BC337629891709en-001001` — port table, Service Tool §8, PI-200
  setup, SNMP/Modbus channel config.
  <https://assets.danfoss.com/documents/584955/BC337629891709en-001001.pdf>
- **AK-SM 820A/850A/880A Data sheet** `AI354138789910en-000901` — port table, fieldbus capacities.
  <https://assets.danfoss.com/documents/584950/AI354138789910en-000901.pdf>
- **IANA Private Enterprise Numbers** — PEN **9615 = Danfoss A/S** (confirms the `1.3.6.1.4.1.9615`
  arc). <https://www.iana.org/assignments/enterprise-numbers>

## Vulnerability research (2025) — protocol surface only

- **CISA ICSA-25-140-03** (Update A) — CVE-2025-41450 / -41451 / -41452.
  <https://www.cisa.gov/news-events/ics-advisories/icsa-25-140-03>
- **Danfoss DSA-2025-03-01**.
  <https://www.danfoss.com/en/service-and-support/coordinated-vulnerability-disclosure/danfoss-security-advisories/dsa-2025-03-01/>
- **Claroty Team82**, "Freeze the Controller, Defrost the Food" — documents the `xml.cgi?action=getauth`
  auth endpoint, the `load_nginx_headers` / `headers.conf` DoS, and the SMTP-field command injection.
  <https://claroty.com/team82/research/freeze-the-controller-defrost-the-food-uncovering-vulnerabilities-in-danfoss-refrigeration-controllers>

| CVE | Class | Fixed in |
|---|---|---|
| CVE-2025-41450 | Improper authentication ("code-of-the-day") | R4.2 |
| CVE-2025-41451 | OS command injection (alarm/SMTP field) | 4.3.1 |
| CVE-2025-41452 | External control of config (`load_nginx_headers` DoS) | 4.3.1 |
