# coldstore — a refrigeration system-manager decoy

A second lure to run beside Cowrie on an edge. It presents the surface that attackers scanned for
in the October 2026 campaign against French grocery chains: an internet-exposed **refrigeration
system manager** of the Danfoss AK-SM family. It is one stdlib Python file (`coldstore.py`) you run
directly. Five listeners — the exact external port profile of a real AK-SM 800A, verified from the
device firmware's own firewall (`firewall1.sh`) — share one simulated store:

| listener | port | what it imitates |
|---|---|---|
| Modbus/TCP | 502 | the southbound control bus an AK-SM exposes; reads return live case temperatures and setpoints, writes are accepted and reflected |
| StoreView-Web (HTTPS) | 8443 | the remote management UI (`nginx/1.26.0`, title *Danfoss - StoreView Web*): login, dashboard, alarms, configuration, and `xml.cgi` |
| SNMP | 5136/udp | the device's SNMP agent (Danfoss uses fixed UDP **5136**, not 161): answers the system group with the unit's real identity under Danfoss's enterprise OID `1.3.6.1.4.1.9615` |
| Service Tool | 1041/tcp | the proprietary Danfoss Service Tool port — accepts and records the client's opening bytes |
| PI200 | 1041/udp | the proprietary Danfoss PI200 discovery port — records the datagram |

It is a **decoy**. There is no refrigeration behind it — the plant is a time-driven simulation,
and a "write" (a Modbus register write, a setpoint change in the web UI) is stored in memory and
shown back on the next read so the caller believes it took effect, while the attempt is logged as a
control action. Nothing is actuated; nothing reaches out. Run it directly:

```
python3 coldstore.py            # all five listeners on one shared plant; Ctrl-C to stop
```

## What it logs

One JSON line per interaction in `/var/log/coldstore/coldstore.jsonl` (also the journal), with the
caller's real address and an ISO-8601 Europe/Berlin timestamp. Scans and reads are `severity:
"info"`; the actions that matter — a register/coil write, a setpoint change, a login — are
`severity: "control"` and carry the case name and the value the attacker tried to set. Example:

```json
{"ts":"2026-10-12T18:40:11+02:00","proto":"modbus","action":"setpoint","severity":"control",
 "src":"203.0.113.9:51044","fc":6,"node":20,"case":"Surgeles Bac 1","new_setpoint_c":45.0,"register":1020}
{"ts":"2026-10-12T18:41:02+02:00","proto":"storeview","action":"web_login","severity":"control",
 "src":"203.0.113.9:51090","username":"admin","password":"Danfoss2019"}
```

## The simulated store

A fictional supermarket (`Supermarche Pre-Vert`, unit `PREVERT-SM01`) with two suction groups —
a medium-temperature rack of chilled cabinets (charcuterie, cremerie, fruits et legumes, …) and a
low-temperature rack of freezers — modelled as twelve Danfoss-style case controllers. Air
temperatures cycle around each setpoint with the compressor, climb during periodic defrost and
recover, and carry a little deterministic noise, so the plant looks alive across restarts. Raise a
setpoint and the case drifts toward it; force a compressor coil off and the cabinet warms. Device
identification over Modbus (FC 43/14) answers `Danfoss` / `AK-SM 800A` / `ADAP-KOOL`.

## Register map (Modbus, 0-based)

| area | address | meaning |
|---|---|---|
| holding (R/W) | `1000 + node` | setpoint, °C×10 signed — the attack target |
| holding (R/W) | `1200 / 1400 / 1600 + node` | alarm high / alarm low / differential |
| input (R) | `3000 / 3200 / 3400 + node` | air temp / evaporator temp / compressor run ratio |
| input (R) | `2900 / 2901` | MT / LT suction pressure, bar×100 |
| coil (R/W) | `100 + node` | compressor enable (0 = forced off) |
| coil (R/W) | `300 + node` | defrost start |
| discrete (R) | `100 + node` | alarm active |

`node` is a case address (1–8 chilled, 20–23 frozen).

## Emulated endpoints and exploit logging

The web side mirrors the real device's structure: an `nginx` front, the page title *Danfoss
StoreView*, and the single API/auth endpoint **`xml.cgi`** (`action=getauth` for authentication,
`action=load_nginx_headers`, `getstatus`, `set_email`, …), plus the configuration pages (network,
users, alarms, e-mail/SMTP, logging, maintenance). It emulates the *presence* of the endpoints
named in the public advisories so an exploit attempt gets a plausible response and is logged as a
high-signal `exploit_attempt`:

| signature | what it matches | from |
|---|---|---|
| `auth_getauth` | `xml.cgi?action=getauth` (the "code of the day" auth path) | CVE-2025-41450 |
| `command_injection_attempt` | shell metacharacters in a settings field (e.g. e-mail/SMTP) | CVE-2025-41451 |
| `path_traversal_attempt` | `../` or `/etc/passwd` in a path or parameter | generic probing |

It does **not** implement the authentication bypass or run any injected command. There is no
vulnerable code behind the endpoints: the honeypot captures the payload verbatim, returns a
believable response, and actuates nothing. The published exploit therefore "lands" (the attacker
sees a response and is logged) but cannot compromise the host — which also means a genuine
firmware-level exploit will not pop it, by design.

## Install

```
sudo ./install.sh          # user, cert, systemd unit, firewall; prints a health check
sudo ./uninstall.sh        # keeps the log; --purge removes cert, log and user
```

Hardened unit (`coldstore.service`): runs as the unprivileged `coldstore` user with only
`CAP_NET_BIND_SERVICE`, a read-only filesystem apart from the log directory, a syscall filter,
memory and task caps, and no outbound capability. The web listener uses a self-signed device-style
certificate (`/etc/coldstore/`). Robust against malformed input: bounded reads, per-connection
request and idle limits, a per-address connection cap, and correct Modbus exception responses.

## Tests

```
python3 -m unittest test_coldstore      # Modbus, web UI, SNMP, the proprietary ports, logging
```

36 tests: Modbus framing and semantics, the StoreView web surface (incl. byte-exact nginx
error/405/204 fixtures), the SNMP system group (v1/v2c GET + GETNEXT walk, Danfoss OID, bad-community
drop, SET logged as control and changes nothing), the Service Tool / PI200 capture, and that every
interaction is logged with the right severity.

## Discovery

All five ports are reachable from the internet, so Shodan / Censys / ZoomEye crawlers index the
decoy on their own over time: Modbus 502 reports `Danfoss AK-SM 800A`, 8443 shows `nginx` +
*Danfoss - StoreView Web*, and SNMP on 5136/udp answers `sysDescr = Danfoss AK-SM 800A ADAP-KOOL
System Manager, firmware G08.053` with `sysObjectID = enterprises.9615` — three independent,
mutually-consistent Danfoss fingerprints. An on-demand Shodan scan to index it immediately needs a
paid Shodan plan with scan credits (`POST https://api.shodan.io/shodan/scan ips=<IP>`); the free OSS
tier returns "upgrade your API plan", so discovery is left to the passive crawlers.

## Verified against the real firmware

The device fingerprint is not guessed. The AK-SM 800A ships its base OS as a public, ungated
download (`Danux4.14.017.194.lpk`, a 7-Zip wrapping a SWUpdate `.swu` → an ext4 root filesystem
for an NXP i.MX6 / MSC-SM2 module, Yocto "Poky 2.5"). Unpacking it confirms the surface this decoy
presents:

| fact | value (from firmware) | where |
|---|---|---|
| web server | **nginx/1.26.0** | `/usr/sbin/nginx`, error-page body |
| web architecture | public nginx → `sm_fcgi_app` FastCGI auth proxy → `sm_app` | `/opt/scripts/sm_app.sh` |
| internal proxy ports | HTTP `3080`, HTTPS `3443` (external HTTP/HTTPS DNAT'd in) | `/opt/scripts/firewall1.sh` |
| TLS server cert | subject `CN=DanfossSM800A, OU=SM800A, O=Danfoss, L=Baltimore, ST=MD, C=US` | `/opt/create_ssl_cert.sh` |
| TLS issuer (CA) | `CN=SelfSigned-DanfossSM800A, OU=Certificate_Authority` | same |
| external ports | TCP 22 (ssh), TCP 1041 (Service Tool) + UDP 1041 (PI200), UDP 5136 (SNMP), HTTP/HTTPS | `firewall1.sh` |
| internal-only | UDP 5003/5005 (host net), TCP 3080/3443 (proxy targets) | `firewall1.sh` |

`install.sh` reproduces that exact certificate chain and the banner is set to the exact nginx
version, so an attacker who inspects the TLS certificate or the `Server` header sees what a real
device shows. The vulnerable binary itself (`sm_fcgi_app`, where CVE-2025-41450/41451 live) is **not**
in this base-OS package — it is delivered on the device's `/danfoss` application partition — so the
decoy's endpoint behaviour is modelled from the public Claroty advisories, never copied from
vulnerable code, and nothing exploitable was reconstructed.

### The port profile (SNMP 5136, Service Tool / PI200 1041)

The decoy now opens the same external ports a real AK-SM 800A does. On quecheese, TCP 22 is the
Cowrie lure and HTTP/HTTPS (80/443) belong to the krisnet site, so StoreView keeps its 8443; the
three remaining device ports are served directly:

- **SNMP, UDP 5136.** The firmware ships no net-snmp agent or MIB — the AK-SM's SNMP is Danfoss
  proprietary and primarily trap-oriented — so this is a **modelled** minimal SNMP v1/v2c responder
  for the system group only. It answers GET/GETNEXT with the unit's real identity (`sysDescr =
  Danfoss AK-SM 800A ADAP-KOOL System Manager, firmware G08.053`, `sysObjectID = 1.3.6.1.4.1.9615`,
  the Danfoss IANA enterprise number), drops a wrong community silently (as a real agent does, and
  so it is not an amplification relay), and refuses SET while logging it as a control event. It
  exists so a scanner can fingerprint the box as Danfoss; it reconstructs no device-specific logic.
- **Service Tool, TCP 1041** and **PI200, UDP 1041.** Proprietary Danfoss protocols with no public
  specification. There is nothing faithful to reply with — a wrong answer is a worse tell than a
  quiet open port — so these are **capture-and-log only**: the TCP port accepts and records the
  client's opening bytes, the UDP port records the datagram, and neither sends a crafted response.

**Run dynamically.** The device's own nginx binary (ARM EABI5, from the rootfs) was executed under
emulation: it reports `nginx/1.26.0`, `built with OpenSSL 1.0.2o (2018)`, cross-built for `arm`,
with `--http_ssl_module`/`gzip_static`/`threads`. A live nginx 1.26.0 was then run as a server and
its exact error responses captured on the wire; the decoy now emits a **byte-identical** nginx 404
and 405 (fixed template, `Content-Type: text/html` with no charset, header order `Server, Date,
Content-Type, Content-Length, Connection`, `Connection` mirroring the request). Previously unknown
paths returned a themed "page not found", an easy tell. The base `/etc/nginx/nginx.conf` in the
package is an incomplete leftover — at runtime `sm_app.sh` starts nginx with
`/danfoss/nginx-auth-proxy/nginx.conf` from the application partition — which is the final
confirmation that the StoreView web config and its login/`xml.cgi` responses are not in this
download and remain modelled from the public advisories.

## The application firmware (StoreView web surface)

The **application** firmware also downloads ungated (`SM800A-5.3.2.spk`, a 7-Zip over the same
SWUpdate wrapper, ~47 MB) and contains the StoreView web application and its nginx config -- the
layer absent from the base-OS package. From it the decoy's HTTP surface is now matched to the real
device, not inferred:

- **`xml.cgi` is POST-only.** The real `location ~ \.cgi$` returns `405 Not Allowed` for GET/HEAD
  and `204 No Content` for `OPTIONS`; only `POST` reaches the FastCGI app. The decoy does the same
  (and still logs an exploit-shaped GET as a probe).
- **Five response headers on every reply** (from `headers.conf`, applied `always`, so they appear
  on errors too): `Cache-Control: no-store, no-cache`, `Access-Control-Allow-Origin: *`,
  `Access-Control-Allow-Methods: GET, POST, OPTIONS`, an `Access-Control-Allow-Headers` list that
  includes the device's custom `aksm-auth` token header, and `Strict-Transport-Security`.
- **TLS 1.2 only**, with the device's exact nginx cipher list.
- **Page title** `Danfoss - StoreView Web`, root served with `try_files ... =404`.

The decoy's 404/405/204 responses are **byte-for-byte** equal to the real device's (fixtures in
`testdata/`, asserted by the test-suite). The full React SPA (hundreds of JS chunks, tens of MB) is
deliberately **not** shipped -- it is not a scanner/fingerprint surface and would bloat a stdlib
lure -- so a browser sees the real shell but an empty app. The vulnerable `sm_fcgi_app` binary is
present in the firmware but its auth/injection logic was **not** read into the decoy: endpoint
behaviour stays modelled, nothing exploitable was reconstructed.

## Not wired into the estate (yet)

This runs standalone on the edge; its evidence is its own JSONL log. It does not tunnel into the
shibboleth server and does not produce estate records. Shipping `severity: "control"` events to the
collector as a new record kind is the natural next step.
