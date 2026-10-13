# Analysis — reverse-engineering the Danfoss AK-SM 800A protocol surface

This folder documents how the decoy's protocol fidelity was validated against **two independent
sources**, and judges, per protocol, how accurate the emulation is.

1. **Static reverse-engineering of the real server binary `sm_app`** — the AK-SM 800A application
   (ARM EABI5, dynamically linked, **full DWARF debug info, not stripped**, 1617 `TFN_*` symbols),
   extracted from publicly downloadable Danfoss firmware. This is *ground truth for the firmware the
   decoy imitates.* Tools: `pahole` (struct layouts from DWARF), `nm`, `readelf`,
   `arm-linux-gnueabihf-objdump` (ARM disassembly), `strings`, plus the firmware's own plaintext
   scripts (`firewall1.sh`, `create_ssl_cert.sh`, the `nginx-auth-proxy` config).
2. **Public documentation** — the Danfoss AK-SM 800A User Guide and datasheet port tables, the IANA
   Private Enterprise Number registry, the CISA advisory **ICSA-25-140-03**, and Claroty Team82's
   research. See [`sources.md`](sources.md).

Where the two disagree, **the binary wins** — it is the firmware the decoy mirrors. Notably the
binary reveals more than Danfoss documents publicly (e.g. a TLS Service Tool listener on TCP 1041
that the public port table does not mention).

> Nothing here weaponizes anything. No exploit, no auth-bypass algorithm, no command execution. The
> `TFN_*` catalogue is a list of symbol names; the certificates are public X.509 certificates; the
> private keys are **not** republished here (see [`certs/README.md`](certs/README.md)).

## The real protocol stack (reconstructed)

| Port | Real service | Transport | Evidence |
|---|---|---|---|
| TCP 1041 | **Service Tool** | **TLS 1.2** | `firewall1.sh` *"Service Tool tcp - (1041)"*; `SSL_accept` / `SSL_CTX_use_certificate_file` @OpenSSL 1.0.2d loading `/danfoss/certs/st_cert.pem`; source paths `code/ethernet/ServiceTool/{soc,st_LocalHandler,UploadTask}.c`; app layer = **1617 `TFN_*`** functions inside TLS |
| UDP 1041 | **PI-200** discovery/gateway | UDP (plaintext) | `Init_PI200_port` (UDP bind); `PI200_send_query` emits a **64-byte** query; messages `CHAN_PI200_QUERY` / `CHAN_PI200_VERIFY` → `AK2_PI200_NW_LIST_RESP`; node records = 128-byte `eth485_node` |
| UDP 5136 | SNMP (device is a **client**/poller) | UDP | `firewall1.sh` opens 5136; docs: "Danfoss SNMP 160" southbound capacity. No net-snmp agent / MIB in firmware |
| TCP 80/443 | HTTP / **StoreView-Web** | **TLS 1.2** | nginx → `sm_fcgi_app` → `Task_Web` in `sm_app`; `firewall1.sh` DNAT 80/443→3080/3443; nginx cert `cert.pem`; `xml.cgi?action=getauth` (Claroty) |
| ~~TCP 502~~ | **none** (AK-SM is a Modbus *master*) | — | No 502 line in `firewall1.sh`; no Modbus-slave strings in `sm_app` |

Two DWARF structs are often mistaken for wire formats but are **not**: `hm_header_st` /
`dtls1_retransmit_state` are **OpenSSL DTLS internals**, and `message_header_struct`
(`SIZE`/`TARGET_QID`/`SOURCE_QID`) is the **internal MQX message-queue IPC** header. The only real
network discovery record is [`eth485_node`](structs/eth485_node.txt) (128 bytes).

## Accuracy judgment — decoy vs. real

| Surface | Grade | Verdict |
|---|---|---|
| Port set 1041 tcp+udp, 5136 udp | **A** | Matches `firewall1.sh` exactly — and *exceeds* public docs (which omit TCP 1041). Matches the device, not just the brochure. |
| StoreView-Web transport | **A−** | TLS 1.2 + exact nginx cipher list + `nginx/1.26.0` + `xml.cgi?action=getauth` + 2023 `Last-Modified` + `ver="G08.053"` (real EDF `G0x.0yy` convention; 08.053 is a documented version). Only deviation: port **8443 vs real 443** (this edge host already serves 443). |
| **Service Tool TCP 1041** | **A−** (was C) | **Now a TLS server presenting the genuine device certificate** (see [`service-tool-1041.md`](service-tool-1041.md)). A TLS scanner gets a real handshake + the real cert. The `TFN_*` app layer inside TLS is deliberately *not* emulated — unspecified, and a wrong reply would be a worse tell than silence. |
| **PI-200 UDP 1041** | **B−** (was C) | **Now decodes and flags** discovery queries (the 64-byte `PI200_send_query` shape) as `pi200_query`. No reply is sent: the response envelope is not recoverable without inventing it. |
| SNMP identity | **C (intentional)** | Real device is an SNMP *client*, not an agent. The decoy runs an agent responder — a deliberate fabrication for Shodan indexing. PEN 9615 is real; the specific OID values are plausible-but-invented. |
| **Modbus/TCP 502** | **D (kept on purpose)** | The real AK-SM 800A does **not** listen on 502 (it is a Modbus *master*). Kept deliberately as the cold-chain lure's primary attack surface and the strongest draw for Modbus scanners. A tell only to someone who knows AK-SM internals deeply. |
| Service Tool app layer (1617 TFNs in TLS) | **N/A (correct to omit)** | Not emulated — faking it would invent a protocol, and it is unreachable without the real multi-process stack + the StoreView Desktop client. |

**Bottom line.** The decoy is high-fidelity on everything a scanner actually indexes: port shape,
web + Service Tool TLS transport (the latter now presenting the real device certificate), and
device identity strings. Two deviations are retained *on purpose* (Modbus 502 as the lure surface;
8443 for the shared host). Nothing in the wire behaviour is invented.

## Contents

- [`ports.md`](ports.md) — the port map, firmware ground truth vs. public docs.
- [`service-tool-1041.md`](service-tool-1041.md) — the TLS Service Tool port, the certificate, the `TFN_*` catalogue.
- [`pi200-1041.md`](pi200-1041.md) — the PI-200 UDP discovery protocol and the `eth485_node` record.
- [`structs/`](structs/) — `pahole` DWARF dumps of the key structs.
- [`tfn-catalog.txt`](tfn-catalog.txt) — all 1617 `TFN_*` application-function names.
- [`certs/`](certs/) — the device's public certificates and their fingerprints.
- [`pcaps/`](pcaps/) — captured handshakes (Modbus, SNMP, StoreView TLS, Service Tool TLS with the real cert).
- [`sources.md`](sources.md) — documentation + CVE references.
