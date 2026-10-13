# Port map — firmware ground truth vs. public documentation

## From the firmware's own firewall (`firewall1.sh`, ground truth)

The AK-SM 800A ships its own iptables script. The external (eth0/eth1) ACCEPT rules are:

| Port | Proto | Firmware label | In decoy |
|---|---|---|---|
| 22 | TCP | SSH | Cowrie (separate lure) |
| 1041 | TCP | `Service Tool tcp - (1041)` | ✅ TLS server |
| 1041 | UDP | `PI200 (1041) port` | ✅ decode + flag |
| 5136 | UDP | `SNMP (5136) port` | ✅ modelled agent |
| 3080 / 3443 | TCP | internal nginx forwarder (DNAT target of 80/443) | not external |
| 5003 | UDP | `Host Param Server Access` (conditional) | skipped (internal) |
| 5005 | UDP | `Host Server Access` (conditional) | skipped (internal) |

**80/443** are DNAT-forwarded to the internal nginx on 3080/3443 (`sm_fcgi_app` → `Task_Web`).
There is **no `502` / Modbus rule anywhere** in `firewall1.sh`.

## From the public Danfoss port table (User Guide + datasheet)

| Port | Proto | Documented use |
|---|---|---|
| 5136 | UDP | SNMP |
| 1041 | UDP | PI-200 |
| 443 | TCP | HTTPS (StoreView Web) |
| 80 | TCP | HTTP |
| 5003, 5005 | UDP | Host network communication |

## Reconciliation

- **TCP 1041 (Service Tool).** Present and TLS in the firmware; **absent** from the public port
  table (which lists only *UDP* 1041 = PI-200). The binary wins — the decoy keeps TCP 1041.
- **Modbus 502.** Not in the firmware and not in the docs. The AK-SM is a Modbus *master* (it reaches
  downstream controllers and X-Gate gateways), so it never listens on 502. The decoy keeps 502 as a
  **deliberate lure deviation** — it is the cold-chain attack surface and the main Modbus-scanner draw.
- **SNMP 5136.** Confirmed by both. The device uses 5136 (not 161), but as an SNMP *client* polling
  southbound Danfoss SNMP devices; it is not a documented agent. The decoy's agent is a deliberate
  fabrication for fingerprinting.
- **StoreView 8443.** The real port is 443; the decoy uses 8443 because this edge host already serves
  443. Everything else about the surface matches.
