#!/usr/bin/env python3
"""coldstore - a decoy of a supermarket refrigeration system manager (Danfoss AK-SM 800A-style).

One stdlib Python 3 file, no dependencies.  Run it directly:

    python3 coldstore.py

Five listeners share one simulated refrigeration plant and one log, matching the external port
profile of a real AK-SM 800A (verified from the device firmware's own firewall script,
`firewall1.sh`):

    Modbus/TCP     502   southbound control bus  (reads live temps/setpoints; writes reflected)
    StoreView-Web  8443  remote management UI over HTTPS  (nginx/1.26.0, xml.cgi, login, dashboard)
    SNMP           5136  UDP  system-group responder  (Danfoss identity; Shodan fingerprint)
    Service Tool   1041  TCP  TLS service port  (presents the device cert; captures first bytes, no app reply)
    PI200          1041  UDP  discovery port  (decodes + flags query/scan datagrams; no reply)

Two deliberate deviations from a real AK-SM 800A, kept on purpose:
  * Modbus/TCP 502 is a *listener* here.  A real AK-SM 800A is a Modbus master (it reaches
    downstream controllers), so it does not listen on 502 - the firmware's own firewall never
    opens it.  We expose it anyway because it is the cold-chain lure's primary attack surface and
    the strongest draw for Modbus scanners (Shodan).  See analysis/ for the firmware evidence.
  * StoreView-Web is on 8443, not the real 443, because this edge host already serves another
    site on 80/443.  Everything else about the TLS and HTTP surface matches the device.

It is a DECOY.  Nothing is actuated: a "write" (a Modbus register write, a web setpoint change) is
stored in memory and shown back on the next read so the caller believes it took effect, while the
attempt is logged as a control action.  The web side emulates the *presence* of the endpoints named
in the published advisories (CVE-2025-41450 code-of-the-day auth, CVE-2025-41451 command injection)
so an exploit attempt gets a plausible response and is logged - it implements neither the auth bypass
nor any command execution.  The host cannot be popped; nothing ever reaches out.

Env:
  COLDSTORE_LOG              append-only JSONL path (default: none, stderr only)
  COLDSTORE_MODBUS_BIND      host:port for Modbus/TCP        (default 0.0.0.0:502)
  COLDSTORE_WEB_BIND         host:port for StoreView-Web     (default 0.0.0.0:8443)
  COLDSTORE_SNMP_BIND        host:port for SNMP (UDP)        (default 0.0.0.0:5136)
  COLDSTORE_SERVICETOOL_BIND host:port for Service Tool/TCP  (default 0.0.0.0:1041)
  COLDSTORE_PI200_BIND       host:port for PI200/UDP         (default 0.0.0.0:1041)
  COLDSTORE_CERT, COLDSTORE_KEY   PEM cert/key; when both are present the web UI is HTTPS,
                                  otherwise plain HTTP (a real unit is HTTPS)
  COLDSTORE_ST_CERT, COLDSTORE_ST_KEY   PEM cert/key for the Service Tool TLS port (1041/tcp).
                                  The real device uses its own cert there (/danfoss/certs/st_cert.pem);
                                  if unset, falls back to COLDSTORE_CERT/KEY, then to plaintext capture.
  Set any *_BIND to the empty string to disable that listener.
"""
import calendar
import datetime
import email.utils
import hashlib
import html
import http.server
import json
import math
import os
import re
import signal
import socket
import socketserver
import ssl
import struct
import sys
import threading
import time
import urllib.parse

try:
    from zoneinfo import ZoneInfo
    _TZ = ZoneInfo("Europe/Berlin")
except Exception:                                  # pragma: no cover
    _TZ = None

# This module doubles as its own "model" namespace: the Modbus/web handlers below reference
# constants and helpers as ``model.X``; ``model`` is this module itself.
model = sys.modules[__name__]


# ===================================================================================================
# Logging - append-only JSON lines, one per interaction, ISO-8601 Europe/Berlin with explicit offset.
# ===================================================================================================
def _now():
    dt = datetime.datetime.now(_TZ) if _TZ else datetime.datetime.now().astimezone()
    return dt.isoformat(timespec="seconds")


class Logger:
    def __init__(self, path=None, echo=True):
        self.path = path
        self.echo = echo
        self.lock = threading.Lock()
        self._fh = None
        if path:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            self._fh = open(path, "a", encoding="utf-8")

    def event(self, proto, action, severity="info", **fields):
        rec = {"ts": _now(), "proto": proto, "action": action, "severity": severity}
        for k, v in fields.items():
            if isinstance(v, str):
                v = v[:512]
            rec[k] = v
        line = json.dumps(rec, ensure_ascii=False, sort_keys=False)
        with self.lock:
            if self._fh:
                try:
                    self._fh.write(line + "\n")
                    self._fh.flush()
                except OSError:
                    pass
            if self.echo:
                sys.stderr.write("coldstore " + line + "\n")
                sys.stderr.flush()
        return rec

    def bind(self, proto):
        def log(action, **kw):
            return self.event(proto, action, **kw)
        return log

    def close(self):
        with self.lock:
            if self._fh:
                self._fh.close()
                self._fh = None


# ===================================================================================================
# The simulated refrigeration plant (time-driven; no actuator behind any value).
# ===================================================================================================
STORE_NAME = "Frischmarkt Gruental"
STORE_ID = "GRUENTAL-SM01"
SITE = "Gruental - Markt Mitte"
DEVICE_MODEL = "AK-SM 800A"
DEVICE_VENDOR = "Danfoss"
FIRMWARE = "G08.053"
UNIT_SERIAL = "084B21190734"

MT, LT = "MT", "LT"


def _noise(key, t, amp):
    """Small deterministic pseudo-noise in [-amp, +amp], changing about once a minute."""
    h = hashlib.sha256(("%s|%d" % (key, int(t // 60))).encode()).digest()
    frac = struct.unpack(">I", h[:4])[0] / 0xFFFFFFFF  # 0..1
    return (frac * 2 - 1) * amp


class Case:
    """One refrigerated cabinet / case controller (a Danfoss AK-CC-style node)."""

    def __init__(self, node, name, kind, setpoint, diff, alarm_hi, alarm_lo,
                 defrost_every_h, defrost_min, defrost_phase_h):
        self.node = node                 # Modbus-ish node address 1..199
        self.name = name
        self.kind = kind                 # MT or LT
        self.setpoint = float(setpoint)  # design setpoint (degC)
        self.diff = float(diff)          # compressor differential (degC)
        self.alarm_hi = float(alarm_hi)
        self.alarm_lo = float(alarm_lo)
        self.defrost_every_h = defrost_every_h
        self.defrost_min = defrost_min
        self.defrost_phase_h = defrost_phase_h

    # ---- live, time-derived state (no actuator behind any of this) -------------------------
    def effective_setpoint(self, overrides):
        o = overrides.get(("sp", self.node))
        return float(o["value"]) if o else self.setpoint

    def in_defrost(self, t):
        period = self.defrost_every_h * 3600.0
        phase = (t - self.defrost_phase_h * 3600.0) % period
        return 0 <= phase < self.defrost_min * 60.0, phase, period

    def air_temp(self, t, overrides):
        sp = self.effective_setpoint(overrides)
        # compressor cycling: a slow triangle around the setpoint within the differential
        cyc_period = 1500.0 if self.kind == MT else 2400.0
        tri = abs(((t % cyc_period) / cyc_period) * 2 - 1)      # 0..1..0
        temp = sp - self.diff / 2 + tri * self.diff
        # periodic defrost: air rises well above setpoint, then recovers over ~30 min
        on, phase, _ = self.in_defrost(t)
        bump = 8.0 if self.kind == MT else 6.0
        if on:
            temp = sp + bump * (phase / (self.defrost_min * 60.0))
        else:
            rec = (phase - self.defrost_min * 60.0)
            if 0 <= rec < 1800.0:
                temp = sp + bump * (1 - rec / 1800.0) * 0.6
        temp += _noise("air%d" % self.node, t, 0.3)
        # a forced compressor-off override lets the cabinet drift warm (logged control action)
        if overrides.get(("comp", self.node), {}).get("value") == 0:
            drift = min(20.0, (t - overrides[("comp", self.node)]["at"]) / 180.0)
            temp = max(temp, sp + drift)
        return round(temp, 1)

    def evap_temp(self, t, overrides):
        return round(self.air_temp(t, overrides) - (6.0 if self.kind == MT else 8.0)
                     + _noise("evap%d" % self.node, t, 0.2), 1)

    def compressor_on(self, t, overrides):
        if overrides.get(("comp", self.node), {}).get("value") == 0:
            return False
        on, _, _ = self.in_defrost(t)
        if on:
            return False
        sp = self.effective_setpoint(overrides)
        return self.air_temp(t, overrides) > sp

    def alarm_active(self, t, overrides):
        temp = self.air_temp(t, overrides)
        on, _, _ = self.in_defrost(t)
        if on:
            return False                 # defrost high temps are expected, not alarms
        return temp > self.alarm_hi or temp < self.alarm_lo

    def view(self, t, overrides):
        return {
            "node": self.node, "name": self.name, "kind": self.kind,
            "air": self.air_temp(t, overrides), "evap": self.evap_temp(t, overrides),
            "setpoint": self.effective_setpoint(overrides),
            "alarm_hi": self.alarm_hi, "alarm_lo": self.alarm_lo,
            "compressor": self.compressor_on(t, overrides),
            "defrost": self.in_defrost(t)[0],
            "alarm": self.alarm_active(t, overrides),
            "overridden": ("sp", self.node) in overrides or ("comp", self.node) in overrides,
        }


def default_plant():
    """A believable store: a medium-temp rack of chilled cabinets and a low-temp rack of freezers."""
    cases = [
        # node, name, kind, setpoint, diff, hi, lo, defrost_every_h, defrost_min, phase_h
        Case(1,  "Wurstwaren SB",         MT,  3.0, 2.0,  7.0, -1.0, 6,  22, 0.4),
        Case(2,  "Molkerei 1",            MT,  4.0, 2.0,  8.0,  0.0, 6,  22, 1.1),
        Case(3,  "Molkerei 2",            MT,  4.0, 2.0,  8.0,  0.0, 6,  22, 2.0),
        Case(4,  "Obst und Gemuese",      MT,  6.0, 2.5, 10.0,  1.0, 8,  18, 3.2),
        Case(5,  "Fleischerei SB",        MT,  2.0, 2.0,  6.0, -2.0, 6,  22, 4.0),
        Case(6,  "Fischtheke",            MT,  1.0, 1.5,  5.0, -2.0, 4,  25, 5.1),
        Case(7,  "Feinkost",              MT,  3.0, 2.0,  7.0, -1.0, 6,  22, 0.9),
        Case(8,  "Getraenke",             MT,  5.0, 2.5,  9.0,  1.0, 8,  18, 2.6),
        Case(20, "Tiefkuehltruhe 1",      LT, -22.0, 3.0, -16.0, -30.0, 8, 30, 1.7),
        Case(21, "Tiefkuehltruhe 2",      LT, -22.0, 3.0, -16.0, -30.0, 8, 30, 3.4),
        Case(22, "Tiefkuehlregal",        LT, -21.0, 3.0, -15.0, -30.0, 8, 30, 5.0),
        Case(23, "Speiseeis",             LT, -24.0, 3.0, -18.0, -32.0, 8, 30, 6.3),
    ]
    return Plant(cases)


class Plant:
    def __init__(self, cases):
        self.cases = cases
        self.by_node = {c.node: c for c in cases}
        self.overrides = {}              # (what, node) -> {"value":.., "at":.., "src":..}
        self.started = time.time()

    def now(self):
        return time.time()

    def set_setpoint(self, node, value, src):
        if node in self.by_node:
            self.overrides[("sp", node)] = {"value": float(value), "at": self.now(), "src": src}
            return True
        return False

    def set_compressor(self, node, on, src):
        if node in self.by_node:
            self.overrides[("comp", node)] = {"value": 1 if on else 0, "at": self.now(), "src": src}
            return True
        return False

    def groups(self, t=None):
        t = t or self.now()
        out = {MT: [], LT: []}
        for c in self.cases:
            out[c.kind].append(c.view(t, self.overrides))
        return out

    def summary(self, t=None):
        t = t or self.now()
        views = [c.view(t, self.overrides) for c in self.cases]
        return {
            "store": STORE_NAME, "store_id": STORE_ID, "site": SITE,
            "model": DEVICE_MODEL, "vendor": DEVICE_VENDOR, "firmware": FIRMWARE,
            "cases": len(views),
            "alarms": sum(1 for v in views if v["alarm"]),
            "overridden": sum(1 for v in views if v["overridden"]),
        }


# ===================================================================================================
# Modbus/TCP decoy (southbound control surface).
#
# Register map (0-based Modbus addressing; a "node" is a case controller address):
#   holding (R/W, FC 3/6/16): 0 = number of cases; 1000+node setpoint degCx10 signed (attack target);
#       1200+node alarm-hi, 1400+node alarm-lo, 1600+node differential.
#   input  (R, FC 4): 2900/2901 MT/LT suction bar x100; 3000+node air, 3200+node evap, 3400+node run%.
#   coils  (R/W, FC 1/5/15): 100+node compressor enable (0 = forced off, drifts warm); 300+node defrost.
#   discrete (R, FC 2): 100+node alarm active; 300+node door.
#   device identification (FC 43/MEI 14): Danfoss / AK-SM 800A / firmware.
# ===================================================================================================
MAX_PDU = 256
MAX_REG_QTY = 125
MAX_BIT_QTY = 2000
MAX_RAW_OVERRIDES = 4096

EXC_ILLEGAL_FUNCTION = 0x01
EXC_ILLEGAL_DATA_ADDRESS = 0x02
EXC_ILLEGAL_DATA_VALUE = 0x03
EXC_SERVER_FAILURE = 0x04


def _s16(v):
    v = int(v) & 0xFFFF
    return v - 0x10000 if v >= 0x8000 else v


def _u16(v):
    return int(round(v)) & 0xFFFF


class Registers:
    """Maps the Modbus address space onto the plant model, plus a bounded store for writes to
    addresses the model does not own (so a scan that writes anywhere reads back consistently)."""

    def __init__(self, plant):
        self.plant = plant
        self.raw_hold = {}
        self.raw_coil = {}

    # ---- reads ---------------------------------------------------------------------------------
    def holding(self, addr, t):
        if addr in self.raw_hold:
            return self.raw_hold[addr]
        if addr == 0:
            return len(self.plant.cases)
        for base, attr in ((1000, "sp"), (1200, "alarm_hi"), (1400, "alarm_lo"), (1600, "diff")):
            if base <= addr < base + 256:
                c = self.plant.by_node.get(addr - base)
                if not c:
                    return 0
                if attr == "sp":
                    return _u16(c.effective_setpoint(self.plant.overrides) * 10)
                return _u16(getattr(c, attr) * 10)
        return 0

    def input_reg(self, addr, t):
        if addr == 2900:
            return _u16(230 + int(model._noise("sucMT", t, 8)))   # ~2.3 bar
        if addr == 2901:
            return _u16(140 + int(model._noise("sucLT", t, 6)))   # ~1.4 bar
        for base, kind in ((3000, "air"), (3200, "evap"), (3400, "comp%")):
            if base <= addr < base + 256:
                c = self.plant.by_node.get(addr - base)
                if not c:
                    return 0
                if kind == "air":
                    return _u16(c.air_temp(t, self.plant.overrides) * 10)
                if kind == "evap":
                    return _u16(c.evap_temp(t, self.plant.overrides) * 10)
                return _u16(72 if c.compressor_on(t, self.plant.overrides) else 0)
        return 0

    def coil(self, addr, t):
        if addr in self.raw_coil:
            return self.raw_coil[addr]
        if 100 <= addr < 356:
            c = self.plant.by_node.get(addr - 100)
            return bool(c and c.compressor_on(t, self.plant.overrides))
        if 300 <= addr < 556:
            c = self.plant.by_node.get(addr - 300)
            return bool(c and c.in_defrost(t)[0])
        return False

    def discrete(self, addr, t):
        if 100 <= addr < 356:
            c = self.plant.by_node.get(addr - 100)
            return bool(c and c.alarm_active(t, self.plant.overrides))
        if 300 <= addr < 556:
            return False                 # doors: closed
        return False

    # ---- writes (accepted, reflected, logged) --------------------------------------------------
    def write_holding(self, addr, value, src, log):
        if 1000 <= addr < 1256:
            node = addr - 1000
            if node in self.plant.by_node:
                self.plant.set_setpoint(node, _s16(value) / 10.0, src)
                c = self.plant.by_node[node]
                log("setpoint", severity="control", node=node, case=c.name,
                    new_setpoint_c=_s16(value) / 10.0, register=addr)
                return
        if len(self.raw_hold) < MAX_RAW_OVERRIDES:
            self.raw_hold[addr] = value & 0xFFFF
        log("write_holding", severity="info", register=addr, value=value & 0xFFFF)

    def write_coil(self, addr, on, src, log):
        if 100 <= addr < 356:
            node = addr - 100
            if node in self.plant.by_node:
                self.plant.set_compressor(node, on, src)
                c = self.plant.by_node[node]
                log("compressor", severity="control", node=node, case=c.name,
                    enabled=bool(on), coil=addr)
                return
        if 300 <= addr < 556 and on:
            node = addr - 300
            if node in self.plant.by_node:
                log("defrost_start", severity="control", node=node,
                    case=self.plant.by_node[node].name, coil=addr)
                return
        if len(self.raw_coil) < MAX_RAW_OVERRIDES:
            self.raw_coil[addr] = bool(on)
        log("write_coil", severity="info", coil=addr, value=bool(on))


class _ModbusHandler(socketserver.BaseRequestHandler):
    def handle(self):
        srv = self.server
        src = "%s:%d" % self.client_address[:2]
        if not srv.gate(self.client_address[0]):
            return
        srv.log_event("connect", severity="info", src=src)
        self.request.settimeout(60)
        n = 0
        try:
            while n < 2000:
                frame = self._read_frame()
                if frame is None:
                    break
                n += 1
                tid, uid, pdu = frame
                resp = self._dispatch(uid, pdu, src)
                if resp is None:
                    break
                mbap = struct.pack(">HHHB", tid, 0, len(resp) + 1, uid)
                self.request.sendall(mbap + resp)
        except (socket.timeout, OSError):
            pass
        finally:
            srv.ungate(self.client_address[0])
            srv.log_event("disconnect", severity="info", src=src, requests=n)

    def _read_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.request.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    def _read_frame(self):
        head = self._read_exact(6)
        if head is None:
            return None
        tid, pid, length = struct.unpack(">HHH", head)
        if pid != 0 or length < 2 or length > MAX_PDU:
            return None
        body = self._read_exact(length)
        if body is None or len(body) < 2:
            return None
        return tid, body[0], body[1:]

    def _exc(self, fc, code, src, note):
        self.server.log_event("modbus_exception", severity="info", src=src, fc=fc, exc=code, note=note)
        return struct.pack(">BB", fc | 0x80, code)

    def _dispatch(self, uid, pdu, src):
        fc = pdu[0]
        data = pdu[1:]
        t = self.server.plant.now()
        regs = self.server.regs
        log = lambda action, **kw: self.server.log_event(action, src=src, fc=fc, **kw)
        try:
            if fc in (1, 2):                                   # read coils / discrete inputs
                addr, qty = struct.unpack(">HH", data[:4])
                if not (1 <= qty <= MAX_BIT_QTY):
                    return self._exc(fc, EXC_ILLEGAL_DATA_VALUE, src, "qty")
                if addr + qty > 0x10000:
                    return self._exc(fc, EXC_ILLEGAL_DATA_ADDRESS, src, "range")
                read = regs.coil if fc == 1 else regs.discrete
                bits = [read(addr + i, t) for i in range(qty)]
                nbytes = (qty + 7) // 8
                out = bytearray(nbytes)
                for i, b in enumerate(bits):
                    if b:
                        out[i // 8] |= 1 << (i % 8)
                return struct.pack(">BB", fc, nbytes) + bytes(out)

            if fc in (3, 4):                                   # read holding / input registers
                addr, qty = struct.unpack(">HH", data[:4])
                if not (1 <= qty <= MAX_REG_QTY):
                    return self._exc(fc, EXC_ILLEGAL_DATA_VALUE, src, "qty")
                if addr + qty > 0x10000:
                    return self._exc(fc, EXC_ILLEGAL_DATA_ADDRESS, src, "range")
                read = regs.holding if fc == 3 else regs.input_reg
                vals = b"".join(struct.pack(">H", read(addr + i, t) & 0xFFFF) for i in range(qty))
                if addr >= 1000:
                    log("read_registers", severity="info", addr=addr, qty=qty)
                return struct.pack(">BB", fc, qty * 2) + vals

            if fc == 5:                                        # write single coil
                addr, val = struct.unpack(">HH", data[:4])
                if val not in (0x0000, 0xFF00):
                    return self._exc(fc, EXC_ILLEGAL_DATA_VALUE, src, "coilval")
                regs.write_coil(addr, val == 0xFF00, src, log)
                return struct.pack(">BHH", fc, addr, val)

            if fc == 6:                                        # write single holding register
                addr, val = struct.unpack(">HH", data[:4])
                regs.write_holding(addr, val, src, log)
                return struct.pack(">BHH", fc, addr, val)

            if fc == 15:                                       # write multiple coils
                addr, qty, bc = struct.unpack(">HHB", data[:5])
                if not (1 <= qty <= MAX_BIT_QTY) or bc != (qty + 7) // 8 or len(data) < 5 + bc:
                    return self._exc(fc, EXC_ILLEGAL_DATA_VALUE, src, "mcoil")
                body = data[5:5 + bc]
                for i in range(qty):
                    regs.write_coil(addr + i, bool(body[i // 8] & (1 << (i % 8))), src, log)
                return struct.pack(">BHH", fc, addr, qty)

            if fc == 16:                                       # write multiple holding registers
                addr, qty, bc = struct.unpack(">HHB", data[:5])
                if not (1 <= qty <= MAX_REG_QTY) or bc != qty * 2 or len(data) < 5 + bc:
                    return self._exc(fc, EXC_ILLEGAL_DATA_VALUE, src, "mreg")
                for i in range(qty):
                    (val,) = struct.unpack(">H", data[5 + i * 2:7 + i * 2])
                    regs.write_holding(addr + i, val, src, log)
                return struct.pack(">BHH", fc, addr, qty)

            if fc == 0x2B:                                     # encapsulated: device identification
                if len(data) >= 3 and data[0] == 0x0E:
                    return self._device_id(data[1], data[2], src)
                return self._exc(fc, EXC_ILLEGAL_FUNCTION, src, "mei")

            return self._exc(fc, EXC_ILLEGAL_FUNCTION, src, "fc")
        except struct.error:
            return self._exc(fc, EXC_ILLEGAL_DATA_VALUE, src, "short")

    def _device_id(self, read_code, object_id, src):
        self.server.log_event("device_id", severity="info", src=src, read_code=read_code)
        basic = [(0x00, model.DEVICE_VENDOR), (0x01, model.DEVICE_MODEL), (0x02, model.FIRMWARE)]
        regular = [(0x03, "https://www.danfoss.com"), (0x04, "ADAP-KOOL"),
                   (0x05, model.DEVICE_MODEL), (0x06, "System Manager")]
        if read_code == 4:
            allobj = dict(basic + regular)
            if object_id not in allobj:
                return self._exc(0x2B, EXC_ILLEGAL_DATA_ADDRESS, src, "obj")
            objs, conformity = [(object_id, allobj[object_id])], 0x83
        elif read_code == 1:
            objs, conformity = basic, 0x81
        else:
            objs, conformity = basic + regular, 0x83
        body = bytearray()
        for oid, val in objs:
            v = val.encode("ascii", "replace")[:245]
            body += struct.pack(">BB", oid, len(v)) + v
        head = struct.pack(">BBBBBB", 0x2B, 0x0E, read_code, conformity, 0x00, 0x00)
        return head + struct.pack(">B", len(objs)) + bytes(body)


class ColdstoreModbus(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 32

    def __init__(self, bind, plant, log_event, max_per_ip=8):
        self.plant = plant
        self.regs = Registers(plant)
        self.log_event = log_event
        self.max_per_ip = max_per_ip
        self._active = {}
        self._lock = threading.Lock()
        socketserver.ThreadingTCPServer.__init__(self, bind, _ModbusHandler)

    def gate(self, ip):
        with self._lock:
            if self._active.get(ip, 0) >= self.max_per_ip:
                return False
            self._active[ip] = self._active.get(ip, 0) + 1
            return True

    def ungate(self, ip):
        with self._lock:
            self._active[ip] = max(0, self._active.get(ip, 0) - 1)


# ===================================================================================================
# StoreView-Web decoy (remote management UI over HTTPS; nginx/1.26.0 + xml.cgi).
# ===================================================================================================
SERVER_BANNER = "nginx/1.26.0"                        # exact version in Danux 4.14.017.194 firmware (verified)
PAGE_TITLE = "Danfoss - StoreView Web"  # exact <title> from firmware html/index.html

# Response headers the real StoreView nginx adds to EVERY reply (verified ex firmware:
# nginx-auth-proxy/headers.conf, applied with `always`, so they appear on errors too).
EXTRA_HEADERS = (
    ("Cache-Control", "no-store, no-cache"),
    ("Access-Control-Allow-Origin", "*"),
    ("Access-Control-Allow-Methods", "GET, POST, OPTIONS"),
    ("Access-Control-Allow-Headers",
     "aksm-auth,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type"),
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
)
EXTRA_HEADER_BLOCK = "".join("%s: %s\r\n" % (k, v) for k, v in EXTRA_HEADERS)

# The StoreView SPA shell is served by nginx from disk, so its static responses carry the firmware
# build mtime (the 5.3.x application shipped in 2023) as Last-Modified / ETag / Accept-Ranges,
# exactly as a real nginx does for a static file. Dynamic xml.cgi responses and error pages do not.
BUILD_EPOCH = calendar.timegm((2023, 3, 14, 9, 12, 34, 0, 0, 0))   # 2023-03-14 09:12:34 GMT
LAST_MODIFIED = email.utils.formatdate(BUILD_EPOCH, usegmt=True)

# request shapes that match the published exploit chain or generic probing; emulated + logged only
_SHELL = re.compile(r"[;&|`]|\$\(|\$\{|\|\||&&|\n|\r|%0a|%0d|\bnc\b|/bin/|wget|curl\s", re.I)
_TRAVERSAL = re.compile(r"\.\./|\.\.%2f|%2e%2e/|/etc/passwd|/etc/shadow", re.I)


def classify(path, params):
    """Return (tag, note) when a request matches a known exploit/probe shape, else None.
    params is a dict of lists (query or form)."""
    action = (params.get("action", [""])[0] or "").lower()
    if path.endswith("xml.cgi") and action == "getauth":
        return "auth_getauth", "authentication endpoint (code-of-the-day target, CVE-2025-41450)"
    flat = " ".join(v for vs in params.values() for v in vs)
    if _SHELL.search(flat):
        return "command_injection_attempt", "shell metacharacters in a field (CVE-2025-41451 class)"
    if _TRAVERSAL.search(path) or _TRAVERSAL.search(flat):
        return "path_traversal_attempt", "directory traversal in path or parameter"
    return None


CSS = """
*{box-sizing:border-box} body{margin:0;font-family:Arial,Helvetica,sans-serif;background:#eceff1;color:#222;font-size:14px}
.top{background:#1a1a1a;color:#fff;display:flex;align-items:center;gap:14px;padding:0 16px;height:46px}
.top .brand{font-weight:bold;color:#E2000F;letter-spacing:.5px}
.top .sub{color:#bbb;font-size:12px}
.top .right{margin-left:auto;color:#bbb;font-size:12px}
.wrap{max-width:1100px;margin:16px auto;padding:0 16px}
.card{background:#fff;border:1px solid #cfd8dc;border-radius:3px;margin-bottom:16px}
.card h2{margin:0;padding:10px 14px;font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:#455a64;border-bottom:1px solid #eceff1;background:#f5f7f8}
.card .body{padding:12px 14px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid #eceff1}
th{color:#607d8b;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.04em}
td.num{font-family:Consolas,monospace;text-align:right}
.ok{color:#2e7d32}.warn{color:#E2000F;font-weight:bold}.muted{color:#90a4ae}
.pill{display:inline-block;border-radius:3px;padding:1px 7px;font-size:11px;background:#eceff1;color:#546e7a}
.pill.on{background:#e8f5e9;color:#2e7d32}.pill.al{background:#fdecec;color:#E2000F}
.login{max-width:360px;margin:7vh auto;background:#fff;border:1px solid #cfd8dc;border-radius:3px}
.login .head{background:#1a1a1a;color:#fff;padding:16px;text-align:center}
.login .head .brand{color:#E2000F;font-weight:bold;font-size:18px}
.login form{padding:20px}
.login label{display:block;font-size:12px;color:#607d8b;margin:10px 0 4px}
.login input{width:100%;padding:8px;border:1px solid #b0bec5;border-radius:3px}
.login button{margin-top:16px;width:100%;padding:9px;background:#E2000F;color:#fff;border:0;border-radius:3px;font-weight:bold;cursor:pointer}
.foot{color:#90a4ae;font-size:11px;text-align:center;margin:18px 0}
input.sp{width:70px;font-family:Consolas,monospace;text-align:right;padding:3px}
.btn{background:#455a64;color:#fff;border:0;border-radius:3px;padding:4px 10px;cursor:pointer;font-size:12px}
nav.sub{margin-bottom:12px}
nav.sub a{display:inline-block;margin-right:6px}
"""

NAV = ("<nav class=\"sub\"><a class=\"pill\" href=\"/dashboard\">Refrigeration</a>"
       "<a class=\"pill\" href=\"/alarms\">Alarms</a><a class=\"pill\" href=\"/configuration\">Configuration</a>"
       "<a class=\"pill\" href=\"/device\">Unit</a></nav>")


def _page(title, body, user=None):
    s = model
    right = ("%s | %s" % (user, time.strftime("%Y-%m-%d %H:%M"))) if user else time.strftime("%Y-%m-%d %H:%M")
    return ("<!doctype html><html><head><meta charset=\"utf-8\"><title>%s</title>"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><style>%s</style></head><body>"
            "<div class=\"top\"><span class=\"brand\">Danfoss</span><span>StoreView Web</span>"
            "<span class=\"sub\">%s &middot; %s</span><span class=\"right\">%s</span></div>"
            "<div class=\"wrap\">%s</div><div class=\"foot\">%s %s &middot; firmware %s &middot; unit %s</div>"
            "</body></html>") % (PAGE_TITLE, CSS, html.escape(s.DEVICE_MODEL),
                                 html.escape(s.STORE_NAME), html.escape(right), body,
                                 html.escape(s.DEVICE_VENDOR), html.escape(s.DEVICE_MODEL),
                                 html.escape(s.FIRMWARE), html.escape(s.UNIT_SERIAL))


def login_page(note=""):
    s = model
    n = ("<div style=\"color:#E2000F;font-size:12px;text-align:center;margin-top:8px\">%s</div>" % html.escape(note)) if note else ""
    return ("<!doctype html><html><head><meta charset=\"utf-8\"><title>%s</title>"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><style>%s</style></head><body>"
            "<div class=\"login\"><div class=\"head\"><div class=\"brand\">Danfoss</div>"
            "<div>StoreView Web</div><div style=\"color:#bbb;font-size:12px;margin-top:4px\">%s &middot; %s</div></div>"
            "<form method=\"POST\" action=\"/login\"><label>User</label><input name=\"user\" autocomplete=\"username\">"
            "<label>Password</label><input name=\"password\" type=\"password\" autocomplete=\"current-password\">"
            "<button type=\"submit\">Log in</button>%s</form></div>"
            "<div class=\"foot\">%s %s &middot; firmware %s</div></body></html>") % (
                PAGE_TITLE, CSS, html.escape(s.DEVICE_MODEL), html.escape(s.STORE_NAME), n,
                html.escape(s.DEVICE_VENDOR), html.escape(s.DEVICE_MODEL), html.escape(s.FIRMWARE))


def dashboard(plant, user):
    groups = plant.groups()
    rows = []
    for kind, label in ((model.MT, "Rack A &middot; Medium temperature"), (model.LT, "Rack B &middot; Low temperature")):
        body = ["<table><thead><tr><th>Addr</th><th>Case</th><th>Air &deg;C</th><th>Evap &deg;C</th>"
                "<th>Setpoint &deg;C</th><th>Limits</th><th>State</th><th>Change setpoint</th></tr></thead><tbody>"]
        for c in groups[kind]:
            state = ("<span class=\"pill al\">ALARM</span>" if c["alarm"] else
                     "<span class=\"pill\">defrost</span>" if c["defrost"] else
                     "<span class=\"pill on\">cooling</span>" if c["compressor"] else
                     "<span class=\"pill\">idle</span>")
            tcls = "num warn" if c["alarm"] else "num"
            body.append(
                "<tr><td class=\"num\">%d</td><td>%s%s</td><td class=\"%s\">%.1f</td><td class=\"num muted\">%.1f</td>"
                "<td class=\"num\">%.1f</td><td class=\"num muted\">%.1f / %.1f</td><td>%s</td>"
                "<td><form method=\"POST\" action=\"/setpoint\" style=\"margin:0\">"
                "<input type=\"hidden\" name=\"node\" value=\"%d\">"
                "<input class=\"sp\" name=\"value\" value=\"%.1f\"> <button class=\"btn\">Set</button></form></td></tr>"
                % (c["node"], html.escape(c["name"]),
                   " <span class=\"pill\">ovr</span>" if c["overridden"] else "",
                   tcls, c["air"], c["evap"], c["setpoint"], c["alarm_hi"], c["alarm_lo"], state,
                   c["node"], c["setpoint"]))
        body.append("</tbody></table>")
        rows.append("<div class=\"card\"><h2>%s</h2><div class=\"body\" style=\"padding:0\">%s</div></div>" % (label, "".join(body)))
    summ = plant.summary()
    head = ("<div class=\"card\"><h2>Refrigeration overview</h2><div class=\"body\">"
            "Site <b>%s</b> &middot; unit <b>%s</b> &middot; <b>%d</b> cases &middot; "
            "<span class=\"%s\">%d active alarm(s)</span>%s</div></div>") % (
                html.escape(summ["site"]), html.escape(model.STORE_ID), summ["cases"],
                "warn" if summ["alarms"] else "ok", summ["alarms"],
                (" &middot; <span class=\"warn\">%d setpoint override(s)</span>" % summ["overridden"]) if summ["overridden"] else "")
    return _page("Refrigeration", NAV + head + "".join(rows), user)


def alarms_page(plant, user):
    groups = plant.groups()
    al = [c for kind in groups for c in groups[kind] if c["alarm"]]
    body = ["<div class=\"card\"><h2>Active alarms</h2><div class=\"body\" style=\"padding:0\"><table>"
            "<thead><tr><th>Addr</th><th>Case</th><th>Air &deg;C</th><th>High limit</th><th>Since</th></tr></thead><tbody>"]
    if not al:
        body.append("<tr><td colspan=\"5\" class=\"muted\" style=\"padding:14px\">No active alarms.</td></tr>")
    for c in al:
        body.append("<tr><td class=\"num\">%d</td><td>%s</td><td class=\"num warn\">%.1f</td>"
                    "<td class=\"num muted\">%.1f</td><td class=\"muted\">—</td></tr>"
                    % (c["node"], html.escape(c["name"]), c["air"], c["alarm_hi"]))
    body.append("</tbody></table></div></div>")
    return _page("Alarms", NAV + "".join(body), user)


def configuration_page(user):
    links = [("Network", "/config/network"), ("Users", "/config/users"), ("Alarms", "/config/alarms"),
             ("E-mail (SMTP)", "/config/email"), ("Logging", "/config/logging"), ("Maintenance", "/config/maintenance")]
    lis = "".join("<tr><td><a href=\"%s\">%s</a></td><td class=\"muted\">configured</td></tr>" % (u, html.escape(n)) for n, u in links)
    return _page("Configuration", NAV + "<div class=\"card\"><h2>Configuration</h2>"
                 "<div class=\"body\" style=\"padding:0\"><table><tbody>%s</tbody></table></div></div>" % lis, user)


def email_page(user):
    body = ("<div class=\"card\"><h2>E-mail (SMTP)</h2><div class=\"body\">"
            "<form method=\"POST\" action=\"/xml.cgi\"><input type=\"hidden\" name=\"action\" value=\"set_email\">"
            "<label>SMTP server</label><br><input name=\"smtp_server\" value=\"smtp.gruental.local\" style=\"width:280px\"><br><br>"
            "<label>From address</label><br><input name=\"from_addr\" value=\"ak-sm@gruental.local\" style=\"width:280px\"><br><br>"
            "<label>Recipient</label><br><input name=\"to_addr\" value=\"wartung@gruental.local\" style=\"width:280px\"><br><br>"
            "<button class=\"btn\">Save</button></form></div></div>")
    return _page("E-mail", NAV + body, user)


def device_page(user):
    s = model
    rows = [("Vendor", s.DEVICE_VENDOR), ("Model", s.DEVICE_MODEL), ("Application", "ADAP-KOOL System Manager"),
            ("Firmware", s.FIRMWARE), ("Unit serial", s.UNIT_SERIAL), ("Store", s.STORE_NAME),
            ("Store id", s.STORE_ID), ("Modbus/IP", "enabled (southbound, Eth1)")]
    tr = "".join("<tr><th style=\"width:180px\">%s</th><td>%s</td></tr>" % (html.escape(k), html.escape(v)) for k, v in rows)
    return _page("Unit", NAV + "<div class=\"card\"><h2>System manager</h2><div class=\"body\" style=\"padding:0\"><table>%s</table></div></div>" % tr, user)


# ---- xml.cgi, the device's single API/auth endpoint -------------------------------------------
def xml_response(action, ok=True, extra=""):
    status = "ok" if ok else "error"
    return ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            "<sm model=\"%s\" ver=\"%s\"><result action=\"%s\" status=\"%s\"/>%s</sm>\n"
            % (model.DEVICE_MODEL, model.FIRMWARE, html.escape(action or ""), status, extra))


class _WebHandler(http.server.BaseHTTPRequestHandler):
    server_version = SERVER_BANNER
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def version_string(self):
        return SERVER_BANNER

    def log_message(self, *a):
        pass

    def _src(self):
        return "%s:%d" % self.client_address[:2]

    def _send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        # A static page served from disk (the SPA shell) carries the firmware build mtime, like
        # nginx: Last-Modified + a matching ETag + Accept-Ranges. Dynamic (xml.cgi) and non-200
        # replies do not.
        if code == 200 and ctype.startswith("text/html"):
            self.send_header("Last-Modified", LAST_MODIFIED)
            self.send_header("ETag", '"%x-%x"' % (BUILD_EPOCH, len(data)))
            self.send_header("Accept-Ranges", "bytes")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.send_header("Connection", "keep-alive")
        for k, v in EXTRA_HEADERS:
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    # Byte-exact nginx error page (same compiled-in template as nginx/1.26.0 in the firmware).
    # Verified against a live nginx 1.26.0: header order Server, Date, Content-Type (text/html,
    # no charset), Content-Length, Connection; Connection mirrors the request (keep-alive on
    # HTTP/1.1, close on HTTP/1.0 or an explicit close).
    def _nginx_error(self, code, reason):
        body = ("<html>\r\n<head><title>%d %s</title></head>\r\n<body>\r\n"
                "<center><h1>%d %s</h1></center>\r\n<hr><center>%s</center>\r\n"
                "</body>\r\n</html>\r\n" % (code, reason, code, reason, SERVER_BANNER)).encode()
        conn = self.headers.get("Connection", "").lower()
        keep = (self.request_version == "HTTP/1.1") and conn != "close"
        head = ("HTTP/1.1 %d %s\r\n"
                "Server: %s\r\n"
                "Date: %s\r\n"
                "Content-Type: text/html\r\n"
                "Content-Length: %d\r\n"
                "Connection: %s\r\n"
                "%s\r\n"
                % (code, reason, SERVER_BANNER, self.date_time_string(), len(body),
                   "keep-alive" if keep else "close", EXTRA_HEADER_BLOCK)).encode()
        try:
            self.wfile.write(head)
            if self.command != "HEAD":
                self.wfile.write(body)
        except Exception:
            pass
        self.close_connection = not keep

    # 204 No Content, as the real .cgi location returns for OPTIONS (no Content-Type/Length).
    def _send_204(self):
        keep = (self.request_version == "HTTP/1.1") and self.headers.get("Connection", "").lower() != "close"
        head = ("HTTP/1.1 204 No Content\r\n"
                "Server: %s\r\n"
                "Date: %s\r\n"
                "Connection: %s\r\n"
                "%s\r\n"
                % (SERVER_BANNER, self.date_time_string(),
                   "keep-alive" if keep else "close", EXTRA_HEADER_BLOCK)).encode()
        try:
            self.wfile.write(head)
        except Exception:
            pass
        self.close_connection = not keep

    # unknown HTTP methods -> nginx 405 (matches the real server's response to an unknown verb)
    def _method_not_allowed(self):
        self.server.log_event("http", severity="info", src=self._src(),
                              method=self.command, path=self.path[:200],
                              ua=self.headers.get("User-Agent", "")[:200])
        return self._nginx_error(405, "Not Allowed")
    do_PUT = do_DELETE = do_PATCH = do_TRACE = _method_not_allowed

    def do_OPTIONS(self):
        u = urllib.parse.urlsplit(self.path)
        self.server.log_event("http", severity="info", src=self._src(), method="OPTIONS",
                              path=self.path[:200], ua=self.headers.get("User-Agent", "")[:200])
        if u.path.endswith(".cgi"):
            return self._send_204()          # real device: OPTIONS on a .cgi -> 204
        return self._nginx_error(405, "Not Allowed")

    # the base class's own errors (414 URI too long, 400 bad request, 501) render as nginx too
    def send_error(self, code, message=None, explain=None):
        reasons = {400: "Bad Request", 403: "Forbidden", 404: "Not Found",
                   405: "Not Allowed", 408: "Request Time-out", 413: "Request Entity Too Large",
                   414: "Request-URI Too Large", 500: "Internal Server Error",
                   501: "Not Implemented", 505: "HTTP Version Not Supported"}
        try:
            code = int(code)
        except Exception:
            code = 500
        return self._nginx_error(code, reasons.get(code, "Error"))

    def _body(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return b""
        return self.rfile.read(n) if 0 < n <= 65536 else b""

    def _flag(self, path, params):
        hit = classify(path, params)
        if hit:
            tag, note = hit
            self.server.log_event("exploit_attempt", severity="control", src=self._src(),
                                  method=self.command, path=self.path[:200], signature=tag, note=note,
                                  ua=self.headers.get("User-Agent", "")[:200])

    # ---- xml.cgi ------------------------------------------------------------------------------
    def _xml_cgi(self, params):
        action = (params.get("action", [""])[0] or "").lower()
        src = self._src()
        if action == "getauth":
            # the authentication endpoint (code-of-the-day target). logged; no bypass implemented.
            self.server.log_event("auth_getauth", severity="control", src=src,
                                  user=(params.get("user", [""])[0])[:128],
                                  code=(params.get("code", [""])[0] or params.get("password", [""])[0])[:128])
            return self._send(200, xml_response("getauth", ok=False,
                              extra="<auth result=\"denied\"/>"), ctype="text/xml; charset=utf-8")
        if action == "set_email":
            # the e-mail settings action (command-injection surface). logged; nothing is executed.
            self.server.log_event("config_set_email", severity="control", src=src,
                                  smtp_server=(params.get("smtp_server", [""])[0])[:256],
                                  from_addr=(params.get("from_addr", [""])[0])[:256],
                                  to_addr=(params.get("to_addr", [""])[0])[:256])
            return self._send(200, xml_response("set_email", ok=True), ctype="text/xml; charset=utf-8")
        if action == "load_nginx_headers":
            self.server.log_event("config_read", severity="info", src=src, what="nginx_headers")
            return self._send(200, xml_response("load_nginx_headers", ok=True,
                              extra="<headers><header name=\"X-Frame-Options\" value=\"SAMEORIGIN\"/></headers>"),
                              ctype="text/xml; charset=utf-8")
        if action in ("getstatus", "getconfig", "getalarms", ""):
            self.server.log_event("config_read", severity="info", src=src, cgi_action=action or "status")
            return self._send(200, xml_response(action or "getstatus", ok=True), ctype="text/xml; charset=utf-8")
        self.server.log_event("xml_cgi", severity="info", src=src, cgi_action=action)
        return self._send(200, xml_response(action, ok=False), ctype="text/xml; charset=utf-8")

    def do_GET(self):
        srv = self.server
        u = urllib.parse.urlsplit(self.path)
        path, params = u.path, urllib.parse.parse_qs(u.query, keep_blank_values=True)
        srv.log_event("http", severity="info", src=self._src(), method="GET", path=self.path[:200],
                      ua=self.headers.get("User-Agent", "")[:200])
        self._flag(path, params)
        if path in ("/", "/index.html", "/login", "/login.html"):
            return self._send(200, login_page())
        if path.endswith(".cgi"):
            return self._nginx_error(405, "Not Allowed")   # .cgi is POST-only on the real device
        if path == "/dashboard":
            return self._send(200, dashboard(srv.plant, "operator"))
        if path in ("/alarms", "/config/alarms"):
            return self._send(200, alarms_page(srv.plant, "operator"))
        if path == "/configuration":
            return self._send(200, configuration_page("operator"))
        if path == "/config/email":
            return self._send(200, email_page("operator"))
        if path.startswith("/config/"):
            return self._send(200, _page("Configuration", NAV + "<div class=\"card\"><h2>%s</h2><div class=\"body muted\">Settings.</div></div>"
                                         % html.escape(path.rsplit("/", 1)[-1].title()), "operator"))
        if path in ("/device", "/about"):
            return self._send(200, device_page("operator"))
        if path == "/favicon.ico":
            return self._nginx_error(404, "Not Found")
        return self._nginx_error(404, "Not Found")

    def do_HEAD(self):
        return self.do_GET()

    def do_POST(self):
        srv = self.server
        u = urllib.parse.urlsplit(self.path)
        path = u.path
        raw = self._body()
        params = urllib.parse.parse_qs(raw.decode("utf-8", "replace"), keep_blank_values=True)
        # query-string params count too (xml.cgi takes action in either)
        params.update({k: v for k, v in urllib.parse.parse_qs(u.query, keep_blank_values=True).items() if k not in params})
        srv.log_event("http", severity="info", src=self._src(), method="POST", path=self.path[:200],
                      ua=self.headers.get("User-Agent", "")[:200])
        self._flag(path, params)
        if path.endswith(".cgi"):
            return self._xml_cgi(params)
        if path in ("/login", "/login.html"):
            user = (params.get("user", [""])[0])[:128]
            pw = (params.get("password", [""])[0])[:128]
            srv.log_event("web_login", severity="control", src=self._src(), username=user, password=pw)
            return self._send(302, b"", extra={"Location": "/dashboard", "Set-Cookie": "svb=1; Path=/; HttpOnly"})
        if path == "/setpoint":
            try:
                node = int(params.get("node", ["0"])[0])
                value = float(params.get("value", ["0"])[0])
            except ValueError:
                return self._send(302, b"", extra={"Location": "/dashboard"})
            if -60.0 <= value <= 80.0 and srv.plant.set_setpoint(node, value, self._src()):
                c = srv.plant.by_node[node]
                srv.log_event("setpoint", severity="control", src=self._src(), node=node,
                              case=c.name, new_setpoint_c=value, via="web")
            return self._send(302, b"", extra={"Location": "/dashboard"})
        return self._nginx_error(404, "Not Found")


class ColdstoreWeb(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, bind, plant, log_event):
        self.plant = plant
        self.log_event = log_event
        http.server.ThreadingHTTPServer.__init__(self, bind, _WebHandler)


# ===================================================================================================
# SNMP decoy (UDP 5136).
#
# The AK-SM 800A exposes "SNMP" on fixed UDP 5136 (not 161), per the device firewall (firewall1.sh).
# The firmware ships NO net-snmp agent or MIB, so this is a MODELLED minimal SNMP v1/v2c responder
# for the system group only, using the device's real identity and Danfoss's IANA Private Enterprise
# Number 9615 (sysObjectID under 1.3.6.1.4.1.9615).  It exists so a scanner (Shodan, Censys) can
# fingerprint the box as a Danfoss unit; it answers GET/GETNEXT over the system subtree and nothing
# else, drops a wrong community silently, and never changes anything (SET is logged, refused).
# No vulnerable code and no reflection/amplification surface beyond a bounded system-group reply.
# ===================================================================================================
SNMP_COMMUNITY = b"public"
DANFOSS_PEN = (1, 3, 6, 1, 4, 1, 9615)      # Danfoss A/S, IANA enterprise number 9615

_SNMP_GET, _SNMP_GETNEXT, _SNMP_GETRESP, _SNMP_SET = 0xA0, 0xA1, 0xA2, 0xA3


def _ber_len(n):
    if n < 0x80:
        return bytes([n])
    out = bytearray()
    while n:
        out.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(out)]) + bytes(out)


def _ber_tlv(tag, val):
    return bytes([tag]) + _ber_len(len(val)) + val


def _ber_int(n):
    n = int(n)
    length = (n.bit_length() // 8) + 1
    body = n.to_bytes(length, "big", signed=True)
    while len(body) > 1 and ((body[0] == 0x00 and not (body[1] & 0x80))
                             or (body[0] == 0xFF and (body[1] & 0x80))):
        body = body[1:]
    return _ber_tlv(0x02, body)


def _ber_app_uint(tag, n):
    n = int(n) & 0xFFFFFFFF
    body = n.to_bytes(4, "big").lstrip(b"\x00") or b"\x00"
    if body[0] & 0x80:
        body = b"\x00" + body
    return _ber_tlv(tag, body)


def _ber_oid(oid):
    body = bytearray([40 * oid[0] + oid[1]])
    for sub in oid[2:]:
        if sub < 0x80:
            body.append(sub)
        else:
            stack = [sub & 0x7F]
            sub >>= 7
            while sub:
                stack.append((sub & 0x7F) | 0x80)
                sub >>= 7
            body.extend(reversed(stack))
    return _ber_tlv(0x06, bytes(body))


def _ber_read(buf, i):
    """Read one TLV at offset i; return (tag, value_bytes, next_offset)."""
    tag = buf[i]
    i += 1
    length = buf[i]
    i += 1
    if length & 0x80:
        nb = length & 0x7F
        length = int.from_bytes(buf[i:i + nb], "big")
        i += nb
    val = buf[i:i + length]
    return tag, val, i + length


def _parse_oid(b):
    if not b:
        return ()
    out = [b[0] // 40, b[0] % 40]
    cur = 0
    for byte in b[1:]:
        cur = (cur << 7) | (byte & 0x7F)
        if not (byte & 0x80):
            out.append(cur)
            cur = 0
    return tuple(out)


def _snmp_value(kind, val):
    if kind == "str":
        return _ber_tlv(0x04, val)
    if kind == "oid":
        return _ber_oid(val)
    if kind == "ticks":
        return _ber_app_uint(0x43, val)
    if kind == "int":
        return _ber_int(val)
    return _ber_tlv(0x05, b"")           # null


class ColdstoreSNMP(socketserver.ThreadingUDPServer):
    daemon_threads = True
    allow_reuse_address = True
    max_packet_size = 8192

    def __init__(self, bind, plant, log_event, community=SNMP_COMMUNITY):
        self.plant = plant
        self.log_event = log_event
        self.community = community
        socketserver.ThreadingUDPServer.__init__(self, bind, _SnmpHandler)

    # the system group, in lexical OID order (so GETNEXT walks it correctly)
    def system_table(self):
        up = int((time.time() - self.plant.started) * 100)
        descr = "%s %s ADAP-KOOL System Manager, firmware %s" % (DEVICE_VENDOR, DEVICE_MODEL, FIRMWARE)
        return [
            ((1, 3, 6, 1, 2, 1, 1, 1, 0), ("str", descr.encode("ascii", "replace"))),
            ((1, 3, 6, 1, 2, 1, 1, 2, 0), ("oid", DANFOSS_PEN)),
            ((1, 3, 6, 1, 2, 1, 1, 3, 0), ("ticks", up)),
            ((1, 3, 6, 1, 2, 1, 1, 4, 0), ("str", b"service@danfoss.com")),
            ((1, 3, 6, 1, 2, 1, 1, 5, 0), ("str", STORE_ID.encode("ascii", "replace"))),
            ((1, 3, 6, 1, 2, 1, 1, 6, 0), ("str", SITE.encode("ascii", "replace"))),
            ((1, 3, 6, 1, 2, 1, 1, 7, 0), ("int", 72)),
        ]

    def build_response(self, data, src):
        # outer message: SEQUENCE { version INT, community OCTET STRING, pdu }
        tag, msg, _ = _ber_read(data, 0)
        if tag != 0x30:
            return None
        vtag, ver, i = _ber_read(msg, 0)
        ctag, community, i = _ber_read(msg, i)
        ptag, pdu, _ = _ber_read(msg, i)
        version = int.from_bytes(ver, "big") if ver else 0          # 0 = v1, 1 = v2c
        is_v2c = version == 1
        if ptag not in (_SNMP_GET, _SNMP_GETNEXT, _SNMP_SET):
            self.log_event("snmp", severity="info", src=src, op="pdu_%02x" % ptag, dropped=True)
            return None
        # pdu: request-id INT, error-status INT, error-index INT, varbinds SEQUENCE
        rtag, reqid, j = _ber_read(pdu, 0)
        etag, _es, j = _ber_read(pdu, j)
        itag, _ei, j = _ber_read(pdu, j)
        vbtag, vblist, _ = _ber_read(pdu, j)
        oids = []
        k = 0
        while k < len(vblist):
            _t, vb, k = _ber_read(vblist, k)
            otag, ob, _ = _ber_read(vb, 0)
            oids.append(_parse_oid(ob))

        op = {_SNMP_GET: "get", _SNMP_GETNEXT: "getnext", _SNMP_SET: "set"}[ptag]
        first_oid = ".".join(str(x) for x in oids[0]) if oids else ""
        if community != self.community:
            # real agents silently ignore a wrong community (also avoids being an amp relay)
            self.log_event("snmp", severity="info", src=src, op=op, community=community[:64].decode("latin-1"),
                           bad_community=True, oid=first_oid, dropped=True)
            return None

        severity = "control" if ptag == _SNMP_SET else "info"
        self.log_event("snmp", severity=severity, src=src, op=op, version="v2c" if is_v2c else "v1",
                       oid=first_oid, count=len(oids))

        table = self.system_table()
        by_oid = dict(table)
        varbinds = bytearray()
        err_status, err_index = 0, 0

        for idx, oid in enumerate(oids, start=1):
            if ptag == _SNMP_SET:
                # never writable: v1 -> noSuchName (error), v2c -> leave value, report via error
                if not is_v2c and not err_status:
                    err_status, err_index = 2, idx
                varbinds += _ber_tlv(0x30, _ber_oid(oid) + _snmp_value("null", None))
                continue
            if ptag == _SNMP_GET:
                if oid in by_oid:
                    kind, val = by_oid[oid]
                    varbinds += _ber_tlv(0x30, _ber_oid(oid) + _snmp_value(kind, val))
                else:
                    if is_v2c:
                        varbinds += _ber_tlv(0x30, _ber_oid(oid) + bytes([0x80, 0x00]))  # noSuchObject
                    else:
                        if not err_status:
                            err_status, err_index = 2, idx
                        varbinds += _ber_tlv(0x30, _ber_oid(oid) + _snmp_value("null", None))
            else:  # GETNEXT
                nxt = next((e for e in table if e[0] > oid), None)
                if nxt:
                    noid, (kind, val) = nxt
                    varbinds += _ber_tlv(0x30, _ber_oid(noid) + _snmp_value(kind, val))
                else:
                    if is_v2c:
                        varbinds += _ber_tlv(0x30, _ber_oid(oid) + bytes([0x82, 0x00]))  # endOfMibView
                    else:
                        if not err_status:
                            err_status, err_index = 2, idx
                        varbinds += _ber_tlv(0x30, _ber_oid(oid) + _snmp_value("null", None))

        resp_pdu = _ber_tlv(_SNMP_GETRESP,
                            _ber_tlv(0x02, reqid) + _ber_int(err_status) + _ber_int(err_index)
                            + _ber_tlv(0x30, bytes(varbinds)))
        message = _ber_tlv(0x30, _ber_tlv(0x02, ver) + _ber_tlv(0x04, community) + resp_pdu)
        return message


class _SnmpHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        src = "%s:%d" % self.client_address[:2]
        if not data or len(data) > self.server.max_packet_size:
            return
        try:
            resp = self.server.build_response(data, src)
        except Exception:
            self.server.log_event("snmp", severity="info", src=src, op="malformed", dropped=True)
            resp = None
        if resp:
            try:
                sock.sendto(resp, self.client_address)
            except OSError:
                pass


# ===================================================================================================
# Service Tool (TCP 1041) and PI200 (UDP 1041) - the device's two proprietary Danfoss ports.
#
# Both are real external ports (firmware firewall1.sh).  What is faithful to each is grounded in a
# reverse-engineering pass over the real server binary `sm_app` (full DWARF; see analysis/):
#
#   * Service Tool (1041/tcp) is a TLS server.  `sm_app` calls SSL_CTX_use_certificate_file /
#     SSL_accept (OpenSSL 1.0.2d) presenting /danfoss/certs/st_cert.pem, then speaks a proprietary
#     application protocol of ~1617 TFN_* transaction functions *inside* the TLS channel.  We present
#     the device TLS layer exactly (so a TLS scanner sees a real handshake + the device certificate),
#     then capture the client's first application bytes and close.  We do NOT emulate the TFN layer:
#     it is unspecified and a wrong reply would be a worse tell than silence.
#
#   * PI200 (1041/udp) is a broadcast discovery/scan protocol.  `sm_app`'s PI200_send_query emits a
#     64-byte query datagram to udp/1041; node records travel as the 128-byte `eth485_node` struct
#     (protocol_version, store_name[31], unit_name[31], ip, versions, checkbyte).  We decode and flag
#     inbound query/scan datagrams but send no reply: the response envelope is not recoverable from
#     the binary without inventing it, which this decoy never does.
# ===================================================================================================

# The device's TLS profile, verified ex firmware (nginx-auth-proxy/nginx.conf for the web; sm_app
# links OpenSSL 1.0.2d for the Service Tool port).  TLS 1.2 with this cipher list on both ports.
DEVICE_TLS_CIPHERS = (
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
    "DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:"
    "DHE-RSA-CHACHA20-POLY1305")

# PI200 wire facts recovered from sm_app (see analysis/pi200-1041.md).
PI200_QUERY_LEN = 64         # PI200_send_query emits a 64-byte datagram to udp/1041
ETH485_NODE_LEN = 128        # eth485_node discovery record size


def _st_ssl_context():
    """TLS context for the Service Tool port.  Prefer a dedicated ST cert (the real device has a
    separate /danfoss/certs/st_cert.pem), fall back to the web cert, then to None (plaintext capture).
    The real server uses SSLv23_server_method on OpenSSL 1.0.2d, whose practical ceiling is TLS 1.2;
    we pin TLS 1.2 with the device cipher list to match what a modern scanner negotiates."""
    cert = os.environ.get("COLDSTORE_ST_CERT") or os.environ.get("COLDSTORE_CERT")
    key = os.environ.get("COLDSTORE_ST_KEY") or os.environ.get("COLDSTORE_KEY")
    if not (cert and key and os.path.exists(cert) and os.path.exists(key)):
        return None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    try:
        ctx.set_ciphers(DEVICE_TLS_CIPHERS)
    except ssl.SSLError:
        pass
    ctx.load_cert_chain(cert, key)
    return ctx


class _ServiceToolHandler(socketserver.BaseRequestHandler):
    def handle(self):
        srv = self.server
        src = "%s:%d" % self.client_address[:2]
        ctx = srv.ssl_context
        if ctx is None:
            # No cert available: behave as a quiet open port and capture the opening bytes.
            srv.log_event("servicetool_connect", severity="info", src=src, tls=False)
            self.request.settimeout(10)
            try:
                data = self.request.recv(2048)
            except (socket.timeout, OSError):
                data = b""
            if data:
                srv.log_event("servicetool_data", severity="info", src=src,
                              tls=False, bytes=len(data), head=data[:64].hex())
            return
        # Present the device TLS layer, exactly like the real Service Tool port.
        self.request.settimeout(15)
        try:
            tls = ctx.wrap_socket(self.request, server_side=True)
        except (ssl.SSLError, OSError) as exc:
            # A plaintext probe, a legacy-TLS client, or an exploit shape fails the handshake.
            srv.log_event("servicetool_connect", severity="info", src=src, tls=True,
                          handshake="failed", detail=str(exc)[:120])
            return
        cipher = tls.cipher()
        srv.log_event("servicetool_connect", severity="info", src=src, tls=True, handshake="ok",
                      tls_version=(cipher[1] if cipher else None),
                      cipher=(cipher[0] if cipher else None))
        try:
            data = tls.recv(2048)
        except (socket.timeout, OSError):
            data = b""
        if data:
            # First application bytes inside TLS - the start of the proprietary TFN protocol.
            srv.log_event("servicetool_data", severity="info", src=src, tls=True,
                          bytes=len(data), head=data[:64].hex())
        try:
            tls.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            tls.close()
        except OSError:
            pass


class ColdstoreServiceTool(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 16

    def __init__(self, bind, plant, log_event):
        self.plant = plant
        self.log_event = log_event
        self.ssl_context = _st_ssl_context()
        socketserver.ThreadingTCPServer.__init__(self, bind, _ServiceToolHandler)


class _PI200Handler(socketserver.BaseRequestHandler):
    def handle(self):
        data, _sock = self.request
        src = "%s:%d" % self.client_address[:2]
        if not data:
            return
        n = len(data)
        # A 64-byte datagram is the shape of PI200_send_query (device discovery/scan).
        kind = "pi200_query" if n == PI200_QUERY_LEN else "pi200"
        self.server.log_event(kind, severity="info", src=src, bytes=n,
                              node_sized=(n > 0 and n % ETH485_NODE_LEN == 0),
                              head=data[:64].hex())


class ColdstorePI200(socketserver.ThreadingUDPServer):
    daemon_threads = True
    allow_reuse_address = True
    max_packet_size = 8192

    def __init__(self, bind, plant, log_event):
        self.plant = plant
        self.log_event = log_event
        socketserver.ThreadingUDPServer.__init__(self, bind, _PI200Handler)


# ===================================================================================================
# Entry point - start every enabled listener on the one shared plant and log.
# ===================================================================================================
def _bind(spec, default_port):
    """Parse host:port.  Returns None when spec is explicitly empty (listener disabled)."""
    if spec is None:
        return "0.0.0.0", default_port
    if spec == "":
        return None
    host, _, port = spec.rpartition(":")
    return (host or "0.0.0.0"), int(port or default_port)


def main():
    logpath = os.environ.get("COLDSTORE_LOG") or None
    logger = Logger(logpath)
    plant = default_plant()

    servers = []

    mb = _bind(os.environ.get("COLDSTORE_MODBUS_BIND"), 502)
    web = _bind(os.environ.get("COLDSTORE_WEB_BIND"), 8443)
    snmp = _bind(os.environ.get("COLDSTORE_SNMP_BIND"), 5136)
    svc = _bind(os.environ.get("COLDSTORE_SERVICETOOL_BIND"), 1041)
    pi200 = _bind(os.environ.get("COLDSTORE_PI200_BIND"), 1041)

    modbus_srv = ColdstoreModbus(mb, plant, logger.bind("modbus")) if mb else None
    web_srv = ColdstoreWeb(web, plant, logger.bind("storeview")) if web else None
    snmp_srv = ColdstoreSNMP(snmp, plant, logger.bind("snmp")) if snmp else None
    svc_srv = ColdstoreServiceTool(svc, plant, logger.bind("servicetool")) if svc else None
    pi200_srv = ColdstorePI200(pi200, plant, logger.bind("pi200")) if pi200 else None

    web_tls = False
    if web_srv:
        cert, key = os.environ.get("COLDSTORE_CERT"), os.environ.get("COLDSTORE_KEY")
        web_tls = bool(cert and key and os.path.exists(cert) and os.path.exists(key))
        if web_tls:
            ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            # Match the device exactly: TLS 1.2 only, with its nginx cipher list
            # (verified ex firmware nginx-auth-proxy/nginx.conf).
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
            try:
                ctx.set_ciphers(DEVICE_TLS_CIPHERS)
            except ssl.SSLError:
                pass
            ctx.load_cert_chain(cert, key)
            web_srv.socket = ctx.wrap_socket(web_srv.socket, server_side=True)

    def addr(s):
        return "%s:%d" % s if s else "off"

    st_tls = bool(svc_srv and getattr(svc_srv, "ssl_context", None) is not None)
    logger.event("coldstore", "start", severity="info", store=STORE_NAME,
                 model=DEVICE_MODEL, firmware=FIRMWARE,
                 modbus=addr(mb), web=addr(web), snmp=addr(snmp),
                 servicetool=addr(svc), pi200=addr(pi200),
                 web_tls=web_tls, servicetool_tls=st_tls, cases=len(plant.cases))

    for s in (modbus_srv, web_srv, snmp_srv, svc_srv, pi200_srv):
        if s:
            servers.append(s)
            threading.Thread(target=s.serve_forever, kwargs={"poll_interval": 0.5}, daemon=True).start()

    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *a: stop.set())
    signal.signal(signal.SIGINT, lambda *a: stop.set())
    stop.wait()
    logger.event("coldstore", "stop", severity="info")
    for s in servers:
        s.shutdown()
    logger.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
