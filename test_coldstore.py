"""Local tests for the refrigeration decoy: Modbus framing and semantics, the StoreView web UI,
and that every interaction is logged.  No root, no network beyond loopback."""
import http.client
import json
import os
import socket
import struct
import tempfile
import threading
import time
import unittest

# The decoy is one stdlib file (coldstore.py); every public name lives at module top level.
import coldstore as clog
import coldstore as model
from coldstore import (ColdstoreModbus, ColdstoreWeb, ColdstoreSNMP,
                       ColdstoreServiceTool, ColdstorePI200)


def mb(sock, pdu, tid=1, uid=1):
    sock.sendall(struct.pack(">HHHB", tid, 0, len(pdu) + 1, uid) + pdu)
    head = b""
    while len(head) < 6:
        head += sock.recv(6 - len(head))
    _, _, length = struct.unpack(">HHH", head)
    body = b""
    while len(body) < length:
        body += sock.recv(length - len(body))
    pdu = body[1:]                      # strip the unit id
    return pdu[0], pdu[1:]               # function code, data


class ModbusTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.logpath = os.path.join(self.tmp, "log.jsonl")
        self.logger = clog.Logger(self.logpath, echo=False)
        self.plant = model.default_plant()
        self.srv = ColdstoreModbus(("127.0.0.1", 0), self.plant, self.logger.bind("modbus"))
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        self.addCleanup(self.logger.close)
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)

    def logs(self):
        with open(self.logpath) as f:
            return [json.loads(l) for l in f]

    def conn(self):
        s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        self.addCleanup(s.close)
        return s

    def test_read_setpoint_holding(self):
        s = self.conn()
        fc, resp = mb(s, struct.pack(">BHH", 3, 1001, 1))     # holding 1001 = setpoint node 1
        self.assertEqual(fc, 3)
        self.assertEqual(resp[0], 2)
        (raw,) = struct.unpack(">h", resp[1:3])
        self.assertAlmostEqual(raw / 10.0, 3.0, places=1)     # Wurstwaren SB setpoint 3.0

    def test_read_air_temperature_input(self):
        s = self.conn()
        fc, resp = mb(s, struct.pack(">BHH", 4, 3001, 1))     # input 3001 = air temp node 1
        self.assertEqual(fc, 4)
        (raw,) = struct.unpack(">h", resp[1:3])
        self.assertTrue(-5 < raw / 10.0 < 15)                 # a chilled case, plausible range

    def test_write_single_setpoint_reflects(self):
        s = self.conn()
        fc, resp = mb(s, struct.pack(">BHH", 6, 1020, 0x0000 - 0 & 0xFFFF))  # placeholder
        # write +50.0 C to node 20 (a freezer): 500 (0x01F4)
        fc, resp = mb(s, struct.pack(">BHH", 6, 1020, 500))
        self.assertEqual(fc, 6)
        fc, resp = mb(s, struct.pack(">BHH", 3, 1020, 1))     # read it back
        (raw,) = struct.unpack(">h", resp[1:3])
        self.assertAlmostEqual(raw / 10.0, 50.0, places=1)
        self.assertEqual(self.plant.by_node[20].effective_setpoint(self.plant.overrides), 50.0)

    def test_write_negative_setpoint(self):
        s = self.conn()
        fc, resp = mb(s, struct.pack(">Bhh", 6, 21, -180))    # node 21 setpoint -18.0 (holding 1021)
        # correct address:
        fc, resp = mb(s, struct.pack(">BH", 6, 1021) + struct.pack(">h", -180))
        self.assertEqual(fc, 6)
        fc, resp = mb(s, struct.pack(">BHH", 3, 1021, 1))
        (raw,) = struct.unpack(">h", resp[1:3])
        self.assertAlmostEqual(raw / 10.0, -18.0, places=1)

    def test_write_multiple_registers(self):
        s = self.conn()
        payload = struct.pack(">BHHB", 16, 1002, 2, 4) + struct.pack(">hh", 100, 120)  # nodes 2,3 -> 10.0,12.0
        fc, resp = mb(s, payload)
        self.assertEqual(fc, 16)
        self.assertEqual(self.plant.by_node[2].effective_setpoint(self.plant.overrides), 10.0)

    def test_write_coil_compressor_off(self):
        s = self.conn()
        fc, resp = mb(s, struct.pack(">BHH", 5, 104, 0x0000))  # coil 104 = compressor node 4 -> off
        self.assertEqual(fc, 5)
        self.assertEqual(self.plant.overrides[("comp", 4)]["value"], 0)

    def test_read_coils(self):
        s = self.conn()
        fc, resp = mb(s, struct.pack(">BHH", 1, 100, 16))
        self.assertEqual(fc, 1)
        self.assertEqual(resp[0], 2)                           # 16 bits -> 2 bytes

    def test_read_discrete_inputs(self):
        s = self.conn()
        fc, resp = mb(s, struct.pack(">BHH", 2, 100, 8))
        self.assertEqual(fc, 2)

    def test_device_identification(self):
        s = self.conn()
        fc, resp = mb(s, struct.pack(">BBBB", 0x2B, 0x0E, 0x01, 0x00))
        self.assertEqual(fc, 0x2B)
        self.assertIn(b"Danfoss", resp)
        self.assertIn(b"AK-SM 800A", resp)

    def test_illegal_function(self):
        s = self.conn()
        fc, resp = mb(s, struct.pack(">BHH", 0x41, 0, 1))
        self.assertEqual(fc, 0x41 | 0x80)
        self.assertEqual(resp[0], 1)                           # illegal function

    def test_illegal_quantity(self):
        s = self.conn()
        fc, resp = mb(s, struct.pack(">BHH", 3, 0, 200))       # > 125 registers
        self.assertEqual(fc, 3 | 0x80)
        self.assertEqual(resp[0], 3)                           # illegal data value

    def test_control_actions_logged(self):
        s = self.conn()
        mb(s, struct.pack(">BHH", 6, 1001, 450))               # raise node 1 to +45
        time.sleep(0.2)
        lines = self.logs()
        sp = [l for l in lines if l["action"] == "setpoint" and l.get("node") == 1]
        self.assertTrue(sp)
        self.assertEqual(sp[-1]["severity"], "control")
        self.assertEqual(sp[-1]["new_setpoint_c"], 45.0)


class WebTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.logpath = os.path.join(self.tmp, "log.jsonl")
        self.logger = clog.Logger(self.logpath, echo=False)
        self.plant = model.default_plant()
        self.srv = ColdstoreWeb(("127.0.0.1", 0), self.plant, self.logger.bind("storeview"))
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        self.addCleanup(self.logger.close)
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)

    def logs(self):
        with open(self.logpath) as f:
            return [json.loads(l) for l in f]

    def req(self, method, path, body=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        data = r.read()
        c.close()
        return r.status, dict(r.getheaders()), data.decode("utf-8", "replace")

    # --- byte-for-byte match against responses captured from the REAL device's nginx config ---
    import os as _os
    _FIXT = _os.path.join(_os.path.dirname(__file__), "testdata")

    def _raw(self, req):
        import socket, re
        s = socket.create_connection(("127.0.0.1", self.port), timeout=3)
        s.sendall(req); s.settimeout(3); b = b""
        try:
            while True:
                d = s.recv(4096)
                if not d: break
                b += d
        except Exception:
            pass
        s.close()
        return re.sub(rb"Date: [^\r]+", b"Date: <ts>", b)

    def test_404_matches_real_device(self):
        with open(self.__class__._FIXT + "/real_404.bin", "rb") as _f: want = _f.read()
        got = self._raw(b"GET /zzz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        self.assertEqual(got, want)   # incl. the 5 StoreView headers on the error

    def test_cgi_get_is_405_matches_real_device(self):
        with open(self.__class__._FIXT + "/real_cgi_get_405.bin", "rb") as _f: want = _f.read()
        got = self._raw(b"GET /xml.cgi HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        self.assertEqual(got, want)   # .cgi is POST-only

    def test_cgi_options_is_204_matches_real_device(self):
        with open(self.__class__._FIXT + "/real_cgi_options_204.bin", "rb") as _f: want = _f.read()
        got = self._raw(b"OPTIONS /xml.cgi HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        self.assertEqual(got, want)

    def test_login_page(self):
        st, h, body = self.req("GET", "/")
        self.assertEqual(st, 200)
        self.assertIn("StoreView Web", body)
        self.assertIn("Danfoss", body)
        self.assertEqual(h.get("Server"), "nginx/1.26.0")  # exact banner from Danux firmware

    def test_static_page_has_old_last_modified(self):
        st, h, body = self.req("GET", "/")
        self.assertEqual(st, 200)
        self.assertIn("2023", h.get("Last-Modified", ""))          # firmware-era build mtime
        self.assertTrue(h.get("ETag", "").startswith('"'))          # nginx static: ETag present
        self.assertEqual(h.get("Accept-Ranges"), "bytes")

    def test_dynamic_and_error_have_no_last_modified(self):
        # xml.cgi is dynamic (FastCGI) and errors are nginx-generated: no Last-Modified, like the device
        _, hx, _ = self.req("POST", "/xml.cgi", "action=getstatus",
                            {"Content-Type": "application/x-www-form-urlencoded"})
        self.assertNotIn("Last-Modified", hx)
        st, he, _ = self.req("GET", "/nope")
        self.assertEqual(st, 404)
        self.assertNotIn("Last-Modified", he)

    def test_login_records_credentials(self):
        self.req("POST", "/login", "user=admin&password=Danfoss",
                 {"Content-Type": "application/x-www-form-urlencoded"})
        time.sleep(0.2)
        lines = self.logs()
        creds = [l for l in lines if l["action"] == "web_login"]
        self.assertTrue(creds)
        self.assertEqual(creds[-1]["username"], "admin")
        self.assertEqual(creds[-1]["password"], "Danfoss")
        self.assertEqual(creds[-1]["severity"], "control")

    def test_dashboard_renders_cases(self):
        st, h, body = self.req("GET", "/dashboard")
        self.assertEqual(st, 200)
        self.assertIn("Wurstwaren", body)
        self.assertIn("Tiefkuehltruhe", body)
        self.assertIn("Rack A", body)

    def test_setpoint_change_reflects_and_logs(self):
        self.req("POST", "/setpoint", "node=22&value=40.0",
                 {"Content-Type": "application/x-www-form-urlencoded"})
        time.sleep(0.2)
        self.assertEqual(self.plant.by_node[22].effective_setpoint(self.plant.overrides), 40.0)
        lines = self.logs()
        sp = [l for l in lines if l["action"] == "setpoint" and l.get("via") == "web"]
        self.assertTrue(sp and sp[-1]["severity"] == "control")

    def test_setpoint_out_of_range_ignored(self):
        before = self.plant.by_node[23].effective_setpoint(self.plant.overrides)
        self.req("POST", "/setpoint", "node=23&value=999",
                 {"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(self.plant.by_node[23].effective_setpoint(self.plant.overrides), before)

    def test_xml_cgi_getauth_flagged(self):
        # getauth is a POST on the real device; the decoy logs it and answers (no bypass).
        st, h, body = self.req("POST", "/xml.cgi",
                               body="action=getauth&user=admin&code=133742",
                               headers={"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(st, 200)
        self.assertIn("xml", h.get("Content-Type", ""))
        lines = self.logs()
        self.assertTrue([l for l in lines if l["action"] == "auth_getauth" and l["severity"] == "control"])

    def test_xml_cgi_get_is_405_but_logged(self):
        # a GET probe of the auth endpoint gets the real 405, yet the exploit shape is still logged
        st, h, body = self.req("GET", "/xml.cgi?action=getauth&user=admin")
        self.assertEqual(st, 405)
        lines = self.logs()
        self.assertTrue([l for l in lines if l.get("signature") == "auth_getauth"])
        ex = [l for l in lines if l["action"] == "exploit_attempt" and l.get("signature") == "auth_getauth"]
        self.assertTrue(ex)

    def test_command_injection_flagged(self):
        self.req("POST", "/xml.cgi", "action=set_email&smtp_server=1.2.3.4;$(id)>/tmp/x&to_addr=x",
                 {"Content-Type": "application/x-www-form-urlencoded"})
        time.sleep(0.1)
        ex = [l for l in self.logs() if l["action"] == "exploit_attempt"
              and l.get("signature") == "command_injection_attempt"]
        self.assertTrue(ex)

    def test_path_traversal_flagged(self):
        self.req("GET", "/xml.cgi?action=download&file=../../../../etc/passwd")
        ex = [l for l in self.logs() if l["action"] == "exploit_attempt"
              and l.get("signature") == "path_traversal_attempt"]
        self.assertTrue(ex)

    def test_benign_xml_cgi_not_flagged(self):
        self.req("GET", "/xml.cgi?action=getstatus")
        time.sleep(0.1)
        self.assertFalse([l for l in self.logs() if l["action"] == "exploit_attempt"])

    def test_configuration_and_email_pages(self):
        for path, needle in (("/configuration", "Configuration"), ("/config/email", "SMTP")):
            st, h, body = self.req("GET", path)
            self.assertEqual(st, 200)
            self.assertIn(needle, body)

    def test_404(self):
        st, h, body = self.req("GET", "/cgi-bin/luci")
        self.assertEqual(st, 404)


class SnmpTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.logpath = os.path.join(self.tmp, "log.jsonl")
        self.logger = clog.Logger(self.logpath, echo=False)
        self.plant = model.default_plant()
        self.srv = ColdstoreSNMP(("127.0.0.1", 0), self.plant, self.logger.bind("snmp"))
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        self.addCleanup(self.logger.close)
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)

    def logs(self):
        with open(self.logpath) as f:
            return [json.loads(l) for l in f]

    def _msg(self, oid, pdu_tag=0xA0, community=b"public", version=0):
        import coldstore as cs
        vb = cs._ber_tlv(0x30, cs._ber_oid(oid) + cs._ber_tlv(0x05, b""))
        pdu = cs._ber_tlv(pdu_tag, cs._ber_tlv(0x02, bytes([0x2A]))     # request-id 42
                          + cs._ber_int(0) + cs._ber_int(0) + cs._ber_tlv(0x30, vb))
        return cs._ber_tlv(0x30, cs._ber_int(version) + cs._ber_tlv(0x04, community) + pdu)

    def _ask(self, msg):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        try:
            s.sendto(msg, ("127.0.0.1", self.port))
            try:
                data, _ = s.recvfrom(4096)
            except socket.timeout:
                data = b""
        finally:
            s.close()
        return data

    def test_snmp_get_sysdescr_identifies_danfoss(self):
        data = self._ask(self._msg((1, 3, 6, 1, 2, 1, 1, 1, 0)))   # sysDescr.0
        self.assertTrue(data)
        self.assertIn(b"Danfoss AK-SM 800A", data)                  # Shodan's SNMP fingerprint
        time.sleep(0.1)
        self.assertTrue([l for l in self.logs() if l["action"] == "snmp" and l["op"] == "get"])

    def test_snmp_get_sysobjectid_is_danfoss_pen(self):
        import coldstore as cs
        data = self._ask(self._msg((1, 3, 6, 1, 2, 1, 1, 2, 0)))   # sysObjectID.0
        self.assertIn(cs._ber_oid(cs.DANFOSS_PEN), data)            # 1.3.6.1.4.1.9615

    def test_snmp_getnext_walks_system_group(self):
        data = self._ask(self._msg((1, 3, 6, 1, 2, 1, 1), pdu_tag=0xA1))  # GETNEXT of system root
        self.assertIn(b"Danfoss AK-SM 800A", data)                  # next is sysDescr.0

    def test_snmp_bad_community_dropped(self):
        data = self._ask(self._msg((1, 3, 6, 1, 2, 1, 1, 1, 0), community=b"private"))
        self.assertEqual(data, b"")                                 # silently ignored, no response
        time.sleep(0.1)
        self.assertTrue([l for l in self.logs() if l.get("bad_community")])

    def test_snmp_set_is_control_and_changes_nothing(self):
        before = self.plant.summary()
        self._ask(self._msg((1, 3, 6, 1, 2, 1, 1, 4, 0), pdu_tag=0xA3))  # SET sysContact
        time.sleep(0.1)
        self.assertTrue([l for l in self.logs()
                         if l["action"] == "snmp" and l["op"] == "set" and l["severity"] == "control"])
        self.assertEqual(self.plant.summary(), before)


class ProprietaryPortsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.logpath = os.path.join(self.tmp, "log.jsonl")
        self.logger = clog.Logger(self.logpath, echo=False)
        self.plant = model.default_plant()
        self.svc = ColdstoreServiceTool(("127.0.0.1", 0), self.plant, self.logger.bind("servicetool"))
        self.pi = ColdstorePI200(("127.0.0.1", 0), self.plant, self.logger.bind("pi200"))
        self.svc_port = self.svc.server_address[1]
        self.pi_port = self.pi.server_address[1]
        for s in (self.svc, self.pi):
            threading.Thread(target=s.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
            self.addCleanup(s.server_close)
            self.addCleanup(s.shutdown)
        self.addCleanup(self.logger.close)

    def logs(self):
        with open(self.logpath) as f:
            return [json.loads(l) for l in f]

    def test_servicetool_tcp_accepts_and_captures(self):
        s = socket.create_connection(("127.0.0.1", self.svc_port), timeout=3)
        s.sendall(b"\x02\x00SVC-probe")
        time.sleep(0.2)
        s.close()
        cap = [l for l in self.logs() if l["action"] == "servicetool_data"]
        self.assertTrue(cap)
        self.assertIn("5356432d70726f6265", cap[-1]["head"])        # "SVC-probe" captured as hex

    def test_pi200_udp_captures_datagram(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(b"PI200-discover", ("127.0.0.1", self.pi_port))
        time.sleep(0.2)
        s.close()
        self.assertTrue([l for l in self.logs() if l["action"] == "pi200"])


class ModelTest(unittest.TestCase):
    def test_temps_plausible(self):
        p = model.default_plant()
        t = p.now()
        for c in p.cases:
            air = c.air_temp(t, p.overrides)
            if c.kind == model.MT:
                self.assertTrue(-5 < air < 18, "%s %.1f" % (c.name, air))
            else:
                self.assertTrue(-32 < air < -8, "%s %.1f" % (c.name, air))

    def test_override_warms_cabinet(self):
        p = model.default_plant()
        p.set_compressor(1, False, "test")
        p.overrides[("comp", 1)]["at"] = p.now() - 1800     # off for 30 min
        self.assertGreater(p.by_node[1].air_temp(p.now(), p.overrides), p.by_node[1].setpoint + 5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
