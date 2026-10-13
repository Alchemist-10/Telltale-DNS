#!/usr/bin/env python3
"""End-to-end test with a FAKE upstream (no internet needed).
Usage: python3 tests/integration_test.py ./build/dns-filter
"""
import os, random, signal, socket, struct, subprocess, sys, tempfile, threading, time

BIN = sys.argv[1] if len(sys.argv) > 1 else "./dns-filter"
UP_PORT, P1, P2, P3, P4, P5 = 5399, 5391, 5392, 5393, 5394, 5395
tmp = tempfile.mkdtemp()
bl = os.path.join(tmp, "bl.txt")
open(bl, "w").write("blocked.example\n")

def build_query(name, qtype=1, qid=0x1111):
    q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    q += b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\0"
    return q + struct.pack(">HH", qtype, 1)

def ask(port, name, qtype=1, qid=0x1111, timeout=3):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(timeout)
    s.sendto(build_query(name, qtype, qid), ("127.0.0.1", port))
    data, _ = s.recvfrom(4096); s.close()
    return dict(id=struct.unpack(">H", data[:2])[0], rcode=data[3] & 0xF,
                an=struct.unpack(">H", data[6:8])[0], raw=data)

hits = [0]
stop = threading.Event()
def fake_upstream():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", UP_PORT)); s.settimeout(0.2)
    while not stop.is_set():
        try: data, addr = s.recvfrom(4096)
        except socket.timeout: continue
        hits[0] += 1
        end = 12
        while data[end] != 0: end += data[end] + 1
        end += 5
        r = bytearray(data[:end]); r[2:4] = b"\x81\x80"; r[6:8] = b"\x00\x01"
        r += b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + bytes([1, 2, 3, 4])
        s.sendto(bytes(r), addr)
threading.Thread(target=fake_upstream, daemon=True).start()

def start(port, *extra, upstream=f"127.0.0.1:{UP_PORT}"):
    log = os.path.join(tmp, f"log{port}.txt")
    p = subprocess.Popen([BIN, "--port", str(port), "--upstream", upstream, "--blocklist", bl,
                          "--log", log, "--quiet", *extra], stdout=subprocess.DEVNULL)
    time.sleep(1.0)
    return p, log

ok = 0
def check(cond, msg):
    global ok
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond: sys.exit(1)
    ok += 1

p1, log1 = start(P1)
p2, log2 = start(P2, "--sinkhole", "zero")
p3, log3 = start(P3, "--timeout-ms", "500", upstream="127.0.0.1:5398")  # nothing listens there
p4, log4 = start(P4, "--block-tunneling")
reload_bl = os.path.join(tmp, "reload.txt"); open(reload_bl, "w").write("# empty at first\n")
p5 = subprocess.Popen([BIN, "--port", str(P5), "--upstream", f"127.0.0.1:{UP_PORT}", "--blocklist", bl,
                       "--blocklist", reload_bl, "--log", os.path.join(tmp, "log5.txt"), "--quiet"], stdout=subprocess.DEVNULL)
time.sleep(1.0)
try:
    r = ask(P1, "example.com", qid=0x1111)
    check(r["rcode"] == 0 and r["an"] == 1 and r["raw"][-4:] == bytes([1, 2, 3, 4]), "allowed domain is forwarded and answered")
    check(hits[0] == 1, "upstream was queried once")

    r = ask(P1, "example.com", qid=0x2222)
    check(r["id"] == 0x2222, "cached reply carries the NEW query's ID")
    check(hits[0] == 1, "second lookup served from cache (upstream not hit again)")

    check(ask(P1, "blocked.example")["rcode"] == 3, "blocked domain -> NXDOMAIN")
    check(ask(P1, "deep.sub.BLOCKED.Example")["rcode"] == 3, "subdomain + mixed case also blocked")
    check(hits[0] == 1, "blocked queries never reach upstream")

    r = ask(P2, "blocked.example")
    check(r["rcode"] == 0 and r["an"] == 1 and r["raw"][-4:] == bytes(4), "zero mode: A -> 0.0.0.0")
    r = ask(P2, "blocked.example", qtype=28)
    check(r["an"] == 1 and r["raw"][-16:] == bytes(16), "zero mode: AAAA -> ::")

    t0 = time.time(); r = ask(P3, "example.com")
    check(r["rcode"] == 2 and time.time() - t0 < 2, "dead upstream -> SERVFAIL after timeout")

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b"\x00\x01garbage", ("127.0.0.1", P1)); s.close()
    check(ask(P1, "example.com", qid=0x3333)["rcode"] == 0, "server survives malformed packet")

    before = hits[0]
    errs = []
    def worker(t):
        try:
            for i in range(25):
                r = ask(P1, f"host{t}-{i}.test", qid=(t * 100 + i))
                if r["rcode"] != 0 or r["id"] != t * 100 + i: errs.append((t, i))
        except Exception as e: errs.append(repr(e))
    ts = [threading.Thread(target=worker, args=(t,)) for t in range(20)]
    [t.start() for t in ts]; [t.join() for t in ts]
    check(not errs and hits[0] - before == 500, "500 concurrent queries from 20 threads all answered correctly")

    time.sleep(0.2)
    text = open(log1).read()
    check("| BLOCK |" in text and "| CACHE_HIT |" in text and "| ALLOW |" in text and "DROP_MALFORMED" in text,
          "log has ALLOW / CACHE_HIT / BLOCK / DROP_MALFORMED lines")
    check("UPSTREAM_TIMEOUT" in open(log3).read(), "timeout is logged")

    # ---- Phase 3: tunneling detector
    rnd = random.Random(5)
    payload = "".join(rnd.choice("abcdefghijklmnopqrstuvwxyz234567") for _ in range(48))
    tunnel_name = payload + ".t.evil-tunnel.com"
    r = ask(P1, tunnel_name)
    check(r["rcode"] == 0, "flag-only mode still answers a tunneling-looking query")
    r = ask(P1, "a" * 50 + ".evil-tunnel.com")
    time.sleep(0.2)
    text = open(log1).read()
    check("long_label=48,entropy=" in text and "FLAG(long_label=50" in text, "FLAG lines logged with reasons")

    before = hits[0]
    r = ask(P4, tunnel_name)
    check(r["rcode"] == 3 and hits[0] == before, "--block-tunneling sinkholes it and never reaches upstream")
    check(ask(P4, "www.example.com")["rcode"] == 0, "normal names are unaffected in blocking mode")
    time.sleep(0.2)
    check("BLOCK_TUNNEL(" in open(log4).read(), "BLOCK_TUNNEL logged")

    flagged = 0
    for i in range(60):   # slow-and-steady exfiltration: 60 distinct subdomains of one domain
        ask(P1, f"chunk{i}.exfil-site.org", qid=7000 + i)
    time.sleep(0.2)
    check("unique_subdomains=51/60s" in open(log1).read(), "many-unique-subdomains rate signal fires")

    # ---- Phase 3: hot reload with SIGHUP
    check(ask(P5, "reload-me.example")["rcode"] == 0, "before reload: domain is allowed")
    open(reload_bl, "a").write("reload-me.example\n")
    p5.send_signal(signal.SIGHUP); time.sleep(0.7)
    check(ask(P5, "reload-me.example")["rcode"] == 3, "after SIGHUP: new blocklist entry is enforced, no restart")
    check(ask(P5, "blocked.example")["rcode"] == 3, "older entries still blocked")
finally:
    for p in (p1, p2, p3, p4, p5): p.terminate()
    stop.set()
print(f"\n{ok} checks passed")
