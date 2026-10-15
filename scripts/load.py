#!/usr/bin/env python3
"""A load generator for the node's HTTP and WebSocket server, through the port
forward (scripts/perf.sh runs the whole matrix against a quiet node).

  load.py MODE [-p PORT] [-c CONNECTIONS] [-n COUNT] [-s SIZE] [--path PATH] [-t SECONDS]

  http     keep-alive: each of CONNECTIONS workers sends COUNT GET PATH requests in turn
  httpnc   a connection per request: each worker does connect, GET PATH, close, COUNT times
  ws       each of CONNECTIONS sockets sends COUNT text messages of SIZE bytes, waiting for each echo
  ticks    hold CONNECTIONS sockets for SECONDS and count the ticks each one receives
  udp      each worker sends COUNT datagrams of SIZE bytes to the node's UDP port, waiting
           for each echo (1 s timeout: a miss counts as lost)
  udpflood each worker sends COUNT datagrams back to back, then collects echoes for a second:
           what gets through and how many a second

One line per run: operations per second over all workers, latency percentiles
in ms per operation (connect + request + answer for httpnc), errors."""
import base64, os, socket, sys, threading, time

def arg(flag, default, conv=str):
    return conv(sys.argv[sys.argv.index(flag) + 1]) if flag in sys.argv else default

MODE = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else "http"
PORT, CONN, COUNT = arg("-p", 8080, int), arg("-c", 1, int), arg("-n", 1000, int)
SIZE, PATH, SECS = arg("-s", 5, int), arg("--path", "/"), arg("-t", 3.0, float)
HOST = "127.0.0.1"

class Reader:
    def __init__(self, c): self.c, self.buf = c, b""
    def fill(self):
        x = self.c.recv(65536)
        if not x: raise OSError("closed")
        self.buf += x
    def until(self, end):
        while end not in self.buf: self.fill()
        d, self.buf = self.buf.split(end, 1)
        return d + end
    def exact(self, n):
        while len(self.buf) < n: self.fill()
        d, self.buf = self.buf[:n], self.buf[n:]
        return d
    def frame(self):
        h = self.exact(2); n = h[1] & 0x7F
        if n == 126: n = int.from_bytes(self.exact(2), "big")
        return h[0] & 0xF, self.exact(n)

def connect():
    c = socket.create_connection((HOST, PORT), timeout=10)
    c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return c, Reader(c)

def get(c, r, path):
    c.sendall(b"GET " + path.encode() + b" HTTP/1.1\r\nHost: q\r\n\r\n")
    head = r.until(b"\r\n\r\n")
    n = [int(l.split(b":")[1]) for l in head.split(b"\r\n") if l.lower().startswith(b"content-length:")][0]
    r.exact(n)
    return len(head) + n

def upgrade(c, r):
    key = base64.b64encode(os.urandom(16))
    c.sendall(b"GET /ws HTTP/1.1\r\nHost: q\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: "
              + key + b"\r\nSec-WebSocket-Version: 13\r\n\r\n")
    head = r.until(b"\r\n\r\n")
    if not head.startswith(b"HTTP/1.1 101 "): raise OSError("no upgrade: " + head[:40].decode(errors="replace"))

def ws_send(c, op, payload):
    mask = os.urandom(4)
    n = len(payload)
    head = bytes([0x80 | op, 0x80 | n]) if n < 126 else bytes([0x80 | op, 0x80 | 126]) + n.to_bytes(2, "big")
    c.sendall(head + mask + bytes(b ^ mask[i & 3] for i, b in enumerate(payload)))

def echo(c, r, payload):
    ws_send(c, 1, payload)
    while True:
        op, d = r.frame()
        if op == 1 and d.startswith(b"you said: "): return len(d)

lat, errors, byts, lost, lock = [], [0], [0], [0], threading.Lock()

def worker(i):
    mine, b, e, miss = [], 0, 0, 0
    try:
        if MODE == "http":
            c, r = connect()
            for _ in range(COUNT):
                t = time.perf_counter(); b += get(c, r, PATH); mine.append(time.perf_counter() - t)
            c.close()
        elif MODE == "httpnc":
            for _ in range(COUNT):
                t = time.perf_counter(); c, r = connect(); b += get(c, r, PATH); c.close(); mine.append(time.perf_counter() - t)
        elif MODE == "ws":
            c, r = connect(); upgrade(c, r); payload = b"x" * SIZE
            for _ in range(COUNT):
                t = time.perf_counter(); b += echo(c, r, payload); mine.append(time.perf_counter() - t)
            ws_send(c, 8, b""); c.close()
        elif MODE == "ticks":
            c, r = connect(); upgrade(c, r); c.settimeout(SECS + 2); t0 = time.perf_counter(); n = 0
            while time.perf_counter() - t0 < SECS:
                try:
                    op, d = r.frame()
                    if d.startswith(b"tick"): n += 1; b += len(d)
                except socket.timeout: break
            mine = [n]
            ws_send(c, 8, b""); c.close()
        elif MODE == "udp":
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(1.0); payload = b"x" * SIZE
            for _ in range(COUNT):
                t = time.perf_counter(); s.sendto(payload, (HOST, PORT))
                try:
                    d, _ = s.recvfrom(65535); mine.append(time.perf_counter() - t); b += len(d)
                except socket.timeout:
                    miss += 1
            s.close()
        elif MODE == "udpflood":
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(1.0); payload = b"x" * SIZE
            t0 = time.perf_counter()
            for _ in range(COUNT): s.sendto(payload, (HOST, PORT))
            sent_in = time.perf_counter() - t0
            got = 0
            while True:
                try:
                    d, _ = s.recvfrom(65535); got += 1; b += len(d)
                except socket.timeout:
                    break
            mine = [sent_in] * got; miss = COUNT - got
            s.close()
    except OSError as ex:
        e += 1; sys.stderr.write("worker %d: %s\n" % (i, ex))
    with lock:
        lat.extend(mine); errors[0] += e; byts[0] += b; lost[0] += miss

t0 = time.perf_counter()
ths = [threading.Thread(target=worker, args=(i,)) for i in range(CONN)]
for th in ths: th.start()
for th in ths: th.join()
el = time.perf_counter() - t0
if MODE == "udpflood":
    n = len(lat); el = max(lat) if lat else el
    print("%-8s c=%-2d n=%-5d size=%-4d  sent %d in %.2f s (%.0f/s), echoed %d (%.1f%% lost), %5.2f MB/s back"
          % (MODE, CONN, COUNT, SIZE, CONN * COUNT, el, CONN * COUNT / el, n, 100.0 * lost[0] / max(CONN * COUNT, 1), byts[0] / (el + 1.0) / 1e6))
elif MODE == "udpflood":
    n = len(lat); el = max(lat) if lat else el
    print("%-8s c=%-2d n=%-5d size=%-4d  sent %d in %.2f s (%.0f/s), echoed %d (%.1f%% lost), %5.2f MB/s back"
          % (MODE, CONN, COUNT, SIZE, CONN * COUNT, el, CONN * COUNT / el, n, 100.0 * lost[0] / max(CONN * COUNT, 1), byts[0] / (el + 1.0) / 1e6))
elif MODE == "ticks":
    print("ticks  c=%d  %.1f s: %d ticks over all sockets (%.2f per socket per second), errors %d"
          % (CONN, SECS, sum(lat), sum(lat) / max(CONN, 1) / SECS, errors[0]))
else:
    lat.sort(); n = len(lat)
    pc = lambda p: lat[min(n - 1, int(p * n))] * 1000 if n else float("nan")
    print("%-8s c=%-2d n=%-5d size=%-4d path=%-6s  %8.0f ops/s  p50 %6.2f ms  p90 %6.2f  p99 %6.2f  max %7.1f  %5.2f MB/s  errors %d  lost %d  (%d ops in %.1f s)"
          % (MODE, CONN, COUNT, SIZE, PATH, n / el, pc(0.5), pc(0.9), pc(0.99), lat[-1] * 1000 if n else 0, byts[0] / el / 1e6, errors[0], lost[0], n, el))
