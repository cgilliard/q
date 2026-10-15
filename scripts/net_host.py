#!/usr/bin/env python3
"""The host side of the guest's network tests (the guest reaches the host's
loopback as 10.0.2.2 under slirp):
  UDP echo on 127.0.0.1:47654
  TCP echo on 127.0.0.1:47655
  a knocker: every 0.3 s connect to 127.0.0.1:47653 (forwarded to the guest's
  47653), send "knock", expect it back — the guest's TCP server test
  a UDP knocker: every 0.3 s a datagram to 127.0.0.1:47653 (forwarded to the
  guest's 47653), expecting it back — the guest's UDP endpoint test
  an HTTP prober: every 0.3 s connect to 127.0.0.1:47656 (forwarded to the
  guest's 47656), GET / and check the page, upgrade to a WebSocket and check
  the accept key, send "ping" and expect "you said: ping", close — each step
  only after the previous one checked out, so the guest's counters say how far
  a real client got (src/http.fam httplive)."""
import base64, hashlib, os, socket, threading, time

def udp_echo():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 47654))
    while True:
        d, a = s.recvfrom(65535)
        s.sendto(d, a)

def tcp_echo():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 47655))
    s.listen(8)
    while True:
        c, _ = s.accept()
        c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        threading.Thread(target=echo_conn, args=(c,), daemon=True).start()

def echo_conn(c):
    try:
        while True:
            d = c.recv(65536)
            if not d:
                break
            c.sendall(d)
    except OSError:
        pass
    finally:
        c.close()

def knocker():
    while True:
        try:
            c = socket.create_connection(("127.0.0.1", 47653), timeout=1)
            c.sendall(b"knock")
            c.recv(5)
            c.close()
        except OSError:
            pass
        time.sleep(0.3)

class Reader:
    """a socket with a buffer, so bytes that arrive early are not lost"""
    def __init__(self, c):
        self.c, self.buf = c, b""

    def fill(self):
        x = self.c.recv(4096)
        if not x:
            raise OSError("closed")
        self.buf += x

    def until(self, end):
        while end not in self.buf:
            self.fill()
        d, self.buf = self.buf.split(end, 1)
        return d + end

    def exact(self, n):
        while len(self.buf) < n:
            self.fill()
        d, self.buf = self.buf[:n], self.buf[n:]
        return d

    def frame(self):
        """one WebSocket frame: (opcode, payload); the server's are unmasked"""
        h = self.exact(2)
        n = h[1] & 0x7F
        if n == 126:
            n = int.from_bytes(self.exact(2), "big")
        return h[0] & 0xF, self.exact(n)

def ws_send(c, op, payload):
    mask = os.urandom(4)
    c.sendall(bytes([0x80 | op, 0x80 | len(payload)]) + mask
              + bytes(b ^ mask[i & 3] for i, b in enumerate(payload)))

def http_probe_once():
    c = socket.create_connection(("127.0.0.1", 47656), timeout=1)
    r = Reader(c)
    try:
        c.sendall(b"GET / HTTP/1.1\r\nHost: q\r\nConnection: keep-alive\r\n\r\n")
        head = r.until(b"\r\n\r\n")
        if not head.startswith(b"HTTP/1.1 200 "):
            return
        n = [int(l.split(b":")[1]) for l in head.split(b"\r\n") if l.lower().startswith(b"content-length:")][0]
        if b"hello" not in r.exact(n):
            return
        key = base64.b64encode(os.urandom(16))
        c.sendall(b"GET /ws HTTP/1.1\r\nHost: q\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                  b"Sec-WebSocket-Key: " + key + b"\r\nSec-WebSocket-Version: 13\r\n\r\n")
        head = r.until(b"\r\n\r\n")
        want = base64.b64encode(hashlib.sha1(key + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest())
        if not head.startswith(b"HTTP/1.1 101 ") or b"Sec-WebSocket-Accept: " + want not in head:
            return
        ws_send(c, 1, b"ping")
        while True:
            op, d = r.frame()
            if op == 1 and d.startswith(b"tick"):
                continue
            if (op, d) != (1, b"you said: ping"):
                return
            break
        ws_send(c, 8, b"")
        while r.frame()[0] != 8:
            pass
    finally:
        c.close()

def udp_knocker():
    """every 0.3 s a datagram to 127.0.0.1:47653 (forwarded to the guest's
    47653), expecting it back: the guest's UDP endpoint test (src/udpsrv.fam)"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1)
    while True:
        try:
            s.sendto(b"udp knock", ("127.0.0.1", 47653))
            s.recvfrom(64)
        except OSError:
            pass
        time.sleep(0.3)

def http_prober():
    while True:
        try:
            http_probe_once()
        except (OSError, ValueError, IndexError):
            pass
        time.sleep(0.3)

for f in (udp_echo, tcp_echo, http_prober, udp_knocker):
    threading.Thread(target=f, daemon=True).start()
knocker()
