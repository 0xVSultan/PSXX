"""The Nostr event of a card package (core/pkg/pkg.h): the proof that the key signed this package, ready to publish.

  py -3.13 tools/nostr_publish.py <package> [--pub HEX64] [--relay wss://relay.example ...]

Without --relay it prints the event (one JSON line: id, pubkey, created_at, kind, tags, content, sig); with one or more it also sends  ["EVENT", <event>]  to each relay and prints
what the relay answers (["OK", id, true|false, message]). --pub is the x only public key (hex) that signed the package; the default is the key of tools/sign_key.py. The signature is
checked against it before anything is printed or sent: a package that is not signed (a zero signature, see pkg_pack.py build --pub / attach) is refused.

The event is kind 30078 (NIP-78) with the digest of the package as its "d" tag and as its content, and a fixed created_at, so the same package always gives the same event, and
two packages never replace each other on a relay. Publishing is outward facing: nothing is sent unless --relay is given."""
import argparse, base64, hashlib, json, os, socket, ssl, struct, sys, time
from urllib.parse import urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import pkg_pack as P
import bip340


def event_of(data, pub):
    """the complete event of a signed package (raises SystemExit when the signature is not valid for pub)"""
    n = int.from_bytes(data[6:8], "little")
    te = P.HEADER + n * P.ENTRY
    head, sig = data[:te], data[te:te + P.SIG]
    ev_text = P.event_json(pub, head)
    eid = hashlib.sha256(ev_text.encode()).digest()
    if not bip340.verify(pub, eid, sig):
        raise SystemExit("the signature of the package is not valid for the key %s" % pub.hex())
    dig = P.digest(head).hex()
    return {"id": eid.hex(), "pubkey": pub.hex(), "created_at": P.EVENT_TIME, "kind": P.EVENT_KIND, "tags": [["d", dig]], "content": dig, "sig": sig.hex()}


# ---- a small WebSocket client (RFC 6455): one text message out, text messages in ----

def ws_connect(url, timeout):
    u = urlparse(url)
    if u.scheme not in ("ws", "wss"):
        raise SystemExit("not a relay address (ws:// or wss://): %s" % url)
    port = u.port or (443 if u.scheme == "wss" else 80)
    s = socket.create_connection((u.hostname, port), timeout=timeout)
    if u.scheme == "wss":
        s = ssl.create_default_context().wrap_socket(s, server_hostname=u.hostname)
    key = base64.b64encode(os.urandom(16)).decode()
    path = (u.path or "/") + ("?" + u.query if u.query else "")
    s.sendall(("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n" % (path, u.netloc, key)).encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        c = s.recv(4096)
        if not c:
            raise SystemExit("the relay closed the connection")
        buf += c
    if b" 101 " not in buf.split(b"\r\n", 1)[0]:
        raise SystemExit("the relay did not accept the WebSocket: %s" % buf.split(b"\r\n", 1)[0].decode(errors="replace"))
    return s, buf.split(b"\r\n\r\n", 1)[1]


def ws_send(s, text):
    b = text.encode()
    n = len(b)
    head = bytes([0x81]) + (bytes([0x80 | n]) if n < 126 else bytes([0x80 | 126]) + struct.pack(">H", n) if n < 65536 else bytes([0x80 | 127]) + struct.pack(">Q", n))
    mask = os.urandom(4)
    s.sendall(head + mask + bytes(x ^ mask[i % 4] for i, x in enumerate(b)))


def ws_recv(s, pending):
    """the next text message (control frames are answered or skipped); returns (text, rest)"""
    buf = pending
    def need(k):
        nonlocal buf
        while len(buf) < k:
            c = s.recv(65536)
            if not c:
                raise SystemExit("the relay closed the connection")
            buf += c
    while True:
        need(2)
        op, ln = buf[0] & 15, buf[1] & 127
        o = 2
        if ln == 126:
            need(4); ln = struct.unpack(">H", buf[2:4])[0]; o = 4
        elif ln == 127:
            need(10); ln = struct.unpack(">Q", buf[2:10])[0]; o = 10
        need(o + ln)
        payload, buf = buf[o:o + ln], buf[o + ln:]
        if op == 1:
            return payload.decode(errors="replace"), buf
        if op == 8:
            raise SystemExit("the relay closed the connection")
        if op == 9:                                         # ping: pong (masked, as every frame of a client)
            mask = os.urandom(4)
            s.sendall(bytes([0x8A, 0x80 | len(payload)]) + mask + bytes(x ^ mask[i % 4] for i, x in enumerate(payload)))


def publish(url, ev, timeout=15):
    s, rest = ws_connect(url, timeout)
    try:
        ws_send(s, json.dumps(["EVENT", ev], separators=(",", ":"), ensure_ascii=False))
        end = time.time() + timeout
        while time.time() < end:
            msg, rest = ws_recv(s, rest)
            try:
                m = json.loads(msg)
            except ValueError:
                continue
            if isinstance(m, list) and m and m[0] == "OK" and len(m) > 1 and m[1] == ev["id"]:
                return m
        return None
    finally:
        s.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("package")
    ap.add_argument("--pub", help="x only public key, hex (default: the key in release.json next to the package, else the key of tools/sign_key.py)")
    ap.add_argument("--relay", action="append", default=[])
    a = ap.parse_args()
    import sign_key
    rj = os.path.join(os.path.dirname(os.path.abspath(a.package)), "release.json")
    if a.pub:
        pub = bytes.fromhex(a.pub)
    elif os.path.exists(rj):
        pub = bytes.fromhex(json.load(open(rj))["key"])                              # the key the release was made for (release.py build --pub)
    else:
        pub = sign_key.public()
    ev = event_of(open(a.package, "rb").read(), pub)
    print(json.dumps(ev, separators=(",", ":"), ensure_ascii=False))
    for r in a.relay:
        try:
            ans = publish(r, ev)
        except (OSError, ssl.SSLError) as e:
            print("%s: %s" % (r, e), file=sys.stderr)
            continue
        print("%s: %s" % (r, json.dumps(ans) if ans else "no answer"), file=sys.stderr)


if __name__ == "__main__":
    main()
