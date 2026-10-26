"""Test of tools/nostr_publish.py without a network: the event of a package is a valid NIP-01 event (id = SHA-256 of the serialisation, BIP340 signature of the id, the "d" tag is the digest),
refused when the signature is not valid, and the WebSocket client talks to a small relay of its own (a thread on 127.0.0.1) that answers with the OK message.
  py -3.13 tools/test_nostr_publish.py"""
import base64, hashlib, json, os, socket, struct, sys, threading
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import bip340, pkg_pack as P, nostr_publish as N

KEY = hashlib.sha256(b"psxx test signing key").digest()
fails = 0


def check(name, ok):
    global fails
    print("%-70s %s" % (name, "ok" if ok else "FAILED"))
    fails += 0 if ok else 1


pkg, pub = P.build(2, [(1, b"some data" * 20, "stored"), (2, b"more" * 50, "lzma")], key=KEY)
ev = N.event_of(pkg, pub)

# a NIP-01 event: the id is the hash of [0, pubkey, created_at, kind, tags, content] with no spaces, the signature is of the id
text = json.dumps([0, ev["pubkey"], ev["created_at"], ev["kind"], ev["tags"], ev["content"]], separators=(",", ":"), ensure_ascii=False)
check("the id is the SHA-256 of the NIP-01 serialisation", hashlib.sha256(text.encode()).hexdigest() == ev["id"])
check("the signature is a BIP340 signature of the id", bip340.verify(pub, bytes.fromhex(ev["id"]), bytes.fromhex(ev["sig"])))
check("the d tag and the content are the digest of the header and the table", ev["tags"] == [["d", ev["content"]]] and len(ev["content"]) == 64)
check("created_at and kind are the fixed ones", ev["created_at"] == 1792774136 and ev["kind"] == 30078)
check("the same package gives the same event", N.event_of(P.build(2, [(1, b"some data" * 20, "stored"), (2, b"more" * 50, "lzma")], key=KEY)[0], pub) == ev)
other, _ = P.build(2, [(1, b"other", "stored")], key=KEY)
check("another package is another event (another d tag)", N.event_of(other, pub)["tags"] != ev["tags"])
try:
    N.event_of(pkg, bip340.pubkey(hashlib.sha256(b"someone else").digest()))
    check("a key that did not sign the package is refused", False)
except SystemExit:
    check("a key that did not sign the package is refused", True)
unsigned, _ = P.build(2, [(1, b"x", "stored")], pub=pub)
try:
    N.event_of(unsigned, pub)
    check("a package with a zero signature is refused", False)
except SystemExit:
    check("a package with a zero signature is refused", True)

# a relay of our own: the handshake, one masked frame in, the OK message out
got = {}


def relay(srv):
    c, _ = srv.accept()
    req = b""
    while b"\r\n\r\n" not in req:
        req += c.recv(4096)
    k = [l.split(b": ", 1)[1] for l in req.split(b"\r\n") if l.lower().startswith(b"sec-websocket-key")][0]
    acc = base64.b64encode(hashlib.sha1(k + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest())
    c.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + acc + b"\r\n\r\n")
    f = b""
    while len(f) < 2:
        f += c.recv(65536)
    ln, o = f[1] & 127, 2
    if ln == 126:
        while len(f) < 4: f += c.recv(65536)
        ln, o = struct.unpack(">H", f[2:4])[0], 4
    while len(f) < o + 4 + ln:
        f += c.recv(65536)
    mask = f[o:o + 4]
    msg = bytes(x ^ mask[i % 4] for i, x in enumerate(f[o + 4:o + 4 + ln])).decode()
    got["msg"] = json.loads(msg)
    reply = json.dumps(["NOTICE", "hello"]).encode()                       # a message that is not the answer first
    c.sendall(bytes([0x81, len(reply)]) + reply)
    reply = json.dumps(["OK", got["msg"][1]["id"], True, ""]).encode()
    c.sendall(bytes([0x81, len(reply)]) + reply)
    c.close()


srv = socket.socket()
srv.bind(("127.0.0.1", 0))
srv.listen(1)
th = threading.Thread(target=relay, args=(srv,), daemon=True)
th.start()
ans = N.publish("ws://127.0.0.1:%d" % srv.getsockname()[1], ev, timeout=5)
th.join(5)
check("the relay got  [\"EVENT\", event]", got.get("msg", [None])[0] == "EVENT" and got["msg"][1] == ev)
check("the answer is the OK of the event", ans is not None and ans[0] == "OK" and ans[1] == ev["id"] and ans[2] is True)
print("nostr_publish tests: %d failed" % fails)
sys.exit(1 if fails else 0)
