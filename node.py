#!/usr/bin/env python3
"""Node-side client for the keyhunt coordination server.

Wraps every call in a sealed envelope, verifies and decrypts the reply, and
pins the server's identity key so a man in the middle cannot answer for it.

As a library:

    node = Node("node.key", "https://coord.example:8443", server_ed_hex, server_x_hex)
    node.register(gpu="RTX 4090", sw="keyhunt-gpu 1.0")
    targets = node.get_targets()
    blk = node.request_block()
    ... run the search over blk["prefix"] ...
    node.complete_block(blk["block_idx"], seconds=812.4, keys_checked=1<<40)
    node.report_match(privkey_hex, pubkey_hex, block_idx=blk["block_idx"])

As a CLI, mainly for testing and ops:

    node.py --key node.key --server-info server.pub register --gpu "RTX 4090"
    node.py ... targets --out targets.txt
    node.py ... request
    node.py ... stats
"""

import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import protocol as P


class Node:
    def __init__(self, key_path, url, server_ed_hex, server_x_hex, timeout=30):
        with open(key_path) as f:
            secret = json.load(f)
        self.sign_key, self.enc_key = P.load_secret(secret)
        self.ed_hex = secret["ed25519"]
        self.x_hex = secret["x25519"]
        self.url = url.rstrip("/")
        self.server_ed = server_ed_hex
        self.server_x = server_x_hex
        self.timeout = timeout
        self.out_seq = int(time.time() * 1000)   # monotonic across restarts
        self.server_seq = None

    def _call(self, path, op, payload=None, retries=3):
        body = dict(payload or {})
        body["op"] = op
        body["rid"] = os.urandom(8).hex()
        last = None
        for attempt in range(retries):
            self.out_seq += 1
            env = P.seal(body, self.sign_key, self.x_hex,
                         self.server_ed, self.server_x, self.out_seq)
            req = urllib.request.Request(
                self.url + path, data=json.dumps(env).encode(),
                headers={"Content-Type": "application/json"}, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    resp = json.loads(r.read())
            except urllib.error.HTTPError as e:
                detail = e.read().decode(errors="replace")[:200]
                raise RuntimeError("server %d on %s: %s" % (e.code, path, detail))
            except urllib.error.URLError as e:
                last = e
                time.sleep(min(2 ** attempt, 10))
                continue

            sender, reply, ts, seq = P.open_envelope(
                resp, self.ed_hex, self.enc_key,
                lambda h: self.server_x, last_seq=self.server_seq)
            if sender != self.server_ed:
                raise RuntimeError("reply signed by an unexpected key")
            if reply.get("rid") != body["rid"]:
                raise RuntimeError("reply request-id mismatch")
            self.server_seq = seq
            return reply
        raise RuntimeError("cannot reach server: %s" % last)

    # -------------------------------------------------------------- endpoints
    def register(self, gpu, sw):
        return self._call("/v1/register", "register",
                          {"x25519": self.x_hex, "gpu": gpu, "sw": sw})

    def get_targets(self):
        return self._call("/v1/targets", "targets")

    def request_block(self):
        return self._call("/v1/block/request", "block_request")

    def complete_block(self, block_idx, seconds, keys_checked=0):
        return self._call("/v1/block/complete", "block_complete",
                          {"block_idx": block_idx, "seconds": seconds,
                           "keys_checked": keys_checked})

    def report_match(self, privkey_hex, pubkey_hex, block_idx=-1):
        return self._call("/v1/match", "match",
                          {"privkey": privkey_hex, "pubkey": pubkey_hex,
                           "block_idx": block_idx})

    def stats(self):
        return self._call("/v1/stats", "stats")


def _load_server_info(path):
    with open(path) as f:
        d = json.load(f)
    return d["ed25519"], d["x25519"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--key", required=True, help="this node's key file")
    ap.add_argument("--server-info", required=True, help="server public-key json")
    ap.add_argument("--url", default="http://127.0.0.1:8443")
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("register")
    r.add_argument("--gpu", default="unknown")
    r.add_argument("--sw", default="keyhunt-gpu unknown")
    t = sub.add_parser("targets")
    t.add_argument("--out", default="targets.txt")
    sub.add_parser("request")
    c = sub.add_parser("complete")
    c.add_argument("block_idx", type=int)
    c.add_argument("seconds", type=float)
    c.add_argument("--keys", type=int, default=0)
    m = sub.add_parser("match")
    m.add_argument("privkey")
    m.add_argument("pubkey")
    m.add_argument("--block-idx", type=int, default=-1)
    sub.add_parser("stats")
    a = ap.parse_args()

    ed, x = _load_server_info(a.server_info)
    node = Node(a.key, a.url, ed, x)

    if a.cmd == "register":
        print(json.dumps(node.register(a.gpu, a.sw), indent=2))
    elif a.cmd == "targets":
        res = node.get_targets()
        with open(a.out, "w") as f:
            f.write("\n".join(res["targets"]) + "\n")
        print("wrote %d targets to %s (digest %s)" %
              (res["count"], a.out, res["digest"][:16]))
    elif a.cmd == "request":
        print(json.dumps(node.request_block(), indent=2))
    elif a.cmd == "complete":
        print(json.dumps(node.complete_block(a.block_idx, a.seconds, a.keys), indent=2))
    elif a.cmd == "match":
        print(json.dumps(node.report_match(a.privkey, a.pubkey, a.block_idx), indent=2))
    elif a.cmd == "stats":
        print(json.dumps(node.stats(), indent=2))


if __name__ == "__main__":
    main()
