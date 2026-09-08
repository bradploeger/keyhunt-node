#!/usr/bin/env python3
"""Tests for the node's crypto layer that need no server.

These exercise protocol.py directly: a sealed message round-trips, and every
tampering attempt is rejected. The full node<->server integration test lives in
the server repository (test_e2e.py there), since it needs the server code.
"""
import copy
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import protocol as P

FAILS = []
def check(name, cond):
    print(("  ok  " if cond else "  FAIL ") + name)
    if not cond:
        FAILS.append(name)


def main():
    # Two identities: a "node" (sender) and a "server" (recipient).
    node_sec, node_pub = P.generate_identity()
    srv_sec, srv_pub = P.generate_identity()
    node_sign, node_enc = P.load_secret(node_sec)
    srv_sign, srv_enc = P.load_secret(srv_sec)

    print("[seal/open round trip]")
    payload = {"op": "block_request", "rid": "abc123", "nonce_field": 42}
    env = P.seal(payload, node_sign, node_pub["x25519"],
                 srv_pub["ed25519"], srv_pub["x25519"], seq=1)
    sender, got, ts, seq = P.open_envelope(
        env, srv_pub["ed25519"], srv_enc, lambda h: node_pub["x25519"], last_seq=0)
    check("payload survives round trip", got == payload)
    check("sender identity recovered", sender == node_pub["ed25519"])
    check("sequence recovered", seq == 1)

    print("\n[tampered ciphertext rejected]")
    bad = copy.deepcopy(env)
    ba = bytearray(bytes.fromhex(bad["ct"])); ba[0] ^= 0x01; bad["ct"] = ba.hex()
    try:
        P.open_envelope(bad, srv_pub["ed25519"], srv_enc,
                        lambda h: node_pub["x25519"], last_seq=0)
        check("tamper rejected", False)
    except P.ProtocolError:
        check("tamper rejected", True)

    print("\n[wrong recipient cannot decrypt]")
    _, other_pub = P.generate_identity()
    env2 = P.seal(payload, node_sign, node_pub["x25519"],
                  other_pub["ed25519"], other_pub["x25519"], seq=2)
    try:
        P.open_envelope(env2, srv_pub["ed25519"], srv_enc,
                        lambda h: node_pub["x25519"], last_seq=0)
        check("wrong recipient rejected", False)
    except P.ProtocolError:
        check("wrong recipient rejected", True)

    print("\n[replayed / out-of-order sequence rejected]")
    env3 = P.seal(payload, node_sign, node_pub["x25519"],
                  srv_pub["ed25519"], srv_pub["x25519"], seq=5)
    P.open_envelope(env3, srv_pub["ed25519"], srv_enc,
                    lambda h: node_pub["x25519"], last_seq=4)   # accepted
    try:
        P.open_envelope(env3, srv_pub["ed25519"], srv_enc,
                        lambda h: node_pub["x25519"], last_seq=5)  # replay
        check("replay rejected", False)
    except P.ProtocolError:
        check("replay rejected", True)

    print("\n[stale timestamp rejected]")
    old = P.seal(payload, node_sign, node_pub["x25519"],
                 srv_pub["ed25519"], srv_pub["x25519"], seq=9,
                 ts=int(time.time()) - 10000)
    try:
        P.open_envelope(old, srv_pub["ed25519"], srv_enc,
                        lambda h: node_pub["x25519"], last_seq=0)
        check("stale timestamp rejected", False)
    except P.ProtocolError:
        check("stale timestamp rejected", True)

    print("\n[forged signature rejected]")
    # Re-sign with a different key but keep the claimed sender id.
    forged = copy.deepcopy(env)
    attacker_sign, _ = P.load_secret(P.generate_identity()[0])
    hdr = P._header_bytes(P.VERSION,
                          bytes.fromhex(forged["from"]), bytes.fromhex(forged["to"]),
                          bytes.fromhex(forged["epk"]), bytes.fromhex(forged["nonce"]),
                          forged["ts"], forged["seq"])
    forged["sig"] = attacker_sign.sign(hdr + bytes.fromhex(forged["ct"])).hex()
    try:
        P.open_envelope(forged, srv_pub["ed25519"], srv_enc,
                        lambda h: node_pub["x25519"], last_seq=0)
        check("forged signature rejected", False)
    except P.ProtocolError:
        check("forged signature rejected", True)

    print("\n" + ("ALL NODE TESTS PASSED" if not FAILS
                  else "FAILURES: " + ", ".join(FAILS)))
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
