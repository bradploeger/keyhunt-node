# keyhunt-node

Node-side client for the [keyhunt coordination server](#). A node registers with
the server, downloads the search list, leases 216-bit prefix blocks, runs the
GPU search over each, and reports completions and any matches back — all over an
encrypted, signed, public-key-authenticated channel.

The server is a **separate repository**: [`keyhunt-coord-server`](#). This repo
is the node side. The two share `protocol.py` and `keygen.py` verbatim.

## Security

Two keypairs per node: **Ed25519** for signing (this is the node's identity) and
**X25519** for encryption. Every request is sealed with a fresh ephemeral ECDH →
HKDF-SHA256 → ChaCha20-Poly1305 and Ed25519-signed; every reply is verified and
decrypted the same way. The node pins the server's key from `server.pub`, so a
man in the middle cannot answer for it. No passwords or tokens are used anywhere.

## Files

```
node.py            client library + CLI
protocol.py        sealed-envelope layer (shared with keyhunt-coord-server)
keygen.py          make an Ed25519+X25519 identity (shared)
test_protocol.py   crypto-layer tests (no server required)
```

## Setup

```
pip install -r requirements.txt
python3 keygen.py node.key         # -> node.key (secret), node.pub (share)
```

Get `server.pub` from whoever runs the coordination server. Then register,
download the targets, and you're ready to work:

```
python3 node.py --key node.key --server-info server.pub \
    --url https://coord.example:8443 register --gpu "RTX 4090" --sw "keyhunt-gpu 1.0"

python3 node.py --key node.key --server-info server.pub \
    --url https://coord.example:8443 targets --out targets.txt
```

**Never commit `.key` or `.pub` files** — `.gitignore` excludes them.

## Running as a worker

`node.py` is both a CLI (handy for ops and debugging) and a library. A minimal
worker loop that drives the GPU search binary:

```python
from node import Node
import json, subprocess, time

s = json.load(open("server.pub"))
n = Node("node.key", "https://coord.example:8443", s["ed25519"], s["x25519"])
n.register(gpu="RTX 4090", sw="keyhunt-gpu 1.0")
tg = n.get_targets()
open("targets.txt", "w").write("\n".join(tg["targets"]) + "\n")

while True:
    b = n.request_block()
    if not b.get("ok"):
        time.sleep(b.get("retry_after", 60))
        continue
    t0 = time.time()
    subprocess.run(["./keyhunt-gpu", "--prefix", b["prefix"],
                    "--targets", "targets.txt", "--out", "found.txt"], check=True)
    n.complete_block(b["block_idx"], seconds=time.time() - t0, keys_checked=1 << 40)
    for line in open("found.txt"):
        # parse privkey/pubkey from the search tool's output, then:
        # n.report_match(priv_hex, pub_hex, block_idx=b["block_idx"])
        pass
    open("found.txt", "w").close()
```

Parsing `found.txt` into `(privkey, pubkey)` pairs is the one piece of glue that
depends on how you run the search binary; wire it to `keyhunt-gpu`'s output
format. The server re-verifies every match, so a malformed report is rejected
rather than trusted.

## CLI reference

```
node.py --key KEY --server-info SERVER_PUB --url URL <command>

  register --gpu STR --sw STR      announce GPU type and software version
  targets  --out FILE              download the search list
  request                          lease a block
  complete BLOCK_IDX SECONDS       report a completed block
           [--keys N]
  match PRIVKEY PUBKEY             report a found key (both hex)
        [--block-idx N]
  stats                            show fleet stats
```

## Test

```
python3 test_protocol.py
```

Covers the crypto layer end to end: a sealed message round-trips, and tampered
ciphertext, wrong recipient, replayed sequence, stale timestamp, and forged
signature are all rejected. No server needed. The full node↔server integration
test lives in the server repository (`test_e2e.py`).

## License

MIT — see `LICENSE`.
