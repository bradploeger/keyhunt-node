from node import Node
import json, subprocess, time

s = json.load(open("server.pub"))
n = Node("node.key", "http://127.0.0.1:8443", s["ed25519"], s["x25519"])
result = subprocess.run(['nvidia-smi', '--query-gpu=name', '--format=csv,noheader'], capture_output=True, text=True, check=True)
gpu = result.stdout.strip()
result = subprocess.run(['nvidia-smi', '--query-gpu=memory.total', '--format=csv,noheader,nounits'], capture_output=True, text=True, check=True)
mem = int(result.stdout.strip()) / 1024
n.register(gpu=f"{gpu}, {mem:1.1f} GB", sw="keyhunt-gpu 1.0")
tg = n.get_targets()
open("targets.txt", "w").write("\n".join(tg["targets"]) + "\n")

while True:
    b = n.request_block()
    if not b.get("ok"):
        time.sleep(b.get("retry_after", 60))
        continue
    t0 = time.time()
    subprocess.run(["../keyhunt-gpu/keyhunt-gpu", "--prefix", b["prefix"],
                        "--targets", "targets.txt", "--blocks", "512", "--out", "found.txt"], check=True)
    n.complete_block(b["block_idx"], seconds=time.time() - t0, keys_checked=1 << 40)
    # keyhunt-gpu writes lines of the form: pubkey=<66 hex> sealed=<hex blob>
    # The private key is already sealed to the server's X25519 key; the node
    # forwards the blob and never sees the key in the clear.
    for line in open("found.txt"):
        pub_hex = ""
        sealed_hex = ""
        for tok in line.split():
            if tok.startswith("pubkey="):
                pub_hex = tok[len("pubkey="):]
            elif tok.startswith("sealed="):
                sealed_hex = tok[len("sealed="):]
        if pub_hex and sealed_hex:
            n.report_match(sealed_hex, pub_hex, block_idx=b["block_idx"])
    open("found.txt", "w").close()