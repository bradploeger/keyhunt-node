import math
import hashlib
import secp

from node import Node
import json, subprocess, time

KEYHUNT_GPU_PATH = '../keyhunt-gpu/keyhunt-gpu-all.exe'
s = json.load(open("server.pub"))
n = Node("node.key", "http://127.0.0.1:8443", s["ed25519"], s["x25519"])
prefix = ""
proof_ids = []
proof_tg = []
sealedproofs = []

def compute_rate(qty, time, qty_type="key", time_unit="sec"):
    pfx = 0
    pfxs = ["", "K", "M", "G", "T"]
    rate = qty / time
    while rate > 1000.0:
        rate /= 1000.0
        pfx += 1
    return f"{rate:1.2f} {pfxs[pfx]}{qty_type}/{time_unit}"

def block_post_processing(t0: float | int):
    block_time = time.time() - t0
    block_size = 256 - len(b["prefix"]) * 4
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
            if pub_hex not in proof_tg:
                # Report the match
                n.report_match(sealed_hex, pub_hex, block_idx=b["block_idx"])
            else:
                sealedproofs.append(sealed_hex)
                proof_tg.remove(pub_hex)
    if len(proof_tg) == 0:
        rate = compute_rate(1 << block_size, block_time)
        print(f"\nBlock {b['block_idx']} completed in {block_time:0.2f} seconds. ({rate})\n")
        proof_hash = hashlib.sha256("".join(proof_ids).encode("utf-8").strip()).hexdigest()
        proof = ".".join(sealedproofs)
        n.complete_block(block_idx=b["block_idx"], seconds=block_time, p_hash=proof_hash, proof=proof, keys_checked=1 << block_size)

    # Clear the found file
    open("found.txt", "w").close()
    return None

gpu = subprocess.run(['nvidia-smi', '--query-gpu=name', '--format=csv,noheader'], capture_output=True, text=True,
                           check=True).stdout.strip()
mem = int(subprocess.run(['nvidia-smi', '--query-gpu=memory.total', '--format=csv,noheader,nounits'],
                               capture_output=True, text=True, check=True).stdout.strip()) / 1024
n.register(gpu=f"{gpu}, {mem:1.1f} GB", sw="keyhunt-gpu 1.0")
tg = n.get_targets()["targets"]

try:
    while True:
        b = n.request_block()
        if not b.get("ok"):
            time.sleep(b.get("retry_after", 60))
            continue
        prefix = b["prefix"]
        range_nibs = 64 - len(prefix)
        hash = hashlib.sha512(prefix.encode("utf-8")).hexdigest()
        num_proofs = (int(hash[-8:], 16) % 9) + 4
        stop = range_nibs * num_proofs
        proof_ids = [prefix + hash[i:stop:num_proofs] for i in range(num_proofs)]
        proof_tg = [secp.compressed( int(pid, 16) ) for pid in proof_ids]
        open("targets.txt", "w").write("\n".join(tg + proof_tg) + "\n")
        args = [f"{KEYHUNT_GPU_PATH}", "--prefix", b["prefix"], "--targets", "targets.txt", "--out", "found.txt",
                "--checkpoint", "checkpoint.txt", "--blocks" , "512"]
        t0 = time.time()
        subprocess.run(args, check=True)
        block_post_processing(t0)
except KeyboardInterrupt:
    print ("\n--STOP REQUESTED-- Will exit once the current job is finished. \n")
    try:
        if "--resume" not in args:
            args.append("--resume")
        subprocess.run(args, check=True)
        block_post_processing(t0)
    except NameError:
        print("\n Nothing to Finish")
    finally:
        quit()
except subprocess.CalledProcessError as e:
    print(f"Command failed with exit code {e.returncode}")
    print(f"Error message: {e.stderr}")
    quit()





