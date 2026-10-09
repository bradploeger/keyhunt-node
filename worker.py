import math
import traceback

from node import Node
import json, subprocess, time

KEYHUNT_GPU_PATH = '../keyhunt-gpu/keyhunt-gpu.exe'
THREADS = 1 << 8
BLOCKS = 1 << 7
GROUPS = 1 << 14

s = json.load(open("server.pub"))
n = Node("node.key", "https://keyhunt.arkturis.com", s["ed25519"], s["x25519"])

def compute_rate(qty, time, qty_type="key", time_unit="sec"):
    prefix = 0
    prefixes = ["", "K", "M", "G", "T"]
    rate = qty / time
    while rate > 1000.0:
        rate /= 1000.0
        prefix += 1
    return f"{rate:1.2f} {prefixes[prefix]}{qty_type}/{time_unit}"

def block_post_processing(t0: float | int):
    block_time = time.time() - t0
    block_size = 256 - len(b["prefix"]) * 4
    rate = compute_rate(1 << block_size, block_time)
    print(f"Block {b['block_idx']} completed in {block_time:0.2f} seconds. ({rate}) \n")
    n.complete_block(b["block_idx"], seconds=block_time, keys_checked=1 << block_size)

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
            # Report the match
            n.report_match(sealed_hex, pub_hex, block_idx=b["block_idx"])
    # Clear the found file
    open("found.txt", "w").close()
    return None

gpu = subprocess.run(['nvidia-smi', '--query-gpu=name', '--format=csv,noheader'], capture_output=True, text=True,
                     check=True).stdout.strip()
mem = int(subprocess.run(['nvidia-smi', '--query-gpu=memory.total', '--format=csv,noheader,nounits'],
                        capture_output=True, text=True, check=True).stdout.strip()) / 1024
if BLOCKS & (BLOCKS - 1):
    BLOCKS = 1 << int(math.log2(BLOCKS))

if THREADS & (THREADS - 1):
    THREADS = 1 << int(math.log2(THREADS))

n.register(gpu=f"{gpu}, {mem:1.1f} GB", sw="keyhunt-gpu 1.0")
tg = n.get_targets()
open("targets.txt", "w").write("\n".join(tg["targets"]) + "\n")
try:
    while True:
        b = n.request_block()
        if not b.get("ok"):
            time.sleep(b.get("retry_after", 60))
            continue
        args = [f"{KEYHUNT_GPU_PATH}", "--prefix", b["prefix"], "--targets", "targets.txt", "--out", "found.txt",
                "--checkpoint", "checkpoint.txt", "--threads", f"{THREADS}", "--blocks", f"{BLOCKS}",
                "--groups", f"{GROUPS}"]
        t0 = time.time()
        try:
            subprocess.run(args, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Command failed with exit code {e.returncode}")
            print(f"Error message: {e.stderr}")
            quit()
        else:
            block_post_processing(t0)
except KeyboardInterrupt:
    print ("\n--STOP REQUESTED-- Will exiting once the current block is finished. \n")
    try:
        if "--resume" not in args:
            args.append("--resume")
        subprocess.run(args, check=True)
        block_post_processing(t0)
    except NameError:
        print("\n nothing to finish")
    finally:
        quit()








