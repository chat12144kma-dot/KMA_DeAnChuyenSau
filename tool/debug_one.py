"""Chạy lại 1 giao dịch thật và in MỌI slot của Safe bị đổi trong execTransaction."""
import sys, os, json, inspect
from web3 import Web3
from state_reader import load_env, read_state
from simulator import simulate_safe_tx, ZERO
from storage_diff import trace_safe_storage, build_slot_labels
from replay import reset_fork, align_nonce, _clean

prefix = sys.argv[1].lower()
env = load_env()
rpc = os.getenv("RPC_URL", "http://localhost:8545")
w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 300}))
tx = next(t for t in json.load(open("data/real_txs.json"))
          if t["safeTxHash"].lower().startswith(prefix))
safe = Web3.to_checksum_address(tx["safe"])

reset_fork(w3, _clean(env.get("ETH_RPC_ALCHEMY")), tx["blockNumber"] - 1)
align_nonce(w3, safe, tx["nonce"])

sig = inspect.signature(simulate_safe_tx)
kw = {"safe_tx_gas": tx.get("safeTxGas", 0), "base_gas": tx.get("baseGas", 0),
      "gas_price": tx.get("gasPrice", 0), "gas_token": tx.get("gasToken") or ZERO,
      "refund_receiver": tx.get("refundReceiver") or ZERO, "gas": 15_000_000}
kw = {k: v for k, v in kw.items() if k in sig.parameters}

before = read_state(rpc, safe)
res = simulate_safe_tx(w3, safe, tx["to"], tx["data"] or "0x", int(tx["value"]), tx["operation"], **kw)
after = read_state(rpc, safe)

print(f"tx {tx['safeTxHash'][:12]}  nonce {tx['nonce']}  method {tx.get('method')}")
print("status", res["status"], "| safeTxHash khớp:", res["safe_tx_hash"].lower() == tx["safeTxHash"].lower())
print("owners :", [o[:8] for o in before["owners"]])
print("signers:", [s[:8] for s in res["signers"]], "(người gửi exec = signers[0])")

labels = build_slot_labels(before, after)
pad = lambda b: b.rjust(32, b"\0")
h = bytes.fromhex(res["safe_tx_hash"][2:])
for o in before["owners"]:
    inner = Web3.keccak(pad(bytes.fromhex(o[2:])) + pad(b"\x08"))
    labels[int.from_bytes(Web3.keccak(h + inner), "big")] = f"approvedHashes[{o[:8]}][txHash này]"

print("Các slot của Safe bị đổi trong execTransaction:")
for c in trace_safe_storage(w3, res["tx_hash"], safe):
    print(f"  {labels.get(c['slot'], 'UNKNOWN'):<38} {hex(c['slot'])[:14]}…  {c['before']} -> {c['after']}")
