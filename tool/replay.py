"""
replay.py — Roadmap bước 8b: mô phỏng lại giao dịch Safe THẬT (mainnet) để đo FPR.

Với mỗi giao dịch trong data/real_txs.json:
  1. anvil_reset → fork mainnet tại block N-1 (ngay trước khi giao dịch thật thực thi)
  2. chạy run_scenario() của main.py (tĩnh, bất biến, diff, hậu quả)
  3. phân loại: "thường" (bị gắn cờ = báo động giả) | "quản trị" (thay đổi quyền
     kiểm soát hợp lệ — gắn cờ là ĐÚNG, người ký phải tự xác nhận)
  4. kiểm tra độ trung thực: status phải = 1 (giao dịch thật đã thành công),
     safeTxHash tính lại so với hash thật

Kết quả lưu sau MỖI giao dịch vào results/replay_real.json → chạy lại sẽ bỏ qua
giao dịch đã xong (an toàn khi bị lỗi 429 / mất mạng giữa chừng).

Cần: Anvil chạy fork mainnet ở RPC_URL (mặc định http://localhost:8545),
      ETH_RPC_ALCHEMY trong .env (URL dùng cho anvil_reset).
Dùng:  python replay.py            |   LIMIT=10 python replay.py   (chạy thử 10 giao dịch)
       python replay.py --summary   (chỉ in thống kê từ kết quả đã có)
"""

import json
import os
import sys
import time
from collections import Counter
from pathlib import Path

from web3 import Web3

from state_reader import load_env
from checker import verdict
from main import run_scenario
from simulator import ZERO

ROOT = Path(__file__).parent
DATA_FILE = ROOT / "data" / "real_txs.json"
OUT_FILE = ROOT / "results" / "replay_real.json"

ADMIN_METHODS = {"addOwnerWithThreshold", "removeOwner", "swapOwner", "changeThreshold",
                 "enableModule", "disableModule", "setGuard", "setFallbackHandler",
                 "changeMasterCopy"}
CONTROL_INVARIANTS = {"masterCopy", "owners", "threshold", "modules", "guard", "fallbackHandler"}

# Thư viện chính thức của Safe mà người dùng thật delegatecall hằng ngày (MultiSend...).
# Có thể ghi đè bằng DELEGATECALL_ALLOWLIST trong môi trường.
DEFAULT_ALLOWLIST = [
    "0x8D29bE29923b68abfDD21e541b9374737B49cdAD",  # MultiSend v1.1.1
    "0xA238CBeb142c10Ef7Ad8442C6D1f9E89e07e7761",  # MultiSend v1.3.0
    "0x40A2aCCbd92BCA938b02010E17A5b8929b49130D",  # MultiSendCallOnly v1.3.0
    "0x38869bf66a61cF6bDB996A6aE40D5853Fd43B526",  # MultiSend v1.4.1
    "0x9641d764fc13c8B624c04430C7356C1C7C8102e2",  # MultiSendCallOnly v1.4.1
]


def _clean(v: str) -> str:
    return (v or "").strip().strip('"').strip("'")


def reset_fork(w3: Web3, fork_url: str, block: int):
    r = w3.provider.make_request("anvil_reset",
                                 [{"forking": {"jsonRpcUrl": fork_url, "blockNumber": block}}])
    if "error" in r:
        raise RuntimeError(f"anvil_reset lỗi: {r['error']}")


SLOT_NONCE = 5


def align_nonce(w3: Web3, safe: str, nonce: int) -> bool:
    """Nhiều giao dịch của cùng Safe trong 1 block → tại block N-1 nonce còn thấp hơn.
    Đặt slot nonce về đúng nonce giao dịch. Trả về True nếu đã phải chỉnh."""
    cur = int.from_bytes(bytes(w3.eth.get_storage_at(safe, SLOT_NONCE)), "big")
    if cur == nonce:
        return False
    w3.provider.make_request("anvil_setStorageAt",
                             [safe, hex(SLOT_NONCE), "0x" + nonce.to_bytes(32, "big").hex()])
    return True


def classify(tx: dict, findings: list[dict]) -> str:
    changed = {f["invariant"] for f in findings if f["layer"] == "simulation"}
    if tx.get("method") in ADMIN_METHODS or changed & CONTROL_INVARIANTS:
        return "quản trị"
    return "thường"


def load_done() -> dict:
    if OUT_FILE.exists():
        return {r["safeTxHash"]: r for r in json.loads(OUT_FILE.read_text())}
    return {}


def save(done: dict):
    OUT_FILE.parent.mkdir(exist_ok=True)
    OUT_FILE.write_text(json.dumps(list(done.values()), indent=2, ensure_ascii=False))


def summary(done: dict, allowlist: list[str]):
    recs = list(done.values())
    ok = [r for r in recs if r.get("status") == 1]
    err = [r for r in recs if "error" in r]
    failed = [r for r in recs if r.get("status") == 0]
    print("\n" + "=" * 78)
    print(f"Tổng: {len(recs)} giao dịch   |   mô phỏng OK: {len(ok)}   |   "
          f"revert: {len(failed)}   |   lỗi chạy: {len(err)}")

    if ok:
        hm = sum(r["hash_match"] for r in ok)
        nm = sum(r["nonce_match"] for r in ok)
        adj = sum(r.get("nonce_adjusted", False) for r in ok)
        print(f"\n[Độ trung thực]  safeTxHash khớp: {hm}/{len(ok)}   nonce khớp: {nm}/{len(ok)}")
        print(f"  Đã chỉnh nonce (nhiều giao dịch của cùng Safe trong 1 block): {adj}/{len(ok)}")

    normal = [r for r in ok if r["category"] == "thường"]
    admin = [r for r in ok if r["category"] == "quản trị"]
    print(f"\n[1] Báo động giả trên {len(normal)} giao dịch THƯỜNG")
    for k, n in [("static", "Tĩnh"), ("invariants", "Bất biến"), ("diff", "Diff"),
                 ("conseq", "Hậu quả")]:
        fp = sum(r["layers"][k] for r in normal)
        print(f"  {n:<10} FPR = {fp}/{len(normal)} = {fp / max(len(normal), 1):.0%}")
    fp = sum(r["verdict"] != "PASS" for r in normal)
    print(f"  {'Kết hợp':<10} FPR = {fp}/{len(normal)} = {fp / max(len(normal), 1):.0%}")

    flagged = sum(r["verdict"] != "PASS" for r in admin)
    print(f"\n[2] Giao dịch QUẢN TRỊ (thay đổi quyền kiểm soát hợp lệ): "
          f"cảnh báo {flagged}/{len(admin)}  — mong đợi = {len(admin)}/{len(admin)}")

    targets = Counter(r["to"] for r in ok if r["operation"] == 1)
    if targets:
        al = {a.lower() for a in allowlist}
        print("\n[3] Đích delegatecall trong dữ liệu thật (kiểm tra trên Etherscan):")
        for t, c in targets.most_common():
            print(f"  {t}  ×{c}   {'(trong allowlist)' if t.lower() in al else '<-- NGOÀI allowlist'}")

    fps = [r for r in normal if r["verdict"] != "PASS"]
    if fps:
        print("\n[4] Giao dịch thường bị gắn cờ (cần xem nguyên nhân):")
        for r in fps:
            print(f"  {r['safeTxHash'][:12]}… {r['method'] or '-':<22} {'; '.join(r['findings'])}")
    if failed or err:
        print("\n[5] Mô phỏng không thành công:")
        for r in failed + err:
            print(f"  {r['safeTxHash'][:12]}… {r.get('method') or '-':<22} "
                  f"{r.get('error', 'status=0 (revert trên fork)')[:90]}")


if __name__ == "__main__":
    env = load_env()
    rpc = os.getenv("RPC_URL", "http://localhost:8545")
    fork_url = _clean(os.getenv("FORK_URL") or env.get("ETH_RPC_ALCHEMY"))
    attacker = Web3.to_checksum_address(_clean(env["ATTACKER"]))
    allowlist = [a.strip() for a in os.getenv("DELEGATECALL_ALLOWLIST", "").split(",") if a.strip()] \
        or DEFAULT_ALLOWLIST
    done = load_done()

    if "--summary" in sys.argv:
        summary(done, allowlist)
        sys.exit(0)
    if "--redo" in sys.argv:
        # Chạy lại các giao dịch có vấn đề: thường mà bị gắn cờ, nonce lệch, lỗi, revert
        bad = [k for k, r in done.items()
               if "error" in r or r.get("status") != 1 or not r.get("nonce_match")
               or (r.get("category") == "thường" and r.get("verdict") != "PASS")]
        for k in bad:
            done.pop(k)
        print(f"--redo: chạy lại {len(bad)} giao dịch")
    if not fork_url:
        sys.exit("Thiếu ETH_RPC_ALCHEMY trong .env")

    w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 300}))
    txs = json.loads(DATA_FILE.read_text())
    limit = int(os.getenv("LIMIT", str(len(txs))))
    todo = [t for t in txs if t["safeTxHash"] not in done][:limit]
    print(f"{len(txs)} giao dịch trong dữ liệu, {len(done)} đã xong, chạy {len(todo)} giao dịch")

    for i, tx in enumerate(todo, 1):
        tag = f"[{i}/{len(todo)}] {tx['safe'][:8]}… nonce {tx['nonce']:<5} {tx['method'] or '-':<22}"
        rec = {k: tx[k] for k in ("safeTxHash", "safe", "nonce", "to", "operation", "method",
                                  "blockNumber", "transactionHash")}
        try:
            reset_fork(w3, fork_url, tx["blockNumber"] - 1)
            rec["nonce_adjusted"] = align_nonce(w3, Web3.to_checksum_address(tx["safe"]), tx["nonce"])
            sc = {"label": tag, "kind": "real", "to": tx["to"], "data": tx["data"],
                  "operation": tx["operation"], "value": tx["value"], "gas": 15_000_000,
                  "refund": {"safe_tx_gas": tx.get("safeTxGas", 0), "base_gas": tx.get("baseGas", 0),
                             "gas_price": tx.get("gasPrice", 0),
                             "gas_token": tx.get("gasToken") or ZERO,
                             "refund_receiver": tx.get("refundReceiver") or ZERO}}
            out = run_scenario(w3, rpc, tx["safe"], attacker, sc, allowlist)
            res = out["res"]
            tx_f = [f for f in out["findings"] if f["layer"] != "xcheck"]
            rec.update({
                "status": res["status"],
                "hash_match": res["safe_tx_hash"].lower() == tx["safeTxHash"].lower(),
                "nonce_match": res["nonce_used"] == tx["nonce"],
                "category": classify(tx, tx_f),
                "verdict": verdict(tx_f),
                "layers": {k: bool(v) for k, v in out["layers"].items()},
                "findings": [f"{f['layer']}:{f['invariant']}:{f['risk']}" for f in tx_f],
            })
            print(f"{tag} status={res['status']} {rec['category']:<9} {rec['verdict']}")
        except Exception as e:
            rec["error"] = f"{type(e).__name__}: {e}"
            print(f"{tag} LỖI {rec['error'][:80]}")
        done[tx["safeTxHash"]] = rec
        save(done)
        time.sleep(1)               # nhẹ tay với Alchemy (tránh 429)

    summary(done, allowlist)
