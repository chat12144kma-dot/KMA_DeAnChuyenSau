"""
main.py — Chạy bộ kịch bản qua 3 lớp (tĩnh, bất biến, diff storage),
so sánh với baseline theo mẫu và phân tích đóng góp từng lớp (ablation).
"""

import os

from eth_abi import encode
from web3 import Web3

from state_reader import read_state, load_env
from simulator import snapshot, revert, simulate_safe_tx
from checker import static_checks, check_invariants, verdict, format_report
from storage_diff import trace_safe_storage, build_slot_labels, analyze_storage
from baseline import pattern_check

LAYERS = [("static", "Tĩnh"), ("invariants", "Bất biến"), ("diff", "Diff"),
          ("combined", "Kết hợp"), ("base", "Theo mẫu")]


def calldata(sig: str, types: list, values: list) -> str:
    return "0x" + bytes(Web3.keccak(text=sig)[:4]).hex() + encode(types, values).hex()


def build_scenarios(env: dict) -> list[dict]:
    cs = Web3.to_checksum_address
    safe, mal = cs(env["SAFE_ADDRESS"]), cs(env["MALICIOUS_IMPL"])
    attacker, sleeper = cs(env["ATTACKER"]), cs(env["SLEEPER_IMPL"])
    owner0 = cs("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
    future_hash = int.from_bytes(Web3.keccak(text="future-drain-tx"), "big")
    return [
        {"label": "S1 Hợp lệ: gọi rỗng tới owner #2", "kind": "benign",
         "to": cs("0x70997970C51812dc3A010C7d01b50e0d17dc79C8"), "data": "0x", "operation": 0},
        {"label": "S2 Bybit: delegatecall transfer() ngụy trang", "kind": "attack",
         "to": mal, "operation": 1,
         "data": calldata("transfer(address,uint256)", ["address", "uint256"], [mal, 0])},
        {"label": "S3 Thêm owner + hạ threshold xuống 1", "kind": "attack",
         "to": safe, "operation": 0,
         "data": calldata("addOwnerWithThreshold(address,uint256)", ["address", "uint256"], [attacker, 1])},
        {"label": "S4 Bật module của kẻ tấn công", "kind": "attack",
         "to": safe, "operation": 0,
         "data": calldata("enableModule(address)", ["address"], [attacker])},
        {"label": "S5 Đổi fallback handler", "kind": "attack",
         "to": safe, "operation": 0,
         "data": calldata("setFallbackHandler(address)", ["address"], [attacker])},
        {"label": "S6 Cửa hậu: cài sẵn approvedHashes", "kind": "attack",
         "to": sleeper, "operation": 1,
         "data": calldata("transfer(address,uint256)", ["address", "uint256"], [owner0, future_hash])},
    ]


def run_scenario(w3, rpc, safe, sc, allowlist) -> dict:
    snap = snapshot(w3)
    try:
        before = read_state(rpc, safe)
        res = simulate_safe_tx(w3, safe, sc["to"], sc["data"], 0, sc["operation"])
        after = read_state(rpc, safe)
        changes = trace_safe_storage(w3, res["tx_hash"], safe)  # phải trace TRƯỚC khi revert
    finally:
        revert(w3, snap)

    static_f = static_checks(sc, allowlist)
    if res["status"] != 1:
        inv_f = [{"layer": "simulation", "invariant": "status", "risk": "WARN",
                  "message": "Giao dịch revert trên fork — không đánh giá được tác động"}]
        diff_f, touched = [], []
    else:
        inv_f = check_invariants(before, after)
        diff_f, touched = analyze_storage(changes, build_slot_labels(before, after))

    return {"res": res, "findings": static_f + inv_f + diff_f, "touched": touched,
            "layers": {"static": bool(static_f), "invariants": bool(inv_f), "diff": bool(touched)}}


if __name__ == "__main__":
    env = load_env()
    rpc = os.getenv("RPC_URL", "http://localhost:8545")
    w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 60}))
    safe = env["SAFE_ADDRESS"]
    allowlist = [a.strip() for a in os.getenv("DELEGATECALL_ALLOWLIST", "").split(",") if a.strip()]

    rows = []
    for sc in build_scenarios(env):
        print(f"\n=== {sc['label']} ===")
        out = run_scenario(w3, rpc, safe, sc, allowlist)
        base, reason = pattern_check(sc)
        print(f"  safeTxHash: {out['res']['safe_tx_hash']}")
        print(format_report(out["findings"]))
        written = ", ".join(t["label"] for t in out["touched"]) or "(chỉ nonce +1)"
        print(f"  Storage Safe bị ghi: {written}")
        print(f"  [Đối chứng theo mẫu] {base}: {reason}")

        flags = dict(out["layers"])
        flags["combined"] = verdict(out["findings"]) != "PASS"
        flags["base"] = base != "PASS"
        rows.append({"label": sc["label"], "kind": sc["kind"], **flags})

    width = 44 + 8 + 10 * len(LAYERS)
    print("\n" + "=" * width)
    print(f"{'Kịch bản':<44}{'Loại':<8}" + "".join(f"{n:<10}" for _, n in LAYERS))
    print("-" * width)
    for r in rows:
        print(f"{r['label'][:42]:<44}{r['kind']:<8}"
              + "".join(f"{('X' if r[k] else '-'):<10}" for k, _ in LAYERS))
    print("-" * width + "\n(X = gắn cờ)")

    attacks = [r for r in rows if r["kind"] == "attack"]
    benign = [r for r in rows if r["kind"] == "benign"]
    for k, n in LAYERS:
        tp, fp = sum(r[k] for r in attacks), sum(r[k] for r in benign)
        print(f"{n:<10} TPR = {tp}/{len(attacks)} = {tp / len(attacks):.0%}   "
              f"FPR = {fp}/{len(benign)} = {fp / len(benign):.0%}")