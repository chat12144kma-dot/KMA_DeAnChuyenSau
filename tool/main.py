"""
main.py — Chạy bộ kịch bản qua 4 lớp (tĩnh, bất biến, diff storage, hậu quả),
so sánh với baseline theo mẫu và phân tích đóng góp từng lớp (ablation).

Lớp "Hậu quả" (roadmap bước 6): sau khi mô phỏng, cho kẻ tấn công thử khai thác
ngay trên fork (rút ETH, chiếm quyền bằng approvedHashes đã cài) — xem consequences.py.
"""

import json
import os

from eth_abi import encode
from web3 import Web3

from state_reader import read_state, load_env, CONSENSUS_FIELDS, _norm
from simulator import snapshot, revert, simulate_safe_tx
from checker import static_checks, check_invariants, verdict, format_report
from storage_diff import trace_safe_storage, build_slot_labels, analyze_storage
from baseline import pattern_check, pattern_check_realistic
from consequences import (run_consequence_checks, takeover_tx, safe_tx_hash,
                          build_s6_multisend, _safe)

LAYERS = [("static", "Tĩnh"), ("invariants", "Bất biến"), ("diff", "Diff"),
          ("conseq", "Hậu quả"), ("xcheck", "Đối chiếu"),
          ("combined", "Kết hợp"), ("block", "Chặn"),
          ("base", "Theo mẫu"), ("base2", "Thực tế")]

# Mức rủi ro cho từng loại hậu quả (NONE = không có hậu quả → không thành finding)
CONSEQ_RISK = {
    "FUNDS_DRAINED": ("CRITICAL", "Kẻ tấn công rút được {drained_eth} ETH mà không cần chữ ký"),
    "SAFE_BRICKED": ("CRITICAL", "Proxy không còn trả lời ABI Safe — owners mất quyền điều khiển"),
    "TAKEOVER_WITHOUT_SIGNATURES": ("CRITICAL",
                                    "Kẻ tấn công tự thêm mình làm owner (threshold=1) không cần ai ký"),
    "PARTIAL_BACKDOOR": ("WARN", "approvedHashes đã cài sẵn cho {n}/{threshold} owner"),
    "BACKDOOR_FAILED": ("WARN", "Có approvedHashes cài sẵn nhưng khai thác thử thất bại"),
}


def calldata(sig: str, types: list, values: list) -> str:
    return "0x" + bytes(Web3.keccak(text=sig)[:4]).hex() + encode(types, values).hex()


def build_scenarios(w3: Web3, env: dict) -> list[dict]:
    cs = Web3.to_checksum_address
    safe, mal = cs(env["SAFE_ADDRESS"]), cs(env["MALICIOUS_IMPL"])
    attacker, sleeper = cs(env["ATTACKER"]), cs(env["SLEEPER_IMPL"])

    # S6: cài approvedHashes cho đủ `threshold` owner, đúng hash của giao dịch
    # chiếm quyền ở nonce n+1 (ngay sau chính giao dịch S6) — qua MultiSend.
    s = _safe(w3, safe)
    n = s.functions.nonce().call()
    owners, thr = s.functions.getOwners().call(), s.functions.getThreshold().call()
    follow_hash = safe_tx_hash(w3, safe, takeover_tx(safe, attacker), n + 1)
    s6_to, s6_data, s6_op = build_s6_multisend(sleeper, owners[:thr], follow_hash)

    scenarios = [
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
        {"label": "S6 Cửa hậu: MultiSend cài approvedHashes", "kind": "attack",
         "to": s6_to, "operation": s6_op, "data": s6_data},
    ]
    benign_lib = env.get("BENIGN_LIB")
    if benign_lib:
        rcpts = [cs("0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65"),
                 cs("0x9965507D1a55bcC2695C58ba16FB37d819B0A4BC")]
        scenarios.append(
            {"label": "S7 Hợp lệ: delegatecall thư viện chia ETH", "kind": "benign",
             "to": cs(benign_lib), "operation": 1,
             "data": calldata("batchSend(address[],uint256[])", ["address[]", "uint256[]"],
                              [rcpts, [10**17, 10**17]])})
    return scenarios



def consequence_findings(results: list[dict]) -> list[dict]:
    """Chuyển kết quả consequences.py thành finding cùng định dạng với checker."""
    out = []
    for r in results:
        c = r["consequence"]
        if c not in CONSEQ_RISK:
            continue
        risk, tmpl = CONSEQ_RISK[c]
        msg = tmpl.format(drained_eth=r.get("drained_eth"), n=len(r.get("planted", [])),
                          threshold=r.get("threshold"))
        out.append({"layer": "consequence", "invariant": c, "risk": risk, "message": msg})
    return out


def _canon(x) -> str:
    """Chuẩn hoá kết quả trace để so sánh giữa các RPC."""
    return json.dumps(x, sort_keys=True, default=str).lower()


def xcheck_states(primary: dict, witnesses: list[dict], when: str) -> list[dict]:
    """So từng trường bất biến giữa RPC chính và các RPC nhân chứng."""
    out = []
    for ws in witnesses:
        for f in CONSENSUS_FIELDS:
            if _norm(ws[f]) != _norm(primary[f]):
                out.append({"layer": "xcheck", "invariant": f"RPC_DISCREPANCY:{f}", "risk": "CRITICAL",
                            "message": f"[{when}] {primary['rpc']} → {primary[f]}  |  "
                                       f"{ws['rpc']} → {ws[f]}"})
    return out

# Thư viện chính thức của Safe mà người dùng thật delegatecall hằng ngày.
# Có thể ghi đè bằng biến môi trường DELEGATECALL_ALLOWLIST.
DEFAULT_ALLOWLIST = [
    "0x8D29bE29923b68abfDD21e541b9374737B49cdAD",  # MultiSend v1.1.1
    "0xA238CBeb142c10Ef7Ad8442C6D1f9E89e07e7761",  # MultiSend v1.3.0
    "0x40A2aCCbd92BCA938b02010E17A5b8929b49130D",  # MultiSendCallOnly v1.3.0
    "0x38869bf66a61cF6bDB996A6aE40D5853Fd43B526",  # MultiSend v1.4.1
    "0x9641d764fc13c8B624c04430C7356C1C7C8102e2",  # MultiSendCallOnly v1.4.1
]
APPROVED_HASHES_SLOT = 8


def sim_artifact_slots(safe_tx_hash: str, signers: list[str]) -> set[str]:
    """
    Slot approvedHashes[signer][safeTxHash] do CHÍNH simulator tạo ra (approveHash thay
    cho chữ ký off-chain). Safe ≤ v1.2.0 xoá các approval này khi thực thi → diff thấy
    slot lạ bị ghi, dù ngoài đời (chữ ký ECDSA) không hề có. Trả về hex 64 ký tự.
    Chỉ tính cho hash HIỆN TẠI — approval cài sẵn cho giao dịch khác (S6) không bị lọc.
    """
    h = Web3.to_bytes(hexstr=safe_tx_hash)
    out = set()
    for o in signers:
        inner = Web3.keccak(encode(["address", "uint256"],
                                   [Web3.to_checksum_address(o), APPROVED_HASHES_SLOT]))
        out.add(Web3.keccak(encode(["bytes32", "bytes32"], [h, bytes(inner)])).hex()
                .removeprefix("0x").lower())
    return out


def _mentions(obj, slots: set[str]) -> bool:
    """storage_diff in slot KHÔNG có số 0 ở đầu (vd 0x210c… thay vì 0x0210c…) → so cả 2 dạng."""
    s = json.dumps(obj, default=str).lower()
    for a in slots:
        short = a.lstrip("0") or "0"
        if a in s or f"0x{short}" in s or f"unknown(0x{short[:10]}" in s \
                or f"unknown(0x{a[:10]}" in s:
            return True
    return False


def run_scenario(w3, rpc, safe, attacker, sc, allowlist, witnesses=()) -> dict:
    snap = snapshot(w3)
    conseq, xcheck_f = [], []
    try:
        before = read_state(rpc, safe)
        xcheck_f += xcheck_states(before, [read_state(r, safe) for r in witnesses], "trước")
        res = simulate_safe_tx(w3, safe, sc["to"], sc["data"], sc.get("value", 0),
                               sc["operation"], sc.get("gas", 3_000_000),
                               **sc.get("refund", {}))
        after = read_state(rpc, safe)
        xcheck_f += xcheck_states(after, [read_state(r, safe) for r in witnesses], "sau")
        changes = trace_safe_storage(w3, res["tx_hash"], safe)  # phải trace TRƯỚC khi revert
        for r in witnesses:
            ww = Web3(Web3.HTTPProvider(r, request_kwargs={"timeout": 60}))
            if _canon(trace_safe_storage(ww, res["tx_hash"], safe)) != _canon(changes):
                xcheck_f.append({"layer": "xcheck", "invariant": "RPC_DISCREPANCY:trace",
                                 "risk": "CRITICAL",
                                 "message": f"Trace storage của Safe khác nhau giữa {rpc} và {r}"})
        if res["status"] == 1:
            # mỗi phép thử tự snapshot/revert lồng bên trong snapshot của kịch bản
            conseq = run_consequence_checks(w3, safe, attacker)
    finally:
        revert(w3, snap)

    static_f = static_checks(sc, allowlist)
    if res["status"] != 1:
        inv_f = [{"layer": "simulation", "invariant": "status", "risk": "WARN",
                  "message": "Giao dịch revert trên fork — không đánh giá được tác động"}]
        diff_f, touched, conseq_f = [], [], []
    else:
        inv_f = check_invariants(before, after)
        diff_f, touched = analyze_storage(changes, build_slot_labels(before, after))
        artifacts = sim_artifact_slots(res["safe_tx_hash"], res["signers"])
        diff_f = [f for f in diff_f if not _mentions(f, artifacts)]
        touched = [t for t in touched if not _mentions(t, artifacts)]
        conseq_f = consequence_findings(conseq)

    return {"res": res, "findings": static_f + inv_f + diff_f + conseq_f + xcheck_f,
            "touched": touched, "conseq": conseq,
            "layers": {"static": bool(static_f), "invariants": bool(inv_f),
                       "diff": bool(touched), "conseq": bool(conseq_f),
                       "xcheck": bool(xcheck_f)}}


if __name__ == "__main__":
    env = load_env()
    rpc = os.getenv("RPC_URL", "http://localhost:8545")
    w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 60}))
    safe = env["SAFE_ADDRESS"]
    attacker = Web3.to_checksum_address(env["ATTACKER"])
    allowlist = [a.strip() for a in os.getenv("DELEGATECALL_ALLOWLIST", "").split(",") if a.strip()]
    allowlist = allowlist or DEFAULT_ALLOWLIST
    # RPC nhân chứng độc lập để đối chiếu (bỏ qua nếu trùng RPC chính)
    witnesses = [r.strip() for r in os.getenv("RPC_WITNESSES", "").split(",")
                 if r.strip() and r.strip() != rpc]
    print(f"RPC chính: {rpc}   |   nhân chứng: {witnesses or '(không có — bỏ qua đối chiếu)'}")

    rows = []
    for sc in build_scenarios(w3, env):
        print(f"\n=== {sc['label']} ===")
        out = run_scenario(w3, rpc, safe, attacker, sc, allowlist, witnesses)
        base, reason = pattern_check(sc)
        base2, reason2 = pattern_check_realistic(sc)
        print(f"  safeTxHash: {out['res']['safe_tx_hash']}")
        print(format_report(out["findings"]))
        written = ", ".join(t["label"] for t in out["touched"]) or "(chỉ nonce +1)"
        print(f"  Storage Safe bị ghi: {written}")
        hq = ", ".join(r["consequence"] for r in out["conseq"]) or "(không chạy — tx revert)"
        print(f"  Thử khai thác: {hq}")
        print(f"  [Đối chứng theo mẫu] {base}: {reason}")
        print(f"  [Đối chứng thực tế]  {base2}: {reason2}")

        # Tách 2 kết luận: (1) giao dịch có độc hại không — chỉ dựa trên các lớp
        # phân tích giao dịch; (2) môi trường (RPC) có đáng tin không — lớp đối chiếu.
        tx_findings = [f for f in out["findings"] if f["layer"] != "xcheck"]
        tx_verdict = verdict(tx_findings)
        env_bad = out["layers"]["xcheck"]
        env_txt = ("KHÔNG ĐÁNG TIN — dừng ký, kiểm tra lại nguồn dữ liệu" if env_bad
                   else "nhất quán" if witnesses else "chưa đối chiếu")
        print(f"  ➜ Kết luận giao dịch: {tx_verdict}   |   Môi trường RPC: {env_txt}")

        flags = dict(out["layers"])
        flags["combined"] = tx_verdict != "PASS"
        flags["block"] = tx_verdict == "FAIL"
        flags["base"] = base != "PASS"
        flags["base2"] = base2 != "PASS"
        rows.append({"label": sc["label"], "kind": sc["kind"], **flags})

    width = 44 + 8 + 10 * len(LAYERS)
    print("\n" + "=" * width)
    print(f"{'Kịch bản':<44}{'Loại':<8}" + "".join(f"{n:<10}" for _, n in LAYERS))
    print("-" * width)
    for r in rows:
        print(f"{r['label'][:42]:<44}{r['kind']:<8}"
              + "".join(f"{('X' if r[k] else '-'):<10}" for k, _ in LAYERS))
    print("-" * width + "\n(X = gắn cờ;  'Đối chiếu' đánh giá MÔI TRƯỜNG, không tính vào "
                        "'Kết hợp' — 'Kết hợp' là kết luận về GIAO DỊCH)")

    attacks = [r for r in rows if r["kind"] == "attack"]
    benign = [r for r in rows if r["kind"] == "benign"]
    print("\n[1] Phát hiện giao dịch độc hại")
    for k, n in LAYERS:
        if k == "xcheck":
            continue
        tp, fp = sum(r[k] for r in attacks), sum(r[k] for r in benign)
        print(f"  {n:<10} TPR = {tp}/{len(attacks)} = {tp / len(attacks):.0%}   "
              f"FPR = {fp}/{len(benign)} = {fp / len(benign):.0%}")

    print("\n[2] Phát hiện môi trường RPC bị thao túng")
    if witnesses:
        n_env = sum(r["xcheck"] for r in rows)
        print(f"  Đối chiếu  gắn cờ {n_env}/{len(rows)} kịch bản "
              f"(RPC trung thực phải = 0/{len(rows)}; RPC bị thao túng nên = {len(rows)}/{len(rows)})")
    else:
        print("  (không chạy — đặt RPC_WITNESSES để bật đối chiếu)")
