import sys

p = "main.py"
L = open(p, encoding="utf-8").read().split("\n")

def find(pred, start=0, what=""):
    for i in range(start, len(L)):
        if pred(L[i]):
            return i
    sys.exit(f"KHÔNG TÌM THẤY: {what} — chưa sửa gì")

if any("def witness_simulate" in l for l in L):
    sys.exit("main.py đã được vá trước đó — dừng")

WITNESS_FN = '''def witness_simulate(r: str, safe: str, sc: dict) -> dict:
    """Nhân chứng độc lập: Anvil fork riêng (fork từ nhà cung cấp RPC khác) tự mô phỏng lại giao dịch."""
    ww = Web3(Web3.HTTPProvider(r, request_kwargs={"timeout": 60}))
    snap = snapshot(ww)
    try:
        before = read_state(r, safe)
        res = simulate_safe_tx(ww, safe, sc["to"], sc["data"], sc.get("value", 0),
                               sc["operation"], sc.get("gas", 3_000_000),
                               **sc.get("refund", {}))
        after = read_state(r, safe)
        changes = trace_safe_storage(ww, res["tx_hash"], safe)
    finally:
        revert(ww, snap)
    return {"before": before, "after": after, "changes": changes, "status": res["status"]}

'''

NEW_BLOCK = '''    # (a) Neo vào chain thật: chỉ so trạng thái TRƯỚC (giao dịch chưa tồn tại trên chain)
    xcheck_f += xcheck_states(before, [read_state(r, safe) for r in anchors], "trước, chain thật")
    # (b) Nhân chứng tự mô phỏng trên fork riêng → so trước / sau / status / trace
    for r in witnesses:
        wr = witness_simulate(r, safe, sc)
        xcheck_f += xcheck_states(before, [wr["before"]], "trước")
        xcheck_f += xcheck_states(after, [wr["after"]], "sau")
        if wr["status"] != res["status"]:
            xcheck_f.append({"layer": "xcheck", "invariant": "RPC_DISCREPANCY:status",
                             "risk": "CRITICAL",
                             "message": f"Kết quả mô phỏng khác nhau: {rpc} → status {res['status']}  |  "
                                        f"{r} → status {wr['status']}"})
        if _canon(wr["changes"]) != _canon(changes):
            xcheck_f.append({"layer": "xcheck", "invariant": "RPC_DISCREPANCY:trace",
                             "risk": "CRITICAL",
                             "message": f"Trace storage của Safe khác nhau giữa {rpc} và {r}"})'''

# 1) dòng def run_scenario
d = find(lambda l: l.startswith("def run_scenario("), what="def run_scenario")
L[d] = "def run_scenario(w3, rpc, safe, attacker, sc, allowlist, witnesses=(), anchors=()) -> dict:"

# 2) xoá 3 chỗ đối chiếu cũ trong khối try
i = find(lambda l: "xcheck_states(before" in l and "for r in witnesses" in l, d, "đối chiếu 'trước' cũ"); del L[i]
i = find(lambda l: "xcheck_states(after" in l and "for r in witnesses" in l, d, "đối chiếu 'sau' cũ"); del L[i]
s = find(lambda l: l.strip() == "for r in witnesses:", d, "vòng trace cũ")
e = find(lambda l: "Trace storage của Safe khác nhau" in l, s, "cuối vòng trace cũ")
del L[s:e + 1]

# 3) chèn khối mới ngay sau revert(w3, snap)
rv = find(lambda l: l.strip() == "revert(w3, snap)", d, "revert(w3, snap)")
L[rv + 1:rv + 1] = NEW_BLOCK.split("\n")

# 4) chèn hàm witness_simulate phía trên def run_scenario
L[d:d] = WITNESS_FN.split("\n")

# 5) main(): đọc RPC_ANCHORS và truyền vào run_scenario
w = find(lambda l: 'os.getenv("RPC_WITNESSES"' in l, 0, "dòng đọc RPC_WITNESSES")
w2 = find(lambda l: "r.strip() != rpc" in l, w, "cuối khối witnesses")
L.insert(w2 + 1, '    anchors = [r.strip() for r in os.getenv("RPC_ANCHORS", "").split(",") if r.strip()]')
c = find(lambda l: "run_scenario(w3, rpc, safe, attacker, sc, allowlist, witnesses)" in l, 0, "lời gọi run_scenario")
L[c] = L[c].replace("allowlist, witnesses)", "allowlist, witnesses, anchors)")

open(p, "w", encoding="utf-8").write("\n".join(L))
print("Đã vá main.py")
