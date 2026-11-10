"""Đo 2 đối chứng THEO MẪU trên dữ liệu thật (chỉ đọc calldata, không mô phỏng)."""
import json
from collections import Counter
from baseline import pattern_check, pattern_check_realistic
from replay import ADMIN_METHODS

txs = json.load(open("data/real_txs.json"))
cat = {r["safeTxHash"]: r.get("category") for r in json.load(open("results/replay_real.json"))}

for title, fn in [("NGHIÊM NGẶT (selector lạ = cảnh báo)", pattern_check),
                  ("THỰC TẾ (giải mã multiSend, chỉ báo hàm nhạy cảm)", pattern_check_realistic)]:
    normal, admin, reasons = [], [], Counter()
    for t in txs:
        v, why = fn({"data": t.get("data") or "0x"})
        c = cat.get(t["safeTxHash"]) or ("quản trị" if t.get("method") in ADMIN_METHODS else "thường")
        (admin if c == "quản trị" else normal).append(v)
        if c == "thường" and v != "PASS":
            reasons[f"{t.get('method') or '-'}: {why}"] += 1
    fp = sum(v != "PASS" for v in normal)
    print(f"\n== Đối chứng {title} ==")
    print(f"  Thường  : gắn cờ {fp}/{len(normal)} = {fp / len(normal):.0%}  (báo động giả)")
    print(f"  Quản trị: gắn cờ {sum(v != 'PASS' for v in admin)}/{len(admin)}")
    for m, n in reasons.most_common(8):
        print(f"    ×{n}  {m}")
