import sys
p = "ui.py"
L = open(p, encoding="utf-8").read().split("\n")
if any("anc_text" in l for l in L):
    sys.exit("ui.py đã được vá — dừng")

# 1) ô nhập RPC neo, chèn ngay sau dòng witnesses = [...]
i = next((k for k, l in enumerate(L) if l.startswith("    witnesses = [r.strip() for r in wit_text")), None)
if i is None:
    sys.exit("KHÔNG TÌM THẤY dòng witnesses — chưa sửa gì")
L[i + 1:i + 1] = [
    '    anc_text = st.text_input("RPC neo — chain thật (cách nhau bởi dấu phẩy)",',
    '                             value=cfg("RPC_ANCHORS"),',
    '                             help="RPC của mạng thật (vd. Alchemy, Tenderly) để so trạng thái "',
    '                                  "TRƯỚC giao dịch. Bỏ trống = không neo.")',
    '    anchors = [r.strip() for r in anc_text.split(",") if r.strip()]',
]
s = "\n".join(L)

# 2) truyền anchors vào run_scenario
old = "sc, allowlist, witnesses)"
if s.count(old) != 1:
    sys.exit(f"Tìm thấy {s.count(old)} chỗ '{old}' (cần đúng 1) — chưa sửa gì")
s = s.replace(old, "sc, allowlist, witnesses, anchors)")

# 3) lưu anchors cùng kết quả
s = s.replace('"witnesses": witnesses}', '"witnesses": witnesses, "anchors": anchors}', 1)

open(p, "w", encoding="utf-8").write(s)
print("Đã vá ui.py")
