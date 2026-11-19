"""
ui.py — Giao diện web cục bộ (Streamlit) cho công cụ xác minh giao dịch Safe.

Chạy:   streamlit run ui.py      (trong thư mục tool/, đã bật venv, Anvil đang chạy)

File này KHÔNG chứa logic phát hiện mới: nó chỉ gọi main.run_scenario() và trình bày
kết quả cho người không rành kỹ thuật. Mọi con số vẫn do các lớp trong main.py tạo ra.
"""

import json
import os

import streamlit as st
from web3 import Web3

from checker import verdict
from main import DEFAULT_ALLOWLIST, build_scenarios, run_scenario
from state_reader import load_env

st.set_page_config(page_title="Xác minh giao dịch Safe", page_icon="🛡️", layout="wide")

# ----------------------------------------------------------------------------
# Từ điển hiển thị
# ----------------------------------------------------------------------------
LAYER_NAMES = {"static": "Tĩnh (đọc dữ liệu giao dịch)",
               "invariants": "Bất biến (so trạng thái ví trước/sau)",
               "diff": "Diff (ô nhớ của ví bị ghi)",
               "conseq": "Hậu quả (thử khai thác sau giao dịch)",
               "asset": "Tài sản (token/ETH rời ví, quyền tiêu token)",
               "xcheck": "Đối chiếu (so nhiều nguồn RPC)"}

RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "FAIL": 1, "WARN": 2, "INFO": 3}
RISK_ICON = {"CRITICAL": "🔴", "HIGH": "🔴", "FAIL": "🔴", "WARN": "🟡", "INFO": "⚪"}

# Hàm thường gặp → để hiện "giao dịch khai báo gọi hàm gì"
_SIGS = ["transfer(address,uint256)", "approve(address,uint256)",
         "transferFrom(address,address,uint256)",
         "addOwnerWithThreshold(address,uint256)", "removeOwner(address,address,uint256)",
         "swapOwner(address,address,address)", "changeThreshold(uint256)",
         "enableModule(address)", "disableModule(address,address)",
         "setFallbackHandler(address)", "setGuard(address)",
         "multiSend(bytes)", "batchSend(address[],uint256[])"]
SELECTORS = {bytes(Web3.keccak(text=s)[:4]).hex(): s for s in _SIGS}

# Diễn giải bằng lời thường. Dò từ khoá trong (invariant + message) của finding.
PLAIN = [
    (("mastercopy", "singleton", "slot 0", "slot0", "implementation"),
     "Giao dịch **thay mã điều khiển của ví** (masterCopy, ô nhớ số 0) — đúng cơ chế vụ Bybit. "
     "Sau đó ví chạy theo mã của người khác và họ có thể rút toàn bộ tài sản."),
    (("funds_drained",),
     "Sau giao dịch này, **người lạ rút được tiền khỏi ví mà không cần chữ ký nào**."),
    (("safe_bricked",),
     "Sau giao dịch này, **ví không còn hoạt động như một Safe** — các chủ ví mất quyền điều khiển."),
    (("takeover_without_signatures",),
     "Sau giao dịch này, **người lạ tự thêm mình làm chủ ví** mà không cần ai ký."),
    (("approvedhashes", "backdoor"),
     "Giao dịch **cài sẵn sự chấp thuận** cho một giao dịch khác trong tương lai (cửa hậu)."),
    (("threshold",),
     "Giao dịch **thay đổi số chữ ký cần thiết** để ví chuyển tiền."),
    (("owner",),
     "Giao dịch **thay đổi danh sách người có quyền ký** của ví."),
    (("module",),
     "Giao dịch **bật/tắt module** — module có thể chuyển tiền mà không cần chữ ký của chủ ví."),
    (("fallback",),
     "Giao dịch **đổi fallback handler** — thành phần xử lý các lời gọi lạ gửi tới ví."),
    (("guard",),
     "Giao dịch **đổi guard** — thành phần có quyền chặn/cho phép mọi giao dịch của ví."),
    (("approve", "allowance", "vô hạn"),
     "Giao dịch **cấp quyền tiêu token của ví** cho một địa chỉ khác."),
    (("delegatecall",),
     "Giao dịch dùng **DelegateCall**: mã của địa chỉ đích được chạy *ngay bên trong ví*, "
     "có toàn quyền sửa ví."),
    (("rpc_discrepancy",),
     "Các nguồn dữ liệu (RPC) **trả lời khác nhau** về cùng một trạng thái."),
]


# ----------------------------------------------------------------------------
# Hàm phụ
# ----------------------------------------------------------------------------
def describe_call(sc: dict) -> str:
    data = (sc.get("data") or "0x").lower()
    if data in ("0x", ""):
        return "Không có dữ liệu (chuyển ETH / gọi rỗng)"
    sel = data[2:10]
    return SELECTORS.get(sel, f"Hàm không nhận diện được (0x{sel})")


def plain_explanations(findings: list[dict]) -> list[str]:
    out = []
    for f in sorted(findings, key=lambda x: RISK_ORDER.get(x.get("risk"), 9)):
        text = f"{f.get('invariant', '')} {f.get('message', '')}".lower()
        for keys, sentence in PLAIN:
            if any(k in text for k in keys) and sentence not in out:
                out.append(sentence)
                break
    return out


def to_jsonable(o):
    if isinstance(o, (bytes, bytearray)):
        return "0x" + bytes(o).hex()
    return str(o)


@st.cache_resource
def get_w3(rpc: str) -> Web3:
    return Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 60}))


# ----------------------------------------------------------------------------
# Cấu hình + kết nối
# ----------------------------------------------------------------------------
env = load_env()


def cfg(key: str, default: str = "") -> str:
    return (env.get(key) if isinstance(env, dict) else None) or os.getenv(key, default)


rpc = cfg("RPC_URL", "http://localhost:8545")
safe = cfg("SAFE_ADDRESS")
attacker = cfg("ATTACKER")
allowlist = [a.strip() for a in cfg("DELEGATECALL_ALLOWLIST").split(",") if a.strip()] \
    or DEFAULT_ALLOWLIST
w3 = get_w3(rpc)

with st.sidebar:
    st.header("Kết nối")
    try:
        chain_id, block = w3.eth.chain_id, w3.eth.block_number
        st.success(f"Đã kết nối nút mô phỏng\n\nChain ID: {chain_id} · Khối: {block}")
        connected = True
    except Exception as e:  # noqa: BLE001
        st.error(f"Không kết nối được {rpc}.\n\nHãy chắc rằng Anvil đang chạy.\n\n{e}")
        connected = False
    st.caption(f"RPC chính: `{rpc}`")
    st.caption(f"Ví Safe: `{safe}`")
    st.divider()
    st.header("Nguồn đối chiếu")
    wit_text = st.text_input("RPC nhân chứng (cách nhau bởi dấu phẩy)",
                             value=cfg("RPC_WITNESSES"),
                             help="Nguồn dữ liệu độc lập để so với RPC chính. "
                                  "Bỏ trống = không đối chiếu.")
    witnesses = [r.strip() for r in wit_text.split(",") if r.strip() and r.strip() != rpc]
    anc_text = st.text_input("RPC neo — chain thật (cách nhau bởi dấu phẩy)",
                             value=cfg("RPC_ANCHORS"),
                             help="RPC của mạng thật (vd. Alchemy, Tenderly) để so trạng thái "
                                  "TRƯỚC giao dịch. Bỏ trống = không neo.")
    anchors = [r.strip() for r in anc_text.split(",") if r.strip()]

st.title("🛡️ Xác minh giao dịch Safe trước khi ký")
st.caption("Công cụ chạy thử giao dịch trên bản sao của blockchain rồi kiểm tra: "
           "sau giao dịch này, ai kiểm soát ví?")

if not connected or not safe:
    st.stop()

# ----------------------------------------------------------------------------
# Bước 1 — chọn / nhập giao dịch
# ----------------------------------------------------------------------------
st.subheader("1. Giao dịch cần kiểm tra")
mode = st.radio("Nguồn giao dịch", ["Kịch bản mẫu (S1–S9)", "Nhập tay"],
                horizontal=True, label_visibility="collapsed")

sc = None
if mode.startswith("Kịch bản"):
    try:
        scenarios = build_scenarios(w3, env)
        label = st.selectbox("Kịch bản", [s["label"] for s in scenarios])
        sc = next(s for s in scenarios if s["label"] == label)
    except Exception as e:  # noqa: BLE001
        st.error(f"Không dựng được kịch bản mẫu (thiếu biến trong .env hoặc state?): {e}")
else:
    c1, c2 = st.columns([3, 1])
    to = c1.text_input("Địa chỉ đích (to)", placeholder="0x…")
    value_eth = c2.text_input("Số ETH gửi kèm", value="0")
    data = st.text_area("Dữ liệu giao dịch (data, dạng hex)", value="0x", height=100)
    op = st.radio("Kiểu gọi (operation)", [0, 1], horizontal=True,
                  format_func=lambda x: "0 — Call (gọi thông thường)" if x == 0
                  else "1 — DelegateCall (chạy mã đích bên trong ví)")
    data = "".join(data.split())
    problems = []
    if to and not Web3.is_address(to):
        problems.append("Địa chỉ đích không hợp lệ.")
    if not data.startswith("0x") or len(data) % 2 or \
            any(ch not in "0123456789abcdefABCDEF" for ch in data[2:]):
        problems.append("Dữ liệu phải là chuỗi hex bắt đầu bằng 0x, số ký tự chẵn.")
    try:
        value_wei = int(Web3.to_wei(value_eth.strip() or "0", "ether"))
    except Exception:  # noqa: BLE001
        problems.append("Số ETH không hợp lệ.")
        value_wei = 0
    for p in problems:
        st.warning(p)
    if to and not problems:
        sc = {"label": "Giao dịch nhập tay", "kind": "unknown",
              "to": Web3.to_checksum_address(to), "data": data,
              "operation": op, "value": value_wei}

if sc:
    with st.container(border=True):
        a, b, c = st.columns(3)
        a.markdown(f"**Gửi tới**\n\n`{sc['to']}`")
        b.markdown(f"**Hàm được gọi**\n\n`{describe_call(sc)}`")
        c.markdown("**Kiểu gọi**\n\n" + ("⚠️ DelegateCall" if sc["operation"] == 1 else "Call"))
        st.caption("Đây là thứ giao dịch *khai báo*. Tên hàm có thể bị ngụy trang — "
                   "kết quả mô phỏng bên dưới mới cho biết điều thực sự xảy ra.")

run = st.button("🔍 Kiểm tra giao dịch", type="primary", disabled=sc is None)

if run and sc:
    with st.spinner("Đang chạy thử giao dịch trên bản sao blockchain…"):
        try:
            out = run_scenario(w3, rpc, safe, Web3.to_checksum_address(attacker),
                               sc, allowlist, witnesses, anchors)
            st.session_state["result"] = {"sc": sc, "out": out, "witnesses": witnesses, "anchors": anchors}
        except Exception as e:  # noqa: BLE001
            st.session_state.pop("result", None)
            st.error(f"Mô phỏng thất bại: {e}")

# ----------------------------------------------------------------------------
# Bước 2 — kết luận
# ----------------------------------------------------------------------------
r = st.session_state.get("result")
if r:
    sc_r, out, wit_r = r["sc"], r["out"], r["witnesses"]
    tx_findings = [f for f in out["findings"] if f.get("layer") != "xcheck"]
    env_findings = [f for f in out["findings"] if f.get("layer") == "xcheck"]
    tx_verdict = verdict(tx_findings)
    env_bad = out["layers"]["xcheck"]

    st.divider()
    st.subheader(f"2. Kết luận — {sc_r['label']}")

    if tx_verdict == "FAIL":
        st.error("## 🔴 KHÔNG KÝ\nGiao dịch này làm thay đổi quyền kiểm soát hoặc tài sản của ví.")
    elif tx_verdict == "WARN":
        st.warning("## 🟡 CẦN XEM LẠI\nCó điểm bất thường. Chỉ ký khi bạn hiểu rõ và đã "
                   "xác nhận với những người ký khác.")
    else:
        st.success("## 🟢 KHÔNG PHÁT HIỆN DẤU HIỆU NGUY HIỂM\nSau giao dịch, quyền kiểm soát ví "
                   "không đổi. Vẫn hãy so mã băm bên dưới với màn hình ví cứng.")

    for sentence in plain_explanations(tx_findings):
        st.markdown(f"- {sentence}")

    # Kết luận thứ hai, tách riêng: môi trường có đáng tin không
    if env_bad:
        st.error("**Nguồn dữ liệu: KHÔNG ĐÁNG TIN.** Các RPC trả lời khác nhau — dừng ký và "
                 "kiểm tra lại nguồn dữ liệu, kể cả khi giao dịch trông vô hại.")
    elif wit_r:
        st.info(f"**Nguồn dữ liệu: nhất quán** giữa RPC chính và {len(wit_r)} nguồn đối chiếu.")
    else:
        st.info("**Nguồn dữ liệu: chưa đối chiếu** (chỉ dùng một RPC). "
                "Thêm RPC nhân chứng ở thanh bên để kiểm tra.")

    st.markdown("**Mã băm giao dịch (safeTxHash) — so từng ký tự với màn hình ví cứng:**")
    st.code(out["res"]["safe_tx_hash"], language=None)

    # ------------------------------------------------------------------------
    # Thứ khai báo ↔ thứ thực sự xảy ra
    # ------------------------------------------------------------------------
    left, right = st.columns(2)
    with left:
        st.markdown("#### Giao dịch khai báo")
        st.markdown(f"- Gửi tới: `{sc_r['to']}`\n"
                    f"- Hàm: `{describe_call(sc_r)}`\n"
                    f"- Kiểu gọi: {'DelegateCall' if sc_r['operation'] == 1 else 'Call'}\n"
                    f"- ETH gửi kèm: {sc_r.get('value', 0) / 10**18}")
    with right:
        st.markdown("#### Thực tế khi chạy thử")
        if out["res"]["status"] != 1:
            st.markdown("- Giao dịch **thất bại (revert)** — không đánh giá được tác động.")
        else:
            written = ", ".join(t["label"] for t in out["touched"]) or "không có (chỉ nonce +1)"
            st.markdown(f"- Ô nhớ của ví bị ghi: **{written}**")
            st.markdown("- Thay đổi tài sản: " + ("; ".join(out["moves"]) or "không đổi"))
            hq = [c["consequence"] for c in out["conseq"]]
            st.markdown("- Thử khai thác sau giao dịch: " + (", ".join(hq) or "không chạy"))

    # ------------------------------------------------------------------------
    # Chi tiết kỹ thuật
    # ------------------------------------------------------------------------
    with st.expander("Chi tiết kỹ thuật"):
        st.markdown("**Kết quả từng lớp kiểm tra**")
        st.table([{"Lớp": LAYER_NAMES.get(k, k),
                   "Kết quả": ("— chưa chạy" if k == "xcheck" and not wit_r
                               else "⚠️ Gắn cờ" if v else "✓ Sạch")}
                  for k, v in out["layers"].items()])

        allf = sorted(out["findings"], key=lambda x: RISK_ORDER.get(x.get("risk"), 9))
        if allf:
            st.markdown("**Các phát hiện**")
            st.table([{"Mức": f"{RISK_ICON.get(f.get('risk'), '')} {f.get('risk', '')}",
                       "Lớp": f.get("layer", ""),
                       "Bất biến": f.get("invariant", ""),
                       "Nội dung": f.get("message", "")} for f in allf])
        else:
            st.markdown("Không có phát hiện nào.")

        st.markdown("**Dữ liệu giao dịch (data)**")
        st.code(sc_r["data"], language=None)
        st.caption(f"Kết luận giao dịch: {tx_verdict} · Số phát hiện về môi trường: "
                   f"{len(env_findings)} · Người ký mô phỏng: {len(out['res'].get('signers', []))}")

    report = {"scenario": sc_r, "tx_verdict": tx_verdict, "env_untrusted": env_bad,
              "rpc": rpc, "witnesses": wit_r, "safe": safe,
              "safe_tx_hash": out["res"]["safe_tx_hash"], "layers": out["layers"],
              "findings": out["findings"], "touched": out["touched"],
              "moves": out["moves"], "conseq": out["conseq"]}
    st.download_button("⬇️ Tải báo cáo xác minh (JSON)",
                       json.dumps(report, ensure_ascii=False, indent=2, default=to_jsonable),
                       file_name="bao_cao_xac_minh.json", mime="application/json")
