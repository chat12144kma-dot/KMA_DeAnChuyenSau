"""
baseline.py — Phương pháp đối chứng THEO MẪU (pattern-based).

Đại diện cho cách hiển thị/kiểm tra phổ biến: giải mã selector của calldata,
cảnh báo nếu là hàm quản trị Safe hoặc approve vô hạn. KHÔNG mô phỏng,
KHÔNG xét ngữ cảnh delegatecall.
"""

from web3 import Web3


def _sel(sig: str) -> str:
    return "0x" + bytes(Web3.keccak(text=sig)[:4]).hex()


KNOWN_SIGNATURES = [
    "transfer(address,uint256)",
    "approve(address,uint256)",
    "addOwnerWithThreshold(address,uint256)",
    "removeOwner(address,address,uint256)",
    "swapOwner(address,address,address)",
    "changeThreshold(uint256)",
    "enableModule(address)",
    "disableModule(address,address)",
    "setGuard(address)",
    "setFallbackHandler(address)",
]
KNOWN = {_sel(s): s for s in KNOWN_SIGNATURES}
SAFE_ADMIN = set(KNOWN_SIGNATURES[2:])


def pattern_check(tx: dict) -> tuple[str, str]:
    data = tx["data"].lower()
    if data in ("", "0x"):
        return "PASS", "Không có calldata"
    name = KNOWN.get(data[:10])
    if name is None:
        return "WARN", f"Selector không xác định {data[:10]}"
    if name in SAFE_ADMIN:
        return "FAIL", f"Gọi hàm quản trị Safe: {name}"
    if name.startswith("approve"):
        amount = int(data[74:138], 16)
        if amount >= 2**255:
            return "FAIL", "approve vô hạn"
    return "PASS", f"Giải mã được: {name}"


MULTISEND_SEL = _sel("multiSend(bytes)")


def _unpack_multisend(data: str) -> list[dict]:
    """Tách multiSend(bytes) thành các lời gọi con: operation(1) to(20) value(32) len(32) data."""
    body = bytes.fromhex(data[2:])[4:]
    off = int.from_bytes(body[0:32], "big")
    n = int.from_bytes(body[off:off + 32], "big")
    blob = body[off + 32: off + 32 + n]
    out, i = [], 0
    while i < len(blob):
        dlen = int.from_bytes(blob[i + 53:i + 85], "big")
        out.append({"operation": blob[i], "to": "0x" + blob[i + 1:i + 21].hex(),
                    "data": "0x" + blob[i + 85:i + 85 + dlen].hex()})
        i += 85 + dlen
    return out


def pattern_check_realistic(tx: dict, depth: int = 0) -> tuple[str, str]:
    """Đối chứng THỰC TẾ: giải mã cả bên trong multiSend; selector lạ KHÔNG bị cảnh báo.
    Chỉ FAIL khi gặp hàm quản trị Safe hoặc approve vô hạn. Vẫn không mô phỏng."""
    data = (tx.get("data") or "0x").lower()
    if data in ("", "0x"):
        return "PASS", "Không có calldata"
    sel = data[:10]
    if sel == MULTISEND_SEL and depth < 3:
        try:
            inner = _unpack_multisend(data)
        except Exception:
            return "WARN", "multiSend không giải mã được"
        for t in inner:
            v, why = pattern_check_realistic(t, depth + 1)
            if v != "PASS":
                return v, f"trong multiSend: {why}"
        return "PASS", f"multiSend gồm {len(inner)} lời gọi, không có hàm nhạy cảm"
    name = KNOWN.get(sel)
    if name in SAFE_ADMIN:
        return "FAIL", f"Gọi hàm quản trị Safe: {name}"
    if name and name.startswith("approve") and len(data) >= 138 and int(data[74:138], 16) >= 2**255:
        return "FAIL", "approve vô hạn"
    return "PASS", f"Không có mẫu nguy hiểm ({name or sel})"