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