"""assets.py — Lớp "Tài sản": đọc sự kiện token trong giao dịch mô phỏng.

Bất biến của Safe không thấy được approve/transfer token, vì dữ liệu đó nằm
trong storage của contract token. Lớp này đọc log của receipt để bù chỗ đó.
"""
from web3 import Web3

T_TRANSFER = bytes(Web3.keccak(text="Transfer(address,address,uint256)"))
T_APPROVAL = bytes(Web3.keccak(text="Approval(address,address,uint256)"))
T_APPROVAL_ALL = bytes(Web3.keccak(text="ApprovalForAll(address,address,bool)"))

UNLIMITED = 2**255  # từ nửa dải uint256 trở lên coi như "vô hạn"


def _addr(topic: bytes) -> str:
    return Web3.to_checksum_address(topic[-20:])


def asset_checks(w3: Web3, tx_hash, safe_address: str,
                 spender_allowlist=()) -> tuple[list[dict], list[str]]:
    """Trả về (findings, moves).

    findings: cùng định dạng với checker (layer/invariant/risk/message).
    moves   : các dòng mô tả thay đổi tài sản, chỉ để hiển thị.
    Phải gọi TRƯỚC khi evm_revert, lúc receipt của giao dịch mô phỏng còn tồn tại.
    """
    safe = Web3.to_checksum_address(safe_address)
    allow = {a.lower() for a in spender_allowlist}
    receipt = w3.eth.get_transaction_receipt(tx_hash)
    findings, moves = [], []

    def flag(kind: str, token: str, spender: str, what: str):
        if spender.lower() in allow:
            return
        code = bytes(w3.eth.get_code(spender))
        # EIP-7702: ví thường có uỷ quyền mang code = 0xef0100 + 20 byte địa chỉ,
        # nhưng vẫn do khoá riêng điều khiển → vẫn tính là EOA.
        delegated = len(code) == 23 and code[:3] == b"\xef\x01\x00"
        is_eoa = len(code) == 0 or delegated
        risk = "HIGH" if is_eoa else "WARN"
        who = ("ví thường (EOA, có uỷ quyền EIP-7702)" if delegated
               else "ví thường (EOA)" if is_eoa else "contract ngoài allowlist")
        findings.append({
            "layer": "asset", "invariant": kind, "risk": risk,
            "message": f"{what} trên token {token} cho {spender} — {who}; "
                       f"bên này rút được token của Safe bất cứ lúc nào, không cần chữ ký"})

    for lg in receipt["logs"]:
        topics = [bytes(t) for t in lg["topics"]]
        if len(topics) < 3 or _addr(topics[1]) != safe:
            continue  # chỉ xét sự kiện mà Safe là chủ / bên gửi
        token = Web3.to_checksum_address(lg["address"])
        other = _addr(topics[2])
        value = int.from_bytes(bytes(lg["data"])[:32], "big")

        if topics[0] == T_APPROVAL and len(topics) == 3:      # ERC20 approve
            if value >= UNLIMITED:
                moves.append(f"approve VÔ HẠN token {token} cho {other}")
                flag("UNLIMITED_APPROVAL", token, other, "Approve vô hạn")
            elif value > 0:
                moves.append(f"approve {value} đơn vị token {token} cho {other}")
            else:
                moves.append(f"thu hồi approve token {token} của {other}")
        elif topics[0] == T_APPROVAL_ALL:                     # NFT: toàn quyền
            if value:
                moves.append(f"setApprovalForAll token {token} cho {other}")
                flag("APPROVAL_FOR_ALL", token, other, "Cấp toàn quyền NFT")
        elif topics[0] == T_TRANSFER and len(topics) == 3:    # ERC20 transfer
            moves.append(f"chuyển {value} đơn vị token {token} tới {other}")

    return findings, moves