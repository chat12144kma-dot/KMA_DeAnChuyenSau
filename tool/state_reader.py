"""
state_reader.py — Đọc state của Safe multisig TRỰC TIẾP TỪ STORAGE.

Không gọi hàm qua ABI, vì sau khi masterCopy bị ghi đè, logic contract đã bị thay
(các hàm có thể revert hoặc trả dữ liệu giả). Storage thì luôn đọc được.

Layout Safe v1.4.1:
  slot 0 : masterCopy
  slot 1 : modules  (mapping address=>address, linked list từ SENTINEL)
  slot 2 : owners   (mapping address=>address, linked list từ SENTINEL)
  slot 4 : threshold
  slot 5 : nonce
  keccak256("fallback_manager.handler.address") : fallbackHandler
  keccak256("guard_manager.guard.address")      : guard
"""

import os
import sys
from pathlib import Path

from eth_abi import encode
from web3 import Web3

ZERO = "0x0000000000000000000000000000000000000000"
SENTINEL = "0x0000000000000000000000000000000000000001"

SLOT_MASTER_COPY = 0
SLOT_MODULES_MAPPING = 1
SLOT_OWNERS_MAPPING = 2
SLOT_THRESHOLD = 4
SLOT_NONCE = 5
SLOT_FALLBACK_HANDLER = int.from_bytes(Web3.keccak(text="fallback_manager.handler.address"), "big")
SLOT_GUARD = int.from_bytes(Web3.keccak(text="guard_manager.guard.address"), "big")

CONSENSUS_FIELDS = ["masterCopy", "fallbackHandler", "guard", "owners", "threshold", "nonce", "modules"]


def mapping_slot(key_address: str, mapping_position: int) -> int:
    """Vị trí storage của mapping[key] = keccak256(abi.encode(key, position))."""
    packed = encode(["address", "uint256"], [Web3.to_checksum_address(key_address), mapping_position])
    return int.from_bytes(Web3.keccak(packed), "big")


def read_slot_uint(w3: Web3, addr: str, slot: int) -> int:
    return int.from_bytes(bytes(w3.eth.get_storage_at(addr, slot)), "big")


def read_slot_as_address(w3: Web3, addr: str, slot: int) -> str:
    raw = bytes(w3.eth.get_storage_at(addr, slot))
    return Web3.to_checksum_address("0x" + raw[-20:].hex())


def read_linked_list(w3: Web3, addr: str, mapping_position: int, limit: int = 100) -> list[str]:
    """Duyệt danh sách liên kết của Safe: SENTINEL -> a -> b -> ... -> SENTINEL."""
    items = []
    current = read_slot_as_address(w3, addr, mapping_slot(SENTINEL, mapping_position))
    while current.lower() not in (SENTINEL, ZERO) and len(items) < limit:
        items.append(current)
        current = read_slot_as_address(w3, addr, mapping_slot(current, mapping_position))
    return items


def read_state(rpc_url: str, safe_address: str) -> dict:
    """Đọc toàn bộ state quan trọng của Safe từ một RPC, chỉ dùng eth_getStorageAt."""
    w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 30}))
    safe = Web3.to_checksum_address(safe_address)
    return {
        "rpc": rpc_url,
        "masterCopy": read_slot_as_address(w3, safe, SLOT_MASTER_COPY),
        "fallbackHandler": read_slot_as_address(w3, safe, SLOT_FALLBACK_HANDLER),
        "guard": read_slot_as_address(w3, safe, SLOT_GUARD),
        "owners": read_linked_list(w3, safe, SLOT_OWNERS_MAPPING),
        "threshold": read_slot_uint(w3, safe, SLOT_THRESHOLD),
        "nonce": read_slot_uint(w3, safe, SLOT_NONCE),
        "modules": read_linked_list(w3, safe, SLOT_MODULES_MAPPING),
    }


def _norm(value):
    if isinstance(value, list):
        return sorted(v.lower() for v in value)
    if isinstance(value, str):
        return value.lower()
    return value


def read_multi_rpc(rpc_list: list[str], safe_address: str) -> dict:
    """Đọc state từ nhiều RPC, kiểm tra chéo mọi trường, trả về state đồng thuận."""
    states = []
    for rpc in rpc_list:
        try:
            states.append(read_state(rpc, safe_address))
        except Exception as e:
            print(f"[WARN] RPC {rpc} lỗi: {e}")

    if not states:
        raise RuntimeError("Không đọc được state từ RPC nào")
    if len(states) < len(rpc_list):
        print(f"[WARN] Chỉ {len(states)}/{len(rpc_list)} RPC trả lời — độ tin cậy giảm")

    base = states[0]
    mismatches = []
    for s in states[1:]:
        for field in CONSENSUS_FIELDS:
            if _norm(s[field]) != _norm(base[field]):
                mismatches.append(f"  {field}: {base['rpc']} → {base[field]} | {s['rpc']} → {s[field]}")
    if mismatches:
        raise RuntimeError("RPC không nhất quán:\n" + "\n".join(mismatches))
    return base


def load_env() -> dict:
    env_path = Path(__file__).parent / ".env"
    env = {}
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    return env


if __name__ == "__main__":
    safe_addr = sys.argv[1] if len(sys.argv) >= 2 else load_env().get("SAFE_ADDRESS")
    if not safe_addr:
        print("Usage: python state_reader.py <safe_address>  (hoặc đặt SAFE_ADDRESS trong .env)")
        sys.exit(1)

    rpcs_env = os.getenv("RPC_URLS", "http://localhost:8545")
    rpcs = [r.strip() for r in rpcs_env.split(",") if r.strip()]

    print(f"Đọc state của Safe {safe_addr} từ {len(rpcs)} RPC")
    state = read_multi_rpc(rpcs, safe_addr)
    print("\nKết quả:")
    for k, v in state.items():
        print(f"  {k}: {v}")