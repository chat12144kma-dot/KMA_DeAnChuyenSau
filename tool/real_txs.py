"""
real_txs.py — Roadmap bước 8a: tải các giao dịch Safe THẬT đã thực thi trên mainnet.

Nguồn: Safe Transaction Service (API chính thức của Safe), cần API key miễn phí
tạo tại Safe API Dashboard, lưu vào .env dạng:  SAFE_API_KEY="eyJ..."

Chỉ lưu những trường cần để mô phỏng lại (to, value, data, operation, nonce,
blockNumber...) vào data/real_txs.json — chạy một lần, các bước sau đọc file này.

Dùng:
  python real_txs.py                         # đọc danh sách Safe từ data/safes.txt
  python real_txs.py 0xSafe1 0xSafe2 ...     # hoặc truyền địa chỉ trực tiếp
  LIMIT=20 python real_txs.py ...            # số giao dịch tối đa mỗi Safe (mặc định 20)
"""

import json
import os
import sys
import time
import urllib.request
from pathlib import Path

from web3 import Web3

from state_reader import load_env

API_BASE = "https://api.safe.global/tx-service/eth/api/v2"
DATA_DIR = Path(__file__).parent / "data"
SAFES_FILE = DATA_DIR / "safes.txt"
OUT_FILE = DATA_DIR / "real_txs.json"
SLEEP = 0.3          # giới hạn mặc định của Safe API là 5 request/giây


def _clean(v: str) -> str:
    """load_env giữ nguyên dấu nháy trong .env → bỏ đi."""
    return v.strip().strip('"').strip("'")


def api_get(url: str, api_key: str) -> dict:
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {api_key}",
                                               "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


def fetch_safe_txs(safe: str, api_key: str, limit: int) -> list[dict]:
    """Lấy tối đa `limit` giao dịch đã thực thi THÀNH CÔNG của một Safe (mới nhất trước)."""
    url = f"{API_BASE}/safes/{safe}/multisig-transactions/?executed=true&limit=100"
    out = []
    while url and len(out) < limit:
        page = api_get(url, api_key)
        for t in page.get("results", []):
            if not (t.get("isExecuted") and t.get("isSuccessful")) or not t.get("blockNumber"):
                continue
            decoded = t.get("dataDecoded") or {}
            out.append({
                "safe": Web3.to_checksum_address(t["safe"]),
                "nonce": int(t["nonce"]),
                "to": Web3.to_checksum_address(t["to"]),
                "value": int(t.get("value") or 0),
                "data": t.get("data") or "0x",
                "operation": int(t.get("operation") or 0),
                # tham số refund — cần để safeTxHash tính lại trùng với hash thật
                "safeTxGas": int(t.get("safeTxGas") or 0),
                "baseGas": int(t.get("baseGas") or 0),
                "gasPrice": int(t.get("gasPrice") or 0),
                "gasToken": t.get("gasToken") or "0x0000000000000000000000000000000000000000",
                "refundReceiver": t.get("refundReceiver") or "0x0000000000000000000000000000000000000000",
                "blockNumber": int(t["blockNumber"]),
                "transactionHash": t.get("transactionHash"),
                "safeTxHash": t.get("safeTxHash"),
                "method": decoded.get("method"),        # để phân loại kết quả sau này
            })
            if len(out) >= limit:
                break
        url = page.get("next")
        time.sleep(SLEEP)
    return out


def load_safes(argv: list[str]) -> list[str]:
    if argv:
        return argv
    if SAFES_FILE.exists():
        lines = [l.split("#")[0].strip() for l in SAFES_FILE.read_text().splitlines()]
        return [l for l in lines if l]
    sys.exit(f"Chưa có danh sách Safe: truyền địa chỉ làm tham số hoặc tạo {SAFES_FILE}")


if __name__ == "__main__":
    env = load_env()
    api_key = _clean(os.getenv("SAFE_API_KEY") or env.get("SAFE_API_KEY", ""))
    if not api_key:
        sys.exit("Thiếu SAFE_API_KEY trong .env (tạo miễn phí tại Safe API Dashboard)")
    limit = int(os.getenv("LIMIT", "20"))

    DATA_DIR.mkdir(exist_ok=True)
    all_txs = []
    for safe in load_safes(sys.argv[1:]):
        safe = Web3.to_checksum_address(safe)
        try:
            txs = fetch_safe_txs(safe, api_key, limit)
        except Exception as e:
            print(f"[LỖI] {safe}: {e}")
            continue
        methods = {}
        for t in txs:
            k = t["method"] or ("(gọi rỗng)" if t["data"] == "0x" else "(không giải mã)")
            methods[k] = methods.get(k, 0) + 1
        print(f"{safe}: {len(txs)} giao dịch  {dict(sorted(methods.items(), key=lambda x: -x[1]))}")
        all_txs += txs

    OUT_FILE.write_text(json.dumps(all_txs, indent=2))
    print(f"\nĐã lưu {len(all_txs)} giao dịch vào {OUT_FILE}")
