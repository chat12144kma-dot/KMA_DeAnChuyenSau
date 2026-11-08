"""
proxy.py — Roadmap bước 7: RPC proxy ĐỘC HẠI đứng trước Anvil.

Chuyển tiếp mọi JSON-RPC tới UPSTREAM_RPC, nhưng "nói dối" ở những chỗ tool
dựa vào để phát hiện tấn công:

  hide_slot0 : eth_getStorageAt(SAFE, slot 0) luôn trả masterCopy GỐC
               → lớp Bất biến không thấy masterCopy bị ghi đè (S2 Bybit)
  hide_trace : debug_traceTransaction — xoá storage của SAFE trong kết quả
               prestateTracer (diffMode) → lớp Diff không thấy slot nào bị ghi

Các phương thức khác (eth_call, eth_getBalance, evm_snapshot...) giữ nguyên,
để thí nghiệm cho thấy lớp nào còn đứng vững khi nguồn dữ liệu bị thao túng.

Chạy:  python proxy.py          (đọc SAFE_ADDRESS, SAFE_MASTER_COPY từ .env)
Biến:  UPSTREAM_RPC (mặc định http://localhost:8545), PROXY_PORT (8546),
       PROXY_MODES  (mặc định "hide_slot0,hide_trace")
"""

import json
import os
import traceback
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from state_reader import load_env

env = load_env()
UPSTREAM = os.getenv("UPSTREAM_RPC", "http://127.0.0.1:8545")
# Không đi qua proxy hệ thống (http_proxy...) khi gọi Anvil cục bộ
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
PORT = int(os.getenv("PROXY_PORT", "8546"))
SAFE = env["SAFE_ADDRESS"].lower()
REAL_MASTER_COPY = env["SAFE_MASTER_COPY"].lower()
MODES = {m.strip() for m in os.getenv("PROXY_MODES", "hide_slot0,hide_trace").split(",") if m.strip()}

stats = {"hide_slot0": 0, "hide_trace": 0}


def forward(body: bytes):
    req = urllib.request.Request(UPSTREAM, data=body,
                                 headers={"Content-Type": "application/json"})
    with _opener.open(req, timeout=120) as r:
        return json.loads(r.read())


def tamper(req: dict, resp: dict) -> dict:
    method, params = req.get("method"), req.get("params") or []
    if "error" in resp:
        return resp

    if ("hide_slot0" in MODES and method == "eth_getStorageAt"
            and str(params[0]).lower() == SAFE and int(params[1], 16) == 0):
        fake = "0x" + REAL_MASTER_COPY[2:].rjust(64, "0")
        if resp.get("result") != fake:
            stats["hide_slot0"] += 1
            print(f"[proxy] LIE eth_getStorageAt slot0: {resp.get('result')} -> masterCopy gốc")
        resp["result"] = fake

    if "hide_trace" in MODES and method == "debug_traceTransaction":
        res = resp.get("result")
        if isinstance(res, dict):
            for side in ("pre", "post"):
                accounts = res.get(side) or {}
                for addr, acct in accounts.items():
                    if addr.lower() == SAFE and isinstance(acct, dict) and acct.get("storage"):
                        stats["hide_trace"] += 1
                        print(f"[proxy] LIE trace: xoá {len(acct['storage'])} slot của Safe ({side})")
                        acct.pop("storage")
    return resp


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        req = {}
        try:
            req = json.loads(body)
            resp = forward(body)
            if isinstance(req, list):                   # batch request
                resp = [tamper(q, r) for q, r in zip(req, resp)]
            else:
                resp = tamper(req, resp)
        except Exception as e:
            traceback.print_exc()
            rid = req.get("id") if isinstance(req, dict) else None
            resp = {"jsonrpc": "2.0", "id": rid,
                    "error": {"code": -32603, "message": f"proxy error: {e}"}}
        out = json.dumps(resp).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *args):                       # tắt log mặc định cho gọn
        pass


if __name__ == "__main__":
    print(f"[proxy] :{PORT} -> {UPSTREAM}   modes={sorted(MODES)}   safe={SAFE}")
    try:
        ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
    except KeyboardInterrupt:
        print(f"\n[proxy] đã nói dối: {stats}")
