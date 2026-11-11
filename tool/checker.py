"""
checker.py — Đánh giá một Safe transaction qua 2 lớp:
  - Lớp tĩnh     : xem tx trước khi chạy (delegatecall ngoài allowlist)
  - Lớp mô phỏng : so sánh 7 bất biến trước/sau khi chạy trên fork
"""

ZERO = "0x0000000000000000000000000000000000000000"
BLOCKING = ("CRITICAL", "HIGH")


MULTISEND_SELECTOR = "0x8d80ff0a"  # multiSend(bytes)


def unpack_multisend(data: str) -> list[dict]:
    """Tách gói multiSend thành các lệnh con: operation(1) to(20) value(32) len(32) data."""
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


def static_checks(tx: dict, allowlist=(), _depth: int = 0) -> list[dict]:
    """Cảnh báo delegatecall tới địa chỉ ngoài allowlist — kể cả lệnh con LỒNG trong
    multiSend (lệnh con operation=1 cũng chạy trong ngữ cảnh storage của Safe)."""
    findings = []
    if tx["operation"] != 1:
        return findings
    allowed = {a.lower() for a in allowlist}
    if tx["to"].lower() not in allowed:
        where = "delegatecall" if _depth == 0 else f"delegatecall lồng trong multiSend (tầng {_depth})"
        findings.append({
            "layer": "static", "invariant": "operation", "risk": "WARN",
            "message": f"{where} tới {tx['to']} — địa chỉ không nằm trong allowlist",
        })
        return findings
    data = (tx.get("data") or "0x").lower()
    if data[:10] == MULTISEND_SELECTOR and _depth < 4:
        try:
            inner = unpack_multisend(data)
        except Exception:
            findings.append({
                "layer": "static", "invariant": "multiSend", "risk": "WARN",
                "message": "Không giải mã được gói multiSend — không kiểm tra được lệnh con",
            })
            return findings
        for sub in inner:
            findings += static_checks(sub, allowlist, _depth + 1)
    return findings


def check_invariants(before: dict, after: dict) -> list[dict]:
    findings = []

    def add(inv, risk, msg):
        findings.append({"layer": "simulation", "invariant": inv, "risk": risk,
                         "before": before[inv], "after": after[inv], "message": msg})

    if before["masterCopy"].lower() != after["masterCopy"].lower():
        add("masterCopy", "CRITICAL",
            "masterCopy (slot 0) bị ghi đè — Safe trỏ sang logic khác (mẫu tấn công Bybit)")

    if before["fallbackHandler"].lower() != after["fallbackHandler"].lower():
        add("fallbackHandler", "HIGH", "Fallback handler bị thay — lời gọi lạ tới Safe sẽ chạy code mới")

    if before["guard"].lower() != after["guard"].lower():
        risk = "CRITICAL" if after["guard"].lower() == ZERO else "HIGH"
        add("guard", risk, "Guard bị gỡ bỏ" if risk == "CRITICAL" else "Guard bị thay")

    b_own = {o.lower() for o in before["owners"]}
    a_own = {o.lower() for o in after["owners"]}
    if b_own != a_own:
        add("owners", "HIGH", f"Owner thêm: {sorted(a_own - b_own)}  bỏ: {sorted(b_own - a_own)}")

    if before["threshold"] != after["threshold"]:
        lowered = after["threshold"] < before["threshold"]
        add("threshold", "CRITICAL" if lowered else "HIGH",
            f"Threshold {before['threshold']} → {after['threshold']}"
            + (" (giảm — cần ít chữ ký hơn)" if lowered else ""))

    added = {m.lower() for m in after["modules"]} - {m.lower() for m in before["modules"]}
    if added:
        add("modules", "CRITICAL",
            f"Module mới {sorted(added)} — module thực thi được giao dịch KHÔNG cần chữ ký")

    if after["nonce"] != before["nonce"] + 1:
        add("nonce", "WARN", f"Nonce {before['nonce']} → {after['nonce']} (kỳ vọng tăng đúng 1)")

    return findings


def verdict(findings: list[dict]) -> str:
    if any(f["risk"] in BLOCKING for f in findings):
        return "FAIL"
    if findings:
        return "WARN"
    return "PASS"


def format_report(findings: list[dict]) -> str:
    v = verdict(findings)
    if v == "PASS":
        return "  [PASS] Không phát hiện vi phạm."
    lines = [f"  [{v}] {len(findings)} phát hiện:"]
    for f in findings:
        lines.append(f"    - ({f['layer']}) [{f['risk']}] {f['invariant']}: {f['message']}")
        if "before" in f:
            lines.append(f"        trước: {f['before']}")
            lines.append(f"        sau  : {f['after']}")
    return "\n".join(lines)