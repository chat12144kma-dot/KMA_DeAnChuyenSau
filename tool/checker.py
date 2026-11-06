"""
checker.py — Đánh giá một Safe transaction qua 2 lớp:
  - Lớp tĩnh     : xem tx trước khi chạy (delegatecall ngoài allowlist)
  - Lớp mô phỏng : so sánh 7 bất biến trước/sau khi chạy trên fork
"""

ZERO = "0x0000000000000000000000000000000000000000"
BLOCKING = ("CRITICAL", "HIGH")


def static_checks(tx: dict, allowlist=()) -> list[dict]:
    findings = []
    allowed = {a.lower() for a in allowlist}
    if tx["operation"] == 1 and tx["to"].lower() not in allowed:
        findings.append({
            "layer": "static", "invariant": "operation", "risk": "WARN",
            "message": f"delegatecall tới {tx['to']} — địa chỉ không nằm trong allowlist",
        })
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