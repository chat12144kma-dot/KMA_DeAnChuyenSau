"""
storage_diff.py — Lớp 3: diff TOÀN BỘ storage của Safe trong giao dịch.

Dùng debug_traceTransaction + prestateTracer (diffMode) để lấy mọi slot bị ghi,
gắn nhãn theo layout Safe đã biết; slot không nhận diện được → cảnh báo.
"""

from state_reader import (
    mapping_slot, SENTINEL,
    SLOT_MASTER_COPY, SLOT_MODULES_MAPPING, SLOT_OWNERS_MAPPING,
    SLOT_THRESHOLD, SLOT_NONCE, SLOT_FALLBACK_HANDLER, SLOT_GUARD,
)

SLOT_OWNER_COUNT = 3
TRACER = {"tracer": "prestateTracer", "tracerConfig": {"diffMode": True}}


def _lower_keys(d):
    return {k.lower(): v for k, v in (d or {}).items()}


def trace_safe_storage(w3, tx_hash: str, safe_address: str) -> list[dict]:
    """Trả về danh sách slot của Safe bị thay đổi: {slot, before, after} (dạng int)."""
    resp = w3.provider.make_request("debug_traceTransaction", [tx_hash, TRACER])
    if "error" in resp:
        raise RuntimeError(f"debug_traceTransaction lỗi: {resp['error']}")

    pre = _lower_keys(resp["result"].get("pre"))
    post = _lower_keys(resp["result"].get("post"))
    key = safe_address.lower()

    pre_st = {int(k, 16): int(v, 16) for k, v in (pre.get(key) or {}).get("storage", {}).items()}
    post_st = {int(k, 16): int(v, 16) for k, v in (post.get(key) or {}).get("storage", {}).items()}

    changes = []
    for slot in sorted(set(pre_st) | set(post_st)):
        b, a = pre_st.get(slot, 0), post_st.get(slot, 0)
        if a != b:
            changes.append({"slot": slot, "before": b, "after": a})
    return changes


def build_slot_labels(before: dict, after: dict) -> dict[int, str]:
    """Bản đồ slot → tên, cho các slot thuộc layout Safe đã biết."""
    labels = {
        SLOT_MASTER_COPY: "masterCopy",
        SLOT_OWNER_COUNT: "ownerCount",
        SLOT_THRESHOLD: "threshold",
        SLOT_NONCE: "nonce",
        SLOT_FALLBACK_HANDLER: "fallbackHandler",
        SLOT_GUARD: "guard",
    }
    for o in {SENTINEL, *before["owners"], *after["owners"]}:
        labels[mapping_slot(o, SLOT_OWNERS_MAPPING)] = f"owners[{o}]"
    for m in {SENTINEL, *before["modules"], *after["modules"]}:
        labels[mapping_slot(m, SLOT_MODULES_MAPPING)] = f"modules[{m}]"
    return labels


def analyze_storage(changes: list[dict], labels: dict[int, str]):
    """
    Trả về (findings, touched):
      touched  : mọi slot bị ghi, trừ nonce tăng đúng 1
      findings : cảnh báo cho slot KHÔNG thuộc layout đã biết
    """
    findings, touched = [], []
    for c in changes:
        label = labels.get(c["slot"])
        if label == "nonce" and c["after"] == c["before"] + 1:
            continue
        touched.append({**c, "label": label or f"UNKNOWN({hex(c['slot'])[:12]}…)"})
        if label is None:
            findings.append({
                "layer": "storage-diff", "invariant": f"slot {hex(c['slot'])}", "risk": "WARN",
                "before": hex(c["before"]), "after": hex(c["after"]),
                "message": "Slot ngoài layout đã biết bị ghi — có thể là cửa hậu "
                           "(vd. approvedHashes cài sẵn cho giao dịch tương lai)",
            })
    return findings, touched