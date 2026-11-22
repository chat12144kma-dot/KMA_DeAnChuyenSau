import sys
p = "main.py"
s = open(p, encoding="utf-8").read()
if "def read_state_retry" in s:
    sys.exit("Đã vá trước đó — dừng")

FN = '''def read_state_retry(r: str, safe: str, tries: int = 5) -> dict:
    """Đọc trạng thái từ RPC công khai; tự đợi và thử lại khi bị giới hạn tốc độ."""
    import time
    for k in range(tries):
        try:
            return read_state(r, safe)
        except Exception as e:
            if k == tries - 1:
                raise
            wait = 3 * (k + 1)
            print(f"  (neo {r.split('/')[2]} lỗi: {str(e)[:60]}… — thử lại sau {wait}s)")
            time.sleep(wait)


'''
old_call = "[read_state(r, safe) for r in anchors]"
if old_call not in s or "def witness_simulate" not in s:
    sys.exit("KHÔNG TÌM THẤY chỗ cần sửa — chưa sửa gì")
s = s.replace(old_call, "[read_state_retry(r, safe) for r in anchors]")
s = s.replace("def witness_simulate", FN + "def witness_simulate", 1)
open(p, "w", encoding="utf-8").write(s)
print("Đã vá main.py")
