# Task 2 — Đối chiếu với RPC thật (Safe Sepolia 0xb0A4…0737), 19–20/11/2026

## Thiết lập
- 3 fork Anvil ghim block 12169402, chain id 11155111, Safe được nạp 1 ETH (anvil_setBalance) trên cả 3:
  - :8545 RPC chính — fork từ Alchemy
  - :8547 nhân chứng 1 — fork từ Infura (--compute-units-per-second 50)
  - :8548 nhân chứng 2 — fork từ Tenderly (sepolia.gateway.tenderly.co)
- Neo chain thật (RPC_ANCHORS): Alchemy + Tenderly — chỉ so trạng thái TRƯỚC mô phỏng
- Proxy giả mạo: proxy.py :8546 → :8545, modes hide_slot0 + hide_trace (chạy với SAFE_ADDRESS của Safe Sepolia)

## Thay đổi phương pháp so với 12/11
- 12/11: nhân chứng = chính node Anvil sau proxy → chưa phải nhân chứng độc lập.
- Nay: RPC_WITNESSES = Anvil fork độc lập, mỗi fork TỰ MÔ PHỎNG lại giao dịch (main.witness_simulate),
  so trước / sau / status / trace; RPC_ANCHORS = RPC mạng thật, chỉ so trạng thái trước (read_state_retry).

## Kết quả
| Cấu hình | RPC chính | Nguồn đối chiếu | Gắn cờ môi trường | Chặn TPR / FPR |
|---|---|---|---|---|
| A  | fork trung thực | 2 neo + 2 nhân chứng | 0/9 | 6/6 / 0/3 |
| B  | proxy giả mạo   | 2 neo + 2 nhân chứng | 9/9 | 6/6 / 0/3 |
| C0 | proxy giả mạo   | chỉ 2 neo            | 0/9 | — |
| C1 | proxy giả mạo   | 1 nhân chứng (Infura)   | 9/9 | — |
| C2 | proxy giả mạo   | 1 nhân chứng (Tenderly) | 9/9 | — |

Cấu hình B: proxy nói dối 14 lần/lần chạy (1 hide_slot0, 13 hide_trace); Bất biến 3/6 (sót S2), Diff 0/6;
nhân chứng thấy masterCopy sau S2 = 0x7795… (MaliciousImpl) trong khi proxy báo masterCopy gốc.

## Kết luận cho RQ3
1. So trạng thái trước với chain thật không đủ: proxy chỉ nói dối kết quả SAU mô phỏng (C0 = 0/9).
2. Một nhân chứng mô phỏng độc lập là đủ trước proxy này (C1, C2 = 9/9), không báo nhầm khi RPC trung thực (A = 0/9).
3. Hạn chế: RPC miễn phí thường không phục vụ trạng thái lịch sử (PublicNode, dRPC, BlockPI bị loại)
   hoặc giới hạn tốc độ (Infura, 1RPC) → chỉ có 3 nhà cung cấp độc lập. Lớp neo chưa có kịch bản đo
   riêng (vd. fork dựng từ trạng thái giả).

## File
xcheck_sepolia_A.txt, _B.txt, _C0.txt, _C1.txt, _C2.txt
