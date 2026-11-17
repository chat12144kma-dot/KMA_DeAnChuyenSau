# Đối chiếu safeTxHash — Safe Sepolia thật

- Safe: 0xb0A42015E7e24AA643704998fB491BD03CB50737 (2/3, v1.4.1), nonce 0
- Chain ID: 11155111 (Sepolia)
- Domain hash: 0x3D2CFEFBC48FF15195D42D58CEBCEFF7622E90D1F95C375E71524D1FC438CA67
- Ngày chạy: 18/11/2026
- Hash tool lấy từ results/ablation_sepolia_that.txt

## 1. Tool vs safe-tx-hashes-util vs on-chain

| KB | safeTxHash (tool) | safe-tx-hashes-util | getTransactionHash on-chain (Infura) | Khớp |
|----|-------------------|---------------------|--------------------------------------|------|
| S2 | 0x474be47ae22b37b072a1569f2c2615882af27353317ae6f30fb4c6b83a4437f9 | 0x474be47ae22b37b072a1569f2c2615882af27353317ae6f30fb4c6b83a4437f9 | 0x474be47ae22b37b072a1569f2c2615882af27353317ae6f30fb4c6b83a4437f9 | ✅ 3/3 nguồn |
| S6 | 0xc2fd3548205d8321f1e8c3e336a49185ea4227030c3af29d1b3d698376b63d5a | 0xc2fd3548205d8321f1e8c3e336a49185ea4227030c3af29d1b3d698376b63d5a | (chưa chạy) | ✅ |
| S7 | 0x8b14ebe25aa25a238bbd13c10a24e866e89411f7e64de62746717d2b13032d20 | 0x8b14ebe25aa25a238bbd13c10a24e866e89411f7e64de62746717d2b13032d20 | (chưa chạy) | ✅ |

Output đầy đủ: results/sth_sepolia_S2.txt, sth_sepolia_S6.txt, sth_sepolia_S7.txt

## 2. Cảnh báo của safe-tx-hashes-util

| KB | Loại | Cảnh báo | Nhận xét |
|----|------|----------|----------|
| S2 | Tấn công (ghi đè slot 0) | untrusted delegate call → 0x77952BA1…cb7a (MaliciousImpl) | Mô phỏng báo "successfully executed", trace không hiện slot 0 bị ghi đè |
| S6 | Tấn công (backdoor approvedHashes) | untrusted delegate call → 0x38869bf6…B526 (MultiSend v1.4.1 chính thức) | Cảnh báo vì lớp vỏ MultiSend, không mở multiSend nên không thấy 2 delegatecall lồng tới SleeperImpl |
| S7 | Hợp lệ (BatchTransfer) | untrusted delegate call → 0x789a4b1A…d596 | Cùng cảnh báo với S2 → không phân biệt được tấn công và hợp lệ |

## 3. Multisig Inspector (Manual Input, Sepolia, nonce 0)

recomputedSafeTxHash của MI khớp safeTxHash của tool: 9/9.
Mỗi KB chạy 2 lần: nhập hash đúng (_dung) và hash sai 1 ký tự (_sai).
File: results/multisig_inspec_result/sepolia/S*_hash_dung.json, S*_hash_sai.json (S1.json = không nhập hash → status not_provided)

| KB | Loại | Hash khớp | Hash đúng: status / risk / kết luận | Findings | Hash sai: status / risk |
|----|------|-----------|-------------------------------------|----------|-------------------------|
| S1 | Hợp lệ (chuyển ETH) | ✅ | match / low / normal transfer | Empty transaction | mismatch / critical |
| S2 | Tấn công (ghi đè slot 0) | ✅ | match / critical / Do not sign | Transaction uses DELEGATECALL | mismatch / critical |
| S3 | Tấn công (đổi owner/threshold) | ✅ | match / critical / Do not sign | Threshold materially lowered, Safe control change | mismatch / critical |
| S4 | Tấn công (enableModule) | ✅ | match / critical / Do not sign | Safe control change | mismatch / critical |
| S5 | Tấn công (fallbackHandler) | ✅ | match / high / Do not sign until reviewed | Safe control change | mismatch / critical |
| S6 | Tấn công (backdoor qua multiSend) | ✅ | match / critical / Do not sign | Transaction uses DELEGATECALL ×2 | mismatch / critical |
| S7 | Hợp lệ (delegatecall BatchTransfer) | ✅ | match / critical / Do not sign | Transaction uses DELEGATECALL | mismatch / critical |
| S8 | Tấn công (approve vô hạn) | ✅ | match / high / Do not sign until reviewed | Unlimited token approval | mismatch / critical |
| S9 | Hợp lệ (chuyển token) | ✅ | match / low / normal transfer | (không có) | mismatch / critical |

## 4. Tổng hợp

| Tiêu chí | Tool (cột Chặn) | Multisig Inspector | safe-tx-hashes-util |
|----------|-----------------|--------------------|---------------------|
| Hash khớp tool | — | 9/9 | 3/3 (S2, S6, S7) |
| Phát hiện hash bị sửa | tự tính & đối chiếu | 9/9 (chỉ khi người dùng nhập hash) | so với Transaction Service API |
| Chặn tấn công (S2–S6, S8) | 6/6 | 6/6 | chỉ cảnh báo delegatecall chung (S2, S6) |
| Chặn nhầm hợp lệ (S1, S7, S9) | 0/3 | 1/3 (S7) | S7 cùng cảnh báo như S2 |
| Phân biệt S2 (ghi đè slot 0) và S7 (hợp lệ) | Có (FAIL vs WARN) | Không (cùng "DELEGATECALL") | Không |

Kết quả trùng với lần so sánh trên fork cũ (15–16/11) → không phụ thuộc môi trường.
