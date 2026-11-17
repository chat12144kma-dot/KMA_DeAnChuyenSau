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

## 3. Multisig Inspector (điền khi chạy)

| KB | safeTxHash (tool) | Hash MI | hashCheck | riskLevel | Kết luận MI |
|----|-------------------|---------|-----------|-----------|-------------|
| S1 | 0x84bcc6338c60cc879a4fc8626d1867824d3f17fe49808d93304d899883d539b0 | | | | |
| S2 | 0x474be47ae22b37b072a1569f2c2615882af27353317ae6f30fb4c6b83a4437f9 | | | | |
| S3 | 0xe2c8d9c6c683b64014f5833806260b48d41f6e294731416b90dd395accc1e433 | | | | |
| S4 | 0x9dd4daf468fdcb68abadf46aeccb9778c5450ecca0754cc2bcd2e08e42db99ed | | | | |
| S5 | 0x4ec875227545ad8ee0091550271af30309102da3b6577c8f088fb3069b464ece | | | | |
| S6 | 0xc2fd3548205d8321f1e8c3e336a49185ea4227030c3af29d1b3d698376b63d5a | | | | |
| S7 | 0x8b14ebe25aa25a238bbd13c10a24e866e89411f7e64de62746717d2b13032d20 | | | | |
| S8 | 0xcf6ed8a9cc6e7155842e9ffb4c49a9c323521dcba68fd3256b48d566a6653e44 | | | | |
| S9 | 0xdee8e56fde6fb9bce0f3ba1f513e20ec119075317ab4c155dd2af8bb5b30e0a3 | | | | |
