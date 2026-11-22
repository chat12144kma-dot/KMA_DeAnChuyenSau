# Kết quả thực nghiệm

Bảng dưới đây nối từng tệp với bảng tương ứng trong báo cáo. Môi trường: **E1** = fork Sepolia cục bộ, **E2** = Safe trên Sepolia thật (live fork), **E3** = live fork Ethereum mainnet.

## Kết quả chính

| Tệp | Nội dung | Trong báo cáo |
| --- | --- | --- |
| `ablation_sepolia_that.txt` | S1–S9 trên E2, đầu ra đầy đủ từng kịch bản và bảng ablation | Bảng 4.2, 4.3, D.2 |
| `ablation_buoc9_sau_taisan.txt` | S1–S9 trên E1 sau khi có tầng Tài sản | Phụ lục D.3 |
| `replay_buoc9_taisan.txt`, `replay_real.json` | Phát lại 80 giao dịch Safe thật trên E3 | Bảng 4.4 |
| `hash_match_sepolia.md` | Đối chiếu safeTxHash và kết quả hai công cụ so sánh trên E2 | Bảng 4.1, 4.5, Phụ lục E |
| `sth_sepolia_S2.txt` (`_S6`, `_S7`) | Đầu ra safe-tx-hashes-util trên E2 | Bảng E.1 |
| `sth_S2.txt`, `sth_S6.txt`, `sth_S7.txt` | Đầu ra safe-tx-hashes-util trên E1 | Bảng 4.1 |
| `multisig_inspec_result/sepolia/` | Đầu ra Multisig Inspector trên E2 (`S*_hash_dung.json`, `S*_hash_sai.json`) | Bảng E.2 |
| `multisig_inspec_result/fork_cucbo/` | Đầu ra Multisig Inspector trên E1 (không kiểm tra được hash) | Phụ lục E.2 |
| `compare_inputs.txt`, `compare_inputs_sepolia.txt` | Trường giao dịch S1–S9 dùng làm đầu vào cho hai công cụ so sánh | Phụ lục B.8 |
| `xcheck_sepolia.md`, `xcheck_sepolia_{A,B,C0,C1,C2}.txt` | Đối chiếu đa nguồn trên E2 (RQ3) | Bảng 4.6, Phụ lục F |
| `ablation_buoc9_xcheck_trungthuc.txt`, `ablation_buoc9_proxy_khongdoichieu.txt`, `ablation_buoc9_proxy_doichieu.txt` | Thực nghiệm đối chiếu sơ bộ trên E1 | Phụ lục F.3 |
| `sepolia_deploy.txt` | Đầu ra triển khai 4 contract thử nghiệm lên Sepolia | Bảng A.2 |

## archive/

Kết quả của các lần chạy cũ, được giữ để đối chiếu lịch sử: trước khi sửa bộ lọc simulation artifact (có cảnh báo giả ở tầng Diff), trước khi có tầng Tài sản, và các bước 6–7 của lộ trình. **Không dùng để trích dẫn số liệu.**
