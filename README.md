# Công cụ xác minh độc lập giao dịch multisig Web3

Công cụ dòng lệnh kiểm tra một giao dịch Safe multisig **trước khi ký**: chạy thử giao dịch trên một bản fork của blockchain, rồi kiểm tra sau giao dịch ai kiểm soát ví và tài sản đi đâu. Mục tiêu là cảnh báo các tấn công blind signing kiểu Bybit (02/2025), trong đó người ký thấy một lệnh chuyển tiền nhưng thực chất ký một delegatecall ghi đè masterCopy (slot 0) của ví.

Đề tài chuyên sâu, Học viện Kỹ thuật Mật mã, 2026.

## Cách công cụ hoạt động

1. **Tĩnh:** đọc calldata, cảnh báo delegatecall tới địa chỉ ngoài allowlist (kể cả delegatecall lồng trong multiSend).
2. **Mô phỏng:** chạy giao dịch qua chính `execTransaction` của ví trên fork Anvil (impersonation, không cần private key).
3. **Kiểm tra sau mô phỏng:** so 7 bất biến đọc thẳng từ storage (masterCopy, owners, threshold, modules, guard, fallback handler, nonce), storage diff, exploit probe (thử rút tiền, chiếm quyền trên trạng thái sau), biến động ETH/token.
4. **Đối chiếu đa nguồn:** so kết quả với *anchor RPC* (RPC mạng thật, so trạng thái trước) và *witness node* (fork độc lập tự mô phỏng lại) để phát hiện RPC bị giả mạo.
5. **Kết luận:** `PASS` / `WARN` / `FAIL` về giao dịch, tách riêng kết luận về môi trường RPC, kèm safeTxHash để so với màn hình ví cứng.

## Cấu trúc thư mục

```
.
├── tool/                        Mã nguồn công cụ (Python)
│   ├── main.py                  Chạy bộ kịch bản S1–S9, in bảng ablation
│   ├── state_reader.py          Đọc 7 bất biến từ storage; nạp cấu hình (ENV_FILE)
│   ├── simulator.py             Mô phỏng qua execTransaction trên fork
│   ├── checker.py               Phân tích tĩnh, so bất biến, tổng hợp kết luận
│   ├── storage_diff.py          Storage diff (prestateTracer)
│   ├── consequences.py          Exploit probe trên trạng thái sau
│   ├── assets.py                Biến động ETH/token, approve vô hạn
│   ├── baseline.py              Hai baseline nhận dạng theo mẫu để so sánh
│   ├── proxy.py                 RPC giả mạo (che slot 0 và trace) cho thực nghiệm
│   ├── replay.py                Phát lại giao dịch Safe thật trên fork mainnet
│   ├── real_txs.py              Tải giao dịch thật từ Safe Transaction Service
│   ├── baseline_real.py         Đo hai baseline trên dữ liệu thật
│   ├── debug_one.py             Gỡ lỗi một giao dịch thật
│   ├── ui.py                    Giao diện web (Streamlit), bản nguyên mẫu
│   ├── .env.sepolia             Địa chỉ công khai của môi trường Sepolia thật
│   ├── data/                    Danh sách Safe và 80 giao dịch thật
│   └── results/                 Kết quả thực nghiệm (xem results/README.md)
├── Contracts_Check/contracts/   Contract thử nghiệm (Foundry)
└── archive/                     Mã cũ, chỉ để tra cứu
```

## Cài đặt

Cần Ubuntu (hoặc WSL), Python 3.12 và Foundry.

```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
cd tool
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

- `curl … | bash` tải và chạy script cài Foundry; `foundryup` cài `anvil`, `cast`, `forge`.
- `python3 -m venv venv` tạo môi trường ảo Python trong thư mục `venv`; `source venv/bin/activate` bật nó cho terminal hiện tại.
- `pip install -r requirements.txt` cài các thư viện liệt kê trong tệp.

## Cấu hình

Công cụ đọc cấu hình từ `tool/.env` (mặc định) hoặc tệp khác chọn bằng biến `ENV_FILE`.

- `tool/.env.sepolia`: địa chỉ công khai của ví và contract trên Sepolia thật (có trong repo).
- `tool/.env`: **không có trong repo**, chứa khóa RPC và API (`SEPOLIA_RPC_INFURA`, `ETH_RPC_ALCHEMY`, `SAFE_API_KEY`, …).

| Biến môi trường | Ý nghĩa |
| --- | --- |
| `ENV_FILE` | Tệp cấu hình, ví dụ `.env.sepolia` |
| `RPC_URL` | RPC chính, mặc định `http://localhost:8545` |
| `RPC_WITNESSES` | Danh sách witness node, cách nhau bởi dấu phẩy |
| `RPC_ANCHORS` | Danh sách anchor RPC, cách nhau bởi dấu phẩy |
| `ONLY` | Chỉ chạy một số kịch bản, ví dụ `ONLY=S2,S7` |

## Chạy

Mọi lệnh dưới đây chạy trong thư mục `tool/` với môi trường ảo đã bật.

**1. Khởi động fork Sepolia** (terminal riêng):

```bash
source .env
anvil --fork-url "$SEPOLIA_RPC_INFURA" --port 8545
```

- `source .env` nạp biến trong `.env` vào terminal; `anvil --fork-url …` tạo node fork từ Sepolia ở cổng 8545.

**2. Chạy bộ kịch bản:**

```bash
ENV_FILE=.env.sepolia python main.py | tee results/lan_chay_moi.txt
ENV_FILE=.env.sepolia ONLY=S2,S7 python main.py
```

- Dòng đầu chạy cả 9 kịch bản; `| tee …` vừa in ra màn hình vừa ghi vào tệp.
- Dòng hai chỉ chạy S2 và S7.

**3. Đối chiếu đa nguồn với RPC giả mạo:**

```bash
ENV_FILE=.env.sepolia SAFE_ADDRESS=0xb0A42015E7e24AA643704998fB491BD03CB50737 python proxy.py
ENV_FILE=.env.sepolia RPC_URL=http://localhost:8546 \
  RPC_WITNESSES=http://localhost:8547 python main.py
```

- Lệnh đầu dựng RPC giả mạo ở cổng 8546 (che slot 0 và trace của ví).
- Lệnh sau dùng proxy làm RPC chính và một witness node ở cổng 8547 (một fork Anvil khác, cùng block). Thiết lập đầy đủ ở Phụ lục B.6 của báo cáo.

**4. Phát lại giao dịch thật** (cần fork mainnet ở cổng 8545):

```bash
python replay.py
python replay.py --summary
```

**5. Giao diện web:**

```bash
ENV_FILE=.env.sepolia streamlit run ui.py
```

- Mở trình duyệt tại `http://localhost:8501`.

## Kết quả

Tóm tắt trên ví Safe 2/3 ở Sepolia (6 kịch bản tấn công, 3 hợp lệ): mức Chặn (FAIL) phát hiện 6/6 tấn công, chặn nhầm 0/3; trên 80 giao dịch Safe thật, chặn nhầm 0/75 giao dịch thông thường. Chi tiết và ánh xạ tới báo cáo: [`tool/results/README.md`](tool/results/README.md).

## Lưu ý

- Contract trong `Contracts_Check/contracts/src` là mã tối giản để minh họa cơ chế tấn công, chỉ dùng trên testnet và fork.
- Không commit `tool/.env` hay bất kỳ private key nào.
