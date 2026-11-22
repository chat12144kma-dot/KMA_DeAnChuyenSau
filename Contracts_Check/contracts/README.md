# Contract thử nghiệm

Bốn contract tối giản tự viết để tái hiện cơ chế tấn công và tạo kịch bản đối chứng. Không dựa trên bytecode của vụ Bybit.

| Contract | Kịch bản | Vai trò |
| --- | --- | --- |
| `src/MaliciousImpl.sol` | S2 | Hàm mang chữ ký `transfer(address,uint256)`; khi bị Safe delegatecall sẽ ghi đè slot 0 (masterCopy). Có hàm rút ETH/ERC-20 sau khi chiếm quyền. |
| `src/SleeperImpl.sol` | S6 | Khi bị delegatecall, ghi sẵn `approvedHashes` cho một giao dịch tương lai của kẻ tấn công (backdoor). |
| `src/BatchTransfer.sol` | S7 | Thư viện chia ETH lành tính, cố ý không nằm trong allowlist. |
| `src/MockERC20.sol` | S8, S9 | Token ERC-20 tối giản. |

Địa chỉ đã triển khai trên Sepolia nằm trong `tool/.env.sepolia`.

## Biên dịch và triển khai

```bash
cd Contracts_Check/contracts
forge build
forge create src/MaliciousImpl.sol:MaliciousImpl --rpc-url <SEPOLIA_RPC> \
      --private-key <KHOA_RIENG> --broadcast
```

- `forge build`: biên dịch các contract trong `src/`, kết quả ghi vào `out/` (đã được bỏ qua trong git).
- `forge create … --broadcast`: biên dịch rồi gửi giao dịch triển khai lên mạng. Lặp lại cho ba contract còn lại. Không contract nào có constructor nên không cần tham số.
