// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Thư viện LÀNH TÍNH: chia ETH cho nhiều người nhận trong một giao dịch.
/// Safe gọi bằng delegatecall để tiền đi từ chính Safe. Không ghi storage nào.
contract BatchTransfer {
    event BatchSent(uint256 count, uint256 total);

    function batchSend(address payable[] calldata to, uint256[] calldata amounts) external {
        require(to.length == amounts.length, "len");
        uint256 total;
        for (uint256 i = 0; i < to.length; i++) {
            (bool ok, ) = to[i].call{value: amounts[i]}("");
            require(ok, "send");
            total += amounts[i];
        }
        emit BatchSent(to.length, total);
    }
}