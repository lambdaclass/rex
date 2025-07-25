use ethrex_common::{Address, H160};

// Contract Addresses

pub const COMMON_BRIDGE_L2_ADDRESS: Address = H160([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xff, 0xff,
]);

// Function Signatures

pub const L2_WITHDRAW_SIGNATURE: &str = "withdraw(address)";

pub const L2_WITHDRAW_SIGNATURE_ERC20: &str = "withdrawERC20(address,address,address,uint256)";

pub const CLAIM_WITHDRAWAL_ERC20_SIGNATURE: &str =
    "claimWithdrawalERC20(address,address,uint256,uint256,uint256,bytes32[])";

// Function Selectors
