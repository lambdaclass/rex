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

pub const UPGRADE_SP1_VERIFICATION_KEY_SIGNATURE: &str =
    "upgradeSP1VerificationKey(bytes32,bytes32)";

pub const UPGRADE_RISC0_VERIFICATION_KEY_SIGNATURE: &str =
    "upgradeRISC0VerificationKey(bytes32,bytes32)";

pub const VERIFICATION_KEYS_SIGNATURE: &str = "verificationKeys(bytes32,uint8)";

pub const EMERGENCY_EXECUTE_SIGNATURE: &str = "emergencyExecute(address,uint256,bytes)";

// Function Selectors
