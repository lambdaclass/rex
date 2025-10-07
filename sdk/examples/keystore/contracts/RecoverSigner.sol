// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/Address.sol";

contract RecoverSigner {
    using MessageHashUtils for bytes32;
    using Address for address;

    event RecoveredSigner(
        address signer
    );

    function recoverSigner(
        bytes32 message,
        bytes memory signature
    ) public {
        bytes32 hash = message.toEthSignedMessageHash();
        address signer = ECDSA.recover(hash, signature);
        emit RecoveredSigner(signer);
    }
}
