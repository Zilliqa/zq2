// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Source: https://github.com/Zilliqa/zilliqa-developer/blob/main/contracts/experimental/ERC20ProxyForZRC2/contracts/ScillaConnector.sol
library ScillaConnector {
    uint private constant CALL_SCILLA_WITH_THE_SAME_SENDER = 1;
    uint private constant SCILLA_CALL_PRECOMPILE_ADDRESS = 0x5a494c53;
    uint private constant SCILLA_STATE_READ_PRECOMPILE_ADDRESS = 0x5a494c92;

    /**
     * @dev Calls a ZRC2 contract function with two arguments
     * @param target The address of the ZRC2 contract
     * @param tran_name The name of the function to call
     */
    function callScilla(address target, string memory tran_name) internal {
        bytes memory encodedArgs = abi.encode(
            target,
            tran_name,
            CALL_SCILLA_WITH_THE_SAME_SENDER
        );
        uint256 argsLength = encodedArgs.length;

        assembly {
            let ok := call(
                gas(),
                SCILLA_CALL_PRECOMPILE_ADDRESS,
                0,
                add(encodedArgs, 0x20),
                argsLength,
                0x20,
                0
            )
            if iszero(ok) {
                revert(0, 0)
            }
        }
    }

    function callScilla(
        address target,
        string memory tran_name,
        address arg1
    ) internal {
        bytes memory encodedArgs = abi.encode(
            target,
            tran_name,
            CALL_SCILLA_WITH_THE_SAME_SENDER,
            arg1
        );
        uint256 argsLength = encodedArgs.length;

        assembly {
            let ok := call(
                gas(),
                SCILLA_CALL_PRECOMPILE_ADDRESS,
                0,
                add(encodedArgs, 0x20),
                argsLength,
                0x20,
                0
            )
            if iszero(ok) {
                revert(0, 0)
            }
        }
    }

    /**
     * @dev Calls a ZRC2 contract function with two arguments
     * @param target The address of the ZRC2 contract
     * @param tran_name The name of the function to call
     * @param arg1 The first argument to the function
     * @param arg2 The second argument to the function
     */
    function callScilla(
        address target,
        string memory tran_name,
        address arg1,
        uint128 arg2
    ) internal {
        bytes memory encodedArgs = abi.encode(
            target,
            tran_name,
            CALL_SCILLA_WITH_THE_SAME_SENDER,
            arg1,
            arg2
        );
        uint256 argsLength = encodedArgs.length;

        assembly {
            let ok := call(
                gas(),
                SCILLA_CALL_PRECOMPILE_ADDRESS,
                0,
                add(encodedArgs, 0x20),
                argsLength,
                0x20,
                0
            )
            if iszero(ok) {
                revert(0, 0)
            }
        }
    }

    /**
     * @dev Calls a ZRC2 contract function with two arguments
     * @param target The address of the ZRC2 contract
     * @param tran_name The name of the function to call
     * @param arg1 The first argument to the function
     * @param arg2 The second argument to the function
     */
    function callScillaWithBadGas(
        address target,
        string memory tran_name,
        address arg1,
        uint128 arg2
    ) internal {
        bytes memory encodedArgs = abi.encode(
            target,
            tran_name,
            CALL_SCILLA_WITH_THE_SAME_SENDER,
            arg1,
            arg2
        );
        uint256 argsLength = encodedArgs.length;

        assembly {
            let ok := call(
                21000, // This should not actually be enough to call anything.
                SCILLA_CALL_PRECOMPILE_ADDRESS,
                0,
                add(encodedArgs, 0x20),
                argsLength,
                0x20,
                0
            )
            if iszero(ok) {
                revert(0, 0)
            }
        }
    }

    /**
     * @dev Calls a ZRC2 contract function with three arguments
     * @param target The address of the ZRC2 contract
     * @param tran_name The name of the function to call on the ZRC2 contract
     * @param arg1 The first argument to the function
     * @param arg2 The second argument to the function
     * @param arg3 The third argument to the function
     */
    function callScilla(
        address target,
        string memory tran_name,
        address arg1,
        address arg2,
        uint128 arg3
    ) internal {
        bytes memory encodedArgs = abi.encode(
            target,
            tran_name,
            CALL_SCILLA_WITH_THE_SAME_SENDER,
            arg1,
            arg2,
            arg3
        );
        uint256 argsLength = encodedArgs.length;

        assembly {
            let alwaysSuccessForThisPrecompile := call(
                21000,
                SCILLA_CALL_PRECOMPILE_ADDRESS,
                0,
                add(encodedArgs, 0x20),
                argsLength,
                0x20,
                0
            )
        }
    }

    /**
     * @dev Reads a 128 bit integer from a ZRC2 contract
     * @param target The address of the ZRC2 contract
     * @param variable_name The name of the variable to read from the ZRC2 contract
     * @return The value of the variable
     */
    function readUint128(
        address target,
        string memory variable_name
    ) internal view returns (uint128) {
        bytes memory encodedArgs = abi.encode(target, variable_name);
        uint256 argsLength = encodedArgs.length;
        bytes memory output = new bytes(36);

        assembly {
            let alwaysSuccessForThisPrecompile := staticcall(
                21000,
                SCILLA_STATE_READ_PRECOMPILE_ADDRESS,
                add(encodedArgs, 0x20),
                argsLength,
                add(output, 0x20),
                32
            )
        }

        return abi.decode(output, (uint128));
    }

    /**
     * @dev Reads a 32 bit integer from a ZRC2 contract
     * @param target The address of the ZRC2 contract
     * @param variable_name The name of the variable to read from the ZRC2 contract
     * @return The value of the variable
     */
    function readUint32(
        address target,
        string memory variable_name
    ) internal view returns (uint32) {
        bytes memory encodedArgs = abi.encode(target, variable_name);
        uint256 argsLength = encodedArgs.length;
        bytes memory output = new bytes(36);

        assembly {
            let alwaysSuccessForThisPrecompile := staticcall(
                21000,
                SCILLA_STATE_READ_PRECOMPILE_ADDRESS,
                add(encodedArgs, 0x20),
                argsLength,
                add(output, 0x20),
                32
            )
        }

        return abi.decode(output, (uint32));
    }

    /**
     * @dev Reads a string from a ZRC2 contract
     * @param target The address of the ZRC2 contract
     * @param variable_name The name of the variable to read from the ZRC2 contract
     * @return retVal The value of the variable
     */
    function readString(
        address target,
        string memory variable_name
    ) internal view returns (string memory retVal) {
        bytes memory encodedArgs = abi.encode(target, variable_name);
        uint256 argsLength = encodedArgs.length;
        bool success;
        bytes memory output = new bytes(128);
        uint256 output_len = output.length - 4;
        assembly {
            success := staticcall(
                21000,
                SCILLA_STATE_READ_PRECOMPILE_ADDRESS,
                add(encodedArgs, 0x20),
                argsLength,
                add(output, 0x20),
                output_len
            )
        }
        require(success);

        (retVal) = abi.decode(output, (string));
        return retVal;
    }

    /**
     * @dev Reads a 128 bit integer from a map in a ZRC2 contract
     * @param variable_name The name of the map in the ZRC2 contract
     * @param addressMapKey The key to the map
     * @return The value associated with the key in the map
     */
    function readMapUint128(
        address target,
        string memory variable_name,
        address addressMapKey
    ) internal view returns (uint128) {
        bytes memory encodedArgs = abi.encode(
            target,
            variable_name,
            addressMapKey
        );
        uint256 argsLength = encodedArgs.length;
        bytes memory output = new bytes(36);

        assembly {
            let alwaysSuccessForThisPrecompile := staticcall(
                21000,
                SCILLA_STATE_READ_PRECOMPILE_ADDRESS,
                add(encodedArgs, 0x20),
                argsLength,
                add(output, 0x20),
                32
            )
        }

        return abi.decode(output, (uint128));
    }

    /**
     * @dev Reads a 128 bit integer from a nested map in a ZRC2 contract
     * @param target The address of the ZRC2 contract
     * @param variable_name The name of the map in the ZRC2 contract
     * @param firstMapKey The first key to the map
     * @param secondMapKey The second key to the map
     * @return The value associated with the keys in the map
     */
    function readNestedMapUint128(
        address target,
        string memory variable_name,
        address firstMapKey,
        address secondMapKey
    ) internal view returns (uint128) {
        bytes memory encodedArgs = abi.encode(
            target,
            variable_name,
            firstMapKey,
            secondMapKey
        );
        uint256 argsLength = encodedArgs.length;
        bytes memory output = new bytes(36);

        assembly {
            let alwaysSuccessForThisPrecompile := staticcall(
                21000,
                SCILLA_STATE_READ_PRECOMPILE_ADDRESS,
                add(encodedArgs, 0x20),
                argsLength,
                add(output, 0x20),
                32
            )
        }

        return abi.decode(output, (uint128));
    }
}

contract ScillaInterop {
    using ScillaConnector for address;

    constructor() {}

    function readUint128(
        address scillaContract,
        string memory varName
    ) public view returns (uint128) {
        return scillaContract.readUint128(varName);
    }

    function readString(
        address scillaContract,
        string memory varName
    ) public view returns (string memory) {
        return scillaContract.readString(varName);
    }

    function readMapUint128(
        address scillaContract,
        string memory varName,
        address key
    ) public view returns (uint128) {
        return scillaContract.readMapUint128(varName, key);
    }

    function readNestedMapUint128(
        address scillaContract,
        string memory varName,
        address key1,
        address key2
    ) public view returns (uint128) {
        return scillaContract.readNestedMapUint128(varName, key1, key2);
    }

    function callScillaNoArgs(
        address scillaContract,
        string memory transitionName
    ) public {
        scillaContract.callScilla(transitionName);
    }

    function sendEtherThenCallScilla(
        address recipient,
        address scillaContract,
        string memory transitionName,
        address arg1
    ) public payable {
        (bool sent, ) = recipient.call{value: msg.value}("");
        require(sent, "failed");
        scillaContract.callScilla(transitionName, arg1);
    }

    function callScillaOneArg(
        address scillaContract,
        string memory transitionName,
        address arg1
    ) public {
        scillaContract.callScilla(transitionName, arg1);
    }

    function callScilla(
        address scillaContract,
        string memory transitionName,
        string memory varName,
        address arg1,
        uint128 arg2
    ) public returns (uint128) {
        scillaContract.callScilla(transitionName, arg1, arg2);

        return readMapUint128(scillaContract, varName, arg1);
    }

    function callScillaWithBadGas(
        address scillaContract,
        string memory transitionName,
        string memory varName,
        address arg1,
        uint128 arg2
    ) public returns (uint128) {
        scillaContract.callScillaWithBadGas(transitionName, arg1, arg2);

        return readMapUint128(scillaContract, varName, arg1);
    }

    function callScillaRevert(
        address scillaContract,
        string memory transitionName,
        address arg1,
        uint128 arg2
    ) public {
        scillaContract.callScilla(transitionName, arg1, arg2);
        revert();
    }

    function readAfterWrite(
        address scillaContract,
        string memory transitionName,
        address arg1,
        uint128 arg2,
        string memory fieldName
    ) public {
        address SOME_RANDOM_ADDRESS = 0x00000000005a494c4445504f53495450524f5859;

        // reads to SOME_RANDOM_ADDRESS should give 0 before and after the call
        uint128 beforeWriteRandAddr = readMapUint128(
            scillaContract,
            fieldName,
            SOME_RANDOM_ADDRESS
        );
        require(beforeWriteRandAddr == 0, "Value must be 0");

        // This is the key of our interest - before calling transition its value is 0
        uint128 beforeWrite = readMapUint128(scillaContract, fieldName, arg1);
        require(beforeWrite == 0, "Value must be 0");

        scillaContract.callScilla(transitionName, arg1, arg2);

        // reads to SOME_RANDOM_ADDRESS still gives 0
        uint128 afterWriteRandAddr = readMapUint128(
            scillaContract,
            fieldName,
            SOME_RANDOM_ADDRESS
        );
        require(afterWriteRandAddr == 0, "Value must be 0");

        // Transition has updated this key so it should return updated value
        uint128 afterWrite = readMapUint128(scillaContract, fieldName, arg1);
        require(afterWrite == arg2, "Value must be arg2");
    }

    function callScillaCheckChangeRevert(
        address scillaContract,
        string memory transitionName,
        address arg1,
        uint128 arg2,
        string memory fieldName
    ) public {
        scillaContract.callScilla(transitionName, arg1, arg2);
        uint128 afterWrite = readMapUint128(scillaContract, fieldName, arg1);
        require(afterWrite == arg2, "Value must be arg2");
        revert();
    }

    function readAfterWriteWithRevert(
        address scillaContract,
        string memory transitionName,
        address arg1,
        uint128 arg2,
        string memory fieldName
    ) public {
        uint128 beforeWrite = readMapUint128(scillaContract, fieldName, arg1);
        require(beforeWrite == 0, "Value must be 0");

        (bool ok, ) = address(this).call(
            abi.encodeWithSelector(
                this.callScillaCheckChangeRevert.selector,
                scillaContract,
                transitionName,
                arg1,
                arg2,
                fieldName
            )
        );

        require(!ok, "This call must fail!");

        uint128 afterWrite = readMapUint128(scillaContract, fieldName, arg1);
        require(afterWrite == 0, "Value must be 0");
    }
}
