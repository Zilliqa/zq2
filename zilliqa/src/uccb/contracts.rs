use alloy::sol;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    IVALIDATOR_MANAGER,
    "src/uccb/abi/IValidatorManager.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    IRELAYER_EVENTS,
    "src/uccb/abi/IRelayerEvents.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    IDISPATCHER_EVENTS,
    "src/uccb/abi/IChainDispatcherEvents.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    ICHAINDISPATCHER,
    "src/uccb/abi/IChainDispatcher.json"
);

sol! {
    function SignRelayFunction(uint256 sourceChainId, uint256 targetChainId, address target, bytes calldata bytes, uint256 gasLimit, uint256 nonce);
    function SignDispatchFunction(uint256 messageType, uint256 sourceChainId, uint256 targetChainId, address target, bool success, bytes calldata response, uint256 nonce);
}
