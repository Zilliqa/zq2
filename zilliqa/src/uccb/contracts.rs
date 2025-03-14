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
