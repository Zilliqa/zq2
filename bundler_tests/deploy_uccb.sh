#!/bin/bash
export PRIVATE_KEY=65d7f4da9bedc8fb79cbf6722342960bbdfb9759bc0d9e3fb4989e831ccbc227

ADDRESS=$(cast wallet address $PRIVATE_KEY)
echo "WALLET: ${ADDRESS}"

INIT_DATA=$(cast calldata "initialize(address)" 0x99f7f7c00526426b8dca99302e96d85a0e5fd400)

GW_IMPL=$(forge create \
    --private-key $PRIVATE_KEY \
    --broadcast ./zilliqa/src/contracts/uccb/UccbGateway.sol:UccbGateway \
    | grep "Deployed to:" | awk '{print $3}')
GW_PROXY=$(forge create \
    --private-key $PRIVATE_KEY \
    --broadcast \
    vendor/openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol:ERC1967Proxy \
    --constructor-args $GW_IMPL $INIT_DATA \
    | grep "Deployed to:" | awk '{print $3}')
echo "GATEWAY: ${GW_PROXY}"

PM_IMPL=$(forge create \
    --private-key $PRIVATE_KEY \
    --broadcast ./zilliqa/src/contracts/uccb/UccbPaymaster.sol:UccbPaymaster \
    | grep "Deployed to:" | awk '{print $3}')
PM_PROXY=$(forge create \
    --private-key $PRIVATE_KEY \
    --broadcast \
    vendor/openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol:ERC1967Proxy \
    --constructor-args $PM_IMPL $INIT_DATA \
    | grep "Deployed to:" | awk '{print $3}')
echo "PAYMASTER: ${PM_PROXY}"

SA_IMPL=$(forge create \
    --private-key $PRIVATE_KEY \
    --broadcast ./zilliqa/src/contracts/uccb/UccbSender.sol:UccbSender \
    | grep "Deployed to:" | awk '{print $3}')
SA_PROXY=$(forge create \
    --private-key $PRIVATE_KEY \
    --broadcast \
    vendor/openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol:ERC1967Proxy \
    --constructor-args $SA_IMPL $INIT_DATA \
    | grep "Deployed to:" | awk '{print $3}')
echo "SENDER: ${SA_PROXY}"

# allowed originator/recipient
cast call $GW_PROXY "grantRole(bytes32,address)" 0x52e6646e3be1960bfe4f1c00df28cf16fd83c4e9ee6d7d19ebb8a8e86c95f896 $ADDRESS --private-key $PRIVATE_KEY
cast call $GW_PROXY "grantRole(bytes32,address)" 0xc27fd8deb42354a47807f8ee91a3803da8fe8355b244b1f33deb7be4fa77d3e7 $ADDRESS --private-key $PRIVATE_KEY
cast call $GW_PROXY "setLink(address,bytes,bool)" $SA_PROXY 0x0001000002053914f7c337A02CCf847356783Ab47cAF431D3a1E4e44 false --private-key $PRIVATE_KEY

# stake/deposit paymaster
cast send $PM_PROXY "depositTo()" --value 1ether --private-key $PRIVATE_KEY
cast send $PM_PROXY "addStake(uint32)" 86400 --value 1ether --private-key $PRIVATE_KEY
# register sponsored sender
cast call $PM_PROXY "grantRole(bytes32,address)" 0x66dd01afc7631f150b0e4dbf32dd8403aa9ffd64d59c794f655987d143eb5bf2 $SA_PROXY --private-key $PRIVATE_KEY
