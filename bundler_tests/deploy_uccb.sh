#!/bin/bash
export PRIVATE_KEY=65d7f4da9bedc8fb79cbf6722342960bbdfb9759bc0d9e3fb4989e831ccbc227

ADDRESS=$(cast wallet address $PRIVATE_KEY)
echo "WALLET: ${ADDRESS}"

INIT_DATA=$(cast calldata "initialize(address)" 0x99f7f7c00526426b8dca99302e96d85a0e5fd400)

GW_IMPL=$(forge create --optimize --optimizer-runs 200 \
    --private-key $PRIVATE_KEY \
    --broadcast ./zilliqa/src/contracts/uccb/UccbGateway.sol:UccbGateway \
    | grep "Deployed to:" | awk '{print $3}')
GW_PROXY=$(forge create --optimize --optimizer-runs 200 \
    --private-key $PRIVATE_KEY \
    --broadcast \
    vendor/openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol:ERC1967Proxy \
    --constructor-args $GW_IMPL $INIT_DATA \
    | grep "Deployed to:" | awk '{print $3}')
echo "GATEWAY: ${GW_PROXY}"

SA_IMPL=$(forge create --optimize --optimizer-runs 200 \
    --private-key $PRIVATE_KEY \
    --broadcast ./zilliqa/src/contracts/uccb/UccbSender.sol:UccbSender \
    | grep "Deployed to:" | awk '{print $3}')
SA_PROXY=$(forge create --optimize --optimizer-runs 200 \
    --private-key $PRIVATE_KEY \
    --broadcast \
    vendor/openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol:ERC1967Proxy \
    --constructor-args $SA_IMPL $INIT_DATA \
    | grep "Deployed to:" | awk '{print $3}')
echo "SENDER: ${SA_PROXY}"

PM_IMPL=$(forge create --optimize --optimizer-runs 200 \
    --private-key $PRIVATE_KEY \
    --broadcast ./zilliqa/src/contracts/uccb/UccbPaymaster.sol:UccbPaymaster \
    | grep "Deployed to:" | awk '{print $3}')
PM_PROXY=$(forge create --optimize --optimizer-runs 200 \
    --private-key $PRIVATE_KEY \
    --broadcast \
    vendor/openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol:ERC1967Proxy \
    --constructor-args $PM_IMPL $INIT_DATA \
    | grep "Deployed to:" | awk '{print $3}')
echo "PAYMASTER: ${PM_PROXY}"

# allowed originator/recipient
cast send $GW_PROXY "grantRole(bytes32,address)" 0x6648225b86b157a7976fcdfdf25f480eecb7817c1c7ad2e2d38c803e0c05680b $ADDRESS --private-key $PRIVATE_KEY
cast send $GW_PROXY "grantRole(bytes32,address)" 0x4395ac258ce87896ffc4b11b82c2c2465de0edf678b075f467682e243bd03abb $ADDRESS --private-key $PRIVATE_KEY
cast send $GW_PROXY "setLink(address,bytes)" $SA_PROXY 0x0001000002053914f7c337A02CCf847356783Ab47cAF431D3a1E4e44 --private-key $PRIVATE_KEY

# stake/deposit paymaster
cast send $PM_PROXY "depositTo()" --value 100ether --private-key $PRIVATE_KEY
cast send $PM_PROXY "addStake(uint32)" 86400 --value 100ether --private-key $PRIVATE_KEY
cast send $PM_PROXY "grantRole(bytes32,address)" 0x66dd01afc7631f150b0e4dbf32dd8403aa9ffd64d59c794f655987d143eb5bf2 $SA_PROXY --private-key $PRIVATE_KEY

# set fees and accounts for tests
cast send $GW_PROXY "setFees(uint64,uint128[6])" 1337 [0x100000,0x110000,0x120000,0x130000,0x140000,0x150000] --private-key $PRIVATE_KEY
cast send $GW_PROXY "grantRole(bytes32,address)" 0x6648225b86b157a7976fcdfdf25f480eecb7817c1c7ad2e2d38c803e0c05680b 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 --private-key $PRIVATE_KEY
cast send $GW_PROXY "grantRole(bytes32,address)" 0x4395ac258ce87896ffc4b11b82c2c2465de0edf678b075f467682e243bd03abb 0xe8dcAcED8cC42b9a8517f2c6EB156d8140A46CA6 --private-key $PRIVATE_KEY

# set signer(s)
#cast send $SA_PROXY "setSigners(bytes[],uint64[],uint64,uint48)" "[0xb27aebb3b54effd7af87c4a064a711554ee0f3f5abf56ca910b46422f2b21603bc383d42eb3b927c4c3b0b8381ca30a3]" "[100]" 50 1 --private-key $PRIVATE_KEY
cast send $SA_PROXY "setSigners(bytes[],uint64[],uint64,uint48)" "[0x127aebb3b54effd7af87c4a064a711554ee0f3f5abf56ca910b46422f2b21603bc383d42eb3b927c4c3b0b8381ca30a30e861c6ad56556f0fde034ad20a88b832c1cc2a4152af40704571f992df8627ead0e314cf142322cafa85c868c567362]" "[100]" 50 1 --private-key $PRIVATE_KEY

# send TestCounter.count()
cast send $GW_PROXY "sendMessage(bytes,bytes,bytes[])" 0001000002053914e8dcAcED8cC42b9a8517f2c6EB156d8140A46CA6 0x06661abd "[]" --private-key $PRIVATE_KEY

