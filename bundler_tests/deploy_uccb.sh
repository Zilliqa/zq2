#!/bin/bash
export PRIVATE_KEY=65d7f4da9bedc8fb79cbf6722342960bbdfb9759bc0d9e3fb4989e831ccbc227

CHAIN_ID=$(cast chain-id)
ADDRESS=$(cast wallet address $PRIVATE_KEY)

# CREATE2 address https://github.com/Arachnid/deterministic-deployment-proxy
DEPLOYER=0x4e59b44847b379578588920ca78fbf26c0b4956c
INIT_DATA=$(cast calldata "initialize(address)" $ADDRESS)
SALT=$(cast keccak "ZILLIQA_UCCB_CONTRACTS_2026.07")

# DEPLOY CONTRACTS
BYTECODE=$(cast concat-hex $(forge inspect --optimize --optimizer-runs 200 ./zilliqa/src/contracts/uccb/UccbSender.sol bytecode) $(cast abi-encode "constructor()"))
cast send $DEPLOYER ${SALT}${BYTECODE#0x} --private-key $PRIVATE_KEY
SA_IMPL=$(cast create2 --deployer $DEPLOYER --salt $SALT --init-code $BYTECODE)

BYTECODE=$(cast concat-hex $(forge inspect vendor/openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol bytecode) $(cast abi-encode "constructor(address,bytes)" $SA_IMPL $INIT_DATA))
cast send $DEPLOYER "${SALT}${BYTECODE#0x}" --private-key $PRIVATE_KEY
SA_PROXY=$(cast create2 --deployer $DEPLOYER --salt $SALT --init-code $BYTECODE)

BYTECODE=$(cast concat-hex $(forge inspect --optimize --optimizer-runs 200 ./zilliqa/src/contracts/uccb/UccbPaymaster.sol bytecode) $(cast abi-encode "constructor()"))
cast send $DEPLOYER "${SALT}${BYTECODE#0x}" --private-key $PRIVATE_KEY
PM_IMPL=$(cast create2 --deployer $DEPLOYER --salt $SALT --init-code $BYTECODE)

BYTECODE=$(cast concat-hex $(forge inspect vendor/openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol bytecode) $(cast abi-encode "constructor(address,bytes)" $PM_IMPL $INIT_DATA))
cast send $DEPLOYER "${SALT}${BYTECODE#0x}" --private-key $PRIVATE_KEY
PM_PROXY=$(cast create2 --deployer $DEPLOYER --salt $SALT --init-code $BYTECODE)

BYTECODE=$(cast concat-hex $(forge inspect --optimize --optimizer-runs 200 ./zilliqa/src/contracts/uccb/UccbGateway.sol bytecode) $(cast abi-encode "constructor()"))
cast send $DEPLOYER "${SALT}${BYTECODE#0x}" --private-key $PRIVATE_KEY
GW_IMPL=$(cast create2 --deployer $DEPLOYER --salt $SALT --init-code $BYTECODE)

BYTECODE=$(cast concat-hex $(forge inspect vendor/openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol bytecode) $(cast abi-encode "constructor(address,bytes)" $GW_IMPL $INIT_DATA))
cast send $DEPLOYER "${SALT}${BYTECODE#0x}" --private-key $PRIVATE_KEY
GW_PROXY=$(cast create2 --deployer $DEPLOYER --salt $SALT --init-code $BYTECODE)

# GW_IMPL=$(forge create --optimize --optimizer-runs 200 \
#     --private-key $PRIVATE_KEY \
#     --broadcast ./zilliqa/src/contracts/uccb/UccbGateway.sol:UccbGateway \
#     | grep "Deployed to:" | awk '{print $3}')

# SA_IMPL=$(forge create --optimize --optimizer-runs 200 \
#     --private-key $PRIVATE_KEY \
#     --broadcast ./zilliqa/src/contracts/uccb/UccbSender.sol:UccbSender \
#     | grep "Deployed to:" | awk '{print $3}')

# PM_IMPL=$(forge create --optimize --optimizer-runs 200 \
#     --private-key $PRIVATE_KEY \
#     --broadcast ./zilliqa/src/contracts/uccb/UccbPaymaster.sol:UccbPaymaster \
#     | grep "Deployed to:" | awk '{print $3}')

# GW_PROXY=$(forge create --optimize --optimizer-runs 200 \
#     --private-key $PRIVATE_KEY \
#     --broadcast \
#     vendor/openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol:ERC1967Proxy \
#     --constructor-args $GW_IMPL $INIT_DATA \
#     | grep "Deployed to:" | awk '{print $3}')

# SA_PROXY=$(forge create --optimize --optimizer-runs 200 \
#     --private-key $PRIVATE_KEY \
#     --broadcast \
#     vendor/openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol:ERC1967Proxy \
#     --constructor-args $SA_IMPL $INIT_DATA \
#     | grep "Deployed to:" | awk '{print $3}')
# echo "SENDER: ${SA_PROXY}"

# PM_PROXY=$(forge create --optimize --optimizer-runs 200 \
#     --private-key $PRIVATE_KEY \
#     --broadcast \
#     vendor/openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol:ERC1967Proxy \
#     --constructor-args $PM_IMPL $INIT_DATA \
#     | grep "Deployed to:" | awk '{print $3}')
# echo "PAYMASTER: ${PM_PROXY}"

ORIGINATING_CONTRACT=$(cast keccak256 "ORIGINATING_CONTRACT")
RECEIVING_CONTRACT=$(cast keccak256 "RECEIVING_CONTRACT")
SPONSORED_CONTRACT=$(cast keccak256 "SPONSORED_CONTRACT")

# allowed originator/recipient
cast send $GW_PROXY "grantRole(bytes32,address)" $ORIGINATING_CONTRACT $ADDRESS --private-key $PRIVATE_KEY
cast send $GW_PROXY "grantRole(bytes32,address)" $RECEIVING_CONTRACT $ADDRESS --private-key $PRIVATE_KEY
cast send $GW_PROXY "setLink(address,bytes)" $SA_PROXY $(cast concat-hex "0x000100000282BC14" $GW_PROXY) --private-key $PRIVATE_KEY
cast send $GW_PROXY "setLink(address,bytes)" $SA_PROXY $(cast concat-hex "0x0001000002053914" $GW_PROXY) --private-key $PRIVATE_KEY

# stake/deposit paymaster
cast send $PM_PROXY "depositTo()" --value 100ether --private-key $PRIVATE_KEY
cast send $PM_PROXY "addStake(uint32)" 86400 --value 10ether --private-key $PRIVATE_KEY
cast send $PM_PROXY "grantRole(bytes32,address)" $SPONSORED_CONTRACT $SA_PROXY --private-key $PRIVATE_KEY

# stake/deposit sender
cast send $SA_PROXY "depositTo()" --value 100ether --private-key $PRIVATE_KEY
cast send $SA_PROXY "addStake(uint32)" 86400 --value 10ether --private-key $PRIVATE_KEY

# set fees and accounts for tests
cast send $GW_PROXY "setFees(uint64,uint128[6])" $CHAIN_ID [0x100000,0x110000,0x120000,0x130000,0x140000,0x150000] --private-key $PRIVATE_KEY
cast send $GW_PROXY "grantRole(bytes32,address)" $ORIGINATING_CONTRACT 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 --private-key $PRIVATE_KEY
cast send $GW_PROXY "grantRole(bytes32,address)" $RECEIVING_CONTRACT 0xa46cc63eBF4Bd77888AA327837d20b23A63a56B5 --private-key $PRIVATE_KEY

# set signer(s)
# 0x127aebb3b54effd7af87c4a064a711554ee0f3f5abf56ca910b46422f2b21603bc383d42eb3b927c4c3b0b8381ca30a30e861c6ad56556f0fde034ad20a88b832c1cc2a4152af40704571f992df8627ead0e314cf142322cafa85c868c567362
# 0x137fd66aef29ca78a82d519a284789d59c2bb3880698b461c6c732d094534707d50e345128db372a1e0a4c5d5c42f49c123fc5444cc831c3e5e2dff11f5c16ab14d1b0d44eaac8414fd11a77a33f82d516201ece987081c706edcbef3c8d84d5
# 0x0b035d6cd3321c3b57d14ea09a4f3860899542d2187b5ec87649b1f40980418a096717a671cf62b73880afac252fc5dc151e9399c462f63a6ed5bd54dbc8d2d16bc1759344a289df21435dd708800417cdf6e3a5469ae67bc8182854f1d1e454
# 0x185e3a4d367cbfc966d48710806612cc00f6bfd06aa759340cfe13c3990d26a7ddde63f64468cdba5b2ff132a4639a7f0781dd74cacbf215ee1bef0575a839f4dc584b27829052aa65ff7a5a58818fc5d2cbf82cc7f00c876560e6c6b354f0bb
cast send $SA_PROXY "setSigners(bytes[],uint128[],uint128,uint48)" "[0x127aebb3b54effd7af87c4a064a711554ee0f3f5abf56ca910b46422f2b21603bc383d42eb3b927c4c3b0b8381ca30a30e861c6ad56556f0fde034ad20a88b832c1cc2a4152af40704571f992df8627ead0e314cf142322cafa85c868c567362,0x137fd66aef29ca78a82d519a284789d59c2bb3880698b461c6c732d094534707d50e345128db372a1e0a4c5d5c42f49c123fc5444cc831c3e5e2dff11f5c16ab14d1b0d44eaac8414fd11a77a33f82d516201ece987081c706edcbef3c8d84d5,0x0b035d6cd3321c3b57d14ea09a4f3860899542d2187b5ec87649b1f40980418a096717a671cf62b73880afac252fc5dc151e9399c462f63a6ed5bd54dbc8d2d16bc1759344a289df21435dd708800417cdf6e3a5469ae67bc8182854f1d1e454,0x185e3a4d367cbfc966d48710806612cc00f6bfd06aa759340cfe13c3990d26a7ddde63f64468cdba5b2ff132a4639a7f0781dd74cacbf215ee1bef0575a839f4dc584b27829052aa65ff7a5a58818fc5d2cbf82cc7f00c876560e6c6b354f0bb]" "[10000000000000000000000000,10000000000000000000000000,10000000000000000000000000,10000000000000000000000000]" 9000000000000000000000000 1 --private-key $PRIVATE_KEY

echo "CHAIN: ${CHAIN_ID}"
echo "WALLET: ${ADDRESS}"
echo "SENDER: ${SA_PROXY} @ ${SA_IMPL}"
echo "PAYMASTER: ${PM_PROXY} @ ${PM_IMPL}"
echo "GATEWAY: ${GW_PROXY} @ ${GW_IMPL}"

# send Simple7702Account.entrypoint()
#cast send $GW_PROXY "sendMessage(bytes,bytes,bytes[])" 000100000282bc14a46cc63eBF4Bd77888AA327837d20b23A63a56B5 0xb0d691fe "[]" --private-key $PRIVATE_KEY
#cast send $GW_PROXY "sendMessage(bytes,bytes,bytes[])" 0001000002053914a46cc63eBF4Bd77888AA327837d20b23A63a56B5 0xb0d691fe "[]" --private-key $PRIVATE_KEY
