#cd evm_js_tests
#echo $PATH
#echo "now we run the test..."
#
#curl -X POST http://localhost:4201 -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":"1","method":"eth_getBalance", "params": ["0x6f1ec4ca9228ea36a14f0e4e336e71a1851d679b", "latest"]}'
#ps -e | grep zil
#
#
##npm install
#DEBUG=true MOCHA_TIMEOUT=400000 npx hardhat test --grep "should return a send raw transaction" --bail --network zq2
#
#retVal=$?
#
#pkill -INT zilliqa
#cat npx.out
#if [ $retVal -ne 0 ]; then
#    echo "!!!!!! Error with JS integration test !!!!!!"
#    exit 1
#fi
#
#echo "Success with integration test"
#exit 0
