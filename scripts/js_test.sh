cd evm_js_tests
echo $PATH
echo "now we run the test..."

npm install -g solc
DEBUG=true MOCHA_TIMEOUT=400000 npx hardhat test

retVal=$?

pkill -INT zilliqa
cat npx.out
if [ $retVal -ne 0 ]; then
    echo "!!!!!! Error with JS integration test !!!!!!"
    exit 1
fi

echo "Success with integration test"
exit 0
