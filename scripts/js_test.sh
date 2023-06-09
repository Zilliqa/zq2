export PATH="/scilla/0/bin:$PATH" 
cd evm_js_tests
echo $PATH
echo "now we run the test..."

#npm install
DEBUG=true MOCHA_TIMEOUT=400000 npx hardhat test --grep "should return a send raw transaction" --bail --network zq2

retVal=$?

pkill -INT zilliqa
cat npx.out
if [ $retVal -ne 0 ]; then
    echo "!!!!!! Error with JS integration test !!!!!!"
    exit 1
fi

echo "Success with integration test"
exit 0
