cd evm_js_tests
echo $PATH
echo "now we run the test..."

#npm install
DEBUG=true MOCHA_TIMEOUT=400000 npx hardhat test --grep "should return a send raw transaction" --bail --network zq2

retVal=$?

ps -e | grep zil
pkill -INT zilliqa
cat npx.out
if [ $retVal -ne 0 ]; then
    echo "!!!!!! Error with JS integration test !!!!!!"
    exit 1
fi

echo "Success with integration test"

echo "Zil logs:"
cat zil_log_out.txt

exit 0
