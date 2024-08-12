echo "The CI is running this script."

# Start network early.
pwd
echo "building zilliqa and running it as a detached process"
cargo build --all-targets || exit 1
ls ./target
RUST_BACKTRACE=1 RUST_LOG=zilliqa=trace,jsonrpsee=trace,revm=trace ./target/debug/zilliqa 65d7f4da9bedc8fb79cbf6722342960bbdfb9759bc0d9e3fb4989e831ccbc227 -c config-single-node.toml > logs 2>&1 &
cd evm_scilla_js_tests

# Need to fund scilla addresses which are distinct from zilliqa, or they will fail due to out of funds
echo "Funding tests"
npx hardhat run scripts/FundAccountsFromEth.ts

echo "Running tests"

# Run tests
npx hardhat test --grep 'ERC20 Is ZRC2'

retVal=$?
pkill -INT zilliqa
