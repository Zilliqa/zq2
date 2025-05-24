const { ethers } = require("ethers");

const TOTAL_TXS = 1000;
const ACCOUNT_COUNT = TOTAL_TXS / 10; // more diversity
const RPC_URL = "https://api.zq2-devnet.zilliqa.com/";
const SENDER_PRIVATE_KEY = "<PRIVATE_KEY>";
const SEND_AMOUNT = "0.001"; // ZIL in ETH units

const provider = new ethers.JsonRpcProvider(RPC_URL);
const senderWallet = new ethers.Wallet(SENDER_PRIVATE_KEY, provider);

// Generate recipients
const recipients = Array.from({ length: ACCOUNT_COUNT }, () => ethers.Wallet.createRandom());
console.log("✅ Generated recipient addresses:");
recipients.forEach((r, i) => console.log(`[${i + 1}] ${r.address}`));

async function sendAllInParallel() {
    console.log(`🚀 Starting ${TOTAL_TXS} ZIL transfers at ${new Date().toLocaleTimeString()}`);
    const start = Date.now();

    const baseNonce = await provider.getTransactionCount(senderWallet.address, "latest");

    const txPromises = Array.from({ length: TOTAL_TXS }, (_, i) => {
        const recipient = recipients[i % ACCOUNT_COUNT].address;
        const tx = {
            to: recipient,
            value: ethers.parseEther(SEND_AMOUNT),
            gasLimit: 21000,
            nonce: baseNonce + i,
        };

        return senderWallet.sendTransaction(tx)
            .then((txResp) => {
                console.log(`✅ Tx ${i + 1}: ${txResp.hash}`);
            })
            .catch((err) => {
                console.error(`❌ Tx ${i + 1} failed: ${err.message}`);
            });
    });

    await Promise.all(txPromises);

    const totalTime = ((Date.now() - start) / 1000).toFixed(2);
    console.log(`🎉 Finished sending ${TOTAL_TXS} txs in ${totalTime} seconds`);
}

sendAllInParallel().catch(console.error);
