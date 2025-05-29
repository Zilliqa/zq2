const { ethers } = require("ethers");
const fs = require("fs");
const path = require("path");

// Save original methods
const originalLog = console.log;
const originalError = console.error;

// Create logs directory if not exists
const logDir = "./logs";
if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir);
}

// Create a unique log file
const logFile = path.join(logDir, `tx-batch-log-${new Date().toISOString().replace(/[:.]/g, "-")}.log`);
const logStream = fs.createWriteStream(logFile, { flags: "a" });

// Dual logger functions
function dualLog(...args) {
    const line = args.map(a => (typeof a === "string" ? a : JSON.stringify(a))).join(" ");
    logStream.write(line + "\n");
    originalLog(...args); // use saved original log
}
function dualError(...args) {
    const line = args.map(a => (typeof a === "string" ? a : JSON.stringify(a))).join(" ");
    logStream.write(line + "\n");
    originalError(...args); // use saved original error
}

// Override
console.log = dualLog;
console.error = dualError;

const TOTAL_TXS = 1000;
const ACCOUNT_COUNT = 100;
const SEND_AMOUNT = "0.001"; // In ZIL
const RPC_URL = "https://api.zq2-devnet.zilliqa.com";
const SENDER_PRIVATE_KEY = "<private-key>";
const INTERVAL_MS = 100;
const MAX_RETRIES = 3;

const provider = new ethers.JsonRpcProvider(RPC_URL);
const senderWallet = new ethers.Wallet(SENDER_PRIVATE_KEY, provider);

// Generate recipient addresses
const recipients = Array.from({ length: ACCOUNT_COUNT }, () => ethers.Wallet.createRandom());
console.log("✅ Generated recipient addresses:");
recipients.forEach((r, i) => console.log(`[${i + 1}] ${r.address}`));

let currentNonce = null;

async function delay(ms) {
    return new Promise((res) => setTimeout(res, ms));
}

async function sendTxWithRetry(tx, retries = MAX_RETRIES) {
    for (let attempt = 1; attempt <= retries; attempt++) {
        try {
            const txResp = await senderWallet.sendTransaction(tx);
            console.log(`✅ Tx (nonce: ${tx.nonce}) => ${txResp.hash}`);
            return txResp;
        } catch (err) {
            const msg = err.message?.toLowerCase() || "";
            const code = err.code || "";

            console.error(`❌ Tx (nonce: ${tx.nonce}) failed (Attempt ${attempt}/${retries}): ${err.message}`);

            if (msg.includes("nonce too low") || code === "NONCE_EXPIRED") {
                const latestNonce = await provider.getTransactionCount(senderWallet.address, "latest");
                console.warn(`⚠️ Nonce too low. Updating currentNonce to ${latestNonce}`);
                currentNonce = latestNonce;
                return null;
            }

            if (
                code === "SERVER_ERROR" ||
                code === "NETWORK_ERROR" ||
                msg.includes("503") ||
                msg.includes("unavailable")
            ) {
                const backoff = Math.min(2 ** (attempt - 1), 16) * 1000;
                console.log(`🌐 Network error. Retrying in ${backoff}ms...`);
                await delay(backoff);
                continue;
            }

            if (attempt < retries) {
                await delay(3000);
            } else {
                throw err;
            }
        }
    }

    return null;
}

async function runTransferBatch() {
    const start = Date.now();

    if (currentNonce === null) {
        throw new Error("❌ currentNonce is not initialized.");
    }

    console.log(`🚀 Sending ${TOTAL_TXS} txs in parallel starting at nonce ${currentNonce}`);

    const txPromises = Array.from({ length: TOTAL_TXS }, async (_, i) => {
        const recipient = recipients[i % ACCOUNT_COUNT].address;
        const nonce = currentNonce + i;

        const tx = {
            to: recipient,
            value: ethers.parseEther(SEND_AMOUNT),
            gasLimit: 21000,
            nonce,
        };

        try {
            const result = await sendTxWithRetry(tx);
            return result ? nonce : null;
        } catch (e) {
            console.error(`🛑 Tx permanently failed (nonce: ${nonce}): ${e.message}`);
            return null;
        }
    });

    const results = await Promise.all(txPromises);
    const successCount = results.filter(nonce => nonce !== null).length;

    currentNonce += successCount;

    const totalTime = ((Date.now() - start) / 1000).toFixed(2);
    console.log(`🎉 Batch complete in ${totalTime} sec. ✅ ${successCount}/${TOTAL_TXS} succeeded`);

    const balance = await provider.getBalance(senderWallet.address);
    console.log(`💰 Balance: ${ethers.formatEther(balance)} ZIL`);
}

async function loopIndefinitely() {
    currentNonce = await provider.getTransactionCount(senderWallet.address, "latest");
    console.log(`🔢 Starting with nonce: ${currentNonce}`);

    while (true) {
        console.log(`\n🕓 Starting batch at ${new Date().toLocaleTimeString()}`);
        try {
            await runTransferBatch();
        } catch (e) {
            console.error("🚨 Batch failed with error:", e.message);
        }

        console.log(`🕒 Waiting ${INTERVAL_MS / 1000} sec before next batch...\n`);
        await delay(INTERVAL_MS);
    }
}

loopIndefinitely().catch(console.error);
