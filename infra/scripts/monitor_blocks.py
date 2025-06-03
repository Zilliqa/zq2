import requests
import time
from datetime import datetime, timezone
import sys

RPC_URL = sys.argv[1] if len(sys.argv) > 1 else "http://34.87.110.41:4201"
HEADERS = {"Content-Type": "application/json"}
LOG_FILE = "block_times_devnet.log"
MAX_RETRIES = 5
RETRY_DELAY = 5  # seconds

def get_latest_block_number():
    payload = {
        "method": "eth_blockNumber",
        "params": [],
        "id": 1,
        "jsonrpc": "2.0"
    }
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = requests.post(RPC_URL, headers=HEADERS, json=payload, timeout=10)
            response.raise_for_status()
            result = response.json().get("result")
            if result:
                return int(result, 16)
        except Exception as e:
            time.sleep(RETRY_DELAY)
    return None

def get_block_by_number(block_num_hex):
    payload = {
        "method": "eth_getBlockByNumber",
        "params": [block_num_hex, False],
        "id": 1,
        "jsonrpc": "2.0"
    }
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = requests.post(RPC_URL, headers=HEADERS, json=payload, timeout=10)
            response.raise_for_status()
            result = response.json().get("result")
            if result:
                return result
        except Exception as e:
            time.sleep(RETRY_DELAY)
    return None

def log_line(line):
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def main():
    while True:
        current_block = get_latest_block_number()
        if current_block is not None:
            break

    header = (
        f"{'Block':<12} | {'View':<12} | {'Time':<25} | {'TXs':<5} | "
        f"{'Gas Used / Limit (%)':<35} | Time diff"
    )
    log_line(header)
    log_line("-" * len(header))

    previous_time = None

    while True:
        block_hex = hex(current_block)
        result = get_block_by_number(block_hex)

        if not result:
            time.sleep(1)
            continue

        timestamp = int(result.get("timestamp", "0x0"), 16)
        readable_time = datetime.fromtimestamp(timestamp, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        transactions = result.get("transactions", [])
        tx_count = len(transactions)

        gas_used = int(result.get("gasUsed") or "0x0", 16)
        gas_limit = int(result.get("gasLimit") or "0x0", 16)
        gas_percent = (gas_used / gas_limit * 100) if gas_limit > 0 else 0.0

        view_number = int(result.get("view", "0x0"), 16)
        gas_info = f"{gas_used:<10} / {gas_limit:<10} ({gas_percent:>6.2f}%)"

        line = (
            f"{current_block:<12} | {view_number:<12} | {readable_time:<25} | "
            f"{tx_count:<5} | {gas_info:<35}"
        )

        if previous_time is not None:
            diff = timestamp - previous_time
            line += f" | {diff} sec"
        else:
            line += " |"

        log_line(line)

        previous_time = timestamp
        current_block += 1

if __name__ == "__main__":
    main()
