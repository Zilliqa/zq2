import subprocess
import time

# Path to your Node.js script
node_script = "evm-payment-transfer_parallel_1000_infratest.js"
SLEEPING_TIME = 10

while True:
    try:
        print("Running Node.js script...")
        subprocess.run(["node", node_script], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Script failed with return code {e.returncode}")
    except Exception as e:
        print(f"Unexpected error: {e}")
    
    # Wait for 5 seconds before running again
    print(f"Waiting {SLEEPING_TIME} seconds before next run...")
    time.sleep(SLEEPING_TIME)
