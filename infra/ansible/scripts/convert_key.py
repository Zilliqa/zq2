#!/usr/bin/env python3  
  
import json  
import argparse  
import sys  
import subprocess  
import os  
from typing import Dict, Any  

def parse_args():
    """Main function that accepts command-line arguments for key conversion."""  
    parser = argparse.ArgumentParser(  
        description="Python wrapper for ZQ2 convert-key Rust binary",  
        formatter_class=argparse.RawDescriptionHelpFormatter,  
        epilog="""  
Examples:  
  python3 convert_key.py -k 2774b68a7706cc2a72f7ab02a7b59b97301ee93a4ef3ca2f89d91ea6a6254601 -c 33103  
  python3 convert_key.py --private-key 2774b68a7706cc2a72f7ab02a7b59b97301ee93a4ef3ca2f89d91ea6a6254601 --chain-id 33103  
        """  
    )  
      
    parser.add_argument(  
        '-k', '--private-key',  
        required=True,  
        help='Private key as hex string (64 characters, no 0x prefix)'  
    )  
      
    parser.add_argument(  
        '-c', '--chain-id',  
        type=int,  
        required=True,  
        help='Chain ID (e.g., 33103 for zq2-testnet)'  
    )  
      
    parser.add_argument(  
        '--control-address',  
        help='Optional control address (if not provided, will be derived from private key)'  
    )  
      
    return parser.parse_args()
  
def convert_key_rust(secret_key_hex: str, chain_id: int, control_address: str = None) -> Dict[str, Any]:  
    """  
    Call the Rust convert-key binary and return the parsed JSON result.  
    """  
    # Prepare the input JSON  
    input_data = {  
        "secret_key": secret_key_hex,  
        "chain_id": chain_id  
    }  
      
    if control_address:  
        input_data["control_address"] = control_address  
      
    input_json = json.dumps(input_data)
      
    try:  
        # Run the Rust convert-key binary  
        result = subprocess.run(  
            ["cargo", "run", "--bin", "convert-key"],  
            input=input_json,  
            text=True,  
            capture_output=True,  
            check=True,  
            cwd=os.path.dirname(os.path.abspath(__file__)) + "/../../../"  # Adjust path to repo root  
        )  
          
        # Parse the JSON output  
        return json.loads(result.stdout.strip())  
          
    except subprocess.CalledProcessError as e:  
        raise RuntimeError(f"convert-key binary failed: {e.stderr}")  
    except json.JSONDecodeError as e:  
        raise RuntimeError(f"Failed to parse convert-key output: {e}")  
    except FileNotFoundError:  
        raise RuntimeError("cargo command not found. Make sure Rust and Cargo are installed.")  
  
if __name__ == "__main__":  
    args = parse_args()
    try:  
        # Validate private key format  
        if len(args.private_key) != 64:  
            raise ValueError("Private key must be exactly 64 hex characters")  
          
        # Test if it's valid hex  
        bytes.fromhex(args.private_key)  
          
        # Call the Rust convert-key binary  
        result = convert_key_rust(args.private_key, args.chain_id, args.control_address)  
          
        # Output the result as formatted JSON  
        print(json.dumps(result, indent=2))  
          
    except ValueError as e:  
        if "non-hexadecimal" in str(e):  
            print("Error: Private key contains invalid hex characters", file=sys.stderr)  
        else:  
            print(f"Error: {e}", file=sys.stderr)  
        sys.exit(1)  
    except Exception as e:  
        print(f"Error: {e}", file=sys.stderr)  
        sys.exit(1)  
