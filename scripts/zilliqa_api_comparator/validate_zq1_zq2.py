import os
import time
import sys
import requests
import json
import subprocess
from tabulate import tabulate
from colorama import init, Fore, Style
from deepdiff import DeepDiff
import hashlib

init(autoreset=True)

LOGS_DIR = "logs"
os.makedirs(LOGS_DIR, exist_ok=True)

def make_api_call(url, headers, method, params, output_file, json_output_file):
    start_time = time.time()
    data = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1
    }

    try:
        response = requests.post(url, headers=headers, json=data)
        response_time = time.time() - start_time

        # Save to logs directory
        output_file = os.path.join(LOGS_DIR, output_file)
        json_output_file = os.path.join(LOGS_DIR, json_output_file)

        with open(output_file, 'w') as f:
            f.write(f"Response Time: {response_time:.4f} seconds\n")
            f.write("Response:\n")
            f.write(response.text)

        with open(json_output_file, 'w') as f:
            f.write(response.text)

        return response_time, response.text
    except Exception as e:
        print(f"Error making API call to {url}: {e}")
        return None, None

def display_key_differences(diff, api_method, params):
    section_separator = "\n" + ">" * 40 + "\n\n"
    diff_file = generate_short_diff_filename(api_method, params)

    diff_file = os.path.join(LOGS_DIR, diff_file)
    
    with open(diff_file, 'w') as diff_out:
        if diff:
            diff_out.write(f"Differences for API: {api_method}\n")
            
            if 'dictionary_item_added' in diff:
                print(Fore.RED + "\nKeys present in ZQ1 but missing in ZQ2:")
                diff_out.write("\nKeys present in ZQ1 but missing in ZQ2:\n")
                for item in diff['dictionary_item_added']:
                    print(Fore.RED + f"  {item}")
                    diff_out.write(f"  {item}\n")
                print(section_separator)
                diff_out.write(section_separator)
                
            if 'dictionary_item_removed' in diff:
                print(Fore.RED + "\nKeys present in ZQ2 but missing in ZQ1:")
                diff_out.write("\nKeys present in ZQ2 but missing in ZQ1:\n")
                for item in diff['dictionary_item_removed']:
                    print(Fore.RED + f"  {item}")
                    diff_out.write(f"  {item}\n")
                print(section_separator)
                diff_out.write(section_separator)
                
            if 'values_changed' in diff:
                print(Fore.YELLOW + "\nValues that differ between ZQ2 and ZQ1:")
                diff_out.write("\nValues that differ between ZQ2 and ZQ1:\n")
                for key, value in diff['values_changed'].items():
                    print(Fore.YELLOW + f"  {key}:")
                    print(Fore.YELLOW + f"    ZQ2 -> {value['old_value']}")
                    print(Fore.YELLOW + f"    ZQ1 -> {value['new_value']}")
                    diff_out.write(f"  {key}:\n")
                    diff_out.write(f"    ZQ2 -> {value['old_value']}\n")
                    diff_out.write(f"    ZQ1 -> {value['new_value']}\n")
                print(section_separator)
                diff_out.write(section_separator)
                
            if 'missing_nested_items' in diff:
                print(Fore.MAGENTA + "\nLists empty in ZQ2 but populated in ZQ1:")
                diff_out.write("\nLists empty in ZQ2 but populated in ZQ1:\n")
                for key, value in diff['missing_nested_items'].items():
                    print(Fore.MAGENTA + f"  {key}:\n    ZQ2 -> {value['ZQ2']}\n    ZQ1 -> {value['ZQ1']}")
                    diff_out.write(f"  {key}:\n    ZQ2 -> {value['ZQ2']}\n    ZQ1 -> {value['ZQ1']}\n")
                    print(section_separator)
                    diff_out.write(section_separator)
                
        else:
            print(Fore.GREEN + "No differences detected.")
            diff_out.write("No differences detected.\n")
    
    print(f"\nDifferences written to: {diff_file}")

# Other functions remain unchanged
def generate_unique_file_prefix(method, params):
    param_str = "_".join(str(p) for p in params)
    unique_suffix = hashlib.md5(param_str.encode()).hexdigest()[:8]
    return f"{method}_{unique_suffix}"



def generate_short_diff_filename(method, params):
    param_str = "_".join(str(p) for p in params)
    unique_suffix = hashlib.md5(f"{method}_{param_str}".encode()).hexdigest()[:10]
    return f"{method}_{unique_suffix}_diff.txt"
    
def pretty_print_with_jq(file_path):
    file_path = os.path.join(LOGS_DIR, file_path) if not os.path.isabs(file_path) else file_path

    try:
        result = subprocess.run(['jq', '.', file_path], capture_output=True, text=True)
        if result.returncode == 0:
            paginated_print(result.stdout)
        else:
            print(f"Error pretty printing with jq: {result.stderr}")
    except FileNotFoundError:
        print("Error: jq is not installed. Using Python's JSON formatter.")
        with open(file_path, 'r') as f:
            raw_json = f.read()
            pretty_print_large_json(raw_json)

def pretty_print_large_json(json_text):
    try:
        json_obj = json.loads(json_text)
        pretty_json = json.dumps(json_obj, indent=4)
        paginated_print(pretty_json)
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON: {e}")

def paginated_print(text, lines_per_page=20):
    """Prints text with pagination, allowing user to quit viewing early."""
    lines = text.splitlines()
    for i in range(0, len(lines), lines_per_page):
        print("\n".join(lines[i:i + lines_per_page]))
        
        if i + lines_per_page < len(lines):
            user_input = input("Press Enter to continue, 'q' or 'e' to exit: ").strip().lower()
            if user_input in ['q', 'e']:
                print("Exiting output display.")
                break

def compare_json_files(file1, file2):
    # Ensure file paths include the logs directory
    file1 = os.path.join(LOGS_DIR, file1) if not os.path.isabs(file1) else file1
    file2 = os.path.join(LOGS_DIR, file2) if not os.path.isabs(file2) else file2
    try:
        with open(file1, 'r') as f1, open(file2, 'r') as f2:
            json1 = json.load(f1)
            json2 = json.load(f2)

        diff = DeepDiff(json1, json2, ignore_order=True)

        missing_items = {}
        def check_empty_vs_populated(obj1, obj2, path="root"):
            """Recursively check for empty vs populated lists in JSON structure."""
            if isinstance(obj1, dict) and isinstance(obj2, dict):
                for key in obj1.keys() | obj2.keys():
                    check_empty_vs_populated(obj1.get(key), obj2.get(key), f"{path}['{key}']")
            elif isinstance(obj1, list) and isinstance(obj2, list):
                if not obj1 and obj2:
                    missing_items[path] = {"ZQ2": obj1, "ZQ1": obj2}
                elif obj1 and not obj2:
                    missing_items[path] = {"ZQ2": obj2, "ZQ1": obj1}

        check_empty_vs_populated(json1, json2)

        if missing_items:
            diff['missing_nested_items'] = missing_items

        return diff
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}")
        return None


def generate_short_diff_filename(method, params):
    param_str = "_".join(str(p) for p in params)
    unique_suffix = hashlib.md5(f"{method}_{param_str}".encode()).hexdigest()[:10]
    return f"{method}_{unique_suffix}_diff.txt"

def display_key_differences(diff, api_method, params):
    section_separator = "\n" + ">" * 40 + "\n\n"
    diff_file = generate_short_diff_filename(api_method, params)

    # Save diff file to logs directory
    diff_file = os.path.join(LOGS_DIR, diff_file)
    
    with open(diff_file, 'w') as diff_out:
        if diff:
            diff_out.write(f"Differences for API: {api_method}\n")
            
            if 'dictionary_item_added' in diff:
                print(Fore.RED + "\nKeys present in ZQ1 but missing in ZQ2:")
                diff_out.write("\nKeys present in ZQ1 but missing in ZQ2:\n")
                for item in diff['dictionary_item_added']:
                    print(Fore.RED + f"  {item}")
                    diff_out.write(f"  {item}\n")
                print(section_separator)
                diff_out.write(section_separator)
                
            if 'dictionary_item_removed' in diff:
                print(Fore.RED + "\nKeys present in ZQ2 but missing in ZQ1:")
                diff_out.write("\nKeys present in ZQ2 but missing in ZQ1:\n")
                for item in diff['dictionary_item_removed']:
                    print(Fore.RED + f"  {item}")
                    diff_out.write(f"  {item}\n")
                print(section_separator)
                diff_out.write(section_separator)
                
            if 'values_changed' in diff:
                print(Fore.YELLOW + "\nValues that differ between ZQ2 and ZQ1:")
                diff_out.write("\nValues that differ between ZQ2 and ZQ1:\n")
                for key, value in diff['values_changed'].items():
                    print(Fore.YELLOW + f"  {key}:")
                    print(Fore.YELLOW + f"    ZQ2 -> {value['old_value']}")
                    print(Fore.YELLOW + f"    ZQ1 -> {value['new_value']}")
                    diff_out.write(f"  {key}:\n")
                    diff_out.write(f"    ZQ2 -> {value['old_value']}\n")
                    diff_out.write(f"    ZQ1 -> {value['new_value']}\n")
                print(section_separator)
                diff_out.write(section_separator)
                
            if 'missing_nested_items' in diff:
                print(Fore.MAGENTA + "\nLists empty in ZQ2 but populated in ZQ1:")
                diff_out.write("\nLists empty in ZQ2 but populated in ZQ1:\n")
                for key, value in diff['missing_nested_items'].items():
                    print(Fore.MAGENTA + f"  {key}:\n    ZQ2 -> {value['ZQ2']}\n    ZQ1 -> {value['ZQ1']}")
                    diff_out.write(f"  {key}:\n    ZQ2 -> {value['ZQ2']}\n    ZQ1 -> {value['ZQ1']}\n")
                    print(section_separator)
                    diff_out.write(section_separator)
                
        else:
            print(Fore.GREEN + "No differences detected.")
            diff_out.write("No differences detected.\n")
    
    print(f"\nDifferences written to: {diff_file}")

def load_config(subset=None, method=None):
    with open('config_mainnet.json', 'r') as f:
        config = json.load(f)
    
    api_calls = []
    for main_key, subset_config in config["subsets"].items():
        if subset and subset != main_key:
            continue
        for method_name, call_data in subset_config.items():
            if method and method != method_name:
                continue
            for params in call_data["params"]:
                unique_prefix = generate_unique_file_prefix(method_name, params)
                api_calls.append({
                    "method": method_name,
                    "params": params if isinstance(params, list) else [params],
                    "output_file_prefix": unique_prefix
                })
    return config, api_calls

def format_time(local_time, zilliqa_time):
    if local_time and zilliqa_time:
        if local_time > zilliqa_time:
            return f"{Fore.RED + Style.BRIGHT}{local_time:.4f} sec" + Style.RESET_ALL, f"{zilliqa_time:.4f} sec"
        else:
            return f"{local_time:.4f} sec", f"{zilliqa_time:.4f} sec"
    return "Error", "Error"

def truncate_param(param, length=40):
    """Truncate long parameters for display, preserving start and end."""
    param_str = str(param)
    if len(param_str) > length:
        return f"{param_str[:20]}...{param_str[-20:]}"
    return param_str

def format_params(params):
    """Format parameters for display in table and mismatch prompt."""
    if isinstance(params, dict):
        formatted = {k: truncate_param(v) for k, v in params.items()}
        return str(formatted)
    elif isinstance(params, list):
        return ', '.join(truncate_param(p) for p in params)
    return truncate_param(params)

def prompt_to_view_difference(mismatched_apis):
    if not mismatched_apis:
        print(Fore.GREEN + "\nAll API calls matched.")
        return

    while True:
        print("\nThe following APIs have mismatches:")
        for i, api in enumerate(mismatched_apis):
            print(f"{i + 1}. {api['method']} ({api['params'][0]})")

        choice = input("\nEnter the number of the API you'd like to view the difference for (or 0 to go back to method selection): ").strip()

        if choice.isdigit():
            choice = int(choice)
            if choice == 0:
                return
            elif 1 <= choice <= len(mismatched_apis):
                selected_api = mismatched_apis[choice - 1]
                print(f"\n--- Viewing difference for {selected_api['method']} ({selected_api['params'][0]}) ---")
                diff = compare_json_files(selected_api["local_file"], selected_api["zilliqa_file"])
                display_key_differences(diff, selected_api["method"], selected_api["params"])

                # Validate "y" or "n" input for viewing outputs
                while True:
                    view_outputs = input(f"\nDo you want to view the outputs for {selected_api['method']} ({selected_api['params'][0]})? (y/n): ").strip().lower()
                    if view_outputs in {'y', 'n'}:
                        break
                    print("Invalid input. Please enter 'y' or 'n'.")

                if view_outputs == 'y':
                    print(f"\n ZQ2 Output ({selected_api['local_file']}):")
                    pretty_print_with_jq(selected_api["local_file"])
                    print(f"\n ZQ1 Output ({selected_api['zilliqa_file']}):")
                    pretty_print_with_jq(selected_api["zilliqa_file"])

                # Validate "y" or "n" input for continuing mismatches
                while True:
                    more = input("\nDo you want to view another mismatch? (y/n): ").strip().lower()
                    if more in {'y', 'n'}:
                        break
                    print("Invalid input. Please enter 'y' or 'n'.")

                if more != 'y':
                    return
            else:
                print("Invalid choice. Please enter a valid number.")
        else:
            print("Invalid input. Please enter a valid number.")

def select_method_in_subset(subset):
    config = json.load(open('config_mainnet.json'))
    methods = list(config["subsets"][subset].keys())

    while True:
        print(f"\nAvailable methods in {subset.capitalize()}:")
        for i, method in enumerate(methods, 1):
            print(f"{i}. {method}")
        print("-1. Go back to Available API subsets")

        method_choice = input(f"Select a method to run in {subset.capitalize()} (1-{len(methods)}) or press 0 to run all: ").strip()
        if method_choice == "-1":
            return None 
        elif method_choice == "0" or (method_choice.isdigit() and 1 <= int(method_choice) <= len(methods)):
            method = methods[int(method_choice) - 1] if method_choice != "0" else None
            return method
        else:
            print(f"Invalid choice. Please enter a valid number (-1, 0-{len(methods)}).")

def main():
    while True:
        print("\nAvailable API subsets:")
        print("1. Transaction APIs")
        print("2. Smart Contract APIs")
        print("3. Balance APIs")
        print("4. Block APIs")
        print("5. Blockchain APIs")
        print("0. Run all APIs")
        print("6. Exit")

        subset_choice = input("Select an API subset (1-5) or press 0 to run all, or 6 to exit: ").strip()

        if subset_choice not in {"0", "1", "2", "3", "4", "5", "6"}:
            print("Invalid choice. Please enter a valid option (0-6).")
            continue

        if subset_choice == "6":
            print("Exiting the program.")
            sys.exit()

        subset_map = {
            "1": "transaction",
            "2": "smart_contract",
            "3": "balance",
            "4": "blocks",
            "5": "blockchain"
        }
        subset = subset_map.get(subset_choice, None)

        if subset:
            while True:
                method = select_method_in_subset(subset)
                if method is None: 
                    break

                config, api_calls = load_config(subset=subset, method=method)
                headers = config["headers"]
                results = []
                mismatched_apis = []

                for api_call in api_calls:
                    method = api_call["method"]
                    params = api_call["params"]
                    output_file_prefix = api_call["output_file_prefix"]

                    local_file = f"{output_file_prefix}_ZQ2.json"
                    print(f"Making {method} API call to ZQ2 API - {config['urls']['ZQ2']} with param {params[0]}")

                    local_response_time, _ = make_api_call(
                        config["urls"]["ZQ2"], headers, method, params, f"{output_file_prefix}_ZQ2.txt", local_file
                    )

                    zilliqa_file = f"{output_file_prefix}_ZQ1.json"
                    print(f"Making {method} API call to ZQ1 API - {config['urls']['ZQ1']} with param {params[0]}")
                    zilliqa_response_time, _ = make_api_call(
                        config["urls"]["ZQ1"], headers, method, params, f"{output_file_prefix}_ZQ1.txt", zilliqa_file
                    )

                    diff = compare_json_files(local_file, zilliqa_file)
                    success = not bool(diff)
                    local_time_str, zilliqa_time_str = format_time(local_response_time, zilliqa_response_time)

                    results.append([
                        f"{method} ({format_params(params)})",
                        config["urls"]["ZQ2"],
                        config["urls"]["ZQ1"],
                        local_time_str,
                        zilliqa_time_str,
                        Fore.GREEN + "Match" + Style.RESET_ALL if success else Fore.RED + "Mismatch" + Style.RESET_ALL,
                        local_file,
                        zilliqa_file
                    ])

                    if not success:
                        mismatched_apis.append({
                            "method": method,
                            "params": params,
                            "local_file": local_file,
                            "zilliqa_file": zilliqa_file
                        })

                print("\nResults:")
                print(tabulate(results, headers=["API Method", "ZQ2 URL", "ZQ1 URL", "ZQ2 Time", "ZQ1 Time", "Status", "ZQ2 File", "ZQ1 File"]))
                prompt_to_view_difference(mismatched_apis) 

if __name__ == "__main__":
    main()
