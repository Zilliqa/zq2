# Zilliqa API Comparator

The `Zilliqa API Comparator` is a Python-based tool designed to validate and compare API responses between two Zilliqa network endpoints: ZQ1 and ZQ2. This tool helps verify consistency in data returned by these endpoints and provides insights into response time differences.

## Folder Contents

- **`validate_zq1_zq2.py`**: The main script to run API comparisons.
- **`config_mainnet.json`**: Configuration file containing API endpoints, headers, API subsets, methods, and parameters.
- **`requirements.txt`**: List of required Python packages.
- **`README.md`**: Instructions for setting up and using this script.

## Setup Instructions

### Step 1: Install Dependencies

Clone the `zq2` repository and navigate to the `zilliqa_api_comparator` folder. Install dependencies using `requirements.txt`:

```bash
pip install -r requirements.txt
```

### Step 2: Configuration

Modify the config_mainnet.json file to include your specific API parameters and endpoints as required. Additionally, you can expand the test scenarios by adding more API inputs to the configuration.

### Step 3: Run the Script

Run the script by executing:

```bash
python zilliqa_api_test.py
```

Usage Guide
* Select an API Subset: When prompted, choose a subset to validate (e.g., Transaction APIs, Smart Contract APIs, Balance APIs).
* Choose a Method: You can run a specific method in the subset or choose to run all methods in the subset.
* View Results: The script displays a table summarizing API responses, response times, and mismatches.


## Example Output
The output includes:
A summary table of tested APIs, URLs, response times, and status (match or mismatch).
Highlighted key differences and details on any mismatched JSON fields.
Option to view saved output files for further analysis.

## Additional Features
Detailed JSON Comparison: Saves detailed differences between JSON responses to text files in the results/ folder.

Color-coded Console Output: Displays matched and mismatched values with color highlighting. If the ZQ2 API response time exceeds that of ZQ1, it appears in red for easy identification.

Pagination for Large Outputs: Automatically paginates JSON output for manageable viewing.




