import csv
import json
import sys
from decimal import Decimal

# ----------------------------
# Allow very large CSV fields
# ----------------------------
csv.field_size_limit(sys.maxsize)

# ----------------------------
# Configuration
# ----------------------------
CSV_FILE = "mempool.csv"               # your input CSV file
OUTPUT_GENESIS = "generated-genesis.json"  # output genesis file

# ----------------------------
# Base genesis template
# ----------------------------
BASE_GENESIS = {
    "config": {
        "chainId": 3151908,
        "homesteadBlock": 0,
        "eip150Block": 0,
        "eip155Block": 0,
        "eip158Block": 0,
        "byzantiumBlock": 0,
        "constantinopleBlock": 0,
        "petersburgBlock": 0,
        "istanbulBlock": 0,
        "berlinBlock": 0,
        "londonBlock": 0,
        "terminalTotalDifficulty": 0,
        "terminalTotalDifficultyPassed": True,
        "clique": {
            "period": 1,
            "epoch": 30000
        }
    },
    "nonce": "0x0",
    "timestamp": "0x0",
    "extraData": "0x0000000000000000000000000000000000000000000000000000000000000000a08a32489df0c5df6aff02110802756412428b810000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "gasLimit": "0x4c4b400",
    "difficulty": "0x0",
    "mixHash": "0x" + "00" * 32,
    "coinbase": "0x" + "00" * 20,
    "alloc": {},
    "number": "0x0"
}

# ----------------------------
# Helper functions
# ----------------------------
def eth_to_wei(value):
    """Convert CSV value like 5.4E+13 or 1.02575E+16 into wei (integer)"""
    if value is None or value.strip() == "":
        return 0
    return int(Decimal(value))

def add_balance(alloc, address, value_wei):
    """Add balance to alloc; sum if address already exists"""
    if not address:
        return
    address = address.strip().lower()
    if not address.startswith("0x") or value_wei <= 0:
        return
    if address not in alloc:
        alloc[address] = {"balance": hex(value_wei)}
    else:
        existing = int(alloc[address]["balance"], 16)
        alloc[address]["balance"] = hex(existing + value_wei)

def read_csv_and_generate_alloc():
    """Read CSV and generate genesis alloc"""
    alloc = {}
    with open(CSV_FILE, "rb") as f:
        # Remove NUL bytes and decode safely
        lines = (line.replace(b'\0', b'').decode('utf-8', errors='ignore') for line in f)
        reader = csv.DictReader(lines, delimiter='\t')

        # Strip header spaces
        reader.fieldnames = [name.strip() for name in reader.fieldnames]

        for row in reader:
            from_addr = row.get("fromaddress")
            to_addr = row.get("toaddress")
            value = row.get("value")

            value_wei = eth_to_wei(value)

            # Add balance to from and to addresses
            add_balance(alloc, from_addr, value_wei)
            add_balance(alloc, to_addr, value_wei)

    return alloc

def write_genesis(alloc):
    """Write genesis JSON file"""
    genesis = BASE_GENESIS.copy()
    genesis["alloc"] = alloc

    with open(OUTPUT_GENESIS, "w", encoding="utf-8") as f:
        json.dump(genesis, f, indent=2)

    print(f"\nGenesis file generated: {OUTPUT_GENESIS}")
    print(f"Total accounts: {len(alloc)}")

# ----------------------------
# Main
# ----------------------------
if __name__ == "__main__":
    alloc = read_csv_and_generate_alloc()
    write_genesis(alloc)
