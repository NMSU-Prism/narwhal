import pandas as pd
from web3 import Web3
from datetime import datetime
import json
import os
import csv
import sys
import time

csv.field_size_limit(sys.maxsize)

# ----------------- CONFIGURATION -----------------
GETH_URL = "http://127.0.0.1:8545"  # Update with your Geth RPC URL
MASTER_PRIVATE_KEY = "0x99c03680bbbaa63eee2ba436faeec5200c0000b4d59db398830a0a4563bac3ef"

PRIVATE_KEYS_FILE = "wallet_private_keys.json"
CSV_FILE = "mempool.csv"
TRANSACTION_FILE = "transaction.txt"  # File to save tx bytes

INITIAL_FUND_ETH = 0.05  # ETH to fund newly created accounts (for invalid addresses)
DEFAULT_GAS_LIMIT = 21000

# Your existing chain id:
CHAIN_ID = 3151908

# ----------------- WEB3 SETUP -----------------
web3 = Web3(Web3.HTTPProvider(GETH_URL))

if not web3.is_connected():
    raise Exception("Geth is not connected")

master_account = web3.eth.account.from_key(MASTER_PRIVATE_KEY)
master_address = Web3.to_checksum_address(master_account.address)

print(f"[INFO] Connected to Geth. Master wallet: {master_address}")

# Verify node chainId matches what you expect
node_chain_id = web3.eth.chain_id
print(f"[INFO] Node chainId={node_chain_id}")
if node_chain_id != CHAIN_ID:
    raise Exception(
        f"ChainId mismatch: node={node_chain_id} but expected {CHAIN_ID}. "
        f"Fix your genesis/geth OR update CHAIN_ID in this script."
    )

# ----------------- PRIVATE KEYS -----------------
def load_private_keys():
    if os.path.exists(PRIVATE_KEYS_FILE):
        with open(PRIVATE_KEYS_FILE, "r") as f:
            data = json.load(f)
        # Normalize keys to checksum format
        out = {}
        for addr, pk in data.items():
            try:
                out[Web3.to_checksum_address(addr)] = pk
            except Exception:
                # Skip malformed addresses in the file
                pass
        return out
    return {}

def save_private_keys(private_keys):
    # Persist using checksum addresses
    with open(PRIVATE_KEYS_FILE, "w") as f:
        json.dump(private_keys, f, indent=4)

private_keys = load_private_keys()

# ----------------- FEE HELPERS -----------------
def build_fee_fields():
    """
    Use EIP-1559 fees if the chain has baseFeePerGas, otherwise legacy gasPrice.
    This prevents 'transaction underpriced' issues on London+ chains.
    """
    latest = web3.eth.get_block("latest")
    base_fee = latest.get("baseFeePerGas", None)

    if base_fee is not None:
        max_priority = web3.to_wei(1, "gwei")
        # simple heuristic: maxFee = 2*baseFee + priority
        max_fee = int(base_fee) * 2 + int(max_priority)
        return {
            "type": 2,
            "maxPriorityFeePerGas": int(max_priority),
            "maxFeePerGas": int(max_fee),
        }
    else:
        return {
            "gasPrice": int(web3.eth.gas_price),
        }

def pending_nonce(address: str) -> int:
    return web3.eth.get_transaction_count(Web3.to_checksum_address(address), "pending")

# ----------------- ACCOUNT & FUNDING -----------------
def create_account(private_keys, initial_fund_wei=None):
    """Create a new account and optionally fund it from master wallet."""
    acct = web3.eth.account.create()
    address = Web3.to_checksum_address(acct.address)
    key_hex = acct.key.hex()

    private_keys[address] = key_hex
    save_private_keys(private_keys)
    print(f"[ACCOUNT] New account created: {address}")

    if initial_fund_wei is not None and int(initial_fund_wei) > 0:
        tx = {
            "from": master_address,
            "to": address,
            "value": int(initial_fund_wei),
            "gas": DEFAULT_GAS_LIMIT,
            "nonce": pending_nonce(master_address),
            "chainId": CHAIN_ID,
        }
        tx.update(build_fee_fields())

        signed_tx = web3.eth.account.sign_transaction(tx, MASTER_PRIVATE_KEY)
        tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)
        web3.eth.wait_for_transaction_receipt(tx_hash)
        print(
            f"[FUNDED] Account {address} funded with "
            f"{web3.from_wei(int(initial_fund_wei), 'ether')} ETH, tx: {tx_hash.hex()}"
        )
        time.sleep(0.1)

    return address, key_hex

def ensure_funded(address, required_balance_wei):
    address = Web3.to_checksum_address(address)
    balance = web3.eth.get_balance(address)
    required_balance_wei = int(required_balance_wei)

    if balance >= required_balance_wei:
        return

    fund_amount = required_balance_wei - balance
    print(f"[FUNDING] Funding {address} with {web3.from_wei(fund_amount, 'ether')} ETH")

    tx = {
        "from": master_address,
        "to": address,
        "value": int(fund_amount),
        "gas": DEFAULT_GAS_LIMIT,
        "nonce": pending_nonce(master_address),
        "chainId": CHAIN_ID,
    }
    tx.update(build_fee_fields())

    signed = web3.eth.account.sign_transaction(tx, MASTER_PRIVATE_KEY)
    tx_hash = web3.eth.send_raw_transaction(signed.raw_transaction)
    web3.eth.wait_for_transaction_receipt(tx_hash)
    print(f"[FUNDED] {address} funded, tx: {tx_hash.hex()}")
    time.sleep(0.1)

# ----------------- TX SENDER -----------------
def save_tx_bytes(tx_bytes: bytes, save_file: str):
    with open(save_file, "a") as f:
        f.write("[\n")
        f.write(", ".join([f"0x{b:02x}" for b in tx_bytes]))
        f.write("\n]\n\n")

def estimate_sender_overfund(value_wei: int, gas: int) -> int:
    """
    Conservative amount to fund a new sender so it can send a tx.
    Uses current gas_price as a rough upper bound plus a small cushion.
    """
    cushion = web3.to_wei(0.002, "ether")
    fee_guess = int(gas) * int(web3.eth.gas_price)
    return int(value_wei) + fee_guess + int(cushion)

def send_transaction(from_address, to_address, value, gas, gas_price, private_keys, save_file=TRANSACTION_FILE):
    """
    Send a signed tx from from_address -> to_address.
    - If from_address not in private_keys, create a new funded account and use it.
    - Uses pending nonce to avoid nonce collisions.
    - Uses EIP-1559 fees if available.
    """
    from_address = Web3.to_checksum_address(from_address)
    to_address = Web3.to_checksum_address(to_address)

    value = int(value)
    gas = int(gas) if gas else DEFAULT_GAS_LIMIT

    # Retrieve private key or create+fund sender
    if from_address not in private_keys:
        # Create a new sender and fund it enough
        overfund = estimate_sender_overfund(value, gas)
        from_address, private_key = create_account(private_keys, initial_fund_wei=overfund)
    else:
        private_key = private_keys[from_address]

    # Ensure balance is enough (extra-safe)
    ensure_funded(from_address, estimate_sender_overfund(value, gas))

    tx = {
        "from": from_address,
        "to": to_address,
        "value": value,
        "gas": gas,
        "nonce": pending_nonce(from_address),
        "chainId": CHAIN_ID,
    }
    tx.update(build_fee_fields())

    signed_tx = web3.eth.account.sign_transaction(tx, private_key)
    tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)
    web3.eth.wait_for_transaction_receipt(tx_hash)

    # Save tx bytes
    save_tx_bytes(signed_tx.raw_transaction, save_file)
    return tx_hash

# ----------------- CSV READING -----------------
df = pd.read_csv(CSV_FILE, sep="\t", engine="python", on_bad_lines="skip")

# ----------------- TPS CALCULATION -----------------
def calculate_transactions_per_second(df):
    df = df.copy()
    df["detecttime"] = pd.to_datetime(df["detecttime"], errors="coerce")
    df = df.dropna(subset=["detecttime"])
    total_transactions = len(df)
    if total_transactions <= 1:
        return 0.0
    time_diffs = (df["detecttime"] - df["detecttime"].min()).dt.total_seconds()
    span = float(time_diffs.max() - time_diffs.min())
    if span <= 0:
        return 0.0
    return float(total_transactions) / span

avg_tps = calculate_transactions_per_second(df)
print(f"[INFO] Average transactions per second: {avg_tps:.2f}")

# ----------------- PROCESS TRANSACTIONS -----------------
def process_transactions(df, private_keys):
    total = len(df)
    for index, row in df.iterrows():
        try:
            from_address = row.get("fromaddress")
            to_address = row.get("toaddress")

            value = int(row["value"]) if ("value" in row and not pd.isna(row["value"])) else 0
            gas = int(row["gas"]) if ("gas" in row and not pd.isna(row["gas"])) else DEFAULT_GAS_LIMIT

            # NOTE: We keep gas_price param for compatibility with your CSV,
            # but we will NOT force it into tx if the chain is EIP-1559.
            # This avoids underpriced issues.
            gas_price = int(row["gasprice"]) if ("gasprice" in row and not pd.isna(row["gasprice"])) else int(web3.eth.gas_price)

            # Handle invalid from address: create a new funded sender
            if pd.isna(from_address) or not web3.is_address(str(from_address)):
                # fund enough for at least one tx
                fund_needed = estimate_sender_overfund(value, gas)
                from_address, _ = create_account(private_keys, initial_fund_wei=fund_needed)
            else:
                from_address = Web3.to_checksum_address(str(from_address))

            # Handle invalid to address: create a new account and fund it with INITIAL_FUND_ETH (converted to wei)
            if pd.isna(to_address) or not web3.is_address(str(to_address)):
                to_address, _ = create_account(private_keys, initial_fund_wei=web3.to_wei(INITIAL_FUND_ETH, "ether"))
            else:
                to_address = Web3.to_checksum_address(str(to_address))

            tx_hash = send_transaction(from_address, to_address, value, gas, gas_price, private_keys)
            print(
                f"[SUCCESS] {index+1}/{total} | TX: {tx_hash.hex()} | "
                f"{from_address} -> {to_address} | Value: {web3.from_wei(value, 'ether')} ETH"
            )
        except Exception as e:
            print(f"[FAILED] Row {index} | Error: {e}")

# ----------------- RUN -----------------
process_transactions(df, private_keys)
