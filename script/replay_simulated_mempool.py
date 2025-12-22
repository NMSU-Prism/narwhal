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
GETH_URL = 'http://127.0.0.1:32771'  # Update with your Geth RPC URL
MASTER_PRIVATE_KEY = 'bcdf20249abf0ed6d944c0288fad489e33f66b3960d9e6229c1cd214ed3bbe31'
PRIVATE_KEYS_FILE = 'wallet_private_keys.json'
CSV_FILE = 'mempool.csv'
TRANSACTION_FILE = 'transaction.txt'  # File to save tx bytes
INITIAL_FUND_ETH = 0.05  # Amount to fund newly created accounts
GAS_PRICE_GWEI = 10
GAS_LIMIT = 21000

# ----------------- WEB3 SETUP -----------------
web3 = Web3(Web3.HTTPProvider(GETH_URL))
if not web3.is_connected():
    raise Exception("Geth is not connected")

master_account = web3.eth.account.from_key(MASTER_PRIVATE_KEY)
master_address = master_account.address
print(f"[INFO] Connected to Geth. Master wallet: {master_address}")

# ----------------- PRIVATE KEYS -----------------
def load_private_keys():
    if os.path.exists(PRIVATE_KEYS_FILE):
        with open(PRIVATE_KEYS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_private_keys(private_keys):
    with open(PRIVATE_KEYS_FILE, 'w') as f:
        json.dump(private_keys, f, indent=4)

private_keys = load_private_keys()

# ----------------- ACCOUNT & FUNDING -----------------
def create_account(private_keys, initial_fund_wei=None):
    """Create a new account and optionally fund it from master wallet"""
    account = web3.eth.account.create()
    address = account.address
    key = account.key.hex()
    private_keys[address] = key
    save_private_keys(private_keys)
    print(f"[ACCOUNT] New account created: {address}")

    if initial_fund_wei is not None:
        tx = {
            'from': master_address,
            'to': address,
            'value': initial_fund_wei,
            'gas': GAS_LIMIT,
            'gasPrice': web3.to_wei(GAS_PRICE_GWEI, 'gwei'),
            'nonce': web3.eth.get_transaction_count(master_address),
            'chainId': web3.eth.chain_id
        }
        signed_tx = web3.eth.account.sign_transaction(tx, MASTER_PRIVATE_KEY)
        tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)
        web3.eth.wait_for_transaction_receipt(tx_hash)
        print(f"[FUNDED] Account {address} funded with {web3.from_wei(initial_fund_wei, 'ether')} ETH, tx: {tx_hash.hex()}")
        time.sleep(0.5)

    return address, key

def ensure_funded(address, required_balance_wei):
    balance = web3.eth.get_balance(address)
    if balance < required_balance_wei:
        fund_amount = required_balance_wei - balance
        print(f"[FUNDING] Funding {address} with {web3.from_wei(fund_amount, 'ether')} ETH")
        tx = {
            'from': master_address,
            'to': address,
            'value': fund_amount,
            'gas': GAS_LIMIT,
            'gasPrice': web3.to_wei(GAS_PRICE_GWEI, 'gwei'),
            'nonce': web3.eth.get_transaction_count(master_address),
            'chainId': web3.eth.chain_id
        }
        signed = web3.eth.account.sign_transaction(tx, MASTER_PRIVATE_KEY)
        tx_hash = web3.eth.send_raw_transaction(signed.raw_transaction)
        web3.eth.wait_for_transaction_receipt(tx_hash)
        print(f"[FUNDED] {address} funded, tx: {tx_hash.hex()}")
        time.sleep(0.5)

# ----------------- SEND TRANSACTION -----------------
#def send_transaction(from_address, to_address, value, gas, gas_price, private_keys):
def send_transaction(from_address, to_address, value, gas, gas_price, private_keys, save_file=TRANSACTION_FILE):
    # Retrieve private key
    if from_address not in private_keys:
        from_address, private_key = create_account(private_keys, initial_fund_wei=value + gas*gas_price)
    else:
        private_key = private_keys[from_address]

    # Ensure sufficient balance
    ensure_funded(from_address, value + gas * gas_price)

    tx = {
        'from': from_address,
        'to': to_address,
        'value': value,
        'gas': gas,
        'gasPrice': gas_price,
        'nonce': web3.eth.get_transaction_count(from_address),
        'chainId': web3.eth.chain_id
    }
    signed_tx = web3.eth.account.sign_transaction(tx, private_key)
    tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)
    web3.eth.wait_for_transaction_receipt(tx_hash)

    # ----------------- SAVE TX BYTES -----------------
    tx_bytes = signed_tx.raw_transaction
    with open(save_file, "a") as f:  # append multiple txs
        f.write("[\n")
        f.write(", ".join([f"0x{b:02x}" for b in tx_bytes]))
        f.write("\n]\n\n")

    return tx_hash

# ----------------- CSV READING -----------------
df = pd.read_csv(CSV_FILE, sep="\t", engine="python", on_bad_lines="skip")

# ----------------- TPS CALCULATION -----------------
def calculate_transactions_per_second(df):
    df['detecttime'] = pd.to_datetime(df['detecttime'], errors='coerce')
    df = df.dropna(subset=['detecttime'])
    total_transactions = len(df)
    if total_transactions <= 1:
        return 0
    time_diffs = (df['detecttime'] - df['detecttime'].min()).dt.total_seconds()
    avg_tps = total_transactions / (time_diffs.max() - time_diffs.min())
    return avg_tps

avg_tps = calculate_transactions_per_second(df)
print(f"[INFO] Average transactions per second: {avg_tps:.2f}")

# ----------------- PROCESS TRANSACTIONS -----------------
def process_transactions(df, private_keys):
    total = len(df)
    for index, row in df.iterrows():
        try:
            from_address = row.get('fromaddress')
            to_address = row.get('toaddress')
            value = int(row['value']) if not pd.isna(row['value']) else 0
            gas = int(row['gas']) if not pd.isna(row['gas']) else GAS_LIMIT
            gas_price = int(row['gasprice']) if not pd.isna(row['gasprice']) else web3.to_wei(GAS_PRICE_GWEI, 'gwei')

            # Handle invalid addresses
            if pd.isna(from_address) or not web3.is_address(str(from_address)):
                from_address, _ = create_account(private_keys, initial_fund_wei=value + gas*gas_price)
            else:
                from_address = Web3.to_checksum_address(str(from_address))
            
            if pd.isna(to_address) or not web3.is_address(str(to_address)):
                to_address, _ = create_account(private_keys, initial_fund_wei=INITIAL_FUND_ETH)
            else:
                to_address = Web3.to_checksum_address(str(to_address))

            # Send transaction
            tx_hash = send_transaction(from_address, to_address, value, gas, gas_price, private_keys)
            print(f"[SUCCESS] {index+1}/{total} | TX sent: {tx_hash.hex()} | {from_address} -> {to_address} | Value: {web3.from_wei(value, 'ether')} ETH")
        except Exception as e:
            print(f"[FAILED] Row {index} | Error: {e}")

# ----------------- RUN -----------------
process_transactions(df, private_keys)
