import pandas as pd
from web3 import Web3
import json
import os
import time

# ----------------- CONFIG -----------------
GETH_URL = 'http://127.0.0.1:32771'  # Geth RPC
PRIVATE_KEYS_FILE = 'wallet_private_keys.json'
CSV_FILE = 'mempool.csv'

# ----------------- WEB3 SETUP -----------------
web3 = Web3(Web3.HTTPProvider(GETH_URL))
if not web3.is_connected():
    raise Exception("Geth node is not connected")

# ----------------- LOAD PRIVATE KEYS -----------------
if not os.path.exists(PRIVATE_KEYS_FILE):
    raise Exception(f"{PRIVATE_KEYS_FILE} not found. Run account_setup.py first!")

with open(PRIVATE_KEYS_FILE, 'r') as f:
    private_keys = json.load(f)

print(f"Loaded {len(private_keys)} accounts from {PRIVATE_KEYS_FILE}")

# ----------------- CSV READING -----------------
df = pd.read_csv(CSV_FILE, sep="\t", engine="python", on_bad_lines="skip")

# ----------------- TPS CALCULATION -----------------
def calculate_tps(df):
    df['detecttime'] = pd.to_datetime(df['detecttime'], errors='coerce')
    df = df.dropna(subset=['detecttime'])
    total_tx = len(df)
    if total_tx <= 1:
        return 0
    time_diffs = (df['detecttime'] - df['detecttime'].min()).dt.total_seconds()
    avg_tps = total_tx / (time_diffs.max() - time_diffs.min())
    return avg_tps

avg_tps = calculate_tps(df)
print(f"Average transactions per second (TPS): {avg_tps:.2f}")

# ----------------- SEND TRANSACTIONS -----------------
def send_transaction(from_address, to_address, value, gas=21000, gas_price_gwei=10):
    gas_price = web3.to_wei(gas_price_gwei, 'gwei')
    nonce = web3.eth.get_transaction_count(from_address)
    
    tx = {
        'from': from_address,
        'to': to_address,
        'value': value,
        'gas': gas,
        'gasPrice': gas_price,
        'nonce': nonce,
        'chainId': web3.eth.chain_id
    }
    
    private_key = private_keys[from_address]
    signed_tx = web3.eth.account.sign_transaction(tx, private_key)
    tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)
    web3.eth.wait_for_transaction_receipt(tx_hash)
    return tx_hash

# ----------------- PROCESS -----------------
for index, row in df.iterrows():
    try:
        from_addr = str(row['fromaddress'])
        to_addr = str(row['toaddress'])
        value = int(row['value']) if not pd.isna(row['value']) else 0
        
        if from_addr not in private_keys:
            print(f"Skipping row {index}: from_address {from_addr} not in accounts")
            continue
        
        if to_addr not in private_keys:
            print(f"Skipping row {index}: to_address {to_addr} not in accounts")
            continue
        
        tx_hash = send_transaction(from_addr, to_addr, value)
        print(f"Row {index}: tx sent {from_addr} -> {to_addr}, hash: {tx_hash.hex()}")
    
    except Exception as e:
        print(f"Failed row {index}: {e}")
