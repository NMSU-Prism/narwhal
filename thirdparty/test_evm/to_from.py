import re
from pathlib import Path
import rlp
from eth_account._utils.signing import extract_chain_id, to_standard_v
from eth_account._utils.legacy_transactions import (
    serializable_unsigned_transaction_from_dict,
)
from eth_utils import to_checksum_address
from eth_keys.datatypes import Signature

BALANCE = "0x3635c9adc5dea00000"

def extract_blocks(text: str):
    blocks = []
    depth = 0
    start = None
    for i, ch in enumerate(text):
        if ch == '[':
            if depth == 0:
                start = i
            depth += 1
        elif ch == ']':
            depth -= 1
            if depth == 0 and start is not None:
                block = text[start:i+1]
                if '0x' in block:
                    blocks.append(block)
                start = None
    return blocks

def block_to_bytes(block: str) -> bytes:
    nums = re.findall(r'0x[0-9a-fA-F]+|\d+', block)
    return bytes(int(n, 16) if n.lower().startswith("0x") else int(n) for n in nums)

def be_int(b: bytes) -> int:
    return int.from_bytes(b, "big") if b else 0

def decode_legacy(raw: bytes):
    # [nonce, gasPrice, gas, to, value, data, v, r, s]
    f = rlp.decode(raw)
    if len(f) != 9:
        raise ValueError("Not a legacy signed tx")

    return {
        "nonce": be_int(f[0]),
        "gasPrice": be_int(f[1]),
        "gas": be_int(f[2]),
        "to": None if len(f[3]) == 0 else to_checksum_address(f[3]),
        "value": be_int(f[4]),
        "data": f[5],
        "v": be_int(f[6]),
        "r": be_int(f[7]),
        "s": be_int(f[8]),
    }

def recover_from(tx):
    chain_id = None
    if tx["v"] >= 35:
        chain_id, _ = extract_chain_id(tx["v"])

    unsigned = serializable_unsigned_transaction_from_dict({
        "nonce": tx["nonce"],
        "gasPrice": tx["gasPrice"],
        "gas": tx["gas"],
        "to": tx["to"],
        "value": tx["value"],
        "data": tx["data"],
        "chainId": chain_id,
    })

    msg_hash = unsigned.hash()
    sig = Signature(vrs=(to_standard_v(tx["v"]), tx["r"], tx["s"]))
    pub = sig.recover_public_key_from_msg_hash(msg_hash)
    return pub.to_checksum_address()

def main():
    text = Path("transaction.txt").read_text()
    blocks = extract_blocks(text)

    accounts = set()

    for block in blocks:
        raw = block_to_bytes(block)
        tx = decode_legacy(raw)

        frm = recover_from(tx)
        accounts.add(frm)

        if tx["to"]:
            accounts.add(tx["to"])

    # Print EXACT requested format
    for addr in sorted(accounts):
        print(f'"{addr}": {{')
        print(f'  "balance": "{BALANCE}"')
        print('},')

if __name__ == "__main__":
    main()
