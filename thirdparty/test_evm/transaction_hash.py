import re
from pathlib import Path
import rlp
from eth_account._utils.signing import extract_chain_id, to_standard_v
from eth_account._utils.legacy_transactions import (
    serializable_unsigned_transaction_from_dict,
)
from eth_utils import keccak, to_checksum_address

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

def int_from_big_endian(b: bytes) -> int:
    return int.from_bytes(b, "big") if b else 0

def decode_legacy_signed(raw: bytes):
    # legacy signed tx RLP fields:
    # [nonce, gasPrice, gas, to, value, data, v, r, s]
    fields = rlp.decode(raw)
    if len(fields) != 9:
        raise ValueError(f"Not legacy tx (expected 9 fields), got {len(fields)}")

    nonce = int_from_big_endian(fields[0])
    gas_price = int_from_big_endian(fields[1])
    gas = int_from_big_endian(fields[2])
    to_bytes = fields[3]
    to_addr = None if len(to_bytes) == 0 else to_checksum_address(to_bytes)
    value = int_from_big_endian(fields[4])
    data = fields[5]

    v = int_from_big_endian(fields[6])
    r = int_from_big_endian(fields[7])
    s = int_from_big_endian(fields[8])

    return {
        "nonce": nonce,
        "gasPrice": gas_price,
        "gas": gas,
        "to": to_addr,
        "value": value,
        "data": data,
        "v": v, "r": r, "s": s,
    }

def recover_from(tx):
    # Handle EIP-155 v
    chain_id = None
    if tx["v"] >= 35:
        chain_id, _ = extract_chain_id(tx["v"])
    std_v = to_standard_v(tx["v"])

    unsigned_tx_dict = {
        "nonce": tx["nonce"],
        "gasPrice": tx["gasPrice"],
        "gas": tx["gas"],
        "to": tx["to"],
        "value": tx["value"],
        "data": tx["data"],
        "chainId": chain_id,
    }

    unsigned_tx = serializable_unsigned_transaction_from_dict(unsigned_tx_dict)
    msg_hash = unsigned_tx.hash()

    # Recover public key from (v,r,s)
    from eth_keys.datatypes import Signature
    sig = Signature(vrs=(std_v, tx["r"], tx["s"]))
    pub = sig.recover_public_key_from_msg_hash(msg_hash)

    addr = pub.to_checksum_address()
    return addr, chain_id

def main():
    text = Path("transaction.txt").read_text()
    blocks = extract_blocks(text)
    print(f"Found {len(blocks)} tx blobs\n")

    for i, block in enumerate(blocks):
        raw = block_to_bytes(block)
        tx = decode_legacy_signed(raw)
        sender, chain_id = recover_from(tx)

        print(f"{i:02d} from={sender}  to={tx['to']}  value_wei={tx['value']}  chainId={chain_id}")

if __name__ == "__main__":
    main()
