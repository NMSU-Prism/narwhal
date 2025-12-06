use eyre::{bail, Result};
use rlp::Rlp;
use sha3::{Digest, Keccak256};
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::{BufRead, BufReader, Write},
    path::Path,
};

use k256::ecdsa::{Signature as EcdsaSignature, RecoveryId, VerifyingKey};

use revm::{
    database::InMemoryDB,
    primitives::{Address, Bytes, TxKind, U256},
    state::AccountInfo,
    context::{BlockEnv, TxEnv},
    Context,
    ExecuteCommitEvm,
    MainBuilder,
    MainContext,
    MainnetEvm,
};

/// One decoded transaction with recovered sender and RLP-derived fields.
struct DecodedTx {
    raw: Vec<u8>,
    sender: Address,
    original_nonce: u64,
    gas_price: u128,
    gas_limit: u64,
    kind: TxKind,
    value: U256,
    data: Bytes,
    chain_id: Option<u64>,
}

/// Parse transaction.txt which looks like:
///
/// [
///  0xf8, 0x6c, 0x80, ...
/// ]
///
/// (possibly with blank lines between each block)
fn load_rlp_blocks(path: &str) -> Result<Vec<Vec<u8>>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let mut txs: Vec<Vec<u8>> = Vec::new();
    let mut current: Vec<u8> = Vec::new();
    let mut in_block = false;

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();

        if trimmed.is_empty() {
            continue;
        }

        // Start of a new [ ... ] block
        if trimmed.starts_with('[') {
            in_block = true;
            current.clear();
        }

        if in_block {
            // Remove leading '[' and trailing ']' if present
            let mut s = trimmed;
            if s.starts_with('[') {
                s = &s[1..];
            }
            if s.ends_with(']') {
                s = &s[..s.len() - 1];
            }

            // Split by comma and parse 0x.. tokens
            for part in s.split(',') {
                let p = part.trim();
                if p.is_empty() {
                    continue;
                }
                // Expect forms like 0xf8, 0x6c, etc.
                let p = p.strip_prefix("0x").unwrap_or(p);
                if p.is_empty() {
                    continue;
                }
                let byte = u8::from_str_radix(p, 16)?;
                current.push(byte);
            }

            // If this line ended with ']', close the block
            if trimmed.ends_with(']') {
                in_block = false;
                if !current.is_empty() {
                    txs.push(current.clone());
                }
            }
        }
    }

    Ok(txs)
}

/// Build the sighash for a legacy tx, handling both pre-EIP-155 and EIP-155.
///
/// For legacy tx:
/// - pre-155: keccak(RLP([nonce, gasPrice, gasLimit, to, value, data]))
/// - EIP-155: keccak(RLP([nonce, gasPrice, gasLimit, to, value, data, chain_id, 0, 0]))
fn legacy_sighash(rlp: &Rlp, v: u64) -> Result<[u8; 32]> {
    let chain_id = if v >= 35 {
        Some(((v - 35) / 2) as u64)
    } else {
        None
    };

    let mut stream = rlp::RlpStream::new();
    if let Some(chain_id_val) = chain_id {
        // 6 fields + chain_id + 0 + 0
        stream.begin_list(9);
        for idx in 0..6 {
            let raw = rlp.at(idx)?.as_raw(); // RLP-encoded subfield
            stream.append_raw(raw, 1);
        }
        stream.append(&chain_id_val);
        stream.append(&0u8);
        stream.append(&0u8);
    } else {
        // 6 basic fields
        stream.begin_list(6);
        for idx in 0..6 {
            let raw = rlp.at(idx)?.as_raw();
            stream.append_raw(raw, 1);
        }
    }

    let encoded = stream.out();
    let hash = Keccak256::digest(&encoded);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash);
    Ok(out)
}

/// Recover sender address from (v, r, s) + RLP body.
fn recover_sender_from_rlp(rlp: &Rlp, tx_index: usize) -> Result<Address> {
    let v: u64 = rlp
        .at(6)?
        .as_val()
        .map_err(|e| eyre::eyre!("Tx #{tx_index}: v decode error: {e}"))?;

    let r_bytes = rlp
        .at(7)?
        .data()
        .map_err(|e| eyre::eyre!("Tx #{tx_index}: r decode error: {e}"))?;
    let s_bytes = rlp
        .at(8)?
        .data()
        .map_err(|e| eyre::eyre!("Tx #{tx_index}: s decode error: {e}"))?;

    if r_bytes.len() > 32 || s_bytes.len() > 32 {
        bail!(
            "Tx #{tx_index}: r or s too long (r={}, s={})",
            r_bytes.len(),
            s_bytes.len()
        );
    }

    let sighash = legacy_sighash(rlp, v)?;

    // Build 64-byte signature (r || s), left-padded
    let mut sig_bytes = [0u8; 64];
    sig_bytes[32 - r_bytes.len()..32].copy_from_slice(r_bytes);
    sig_bytes[64 - s_bytes.len()..64].copy_from_slice(s_bytes);

    // Recovery id
    let recid_u8 = if v == 27 || v == 28 {
        (v - 27) as u8
    } else {
        // EIP-155: v = chain_id * 2 + 35 or 36
        ((v - 35) % 2) as u8
    };

    let rec_id = RecoveryId::from_byte(recid_u8)
        .ok_or_else(|| eyre::eyre!("Tx #{tx_index}: bad recovery id {recid_u8}"))?;

    // Signature from bytes
    let sig = EcdsaSignature::from_slice(&sig_bytes)
        .map_err(|e| eyre::eyre!("Tx #{tx_index}: bad r,s signature: {e}"))?;

    // Recover verifying key from prehash
    let vk = VerifyingKey::recover_from_prehash(&sighash, &sig, rec_id)
        .map_err(|e| eyre::eyre!("Tx #{tx_index}: failed to recover pubkey: {e}"))?;

    // Ethereum address = last 20 bytes of keccak256(uncompressed_pubkey[1..])
    let uncompressed = vk.to_encoded_point(false);
    let pubkey_bytes = uncompressed.as_bytes();
    if pubkey_bytes.len() != 65 || pubkey_bytes[0] != 0x04 {
        bail!("Tx #{tx_index}: unexpected pubkey encoding");
    }

    let hash = Keccak256::digest(&pubkey_bytes[1..]);
    let mut addr_bytes = [0u8; 20];
    addr_bytes.copy_from_slice(&hash[12..]);

    Ok(Address::from(addr_bytes))
}

/// Decode a *legacy* Ethereum transaction (type 0) RLP into a DecodedTx.
///
/// Legacy format:
/// [nonce, gasPrice, gasLimit, to, value, data, v, r, s]
fn decode_legacy_tx(raw: &[u8], tx_index: usize) -> Result<DecodedTx> {
    let rlp = Rlp::new(raw);

    if !rlp.is_list() {
        bail!("Tx #{tx_index}: RLP is not a list");
    }
    let count = rlp.item_count()?;
    if count < 9 {
        bail!("Tx #{tx_index}: expected at least 9 RLP items, got {count}");
    }

    // ----- Basic numeric fields -----
    let nonce: u64 = rlp
        .at(0)?
        .as_val()
        .map_err(|e| eyre::eyre!("Tx #{tx_index}: nonce decode error: {e}"))?;
    let gas_price_u128: u128 = rlp
        .at(1)?
        .as_val()
        .map_err(|e| eyre::eyre!("Tx #{tx_index}: gasPrice decode error: {e}"))?;
    let gas_limit: u64 = rlp
        .at(2)?
        .as_val()
        .map_err(|e| eyre::eyre!("Tx #{tx_index}: gasLimit decode error: {e}"))?;

    // ----- To / kind -----
    let to_bytes = rlp
        .at(3)?
        .data()
        .map_err(|e| eyre::eyre!("Tx #{tx_index}: to field decode error: {e}"))?;

    let kind = if to_bytes.is_empty() {
        // Contract creation
        TxKind::Create
    } else {
        if to_bytes.len() != 20 {
            bail!(
                "Tx #{tx_index}: to field length is {}, expected 20",
                to_bytes.len()
            );
        }
        let mut addr_bytes = [0u8; 20];
        addr_bytes.copy_from_slice(to_bytes);
        TxKind::Call(Address::new(addr_bytes))
    };

    // ----- Value -----
    let value_bytes = rlp
        .at(4)?
        .data()
        .map_err(|e| eyre::eyre!("Tx #{tx_index}: value decode error: {e}"))?;
    let value = U256::from_be_slice(value_bytes);

    // ----- Data -----
    let data_bytes = rlp
        .at(5)?
        .data()
        .map_err(|e| eyre::eyre!("Tx #{tx_index}: data decode error: {e}"))?;
    let data: Bytes = data_bytes.to_vec().into();

    // ----- v / chain_id -----
    let v: u64 = rlp
        .at(6)?
        .as_val()
        .map_err(|e| eyre::eyre!("Tx #{tx_index}: v decode error: {e}"))?;

    let chain_id = if v >= 35 {
        Some(((v - 35) / 2) as u64)
    } else {
        None
    };

    // ----- Recover real sender -----
    let sender = recover_sender_from_rlp(&rlp, tx_index)?;

    Ok(DecodedTx {
        raw: raw.to_vec(),
        sender,
        original_nonce: nonce,
        gas_price: gas_price_u128,
        gas_limit,
        kind,
        value,
        data,
        chain_id,
    })
}

fn main() -> Result<()> {
    let tx_file = "/home/narwhal/attack_testbed/transaction.txt";
    let result_path = "/home/narwhal/transaction_results.txt";

    if !Path::new(tx_file).exists() {
        bail!("Tx file not found: {tx_file}");
    }

    // 1. Load raw RLP blobs from your custom [0x.., 0x..] format
    let raw_blocks = load_rlp_blocks(tx_file)?;
    println!("Loaded {} raw transactions", raw_blocks.len());

    // 2. Decode + recover real senders
    let mut decoded_txs: Vec<DecodedTx> = Vec::new();
    for (i, raw) in raw_blocks.iter().enumerate() {
        match decode_legacy_tx(raw, i) {
            Ok(tx) => decoded_txs.push(tx),
            Err(e) => {
                eprintln!("Failed to decode tx #{i}: {e}");
            }
        }
    }
    println!("Successfully decoded {} transactions", decoded_txs.len());

    // 3. Build initial DB with all unique senders pre-funded
    let mut db = InMemoryDB::default();
    let rich_balance = U256::from(1_000_000_000_000_000_000_000_000u128); // 1e24 wei

    let mut seen_senders = HashSet::new();
    for tx in &decoded_txs {
        if seen_senders.insert(tx.sender) {
            db.insert_account_info(tx.sender, AccountInfo::from_balance(rich_balance));
        }
    }

    // 4. Block environment (tune if desired)
    let block_env = BlockEnv {
        number: U256::from(1u64),
        gas_limit: 30_000_000,
        basefee: 1_000_000_000u64, // 1 gwei
        ..Default::default()
    };

    // 5. Build Context and EVM using the already-working Mainnet API
    let ctx = Context::mainnet()
        .with_db(db)
        .with_block(block_env);

    let mut evm: MainnetEvm<_> = ctx.build_mainnet();

    // 6. Local nonce tracking per sender so revm is happy
    let mut local_nonces: HashMap<Address, u64> = HashMap::new();

    // 7. Execute and log results
    let mut out = File::create(result_path)?;

    for (i, tx) in decoded_txs.iter().enumerate() {
        writeln!(out, "==============================")?;
        writeln!(out, "Transaction {}", i + 1)?;
        writeln!(out, "Sender          : {:?}", tx.sender)?;
        writeln!(out, "Original nonce  : {}", tx.original_nonce)?;
        writeln!(out, "Gas price (wei) : {}", tx.gas_price)?;
        writeln!(out, "Gas limit       : {}", tx.gas_limit)?;
        writeln!(out, "Value (wei)     : {}", tx.value)?;
        writeln!(out, "Raw RLP (hex)   : 0x{}", hex::encode(&tx.raw))?;

        // Assign a sequential nonce per sender for this replay
        let entry = local_nonces.entry(tx.sender).or_insert(0);
        let replay_nonce = *entry;
        *entry += 1;

        let tx_env = TxEnv {
            tx_type: 0,
            caller: tx.sender,
            gas_limit: tx.gas_limit,
            gas_price: tx.gas_price,
            kind: tx.kind,
            value: tx.value,
            data: tx.data.clone(),
            nonce: replay_nonce,
            chain_id: None,
            ..TxEnv::default()
        };

        match evm.transact_commit(tx_env) {
            Ok(result) => {
                writeln!(out, "Success : {}", result.is_success())?;
                writeln!(out, "Gas Used: {}", result.gas_used())?;

                let output_hex = result
                    .output()
                    .map(|b| hex::encode(b))
                    .unwrap_or_default();
                writeln!(out, "Output  : 0x{}", output_hex)?;
            }
            Err(e) => {
                writeln!(out, "Error executing tx #{i}: {e}")?;
            }
        }

        writeln!(out, "--- State Changes: (not dumped in this version) ---")?;
    }

    println!("All results written to {}", result_path);
    Ok(())
}
