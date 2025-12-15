// Copyright(C) Facebook, Inc. and its affiliates.
use anyhow::{Context, Result, anyhow, bail};
use clap::{crate_name, crate_version, App, AppSettings, ArgMatches, SubCommand};
use config::Export as _;
use config::Import as _;
use config::{Committee, KeyPair, Parameters, WorkerId};
use consensus::Consensus;
use env_logger::Env;
use primary::{Certificate, Primary};
use store::Store;
use tokio::sync::mpsc::{channel, Receiver};
use worker::Worker;
use revm::context::ContextTr;
use std::fs::{OpenOptions};




/****************/
//Addition

use rlp::Rlp;
use sha3::{Digest, Keccak256};
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::{BufRead, BufReader, self, Write},
    path::Path,
};

//use narwhal_types::{Certificate, BatchDigest};         // e.g. types crate
use crypto::Digest as BatchDigest;
//use worker::Batch;                             // e.g. worker crate
use worker::batch_maker::Batch;

//use store::Store;                              // e.g. store crate

use k256::ecdsa::{Signature as EcdsaSignature, RecoveryId, VerifyingKey};

use revm::{
    database::InMemoryDB,
    primitives::{Address, Bytes, TxKind, U256},
    state::AccountInfo,
    context::{BlockEnv, TxEnv},
    Context as evmContext,
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
/*struct DecodedTx {
    pub sender: Address,
    pub original_nonce: u64,
    pub gas_price: U256,
    pub gas_limit: u64,
    pub value: U256,
    pub kind: revm::primitives::TransactTo,
    pub data: Vec<u8>,
    pub raw: Vec<u8>,
}*/


/*****************/

/// The default channel capacity.
pub const CHANNEL_CAPACITY: usize = 1_000;

#[tokio::main]
async fn main() -> Result<()> {
    let matches = App::new(crate_name!())
        .version(crate_version!())
        .about("A research implementation of Narwhal and Tusk.")
        .args_from_usage("-v... 'Sets the level of verbosity'")
        .subcommand(
            SubCommand::with_name("generate_keys")
                .about("Print a fresh key pair to file")
                .args_from_usage("--filename=<FILE> 'The file where to print the new key pair'"),
        )
        .subcommand(
            SubCommand::with_name("run")
                .about("Run a node")
                .args_from_usage("--keys=<FILE> 'The file containing the node keys'")
                .args_from_usage("--committee=<FILE> 'The file containing committee information'")
                .args_from_usage("--parameters=[FILE] 'The file containing the node parameters'")
                .args_from_usage("--store=<PATH> 'The path where to create the data store'")
                .subcommand(SubCommand::with_name("primary").about("Run a single primary"))
                .subcommand(
                    SubCommand::with_name("worker")
                        .about("Run a single worker")
                        .args_from_usage("--id=<INT> 'The worker id'"),
                )
                .setting(AppSettings::SubcommandRequiredElseHelp),
        )
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .get_matches();

    let log_level = match matches.occurrences_of("v") {
        0 => "error",
        1 => "warn",
        2 => "info",
        3 => "debug",
        _ => "trace",
    };
    let mut logger = env_logger::Builder::from_env(Env::default().default_filter_or(log_level));
    #[cfg(feature = "benchmark")]
    logger.format_timestamp_millis();
    logger.init();

    match matches.subcommand() {
        ("generate_keys", Some(sub_matches)) => KeyPair::new()
            .export(sub_matches.value_of("filename").unwrap())
            .context("Failed to generate key pair")?,
        ("run", Some(sub_matches)) => run(sub_matches).await?,
        _ => unreachable!(),
    }
    Ok(())
}

// Runs either a worker or a primary.
async fn run(matches: &ArgMatches<'_>) -> Result<()> {
    let key_file = matches.value_of("keys").unwrap();
    let committee_file = matches.value_of("committee").unwrap();
    let parameters_file = matches.value_of("parameters");
    let store_path = matches.value_of("store").unwrap();

    // Read the committee and node's keypair from file.
    let keypair = KeyPair::import(key_file).context("Failed to load the node's keypair")?;
    let committee =
        Committee::import(committee_file).context("Failed to load the committee information")?;

    // Load default parameters if none are specified.
    let parameters = match parameters_file {
        Some(filename) => {
            Parameters::import(filename).context("Failed to load the node's parameters")?
        }
        None => Parameters::default(),
    };

    // Make the data store.
    let store = Store::new(store_path).context("Failed to create a store")?;

    let store_clone = store.clone();

    // Channels the sequence of certificates.
    let (tx_output, rx_output) = channel(CHANNEL_CAPACITY);

    // Check whether to run a primary, a worker, or an entire authority.
    match matches.subcommand() {
        // Spawn the primary and consensus core.
        ("primary", _) => {
            let (tx_new_certificates, rx_new_certificates) = channel(CHANNEL_CAPACITY);
            let (tx_feedback, rx_feedback) = channel(CHANNEL_CAPACITY);
            Primary::spawn(
                keypair,
                committee.clone(),
                parameters.clone(),
                store,
                /* tx_consensus */ tx_new_certificates,
                /* rx_consensus */ rx_feedback,
            );
            Consensus::spawn(
                committee,
                parameters.gc_depth,
                /* rx_primary */ rx_new_certificates,
                /* tx_primary */ tx_feedback,
                tx_output,
            );
        }

        // Spawn a single worker.
        ("worker", Some(sub_matches)) => {
            let id = sub_matches
                .value_of("id")
                .unwrap()
                .parse::<WorkerId>()
                .context("The worker id must be a positive integer")?;
            Worker::spawn(keypair.name, id, committee, parameters, store);
        }
        _ => unreachable!(),
    }

    // Analyze the consensus' output.
    analyze(rx_output, store_clone).await;

    // If this expression is reached, the program ends and all other tasks terminate.
    unreachable!();
}

/// Receives an ordered list of certificates and apply any application-specific logic.
/*async fn analyze(mut rx_output: Receiver<Certificate>) {
    while let Some(_certificate) = rx_output.recv().await {
        // NOTE: Here goes the application logic.
    }
}*/


/***********************
Application/Execution Logic

************************/

async fn extract_raw_txs_from_certificate(
    cert: &Certificate,
    batch_store: &mut Store,
) -> anyhow::Result<Vec<Vec<u8>>> {
    let mut raw_blocks = Vec::new();

    for (digest, _worker_id) in cert.header.payload.iter() {

        // println!("Extracting batch with digest: {:?}", digest);
        // println!("Extracting batch with worker: {:?}", _worker_id);

        // Store expects Key=Vec<u8>
        let key: Vec<u8> = digest.as_ref().to_vec();

        // Store::read is async and takes &mut self
        if let Some(batch_bytes) = batch_store.read(key).await? {
            // IMPORTANT:
            // In Narwhal, the batch is stored as serialized bytes.
            // At this point you have raw bytes. You can push the whole batch:
            raw_blocks.push(batch_bytes);

            // If you *really* need individual transactions, you must deserialize `batch_bytes`
            // according to how Narwhal serializes batches in your version.
        }
    }

    Ok(raw_blocks)
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
        .map_err(|e| anyhow!("Tx #{tx_index}: v decode error: {e}"))?;

    let r_bytes = rlp
        .at(7)?
        .data()
        .map_err(|e| anyhow!("Tx #{tx_index}: r decode error: {e}"))?;
    let s_bytes = rlp
        .at(8)?
        .data()
        .map_err(|e| anyhow!("Tx #{tx_index}: s decode error: {e}"))?;

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
        .ok_or_else(|| anyhow!("Tx #{tx_index}: bad recovery id {recid_u8}"))?;

    // Signature from bytes
    let sig = EcdsaSignature::from_slice(&sig_bytes)
        .map_err(|e| anyhow!("Tx #{tx_index}: bad r,s signature: {e}"))?;

    // Recover verifying key from prehash
    let vk = VerifyingKey::recover_from_prehash(&sighash, &sig, rec_id)
        .map_err(|e| anyhow!("Tx #{tx_index}: failed to recover pubkey: {e}"))?;

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
        .map_err(|e| anyhow!("Tx #{tx_index}: nonce decode error: {e}"))?;
    let gas_price_u128: u128 = rlp
        .at(1)?
        .as_val()
        .map_err(|e| anyhow!("Tx #{tx_index}: gasPrice decode error: {e}"))?;
    let gas_limit: u64 = rlp
        .at(2)?
        .as_val()
        .map_err(|e| anyhow!("Tx #{tx_index}: gasLimit decode error: {e}"))?;

    // ----- To / kind -----
    let to_bytes = rlp
        .at(3)?
        .data()
        .map_err(|e| anyhow!("Tx #{tx_index}: to field decode error: {e}"))?;

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
        .map_err(|e| anyhow!("Tx #{tx_index}: value decode error: {e}"))?;
    let value = U256::from_be_slice(value_bytes);

    // ----- Data -----
    let data_bytes = rlp
        .at(5)?
        .data()
        .map_err(|e| anyhow!("Tx #{tx_index}: data decode error: {e}"))?;
    let data: Bytes = data_bytes.to_vec().into();

    // ----- v / chain_id -----
    let v: u64 = rlp
        .at(6)?
        .as_val()
        .map_err(|e| anyhow!("Tx #{tx_index}: v decode error: {e}"))?;

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

async fn analyze(mut rx_output: Receiver<Certificate>,
    mut batch_store: Store) -> anyhow::Result<()> {


    // let mut out = File::create("result.txt")?;
       let mut out = OpenOptions::new()
        .create(true)        // Create the file if it doesn't exist
        .append(true)        // Open in append mode (do not overwrite)
        .open("result.txt")?; // Open the fil



    // Build initial DB with all unique senders pre-funded
    let mut db = InMemoryDB::default();
    let rich_balance = U256::from(1_000_000_000_000_000_000_000_000u128); // 1e24 wei

    let mut seen_senders = HashSet::new();
    // Local nonce tracking per sender so revm is happy
    let mut local_nonces: HashMap<Address, u64> = HashMap::new();

    // for tx in &decoded_txs {
    //     if seen_senders.insert(tx.sender) {
    //         db.insert_account_info(tx.sender, AccountInfo::from_balance(rich_balance));
    //     }
    // }

    // Block environment (tune if desired)
    let block_env = BlockEnv {
        number: U256::from(1u64),
        gas_limit: 30_000_000,
        basefee: 1_000_000_000u64, // 1 gwei
        ..Default::default()
    };

    // Build Context and EVM using the already-working Mainnet API
    let ctx = evmContext::mainnet()
        .with_db(db)
        .with_block(block_env);

    let mut evm: MainnetEvm<_> = ctx.build_mainnet();

    while let Some(certificate) = rx_output.recv().await {

       
        let raw_blocks = extract_raw_txs_from_certificate(&certificate, &mut batch_store).await?;


        //Decode + recover real senders
        let mut decoded_txs: Vec<DecodedTx> = Vec::new();
        for (i, raw) in raw_blocks.iter().enumerate() {
            match decode_legacy_tx(raw, i) {
                Ok(tx) => decoded_txs.push(tx),
                Err(e) => {
                    eprintln!("Failed to decode tx #{i}: {e}");
                }
            }
        }

        writeln!(
            out,
            "Successfully decoded {} transactions for this certificate",
            decoded_txs.len()
        )?;


        // Pre-fund any previously unseen senders (global across certs).
        for tx in &decoded_txs {
            if seen_senders.insert(tx.sender) {
                evm.ctx.db_mut().insert_account_info(tx.sender, AccountInfo::from_balance(rich_balance));
            }
        }        

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

        println!("All results written to result.txt");

    }

    Ok(())

}
