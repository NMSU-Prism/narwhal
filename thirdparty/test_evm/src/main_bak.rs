use eyre::Result;
use hex::encode as hex_encode;
use revm::{
    context::{BlockEnv, Context, TxEnv},
    database::InMemoryDB,
    primitives::{Address, TxKind, U256},
    state::AccountInfo,
    MainContext,   // Context::mainnet()
    MainBuilder,   // ctx.build_mainnet()
    ExecuteEvm,    // evm.transact(...)
};
use serde::Deserialize;
use std::{fs::File, io::BufReader, path::Path, str::FromStr};

#[derive(Debug, Deserialize)]
struct DevGenesisConfig {
    #[serde(default)]
    chainId: Option<u64>,
}

/// Load chainId from your dev-genesis.json.
/// If not found, default to 1337.
fn load_chain_id_from_genesis(path: &str) -> u64 {
    let p = Path::new(path);
    if !p.exists() {
        eprintln!(
            "dev-genesis.json not found at {}, defaulting chainId=1337",
            path
        );
        return 1337;
    }

    let file = File::open(p).expect("failed to open dev-genesis.json");
    let reader = BufReader::new(file);
    let v: serde_json::Value =
        serde_json::from_reader(reader).expect("invalid JSON in dev-genesis.json");

    // Try top-level "chainId" or "config.chainId"
    if let Some(id) = v.get("chainId").and_then(|x| x.as_u64()) {
        id
    } else if let Some(id) = v
        .get("config")
        .and_then(|c| c.get("chainId"))
        .and_then(|x| x.as_u64())
    {
        id
    } else {
        eprintln!("No chainId in dev-genesis.json, defaulting to 1337");
        1337
    }
}

fn main() -> Result<()> {
    // ---------------------------------------------
    // 1) Load chainId from /home/narwhal/dev-genesis.json
    // ---------------------------------------------
    let genesis_path = "/home/narwhal/dev-genesis.json";
    let chain_id = load_chain_id_from_genesis(genesis_path);
    println!("Using chainId from dev-genesis.json: {}", chain_id);

    // ---------------------------------------------
    // 2) Build an in-memory DB and seed accounts
    // ---------------------------------------------
    let mut db = InMemoryDB::default();

    let from = Address::from_str("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266")
        .expect("invalid from address");
    let to = Address::from_str("0xfabb0ac9d68b0b445fb7357272ff202c5651694a")
        .expect("invalid to address");

    // Give `from` a large balance so the tx has funds
    let from_balance = U256::from_str("1000000000000000000000000")?; // 1e24 wei

    db.insert_account_info(
        from,
        AccountInfo {
            balance: from_balance,
            nonce: 0,
            code_hash: Default::default(),
            code: None,
        },
    );

    db.insert_account_info(
        to,
        AccountInfo {
            balance: U256::ZERO,
            nonce: 0,
            code_hash: Default::default(),
            code: None,
        },
    );

    // ---------------------------------------------
    // 3) Build BlockEnv (fake block metadata)
    // ---------------------------------------------
    let mut block = BlockEnv::default();
    block.number = U256::from(1419u64); // arbitrary block number
    block.gas_limit = 30_000_000;
    block.basefee = 1_000_000_000u64;   // 1 gwei

    // ---------------------------------------------
    // 4) Build TxEnv – simple ETH transfer
    // ---------------------------------------------
    let mut tx = TxEnv::default();
    tx.caller = from;
    tx.kind = TxKind::Call(to);
    tx.value = U256::from_str("1000000000000000000")?; // 1 ETH
    tx.gas_limit = 21_000;                             // simple transfer
    tx.gas_price = 1_000_000_000u128;                  // 1 gwei
    tx.nonce = 0;
    tx.chain_id = Some(chain_id);

    // ---------------------------------------------
    // 5) Build Context + EVM and execute tx (offline)
    // ---------------------------------------------
    // Note: we *don’t* pass cfg explicitly; we just take mainnet defaults.
    let ctx = Context::mainnet()
        .with_db(db)
        .with_block(block);

    let mut evm = ctx.build_mainnet();

    // Execute the transaction; this returns ExecResultAndState<ExecutionResult, _>
    let exec = evm.transact(tx)?;

    println!("--------------- EVM RESULT ---------------");
    println!("Success  : {}", exec.result.is_success());
    println!("Gas used : {}", exec.result.gas_used());

    let out_hex = match exec.result.output() {
        Some(bytes) => hex_encode(bytes),
        None => String::new(),
    };
    println!("Output   : 0x{}", out_hex);
    println!("-----------------------------------------");

    println!("State diff (changed accounts):");
    for (addr, acc) in exec.state {
        println!("{:?} -> balance = {}", addr, acc.info.balance);
    }

    Ok(())
}
