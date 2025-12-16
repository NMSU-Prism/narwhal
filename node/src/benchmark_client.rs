// Copyright(C) Facebook, Inc. and its affiliates.
use anyhow::{Context, Result};
// use bytes::BufMut as _;
// use bytes::BytesMut;
use clap::{crate_name, crate_version, App, AppSettings};
use env_logger::Env;
use futures::future::join_all;
use futures::sink::SinkExt as _;
use log::{info, warn};
// use rand::Rng;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::time::{interval, sleep, Duration, Instant};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

use std::fs::File;
use bytes::Bytes; // add at top
use std::io::Read;

//use serde_json::json;




#[tokio::main]
async fn main() -> Result<()> {
    let matches = App::new(crate_name!())
        .version(crate_version!())
        .about("Benchmark client for Narwhal and Tusk.")
        .args_from_usage("<ADDR> 'The network address of the node where to send txs'")
        .args_from_usage("--size=<INT> 'The size of each transaction in bytes'")
        .args_from_usage("--rate=<INT> 'The rate (txs/s) at which to send the transactions'")
        .args_from_usage("--nodes=[ADDR]... 'Network addresses that must be reachable before starting the benchmark.'")
        .setting(AppSettings::ArgRequiredElseHelp)
        .get_matches();

    env_logger::Builder::from_env(Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    let target = matches
        .value_of("ADDR")
        .unwrap()
        .parse::<SocketAddr>()
        .context("Invalid socket address format")?;
    let size = matches
        .value_of("size")
        .unwrap()
        .parse::<usize>()
        .context("The size of transactions must be a non-negative integer")?;
    let rate = matches
        .value_of("rate")
        .unwrap()
        .parse::<u64>()
        .context("The rate of transactions must be a non-negative integer")?;
    let nodes = matches
        .values_of("nodes")
        .unwrap_or_default()
        .into_iter()
        .map(|x| x.parse::<SocketAddr>())
        .collect::<Result<Vec<_>, _>>()
        .context("Invalid socket address format")?;

    info!("Node address: {}", target);

    // NOTE: This log entry is used to compute performance.
    info!("Transactions size: {} B", size);

    // NOTE: This log entry is used to compute performance.
    info!("Transactions rate: {} tx/s", rate);

    let client = Client {
        target,
        size,
        rate,
        nodes,
    };

    // Wait for all nodes to be online and synchronized.
    client.wait().await;

    // Start the benchmark.
    client.send().await.context("Failed to submit transactions")
}

struct Client {
    target: SocketAddr,
    size: usize,
    rate: u64,
    nodes: Vec<SocketAddr>,
}


fn parse_transactions_from_text(s: &str) -> anyhow::Result<Vec<Vec<u8>>> {
    let mut txs: Vec<Vec<u8>> = Vec::new();
    let mut i = 0usize;
    let bytes = s.as_bytes();

    while i < bytes.len() {
        // find next '['
        while i < bytes.len() && bytes[i] != b'[' { i += 1; }
        if i >= bytes.len() { break; }
        i += 1; // skip '['

        // find matching ']'
        let start = i;
        while i < bytes.len() && bytes[i] != b']' { i += 1; }
        if i >= bytes.len() {
            return Err(anyhow::anyhow!("Unclosed '[' in transaction.txt"));
        }
        let inner = &s[start..i]; // content between [ ... ]
        i += 1; // skip ']'

        // parse tokens separated by commas
        let mut tx: Vec<u8> = Vec::new();
        for tok in inner.split(',') {
            let t = tok.trim();
            if t.is_empty() { continue; }

            let v = if let Some(hex) = t.strip_prefix("0x") {
                u8::from_str_radix(hex, 16)
                    .with_context(|| format!("Bad hex byte token: {t}"))?
            } else {
                // allow decimal too (just in case)
                t.parse::<u8>().with_context(|| format!("Bad byte token: {t}"))?
            };

            tx.push(v);
        }

        if !tx.is_empty() {
            txs.push(tx);
        }
    }

    if txs.is_empty() {
        return Err(anyhow::anyhow!("No [ ... ] transactions found in transaction.txt"));
    }
    Ok(txs)
}


impl Client {
    pub async fn send(&self) -> Result<()> {
        const PRECISION: u64 = 20; // Sample precision.
        const BURST_DURATION: u64 = 1000 / PRECISION;

        // The transaction size must be at least 16 bytes to ensure all txs are different.
        if self.size < 9 {
            return Err(anyhow::Error::msg(
                "Transaction size must be at least 9 bytes",
            ));
        }

        // Connect to the mempool.
        let stream = TcpStream::connect(self.target)
            .await
            .context(format!("failed to connect to {}", self.target))?;

        // Submit all transactions.
        // let burst = self.rate / PRECISION;
        // let mut tx = BytesMut::with_capacity(self.size);
        let mut counter = 0;
        // let mut r = rand::thread_rng().gen();
        let mut transport = Framed::new(stream, LengthDelimitedCodec::new());
        let interval = interval(Duration::from_millis(BURST_DURATION));
        tokio::pin!(interval);

        // NOTE: This log entry is used to compute performance.
        info!("Start sending transactions");

    //     async fn send_to_geth(raw: &[u8]) {
    //     let url  = std::env::var("GETH_RPC_URL")
    //         .unwrap_or_else(|_| "http://127.0.0.1:8545".to_string());
    //     let http = reqwest::Client::new();
    //     let hex_tx = format!("0x{}", hex::encode(raw));
    //     let body = json!({
    //         "jsonrpc": "2.0",
    //         "id": 1,
    //         "method": "eth_sendRawTransaction",
    //         "params": [hex_tx]
    //     });

    //     match http.post(&url).json(&body).send().await {
    //         Ok(resp) => {
    //             let status = resp.status();
    //             let text = resp.text().await.unwrap_or_default();
    //             println!("→ Geth RPC status: {status}, body: {text}");
    //         }
    //         Err(e) => println!("→ Geth RPC error: {e}"),
    //     }
    // }



       // Read + parse tx list once
        let mut file = File::open("/home/narwhal/attack_testbed/transaction.txt")
            .context("Failed to open transaction.txt")?;

        let mut text = String::new();
        file.read_to_string(&mut text).context("Failed to read transaction.txt")?;

        let parsed = parse_transactions_from_text(&text)?;
        info!("Loaded {} transactions from transaction.txt", parsed.len());

        // Convert to Bytes for cheap cloning on send
        let txs: Vec<Bytes> = parsed.into_iter().map(Bytes::from).collect();

        let mut idx: usize = 0;

        'main: loop {
            interval.as_mut().tick().await;
            let now = Instant::now();

            let bytes = txs[idx].clone();        // cheap clone
            idx = (idx + 1) % txs.len();         // next tx (wrap around)

            if let Err(e) = transport.send(bytes).await {
                warn!("Failed to send transaction: {}", e);
                break 'main;
            }

            if now.elapsed().as_millis() > BURST_DURATION as u128 {
                warn!("Transaction rate too high for this client");
            }
            counter += 1;
        }
        Ok(())
    }

    pub async fn wait(&self) {
        // Wait for all nodes to be online.
        info!("Waiting for all nodes to be online...");
        join_all(self.nodes.iter().cloned().map(|address| {
            tokio::spawn(async move {
                while TcpStream::connect(address).await.is_err() {
                    sleep(Duration::from_millis(10)).await;
                }
            })
        }))
        .await;
    }
}
