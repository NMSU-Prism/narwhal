// Copyright(C) Facebook, Inc. and its affiliates.
use anyhow::{Context, Result};
use bytes::BufMut as _;
use bytes::BytesMut;
use clap::{crate_name, crate_version, App, AppSettings};
use env_logger::Env;
use futures::future::join_all;
use futures::sink::SinkExt as _;
use log::{info, warn};
use rand::Rng;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::time::{interval, sleep, Duration, Instant};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

use std::fs::File;
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
        let burst = self.rate / PRECISION;
        let mut tx = BytesMut::with_capacity(self.size);
        let mut counter = 0;
        let mut r = rand::thread_rng().gen();
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





        'main: loop {
            interval.as_mut().tick().await;
            let now = Instant::now();

            for x in 0..1 {
                if x == counter % burst {
                    // NOTE: This log entry is used to compute performance.
                    info!("Sending sample transaction {}", counter);

                    tx.put_u8(0u8); // Sample txs start with 0.
                    tx.put_u64(counter); // This counter identifies the tx.
                } else {
                    r += 1;
                    tx.put_u8(1u8); // Standard txs start with 1.
                    tx.put_u64(r); // Ensures all clients send different txs.
                };

                tx.resize(self.size, 0u8);
                let mut bytes = tx.split().freeze();
                if counter == 0 {
                    //bytes = 0xf86f808504a817c80082520894614561d2d143621e126e87831aef287678b442b888016345785d8a0000808360306ba05869d7b8419ecb5d44f5e62a0cfd8f558e4771c95108cc5760f5b0f5af6f0aaaa058d213e2ef9a74761cf627b706162467aa5dbb07279576996d7ded5e0ae230b5
                
                    // bytes = vec![
                    //     0xf8, 0x6f, 0x80, 0x85, 0x04, 0xa8, 0x17, 0xc8,
                    //     0x00, 0x82, 0x52, 0x08, 0x94, 0x61, 0x45, 0x61,
                    //     0xd2, 0xd1, 0x43, 0x62, 0x1e, 0x12, 0x6e, 0x87,
                    //     0x83, 0x1a, 0xef, 0x28, 0x76, 0x78, 0xb4, 0x42,
                    //     0xb8, 0x88, 0x01, 0x63, 0x45, 0x78, 0x5d, 0x8a,
                    //     0x00, 0x80, 0x83, 0x60, 0x30, 0x6b, 0xa0, 0x58,
                    //     0x69, 0xd7, 0xb8, 0x41, 0x9e, 0xcb, 0x5d, 0x44,
                    //     0xf5, 0xe6, 0x2a, 0x0c, 0xfd, 0x8f, 0x55, 0x8e,
                    //     0x47, 0x71, 0xc9, 0x51, 0x08, 0xcc, 0x57, 0x60,
                    //     0xf5, 0xb0, 0xf5, 0xaf, 0x6f, 0x0a, 0xaa, 0xa0,
                    //     0x58, 0xd2, 0x13, 0xe2, 0xef, 0x9a, 0x74, 0x76,
                    //     0x1c, 0xf6, 0x27, 0xb7, 0x06, 0x16, 0x24, 0x67,
                    //     0xaa, 0x5d, 0xbb, 0x07, 0x27, 0x95, 0x76, 0x99,
                    //     0x6d, 0x7d, 0xed, 0x5e, 0x0a, 0xe2, 0x30, 0xb5
                    // ].into();


                  

                    // Open the file that contains your bytes
                    let mut file = File::open("transaction.bin").expect("Failed to open transaction file");

                    // Read all bytes from the file
                    let mut buffer = Vec::new();
                    file.read_to_end(&mut buffer).expect("Failed to read transaction file");

                    // Convert Vec<u8> into Bytes (same as before)
                    bytes = buffer.into();
                }

                // Send a copy to Geth for validation
                // send_to_geth(&bytes).await;


                if let Err(e) = transport.send(bytes).await {
                    warn!("Failed to send transaction: {}", e);
                    break 'main;
                }
            }
            if now.elapsed().as_millis() > BURST_DURATION as u128 {
                // NOTE: This log entry is used to compute performance.
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
