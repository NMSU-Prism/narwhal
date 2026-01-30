use axum::{routing::post, Json, Router};
use anyhow::Context;
use hex::FromHex;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Keccak};
use tokio::sync::mpsc;
use std::net::SocketAddr;


use tokio::time::{sleep, Duration};

// Must match worker's serialized enum variant names/layout for Batch.
// Keep this minimal: we only decode Batch.
type Transaction = Vec<u8>;
type Batch = Vec<Transaction>;

#[derive(Debug, Serialize, Deserialize)]
pub enum WorkerMessage {
    Batch(Batch),
}

#[derive(Debug, Clone, Deserialize)]
struct DigestNotify {
    digest: String,   // "0x..."
    worker_id: u32,
}

#[derive(Debug, Serialize)]
struct ExecResult {
    digest: String,
    tx_hashes: Vec<String>,
    success: bool,
    block_number: Option<u64>,
}

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut k = Keccak::v256();
    k.update(data);
    k.finalize(&mut out);
    out
}

async fn post_digest(
    axum::extract::State(tx): axum::extract::State<mpsc::Sender<DigestNotify>>,
    Json(msg): Json<DigestNotify>,
) -> &'static str {
    let _ = tx.send(msg).await;
    "ok"
}

async fn fetch_batch_from_workers(
    client: &reqwest::Client,
    workers: &[String],
    digest32: &[u8; 32],
) -> anyhow::Result<Vec<u8>> {
    let dhex = hex::encode(digest32); // <-- IMPORTANT: no 0x

    for w in workers {
        let url = format!("{}/batch/{}", w.trim_end_matches('/'), dhex);

        eprintln!("[sidecar] GET {}", url);

        let resp = client.get(&url).send().await?;
        let status = resp.status();

        if status.is_success() {
            let bytes = resp.bytes().await?;
            eprintln!("[sidecar] OK {} bytes from {}", bytes.len(), url);
            return Ok(bytes.to_vec());
        } else {
            let body = resp.text().await.unwrap_or_default();
            eprintln!("[sidecar] FAIL {} status={} body={}", url, status, body);
        }
    }

    anyhow::bail!("batch not found on any worker");
}


async fn geth_send_raw_tx(client: &Client, rpc: &str, raw_tx: &[u8]) -> anyhow::Result<String> {
    let raw_hex = format!("0x{}", hex::encode(raw_tx));
    let body = serde_json::json!({
        "jsonrpc":"2.0",
        "id": 1,
        "method":"eth_sendRawTransaction",
        "params":[raw_hex]
    });

    let resp = client.post(rpc).json(&body).send().await?;
    let v: serde_json::Value = resp.json().await?;

    if let Some(e) = v.get("error") {
        anyhow::bail!("geth error: {}", e);
    }
    Ok(v["result"].as_str().unwrap_or_default().to_string())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Env:
    // WORKERS="http://127.0.0.1:7100,http://127.0.0.1:7101"
    // GETH_RPC="http://127.0.0.1:8545"
    // POST_RESULTS_TO="http://127.0.0.1:7100" (optional)

    let workers_env = std::env::var("WORKERS").unwrap_or_default();
    let workers: Vec<String> = workers_env
        .split(',')
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().to_string())
        .collect();
    anyhow::ensure!(!workers.is_empty(), "WORKERS env is empty");

    eprintln!("[sidecar] WORKERS env raw = {:?}", workers_env);
    eprintln!("[sidecar] WORKERS parsed = {:?}", workers);
    


    let geth_rpc = std::env::var("GETH_RPC").unwrap_or_else(|_| "http://127.0.0.1:8545".to_string());
    // let geth_rpc = std::env::var("GETH_RPC").unwrap_or_else(|_| "http://127.0.0.1:32771".to_string());
    println!("[sidecar] GETH_RPC = {}", geth_rpc);
    let post_results_to = std::env::var("POST_RESULTS_TO").ok();

    let (tx, mut rx) = mpsc::channel::<DigestNotify>(100_000);
    let client = Client::new();

    // Background executor loop
    let workers_bg = workers.clone();
    let geth_rpc_bg = geth_rpc.clone();
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {

            eprintln!("[sidecar] got digest {} worker_id={}", msg.digest, msg.worker_id);

            // parse digest
            let s = msg.digest.strip_prefix("0x").unwrap_or(&msg.digest);
            let dbytes = match Vec::from_hex(s) {
                Ok(b) => b,
                Err(_) => continue,
            };
            if dbytes.len() != 32 { continue; }
            let mut digest32 = [0u8; 32];
            digest32.copy_from_slice(&dbytes);

            // pull raw batch bytes
            // let batch_bytes = match fetch_batch_from_workers(&client, &workers_bg, &digest32).await {
            //     Ok(b) => b,
            //     Err(_) => continue,
            // };

            let batch_bytes = match fetch_batch_from_workers(&client, &workers_bg, &digest32).await {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("[sidecar] fetch_batch_from_workers failed for {}: {}", msg.digest, e);
                    continue;
                }
            };


            eprintln!("[sidecar] fetched batch bytes len={} for digest {}", batch_bytes.len(), msg.digest);


            // verify hash
            if keccak256(&batch_bytes) != digest32 {
                continue;
            }

            eprintln!("[sidecar] hash verified {}", msg.digest);

            // decode
            let wm: WorkerMessage = match bincode::deserialize(&batch_bytes) {
                Ok(x) => x,
                Err(_) => continue,
            };
            let batch = match wm { WorkerMessage::Batch(b) => b };

            eprintln!("[sidecar] decoded batch: {} txs", batch.len());




            // execute: push each raw tx to geth
            let mut ok = true;
            let mut tx_hashes = Vec::with_capacity(batch.len());
            let send_to_geth = false;


            for (i, tx_bytes) in batch.iter().enumerate() {
            if send_to_geth {
                match geth_send_raw_tx(&client, &geth_rpc_bg, tx_bytes).await {
                    Ok(h) if !h.is_empty() => {
                        eprintln!("[sidecar] geth accepted tx[{}] hash={}", i, h);
                        tx_hashes.push(h);
                    }
                    Err(e) => {
                        eprintln!("[sidecar] geth rejected tx[{}]: {}", i, e);
                        ok = false;
                    }
                    _ => {
                        eprintln!("[sidecar] geth returned empty hash for tx[{}]", i);
                        ok = false;
                    }
                }
            } else {
                eprintln!(
                    "[sidecar] DRY-RUN tx[{}] len={} (send disabled)",
                    i,
                    tx_bytes.len()
                );
            }
        }

            // for (i, tx_bytes) in batch.iter().enumerate() {

            //     eprintln!("[sidecar] tx_bytes[0..8]={:02x?} len={}", &tx_bytes[..tx_bytes.len().min(8)], tx_bytes.len());
            //     match geth_send_raw_tx(&client, &geth_rpc_bg, tx_bytes).await {
            //         Ok(h) if !h.is_empty() => {
            //             eprintln!("[sidecar] geth accepted tx[{}] hash={}", i, h);
            //             tx_hashes.push(h);
            //         }
            //         Err(e) => {
            //             eprintln!("[sidecar] geth rejected tx[{}]: {}", i, e);
            //             ok = false;
            //         }
            //         _ => {
            //             eprintln!("[sidecar] geth returned empty hash for tx[{}]", i);
            //             ok = false;
            //         }
            //     }
            // }
            eprintln!("[sidecar] geth submit summary: ok={} hashes={}", ok, tx_hashes.len());


            // optional: send result back
            if let Some(base) = post_results_to.as_ref() {
                let res = ExecResult {
                    digest: msg.digest.clone(),
                    tx_hashes: tx_hashes.clone(),
                    success: ok,
                    block_number: None,
                };

                let url = format!("{}/exec_result", base.trim_end_matches('/'));
                let mut last_err = None;

                for _ in 0..5 {
                    match client.post(&url).json(&res).send().await {
                        Ok(r) => {
                            eprintln!("[sidecar] posted exec_result to {} status={}", url, r.status());
                            last_err = None;
                            break;
                        }
                        Err(e) => {
                            last_err = Some(e.to_string());
                            sleep(Duration::from_millis(200)).await;
                        }
                    }
                }

                if let Some(e) = last_err {
                    eprintln!("[sidecar] failed to post exec_result to {} after retries: {}", url, e);
                }

               
            }

        }
    });

    let client = Client::builder()
                .timeout(std::time::Duration::from_secs(2))
                .build()?;


    // Sidecar HTTP server (Narwhal pushes digest here)
    let app = Router::new()
        .route("/digest", post(post_digest))
        .with_state(tx);

    let addr = SocketAddr::from(([0, 0, 0, 0], 9051));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .context("bind sidecar :9051")?;
    axum::serve(listener, app).await?;

    Ok(())
}
