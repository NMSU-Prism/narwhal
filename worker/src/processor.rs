// Copyright(C) Facebook, Inc. and its affiliates.
use crate::worker::SerializedBatchDigestMessage;
use config::WorkerId;
use crypto::Digest;
use ed25519_dalek::Digest as _;
use ed25519_dalek::Sha512;
use primary::WorkerPrimaryMessage;
use std::convert::TryInto;
use store::Store;
use tokio::sync::mpsc::{Receiver, Sender};

// NEW: Ethereum digest + sidecar notify
use crate::eth_digest::keccak256;
use hex::ToHex;
use serde::Serialize;

#[cfg(test)]
#[path = "tests/processor_tests.rs"]
pub mod processor_tests;

/// Indicates a serialized `WorkerMessage::Batch` message.
pub type SerializedBatchMessage = Vec<u8>;

/// Hashes and stores batches, it then outputs the batch's digest.
pub struct Processor;

/// Key format: b"batch:" || 32-byte digest
fn batch_store_key(digest32: &[u8; 32]) -> Vec<u8> {
    let mut k = b"batch:".to_vec();
    k.extend_from_slice(digest32);
    k
}

#[derive(Serialize)]
struct SidecarDigestNotify {
    digest: String,  // "0x..."
    worker_id: u32,
}

async fn notify_sidecar_digest(digest32: [u8; 32], worker_id: WorkerId) {
    let base = match std::env::var("NARWHAL_SIDECAR_URL") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => return, // sidecar not configured
    };

    let msg = SidecarDigestNotify {
        digest: format!("0x{}", digest32.encode_hex::<String>()),
        worker_id: worker_id as u32,
    };

    // Best-effort notify; do not block consensus pipeline on failures.
    let _ = reqwest::Client::new()
        .post(format!("{}/digest", base.trim_end_matches('/')))
        .json(&msg)
        .send()
        .await;
}

impl Processor {
    pub fn spawn(
        // Our worker's id.
        id: WorkerId,
        // The persistent storage.
        mut store: Store,
        // Input channel to receive batches.
        mut rx_batch: Receiver<SerializedBatchMessage>,
        // Output channel to send out batches' digests.
        tx_digest: Sender<SerializedBatchDigestMessage>,
        // Whether we are processing our own batches or the batches of other nodes.
        own_digest: bool,
    ) {
        tokio::spawn(async move {
            while let Some(batch) = rx_batch.recv().await {
                // --------------------------------------------------------------------
                // (A) Ethereum-friendly digest (Keccak-256) + store for pull by digest
                // --------------------------------------------------------------------
                let eth_digest32 = keccak256(&batch);

                // Store under "batch:<eth_digest32>" so geth-sidecar/validators can pull later.
                // IMPORTANT: must store the exact bytes we later serve (no re-serialization).
                store.write(batch_store_key(&eth_digest32), batch.clone()).await;

                let k = batch_store_key(&eth_digest32);
                match store.read(k.clone()).await {
                    Ok(Some(_)) => eprintln!("[processor] STORED keccak=0x{}", eth_digest32.encode_hex::<String>()),
                    Ok(None) => eprintln!("[processor] ERROR wrote keccak but read-back NONE keccak=0x{}", eth_digest32.encode_hex::<String>()),
                    Err(e) => eprintln!("[processor] read-back error: {:?}", e),
                }
                                // Notify sidecar (digest only), best-effort.
                notify_sidecar_digest(eth_digest32, id).await;

                // --------------------------------------------------------------------
                // (B) Keep Narwhal's original behavior intact
                //     (Narwhal's crypto::Digest is Sha512-trunc(32))
                // --------------------------------------------------------------------
                let digest = Digest(
                    Sha512::digest(&batch).as_slice()[..32]
                        .try_into()
                        .unwrap(),
                );

                // Store the batch under Narwhal's original key too (unchanged behavior).
                // (Some Narwhal components may read batches using this digest key.)
                store.write(digest.to_vec(), batch).await;

                // Deliver the batch's digest to primary (unchanged).
                let message = match own_digest {
                    true => WorkerPrimaryMessage::OurBatch(digest, id),
                    false => WorkerPrimaryMessage::OthersBatch(digest, id),
                };

                let message = bincode::serialize(&message)
                    .expect("Failed to serialize our own worker-primary message");
                tx_digest
                    .send(message)
                    .await
                    .expect("Failed to send digest");
            }
        });
    }
}
