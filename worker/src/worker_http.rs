use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use hex::FromHex;
use serde::Deserialize;
use std::net::SocketAddr;
use store::Store;

use serde::Serialize;
// use axum::response::IntoResponse;
use crate::worker::WorkerMessage;




#[derive(Debug, Serialize)]
struct BatchJson {
    digest: String,
    txs: Vec<String>, // each is 0x-prefixed raw tx bytes
}


/// Key format: b"batch:" || 32-byte digest
fn batch_store_key(digest32: &[u8]) -> Vec<u8> {
    let mut k = b"batch:".to_vec();
    k.extend_from_slice(digest32);
    k
}



/// GET /batch/<digest_hex_without_0x>
/// Returns the raw serialized WorkerMessage::Batch(...) bytes
async fn get_batch(
    Path(dhex): Path<String>,
    State(mut store): State<Store>,
) -> Result<impl IntoResponse, StatusCode> {
    let digest = Vec::from_hex(dhex).map_err(|_| StatusCode::BAD_REQUEST)?;
    if digest.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }


        // 1) Try new key: "batch:" || keccak digest bytes
    let k1 = batch_store_key(&digest);
    match store.read(k1).await {
        Ok(Some(bytes)) => return Ok(bytes),
        Ok(None) => { /* fall through */ }
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    }

    // 2) Fallback: try raw digest bytes (in case it was stored without the "batch:" prefix)
    let k2 = digest.clone(); // same as digest.to_vec()
    match store.read(k2).await {
        Ok(Some(bytes)) => Ok(bytes),
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }

    // match store.read(batch_store_key(&digest)).await {
    //     Ok(Some(bytes)) => Ok(bytes),
    //     Ok(None) => Err(StatusCode::NOT_FOUND),
    //     Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    // }
}


async fn get_batch_json(
    axum::extract::Path(dhex): axum::extract::Path<String>,
    axum::extract::State(mut store): axum::extract::State<Store>,
) -> Result<impl IntoResponse, axum::http::StatusCode> {
    use axum::http::StatusCode;

    let digest = Vec::from_hex(&dhex).map_err(|_| StatusCode::BAD_REQUEST)?;
    if digest.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Use same lookup behavior as existing /batch route.
    let k1 = batch_store_key(&digest);
    let bytes = match store.read(k1).await {
        Ok(Some(b)) => b,
        Ok(None) => match store.read(digest.clone()).await {
            Ok(Some(b)) => b,
            Ok(None) => return Err(StatusCode::NOT_FOUND),
            Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
        },
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };

    // Decode WorkerMessage::Batch(Vec<Vec<u8>>)
    let wm: WorkerMessage =
        bincode::deserialize(&bytes).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let batch = match wm {
        WorkerMessage::Batch(b) => b,
        _ => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };

    let txs = batch
        .into_iter()
        .map(|tx| format!("0x{}", hex::encode(tx)))
        .collect::<Vec<_>>();

    // Ok(axum::Json(BatchJson { digest: dhex, txs }))
    Ok(axum::Json(BatchJson { digest: format!("0x{}", dhex), txs }))

}

/// Optional: sidecar can report execution results back to workers
#[derive(Debug, Deserialize)]
pub struct ExecResult {
    pub digest: String,          // "0x..."
    pub tx_hashes: Vec<String>,  // "0x..."
    pub success: bool,
    pub block_number: Option<u64>,
}

async fn post_exec_result(Json(r): Json<ExecResult>) -> StatusCode {
    eprintln!(
        "[worker_http] exec_result digest={} success={} txs={} block={:?}",
        r.digest,
        r.success,
        r.tx_hashes.len(),
        r.block_number
    );
    StatusCode::OK
}


pub fn spawn_worker_http(store: Store, addr: SocketAddr) {
    tokio::spawn(async move {
        let app = Router::new()
            .route("/batch/:digest", get(get_batch))
            .route("/exec_result", post(post_exec_result))
            .route("/batch_json/:digest", get(get_batch_json))
            .with_state(store);

        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Worker HTTP bind failed on {}: {}", addr, e);
                return;
            }
        };

        let _ = axum::serve(listener, app).await;
    });
}
