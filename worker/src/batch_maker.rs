// Copyright(C) Facebook, Inc. and its affiliates.
use crate::quorum_waiter::QuorumWaiterMessage;
use crate::worker::WorkerMessage;
use bytes::Bytes;
#[cfg(feature = "benchmark")]
use crypto::Digest;
use crypto::PublicKey;
#[cfg(feature = "benchmark")]
use ed25519_dalek::{Digest as _, Sha512};
#[cfg(feature = "benchmark")]
use log::info;
use network::ReliableSender;
#[cfg(feature = "benchmark")]
use std::convert::TryInto as _;
use std::net::SocketAddr;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::{sleep, Duration, Instant};
use std::process::Command;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::path::PathBuf;
use std::fs;



#[cfg(test)]
#[path = "tests/batch_maker_tests.rs"]
pub mod batch_maker_tests;

pub type Transaction = Vec<u8>;
pub type Batch = Vec<Transaction>;

/// Assemble clients transactions into batches.
pub struct BatchMaker {
    /// The preferred batch size (in bytes).
    batch_size: usize,
    /// The maximum delay after which to seal the batch (in ms).
    max_batch_delay: u64,
    /// Channel to receive transactions from the network.
    rx_transaction: Receiver<Transaction>,
    /// Output channel to deliver sealed batches to the `QuorumWaiter`.
    tx_message: Sender<QuorumWaiterMessage>,
    /// The network addresses of the other workers that share our worker id.
    workers_addresses: Vec<(PublicKey, SocketAddr)>,
    /// Holds the current batch.
    current_batch: Batch,
    /// Holds the size of the current batch (in bytes).
    current_batch_size: usize,
    /// A network sender to broadcast the batches to the other workers.
    network: ReliableSender,
}

impl BatchMaker {
    pub fn spawn(
        batch_size: usize,
        max_batch_delay: u64,
        rx_transaction: Receiver<Transaction>,
        tx_message: Sender<QuorumWaiterMessage>,
        workers_addresses: Vec<(PublicKey, SocketAddr)>,
    ) {
        tokio::spawn(async move {
            Self {
                batch_size,
                max_batch_delay,
                rx_transaction,
                tx_message,
                workers_addresses,
                current_batch: Batch::with_capacity(batch_size * 2),
                current_batch_size: 0,
                network: ReliableSender::new(),
            }
            .run()
            .await;
        });
    }

    /// Main loop receiving incoming transactions and creating batches.
    async fn run(&mut self) {

        println!("BatchMaker running");
        let timer = sleep(Duration::from_millis(self.max_batch_delay));
        tokio::pin!(timer);

        loop {
            tokio::select! {
                // Assemble client transactions into batches of preset size.
                Some(transaction) = self.rx_transaction.recv() => {

                //new command
                fn run_go_benchmark() {
                // Build and execute the command
                let output = Command::new("go")
                    .arg("test")
                    .arg("-run=^$")
                    .arg("-bench=^BenchmarkEVM$")
                    .arg("-benchmem")
                    .arg("-count=1")
                    .current_dir("/home/santoshadhikari/go-ethereum/tests") // set working dir
                    .output() // blocks until command finishes
                    .expect("Failed to run Go benchmark");

                        // Print results
                        println!("Go benchmark completed with status: {}", output.status);
                        println!("--- STDOUT ---\n{}", String::from_utf8_lossy(&output.stdout));
                        eprintln!("--- STDERR ---\n{}", String::from_utf8_lossy(&output.stderr));

               
                       // let mut file = File::create("/home/santoshadhikari/go-ethereum/tests/output.log"); // Creates or overwrites the file
                       // writeln!(file, "executed successfully")?;

                          let output_dir = PathBuf::from("/home/santoshadhikari/go-ethereum/tests/output");
                            let output_file_path = output_dir.join("output3.txt");
                            //test
                            // Ensure directory exists
                            if let Err(e) = fs::create_dir_all(&output_dir) {
                                eprintln!("❌ Failed to create directory {:?}: {}", output_dir, e);
                                return;
                            }

                            println!("Attempting to write to {:?}", output_file_path);

                            let file = match File::create(&output_file_path) {
                                Ok(f) => f,
                                Err(e) => {
                                    eprintln!("❌ Failed to create file {:?}: {}", output_file_path, e);
                                    return;
                                }
                            };

                            let mut writer = BufWriter::new(file);

                            if let Err(e) = writeln!(writer, "Hello, World!") {
                                eprintln!("❌ Failed to write to file: {}", e);
                                return;
                            }

                            if let Err(e) = writer.flush() {
                                eprintln!("❌ Failed to flush writer: {}", e);
                                return;
                            }

                        // Check success
                        if !output.status.success() {
                            panic!("Go benchmark failed!");
                        }

                        // Continue execution here only after benchmark completes successfully
                        println!("Continuing execution after Go benchmark...");
                }
                run_go_benchmark(); // <-- Now calls the globally defined function
                println!("Now executing next part...");





                    self.current_batch_size += transaction.len();
                    self.current_batch.push(transaction);
                    if self.current_batch_size >= self.batch_size {
                        self.seal().await;
                        timer.as_mut().reset(Instant::now() + Duration::from_millis(self.max_batch_delay));
                    }
                },

                // If the timer triggers, seal the batch even if it contains few transactions.
                () = &mut timer => {
                    if !self.current_batch.is_empty() {
                        self.seal().await;
                    }
                    timer.as_mut().reset(Instant::now() + Duration::from_millis(self.max_batch_delay));
                }
            }

            // Give the change to schedule other tasks.
            tokio::task::yield_now().await;
        }
    }

    /// Seal and broadcast the current batch.
    async fn seal(&mut self) {
        #[cfg(feature = "benchmark")]
        let size = self.current_batch_size;

        // Look for sample txs (they all start with 0) and gather their txs id (the next 8 bytes).
        #[cfg(feature = "benchmark")]
        let tx_ids: Vec<_> = self
            .current_batch
            .iter()
            .filter(|tx| tx[0] == 0u8 && tx.len() > 8)
            .filter_map(|tx| tx[1..9].try_into().ok())
            .collect();

        // Serialize the batch.
        self.current_batch_size = 0;
        let batch: Vec<_> = self.current_batch.drain(..).collect();
        let message = WorkerMessage::Batch(batch);
        let serialized = bincode::serialize(&message).expect("Failed to serialize our own batch");

        #[cfg(feature = "benchmark")]
        {
            // NOTE: This is one extra hash that is only needed to print the following log entries.
            let digest = Digest(
                Sha512::digest(&serialized).as_slice()[..32]
                    .try_into()
                    .unwrap(),
            );

            for id in tx_ids {
                // NOTE: This log entry is used to compute performance.
                info!(
                    "Batch {:?} contains sample tx {}",
                    digest,
                    u64::from_be_bytes(id)
                );
            }

            // NOTE: This log entry is used to compute performance.
            info!("Batch {:?} contains {} B", digest, size);
        }

        // Broadcast the batch through the network.
        let (names, addresses): (Vec<_>, _) = self.workers_addresses.iter().cloned().unzip();
        let bytes = Bytes::from(serialized.clone());
        let handlers = self.network.broadcast(addresses, bytes).await;

        // Send the batch through the deliver channel for further processing.
        self.tx_message
            .send(QuorumWaiterMessage {
                batch: serialized,
                handlers: names.into_iter().zip(handlers.into_iter()).collect(),
            })
            .await
            .expect("Failed to deliver batch");
    }
}
