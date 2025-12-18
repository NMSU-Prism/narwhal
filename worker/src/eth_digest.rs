use tiny_keccak::{Hasher, Keccak};

/// Ethereum-friendly digest: Keccak-256.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut k = Keccak::v256();
    k.update(data);
    k.finalize(&mut out);
    out
}
