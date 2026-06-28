//! Per-connection nonce partitioning (`extraNonce`).
//!
//! Autolykos2 nonces are 8 bytes. Under the EthereumStratum/1.0.0 dialect the pool
//! hands each connection an **extraNonce1** prefix and tells the miner how many
//! trailing bytes (**extraNonce2**) it owns; the miner only searches its own
//! slice, so two workers never grind the same nonce. On submit the miner returns
//! the *full* 8-byte nonce, and the pool checks the prefix still matches its
//! assignment (a worker can't claim a share mined outside its lane).
//!
//! Wire contract with `gpu-mining-rs`: `prefix_hex_chars + extraNonce2_bytes*2 ==
//! 16`. An empty prefix ([`ExtraNonce::whole`]) hands the miner the entire 8-byte
//! space (extraNonce2 = 8 bytes) — the no-partition policy. A non-empty prefix
//! (e.g. [`ExtraNonce::from_session_id`], a 4-byte lane) splits the space so each
//! worker grinds a disjoint range.

/// Default pool prefix size: a 4-byte lane (2^32 workers, each a 32-bit search
/// range) — the natural split `gpu-mining-rs` expects.
pub const DEFAULT_PREFIX_BYTES: usize = 4;

/// A connection's assigned nonce lane: a prefix of `prefix_len` bytes the pool
/// owns, with the remaining `8 - prefix_len` bytes searched by the miner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExtraNonce {
    prefix: [u8; 8],
    /// Bytes of `prefix` that are the pool assignment (`0..=7`).
    prefix_len: usize,
}

impl ExtraNonce {
    /// A lane from an explicit prefix; only the first `prefix_len` bytes matter.
    /// `prefix_len` is clamped to `0..=7` so the miner always owns ≥1 byte.
    pub fn new(prefix: [u8; 8], prefix_len: usize) -> Self {
        Self {
            prefix,
            prefix_len: prefix_len.min(7),
        }
    }

    /// The whole-space lane: empty prefix, miner owns all 8 nonce bytes (no
    /// partitioning). Valid on the wire (extraNonce1 = "", extraNonce2 = 8 bytes).
    pub fn whole() -> Self {
        Self {
            prefix: [0u8; 8],
            prefix_len: 0,
        }
    }

    /// Derive a [`DEFAULT_PREFIX_BYTES`]-byte lane from a pool-assigned session id
    /// (its low bytes, big-endian, become the prefix). Session ids unique mod
    /// `2^32` give non-overlapping lanes; the daemon's monotonic counter ensures
    /// that.
    pub fn from_session_id(session_id: u64) -> Self {
        let mut prefix = [0u8; 8];
        let id_be = session_id.to_be_bytes();
        prefix[..DEFAULT_PREFIX_BYTES].copy_from_slice(&id_be[8 - DEFAULT_PREFIX_BYTES..]);
        Self {
            prefix,
            prefix_len: DEFAULT_PREFIX_BYTES,
        }
    }

    /// The extraNonce1 hex string advertised to the miner (empty for [`whole`]).
    pub fn prefix_hex(&self) -> String {
        hex::encode(&self.prefix[..self.prefix_len])
    }

    /// The number of trailing bytes the miner controls (extraNonce2 size).
    pub fn extra_nonce2_bytes(&self) -> usize {
        8 - self.prefix_len
    }

    /// Whether a submitted full nonce lies in this connection's lane (its leading
    /// bytes match the assigned prefix). Always true for [`whole`].
    pub fn contains(&self, nonce: &[u8; 8]) -> bool {
        nonce[..self.prefix_len] == self.prefix[..self.prefix_len]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_lane_satisfies_the_16_hex_char_contract() {
        let e = ExtraNonce::from_session_id(0xDEAD_BEEF);
        // 4-byte prefix -> 8 hex chars; miner owns the other 4 bytes (8 hex). 16 total.
        assert_eq!(e.prefix_hex(), "deadbeef");
        assert_eq!(e.prefix_hex().len() + e.extra_nonce2_bytes() * 2, 16);
    }

    #[test]
    fn whole_lane_is_empty_prefix_full_space_and_contains_everything() {
        let e = ExtraNonce::whole();
        assert_eq!(e.prefix_hex(), "");
        assert_eq!(e.extra_nonce2_bytes(), 8);
        assert_eq!(e.prefix_hex().len() + e.extra_nonce2_bytes() * 2, 16);
        assert!(e.contains(&[0xFF; 8]));
        assert!(e.contains(&[0x00; 8]));
    }

    #[test]
    fn high_session_bits_are_ignored_only_low_prefix_bytes_form_the_lane() {
        let a = ExtraNonce::from_session_id(0x0000_0001_1234_5678);
        let b = ExtraNonce::from_session_id(0xFFFF_FFFF_1234_5678);
        assert_eq!(a.prefix_hex(), "12345678");
        assert_eq!(a.prefix_hex(), b.prefix_hex());
    }

    #[test]
    fn contains_accepts_in_lane_and_rejects_out_of_lane_nonces() {
        let e = ExtraNonce::from_session_id(0x1122_3344);
        // In lane: leading 4 bytes match 11223344, trailing 4 are the miner's.
        assert!(e.contains(&[0x11, 0x22, 0x33, 0x44, 0xAA, 0xBB, 0xCC, 0xDD]));
        // Out of lane: a different prefix is another worker's slice.
        assert!(!e.contains(&[0x11, 0x22, 0x33, 0x45, 0xAA, 0xBB, 0xCC, 0xDD]));
    }
}
