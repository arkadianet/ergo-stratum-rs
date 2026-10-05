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
//! ([`ExtraNonce::from_lane`]) splits the space so each worker grinds a disjoint
//! range; [`LanePool`] hands out lanes so no two *live* connections ever share one.
//!
//! Lane size matters: the miner's slice must outlast a job at its hashrate. A
//! 2-byte prefix leaves 2^48 nonces (~78 hours at 1 GH/s, ~4.7 minutes at
//! 1 TH/s); a 4-byte prefix leaves only 2^32 (~4.3 s at 1 GH/s), which starves
//! any modern rig.

use std::collections::HashSet;

/// Default pool prefix size: a 2-byte lane (65,536 concurrent lanes, each a
/// 48-bit search range — large enough for a whole rental-proxy connection).
pub const DEFAULT_PREFIX_BYTES: usize = 2;

/// Largest prefix the pool may take: the miner must always own ≥1 byte.
pub const MAX_PREFIX_BYTES: usize = 7;

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
            prefix_len: prefix_len.min(MAX_PREFIX_BYTES),
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

    /// Lane number `lane` under a `prefix_len`-byte prefix: the low `prefix_len`
    /// bytes of `lane`, big-endian, become the prefix (higher bits are ignored, so
    /// callers keep `lane < 256^prefix_len` — [`LanePool`] does).
    pub fn from_lane(lane: u64, prefix_len: usize) -> Self {
        let prefix_len = prefix_len.min(MAX_PREFIX_BYTES);
        let mut prefix = [0u8; 8];
        let be = lane.to_be_bytes();
        prefix[..prefix_len].copy_from_slice(&be[8 - prefix_len..]);
        Self { prefix, prefix_len }
    }

    /// The lane number this prefix encodes (inverse of [`ExtraNonce::from_lane`]).
    pub fn lane(&self) -> u64 {
        let mut be = [0u8; 8];
        be[8 - self.prefix_len..].copy_from_slice(&self.prefix[..self.prefix_len]);
        u64::from_be_bytes(be)
    }

    /// Bytes of the nonce owned by the pool.
    pub fn prefix_len(&self) -> usize {
        self.prefix_len
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

/// Allocator of non-overlapping lanes for live connections. A lane is reusable
/// only after [`LanePool::release`], so a long-lived connection can never be
/// handed a duplicate of its lane no matter how many others come and go (a bare
/// session counter wraps and collides).
#[derive(Debug)]
pub struct LanePool {
    prefix_len: usize,
    used: HashSet<u64>,
    next: u64,
}

impl LanePool {
    /// A pool of `prefix_len`-byte lanes (clamped to `1..=7`).
    pub fn new(prefix_len: usize) -> Self {
        Self {
            prefix_len: prefix_len.clamp(1, MAX_PREFIX_BYTES),
            used: HashSet::new(),
            next: 0,
        }
    }

    /// Total distinct lanes (`256^prefix_len`).
    pub fn capacity(&self) -> u64 {
        1u64 << (8 * self.prefix_len)
    }

    /// Lanes currently held.
    pub fn in_use(&self) -> usize {
        self.used.len()
    }

    /// Take the next free lane, round-robin from the last one handed out (so a
    /// just-released lane isn't immediately reused). `None` if every lane is held.
    pub fn acquire(&mut self) -> Option<ExtraNonce> {
        let cap = self.capacity();
        if self.used.len() as u64 >= cap {
            return None;
        }
        // At most `used.len()` probes can collide, so this terminates quickly.
        loop {
            let lane = self.next;
            self.next = (self.next + 1) % cap;
            if self.used.insert(lane) {
                return Some(ExtraNonce::from_lane(lane, self.prefix_len));
            }
        }
    }

    /// Return a lane to the pool.
    pub fn release(&mut self, lane: &ExtraNonce) {
        self.used.remove(&lane.lane());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_lane_satisfies_the_16_hex_char_contract() {
        let e = ExtraNonce::from_lane(0xBEEF, DEFAULT_PREFIX_BYTES);
        // 2-byte prefix -> 4 hex chars; miner owns the other 6 bytes (12 hex).
        assert_eq!(e.prefix_hex(), "beef");
        assert_eq!(e.extra_nonce2_bytes(), 6);
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
    fn lane_number_round_trips_and_high_bits_are_ignored() {
        let a = ExtraNonce::from_lane(0x1234_5678, 4);
        assert_eq!(a.prefix_hex(), "12345678");
        assert_eq!(a.lane(), 0x1234_5678);
        let b = ExtraNonce::from_lane(0xFFFF_0000_0000_1234, 2);
        assert_eq!(b.prefix_hex(), "1234");
        assert_eq!(b.lane(), 0x1234);
    }

    #[test]
    fn contains_accepts_in_lane_and_rejects_out_of_lane_nonces() {
        let e = ExtraNonce::from_lane(0x1122_3344, 4);
        // In lane: leading 4 bytes match 11223344, trailing 4 are the miner's.
        assert!(e.contains(&[0x11, 0x22, 0x33, 0x44, 0xAA, 0xBB, 0xCC, 0xDD]));
        // Out of lane: a different prefix is another worker's slice.
        assert!(!e.contains(&[0x11, 0x22, 0x33, 0x45, 0xAA, 0xBB, 0xCC, 0xDD]));
    }

    #[test]
    fn pool_never_hands_out_a_live_lane_twice() {
        let mut pool = LanePool::new(1); // 256 lanes
        let held: Vec<_> = (0..256).map(|_| pool.acquire().unwrap()).collect();
        let distinct: HashSet<u64> = held.iter().map(ExtraNonce::lane).collect();
        assert_eq!(distinct.len(), 256);
        assert!(pool.acquire().is_none(), "exhausted pool refuses");
        pool.release(&held[17]);
        let again = pool.acquire().expect("a released lane is reusable");
        assert_eq!(again.lane(), 17);
    }

    #[test]
    fn pool_skips_lanes_still_held_after_wrapping() {
        let mut pool = LanePool::new(1);
        let first = pool.acquire().unwrap(); // lane 0, held for the whole test
        for _ in 0..600 {
            let l = pool.acquire().unwrap();
            assert_ne!(l.lane(), first.lane(), "a held lane is never reissued");
            pool.release(&l);
        }
        assert_eq!(pool.in_use(), 1);
    }

    #[test]
    fn pool_prefix_is_clamped() {
        assert_eq!(LanePool::new(0).capacity(), 256);
        assert_eq!(LanePool::new(2).capacity(), 65_536);
        assert_eq!(LanePool::new(99).capacity(), 1u64 << 56);
    }
}
