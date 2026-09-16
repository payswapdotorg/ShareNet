//! SHA-256 (FIPS 180-4) — the ledger log's chain commitment.
//!
//! This is format machinery, NOT a general crypto service: the crate's
//! dependency law is `sharenet-protocol + std only`, and the reference
//! core does not re-export its `sha2` dependency. The append-only
//! revocation log chains its records with
//! `SHA-256("sharenet-revocation-chain-v1" || prev_chain || payload)`
//! (the domain-separation pattern of `derive_route_id`). The hash is
//! verified below against the FIPS 180-4 vectors and a Python-`hashlib`
//! oracle, and — critically — it is NOT the trust anchor of the format:
//! every record's payload is a *signed* `SignedCircuitRevocation`
//! envelope re-verified at load. The chain detects deletion, reordering
//! and replay of records; the signatures authenticate the records.
//! (An attacker who can *recompute* the chain can rewrite any unkeyed
//! local file — that limit is documented in the crate README.)

/// Domain-separation context for the ledger chain (house pattern:
/// `ROUTE_ID_CONTEXT` in the protocol core).
pub(crate) const CHAIN_CONTEXT: &[u8] = b"sharenet-revocation-chain-v1";

/// The FIPS 180-4 round constants (cube roots of the first 64 primes).
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// The SHA-256 compression function over one 64-byte block.
fn compress(state: &mut [u32; 8], block: &[u8]) {
    debug_assert_eq!(block.len(), 64);
    let mut w = [0u32; 64];
    for (i, chunk) in block.chunks_exact(4).enumerate() {
        w[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

/// A streaming SHA-256 hasher (the std-only local build of the standard).
#[derive(Clone)]
pub(crate) struct Sha256 {
    state: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

impl Sha256 {
    pub fn new() -> Self {
        Sha256 {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buf: [0u8; 64],
            buf_len: 0,
            total_len: 0,
        }
    }

    pub fn update(&mut self, mut bytes: &[u8]) {
        self.total_len = self.total_len.wrapping_add(bytes.len() as u64);
        if self.buf_len > 0 {
            let take = (64 - self.buf_len).min(bytes.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&bytes[..take]);
            self.buf_len += take;
            bytes = &bytes[take..];
            if self.buf_len == 64 {
                let block = self.buf;
                compress(&mut self.state, &block);
                self.buf_len = 0;
            }
        }
        while bytes.len() >= 64 {
            let (block, rest) = bytes.split_at(64);
            compress(&mut self.state, block);
            bytes = rest;
        }
        if !bytes.is_empty() {
            self.buf[..bytes.len()].copy_from_slice(bytes);
            self.buf_len = bytes.len();
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_len.wrapping_mul(8);
        // Padding: 0x80, zeros, 8-byte big-endian bit length.
        self.update(&[0x80]);
        while self.buf_len != 56 {
            self.update(&[0x00]);
        }
        // Bypass total_len bookkeeping for the length word itself.
        self.buf[56..64].copy_from_slice(&bit_len.to_be_bytes());
        compress(&mut self.state, &self.buf);
        let mut out = [0u8; 32];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

/// The ledger chain step: `SHA-256(CHAIN_CONTEXT || prev_chain || payload)`.
/// `prev_chain` for the first record is the all-zero genesis value.
pub(crate) fn chain_next(prev_chain: &[u8; 32], payload: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(CHAIN_CONTEXT);
    h.update(prev_chain);
    h.update(payload);
    h.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The one-shot hash (test-side helper over the streaming hasher).
    fn sha256(bytes: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(bytes);
        h.finalize()
    }

    /// FIPS 180-4 vectors + a Python-`hashlib` oracle for the boundary
    /// cases (63/64/65/127/128 bytes, multi-block, million-'a').
    #[test]
    fn sha256_matches_standard_vectors() {
        let a63 = "a".repeat(63);
        let a64 = "a".repeat(64);
        let a65 = "a".repeat(65);
        let a127 = "a".repeat(127);
        let a128 = "a".repeat(128);
        let cases: &[(&str, &str)] = &[
            (
                "",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                "abc",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
            (
                a63.as_str(),
                "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34",
            ),
            (
                a64.as_str(),
                "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb",
            ),
            (
                a65.as_str(),
                "635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0",
            ),
            (
                a127.as_str(),
                "c57e9278af78fa3cab38667bef4ce29d783787a2f731d4e12200270f0c32320a",
            ),
            (
                a128.as_str(),
                "6836cf13bac400e9105071cd6af47084dfacad4e5e302c94bfed24e013afb73e",
            ),
        ];
        for (input, want) in cases {
            assert_eq!(hex(&sha256(input.as_bytes())), *want, "input {input:?}");
        }
        let mixed: Vec<u8> = (0u8..=255).collect();
        assert_eq!(
            hex(&sha256(&mixed)),
            "40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880"
        );
        assert_eq!(
            hex(&sha256(&vec![b'a'; 1_000_000])),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    /// Streaming must equal one-shot at EVERY split point (buffer-boundary
    /// correctness — the property the chain relies on).
    #[test]
    fn streaming_matches_one_shot_at_every_split() {
        let data: Vec<u8> = (0u32..200).map(|i| (i * 37 + 11) as u8).collect();
        let want = sha256(&data);
        for split in 0..=data.len() {
            let mut h = Sha256::new();
            h.update(&data[..split]);
            h.update(&data[split..]);
            assert_eq!(h.finalize(), want, "split at {split}");
        }
        // many small updates
        let mut h = Sha256::new();
        for byte in &data {
            h.update(std::slice::from_ref(byte));
        }
        assert_eq!(h.finalize(), want);
    }

    /// The chain step is domain-separated and depends on both arguments.
    #[test]
    fn chain_step_is_domain_separated() {
        let a = chain_next(&[0u8; 32], b"payload");
        let b = chain_next(&[1u8; 32], b"payload");
        let c = chain_next(&[0u8; 32], b"payload2");
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
        // exact value pinned against the Python oracle:
        // hashlib.sha256(b"sharenet-revocation-chain-v1" + bytes(32) + b"hello")
        assert_eq!(
            hex(&chain_next(&[0u8; 32], b"hello")),
            "73fef33ae449522ae19d661a6c3d7dd1e0dd072bc5f953a2e83f67682d3d71cf"
        );
    }
}
