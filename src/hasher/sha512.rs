//! SHA-512 optimized for sBPF.
//!
//! Two paths, both using the same fully-unrolled 80-round compression:
//!
//! - Single-block fast path: buffer up to 111 bytes in a stack buffer, then
//!   run one compress with LLVM-folded round 0 (`state` starts at IVs). The
//!   brine-ed25519 hot path (R ‖ A ‖ short message) stays here.
//! - Streaming path: once total input passes the single-block ceiling we
//!   seed a running `[u64; 8]` state with the IVs and compress each complete
//!   128-byte block as it fills. Finalize pads the trailing block (splitting
//!   across two if data + 0x80 + length doesn't fit in one).

use crate::hasher::Hasher;

#[inline(always)]
const fn rotr(x: u64, n: u32) -> u64 {
    (x >> n) | (x << (64 - n))
}

#[inline(always)]
const fn gamma0(x: u64) -> u64 {
    rotr(x, 1) ^ rotr(x, 8) ^ (x >> 7)
}

#[inline(always)]
const fn gamma1(x: u64) -> u64 {
    rotr(x, 19) ^ rotr(x, 61) ^ (x >> 6)
}

#[inline(always)]
const fn ch(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (!x & z)
}

#[inline(always)]
const fn maj(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (x & z) ^ (y & z)
}

#[inline(always)]
const fn sigma0(x: u64) -> u64 {
    rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39)
}

#[inline(always)]
const fn sigma1(x: u64) -> u64 {
    rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41)
}

/// The 8 SHA-512 initialization vectors.
const IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

/// The 80 SHA-512 round constants.
const K: [u64; 80] = [
    0x428A2F98D728AE22,
    0x7137449123EF65CD,
    0xB5C0FBCFEC4D3B2F,
    0xE9B5DBA58189DBBC,
    0x3956C25BF348B538,
    0x59F111F1B605D019,
    0x923F82A4AF194F9B,
    0xAB1C5ED5DA6D8118,
    0xD807AA98A3030242,
    0x12835B0145706FBE,
    0x243185BE4EE4B28C,
    0x550C7DC3D5FFB4E2,
    0x72BE5D74F27B896F,
    0x80DEB1FE3B1696B1,
    0x9BDC06A725C71235,
    0xC19BF174CF692694,
    0xE49B69C19EF14AD2,
    0xEFBE4786384F25E3,
    0x0FC19DC68B8CD5B5,
    0x240CA1CC77AC9C65,
    0x2DE92C6F592B0275,
    0x4A7484AA6EA6E483,
    0x5CB0A9DCBD41FBD4,
    0x76F988DA831153B5,
    0x983E5152EE66DFAB,
    0xA831C66D2DB43210,
    0xB00327C898FB213F,
    0xBF597FC7BEEF0EE4,
    0xC6E00BF33DA88FC2,
    0xD5A79147930AA725,
    0x06CA6351E003826F,
    0x142929670A0E6E70,
    0x27B70A8546D22FFC,
    0x2E1B21385C26C926,
    0x4D2C6DFC5AC42AED,
    0x53380D139D95B3DF,
    0x650A73548BAF63DE,
    0x766A0ABB3C77B2A8,
    0x81C2C92E47EDAEE6,
    0x92722C851482353B,
    0xA2BFE8A14CF10364,
    0xA81A664BBC423001,
    0xC24B8B70D0F89791,
    0xC76C51A30654BE30,
    0xD192E819D6EF5218,
    0xD69906245565A910,
    0xF40E35855771202A,
    0x106AA07032BBD1B8,
    0x19A4C116B8D2D0C8,
    0x1E376C085141AB53,
    0x2748774CDF8EEB99,
    0x34B0BCB5E19B48A8,
    0x391C0CB3C5C95A63,
    0x4ED8AA4AE3418ACB,
    0x5B9CCA4F7763E373,
    0x682E6FF3D6B2B8A3,
    0x748F82EE5DEFB2FC,
    0x78A5636F43172F60,
    0x84C87814A1F0AB72,
    0x8CC702081A6439EC,
    0x90BEFFFA23631E28,
    0xA4506CEBDE82BDE9,
    0xBEF9A3F7B2C67915,
    0xC67178F2E372532B,
    0xCA273ECEEA26619C,
    0xD186B8C721C0C207,
    0xEADA7DD6CDE0EB1E,
    0xF57D4F7FEE6ED178,
    0x06F067AA72176FBA,
    0x0A637DC5A2C898A6,
    0x113F9804BEF90DAE,
    0x1B710B35131C471B,
    0x28DB77F523047D84,
    0x32CAAB7B40C72493,
    0x3C9EBE0A15C9BEBC,
    0x431D67C49C100D4C,
    0x4CC5D4BECB3E42B6,
    0x597F299CFC657E2A,
    0x5FCB6FAB3AD6FAEC,
    0x6C44198C4A475817,
];

/// One SHA-512 compression: reads a fully-padded 128-byte block and mutates
/// `state` in place. The 80 rounds are fully unrolled via a `round!` macro
/// invoked for each index 0..80.
#[inline(always)]
fn sha512_compress(state: &mut [u64; 8], block: &[u8; 128]) {
    // Every w[i] is written before read; skip the zero-init.
    let mut w_uninit: [core::mem::MaybeUninit<u64>; 80] =
        [const { core::mem::MaybeUninit::uninit() }; 80];
    for i in 0..16 {
        let off = i * 8;
        w_uninit[i].write(u64::from_be_bytes([
            block[off],
            block[off + 1],
            block[off + 2],
            block[off + 3],
            block[off + 4],
            block[off + 5],
            block[off + 6],
            block[off + 7],
        ]));
    }
    // SAFETY: above loop initialized w_uninit[0..16]; the next loop only
    // reads indices that have just been initialized.
    for i in 16..80 {
        let v = unsafe {
            w_uninit[i - 16]
                .assume_init()
                .wrapping_add(gamma0(w_uninit[i - 15].assume_init()))
                .wrapping_add(w_uninit[i - 7].assume_init())
                .wrapping_add(gamma1(w_uninit[i - 2].assume_init()))
        };
        w_uninit[i].write(v);
    }
    // SAFETY: all 80 entries are now initialized.
    let w: [u64; 80] = unsafe { core::mem::transmute(w_uninit) };

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];
    let mut t1: u64;
    let mut t2: u64;

    // One SHA-512 round. The standard shift pattern (h←g, g←f, …, a←t1+t2)
    // is encoded directly; `$i` picks K[i] and w[i].
    macro_rules! round {
        ($i:expr) => {
            t1 = h
                .wrapping_add(sigma1(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(K[$i])
                .wrapping_add(w[$i]);
            t2 = sigma0(a).wrapping_add(maj(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        };
    }

    // 80 rounds, fully unrolled.
    round!(0);
    round!(1);
    round!(2);
    round!(3);
    round!(4);
    round!(5);
    round!(6);
    round!(7);
    round!(8);
    round!(9);
    round!(10);
    round!(11);
    round!(12);
    round!(13);
    round!(14);
    round!(15);
    round!(16);
    round!(17);
    round!(18);
    round!(19);
    round!(20);
    round!(21);
    round!(22);
    round!(23);
    round!(24);
    round!(25);
    round!(26);
    round!(27);
    round!(28);
    round!(29);
    round!(30);
    round!(31);
    round!(32);
    round!(33);
    round!(34);
    round!(35);
    round!(36);
    round!(37);
    round!(38);
    round!(39);
    round!(40);
    round!(41);
    round!(42);
    round!(43);
    round!(44);
    round!(45);
    round!(46);
    round!(47);
    round!(48);
    round!(49);
    round!(50);
    round!(51);
    round!(52);
    round!(53);
    round!(54);
    round!(55);
    round!(56);
    round!(57);
    round!(58);
    round!(59);
    round!(60);
    round!(61);
    round!(62);
    round!(63);
    round!(64);
    round!(65);
    round!(66);
    round!(67);
    round!(68);
    round!(69);
    round!(70);
    round!(71);
    round!(72);
    round!(73);
    round!(74);
    round!(75);
    round!(76);
    round!(77);
    round!(78);
    round!(79);

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

/// SHA-512 compression on a fully-padded 128-byte block, starting from the
/// standard IVs (first and only block). Returns the 64-byte digest.
#[inline(always)]
fn sha512_compress_block(block: &[u8; 128]) -> [u8; 64] {
    let mut state = IV;
    sha512_compress(&mut state, block);
    let mut out = [0u8; 64];
    for i in 0..8 {
        out[i * 8..(i + 1) * 8].copy_from_slice(&state[i].to_be_bytes());
    }
    out
}

/// SHA-512 hasher with two paths:
///
/// - Single-block fast path: accumulate up to 111 bytes in `buffer`, then
///   run one unrolled compress. The common ed25519 challenge case
///   (R ‖ A ‖ short message) stays entirely on this path.
/// - Streaming path: on overflow, flush accumulated bytes into `state` via
///   one compress, then process subsequent complete 128-byte blocks as they
///   arrive. `buffer` holds the current partial-block tail throughout.
///
/// State is always kept live so finalize has a uniform code path.
pub struct Sha512 {
    // Partial block buffer. During the fast path this holds the entire
    // message so far (up to 111 bytes). After overflow it holds the current
    // block-aligned tail (0..128 bytes).
    buffer: [u8; 128],
    // Bytes currently in `buffer`.
    buffer_len: usize,
    // Total bytes consumed by `update` so far.
    total_len: u64,
    // Running state once streaming has started. `None` while we can still
    // stay on the single-block fast path.
    state: Option<[u64; 8]>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest as _;

    fn reference(input: &[u8]) -> [u8; 64] {
        sha2::Sha512::digest(input).into()
    }

    #[test]
    fn hasher_single_block_matches_sha2() {
        let mut buf = [0u8; 112];
        for &n in &[0usize, 1, 31, 32, 55, 56, 75, 111] {
            for (i, b) in buf.iter_mut().enumerate().take(n) {
                *b = i as u8;
            }
            let input = &buf[..n];
            let mut h = Sha512::new();
            h.update(input);
            assert_eq!(h.finalize(), reference(input), "len {n}");
        }
    }

    #[test]
    fn hasher_multi_update_matches_sha2() {
        let r = [0x11u8; 32];
        let a = [0x22u8; 32];
        let m: &[u8] = b"hello world";
        let mut h = Sha512::new();
        h.update(&r);
        h.update(&a);
        h.update(m);
        let mut ref_hasher = sha2::Sha512::new();
        ref_hasher.update(r);
        ref_hasher.update(a);
        ref_hasher.update(m);
        let expected: [u8; 64] = ref_hasher.finalize().into();
        assert_eq!(h.finalize(), expected);
    }

    #[test]
    fn hasher_multi_block_matches_sha2() {
        // Cover lengths that exercise: single-block ceiling, exact block
        // boundaries, and the two-block-padding branch (len mod 128 in
        // [112, 127]).
        let sizes: &[usize] = &[
            111, 112, 119, 120, 127, 128, 129, 191, 200, 255, 256, 384, 500,
        ];
        let mut input = [0u8; 512];
        for (i, b) in input.iter_mut().enumerate() {
            *b = ((i as u64).wrapping_mul(2654435761) as u8) ^ 0x5a;
        }
        for &n in sizes {
            let mut h = Sha512::new();
            h.update(&input[..n]);
            assert_eq!(
                h.finalize(),
                reference(&input[..n]),
                "single-update len {n}"
            );
        }
    }

    #[test]
    fn hasher_chunked_updates_match_sha2() {
        let mut input = [0u8; 400];
        for (i, b) in input.iter_mut().enumerate() {
            *b = (i * 13 + 7) as u8;
        }
        // Split across many arbitrary chunks, forcing the boundary to land
        // in different places relative to block alignment.
        let splits: &[&[usize]] = &[
            &[32, 64, 96, 150, 400],
            &[1, 127, 128, 255, 400],
            &[50, 100, 150, 200, 250, 300, 350, 400],
            &[400],
        ];
        for split in splits {
            let mut h = Sha512::new();
            let mut cursor = 0;
            for &end in *split {
                h.update(&input[cursor..end]);
                cursor = end;
            }
            assert_eq!(h.finalize(), reference(&input[..cursor]), "split {split:?}");
        }
    }

    /// Fuzz `Sha512` against `sha2::Sha512` over random lengths and
    /// contents, with randomly-sized update chunks. Mirrors the scalar
    /// module's fuzz-against-dalek pattern (long-running, ignored by default).
    ///
    /// Run with: `cargo test --release --lib sha512_bpf::tests::fuzz_against_sha2 -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn fuzz_against_sha2() {
        use rand::rngs::{OsRng, StdRng};
        use rand::{RngCore, SeedableRng};

        const CASES: u64 = 1_000_000;
        // Lengths drawn from this upper bound so we exercise 0, single-block
        // (≤ 111), 2-block (≤ 239), and many-block paths.
        const MAX_LEN: usize = 1024;

        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let mut rng = StdRng::from_seed(seed);

        let mut input = [0u8; MAX_LEN];

        for case in 0..CASES {
            // Random length in [0, MAX_LEN].
            let n = (rng.next_u32() as usize) % (MAX_LEN + 1);
            rng.fill_bytes(&mut input[..n]);

            // Reference: sha2 in one shot.
            let expected = reference(&input[..n]);

            // 1. One-shot Sha512.
            {
                let mut h = Sha512::new();
                h.update(&input[..n]);
                assert_eq!(
                    h.finalize(),
                    expected,
                    "one-shot mismatch: case {case} len {n} seed {seed:?}"
                );
            }

            // 2. Sha512 with random chunk splits.
            {
                let mut h = Sha512::new();
                let mut cursor = 0;
                while cursor < n {
                    let remaining = n - cursor;
                    // Chunk size in [1, remaining], biased small to produce
                    // many splits when the message is long.
                    let max_chunk = remaining.min(200);
                    let chunk = ((rng.next_u32() as usize) % max_chunk) + 1;
                    h.update(&input[cursor..cursor + chunk]);
                    cursor += chunk;
                }
                assert_eq!(
                    h.finalize(),
                    expected,
                    "chunked mismatch: case {case} len {n} seed {seed:?}"
                );
            }
        }
    }
}

impl Hasher for Sha512 {
    #[inline(always)]
    fn new() -> Self {
        Self {
            buffer: [0u8; 128],
            buffer_len: 0,
            total_len: 0,
            state: None,
        }
    }

    #[inline(always)]
    fn update(&mut self, mut bytes: &[u8]) {
        // Fast path: stay single-block until we exceed 111 accumulated bytes.
        // The ed25519 hot path (R ‖ A ‖ short message) stays here. We skip
        // the total_len bookkeeping entirely here since the total is just
        // `buffer_len` whenever `state` is still None.
        if self.state.is_none() {
            if self.buffer_len + bytes.len() <= 111 {
                self.buffer[self.buffer_len..self.buffer_len + bytes.len()].copy_from_slice(bytes);
                self.buffer_len += bytes.len();
                return;
            }
            // Transition to streaming. Seed total_len with everything we
            // already have buffered; the streaming branch below accounts for
            // the rest.
            self.state = Some(IV);
            self.total_len = self.buffer_len as u64;
        }

        self.total_len = self.total_len.wrapping_add(bytes.len() as u64);

        // Streaming path: fill `buffer` 128 bytes at a time, compressing each
        // full block. Any tail < 128 stays in `buffer` for the next call.
        let state = self.state.as_mut().unwrap();
        while !bytes.is_empty() {
            let take = (128 - self.buffer_len).min(bytes.len());
            self.buffer[self.buffer_len..self.buffer_len + take].copy_from_slice(&bytes[..take]);
            self.buffer_len += take;
            bytes = &bytes[take..];
            if self.buffer_len == 128 {
                sha512_compress(state, &self.buffer);
                self.buffer_len = 0;
            }
        }
    }

    #[inline(always)]
    fn finalize(mut self) -> [u8; 64] {
        match self.state {
            None => {
                // Pure single-block case — total length is implicit in buffer_len.
                // Pad in place (bytes after buffer_len are zero from `new`).
                self.buffer[self.buffer_len] = 0x80;
                let bit_len = (self.buffer_len as u64).wrapping_mul(8);
                self.buffer[120..128].copy_from_slice(&bit_len.to_be_bytes());
                sha512_compress_block(&self.buffer)
            }
            Some(mut state) => {
                // Streaming: pad the current partial block and finalize.
                let mut block = [0u8; 128];
                block[..self.buffer_len].copy_from_slice(&self.buffer[..self.buffer_len]);
                block[self.buffer_len] = 0x80;
                let bit_len_be = self.total_len.wrapping_mul(8).to_be_bytes();

                if self.buffer_len <= 111 {
                    block[120..128].copy_from_slice(&bit_len_be);
                    sha512_compress(&mut state, &block);
                } else {
                    sha512_compress(&mut state, &block);
                    let mut tail = [0u8; 128];
                    tail[120..128].copy_from_slice(&bit_len_be);
                    sha512_compress(&mut state, &tail);
                }

                let mut out = [0u8; 64];
                for i in 0..8 {
                    out[i * 8..(i + 1) * 8].copy_from_slice(&state[i].to_be_bytes());
                }
                out
            }
        }
    }
}
