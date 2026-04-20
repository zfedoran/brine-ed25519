//! Small scalar helpers for this crate.
//!
//! On Solana we avoid `curve25519-dalek` for scalar handling too, so this
//! module provides the two pieces we still need for verification:
//! checking that `s` is a canonical Ed25519 scalar, and reducing the 64-byte
//! SHA-512 challenge modulo the group order.
//!
//! In the local SBF tests for this crate, moving this logic out of
//! `curve25519-dalek` dropped verify cost from roughly 27k CU to
//! about 23.7k-23.9k CU.
//!
//! Host builds still use `curve25519-dalek` as the reference implementation so
//! tests and off-chain callers stay aligned with the Solana path.

#[cfg(not(any(target_arch = "bpf", target_os = "solana")))]
pub(crate) fn scalar_from_bytes_mod_order_wide(input: &[u8; 64]) -> [u8; 32] {
    curve25519_dalek::scalar::Scalar::from_bytes_mod_order_wide(input).to_bytes()
}

#[cfg(any(target_arch = "bpf", target_os = "solana"))]
pub(crate) fn scalar_from_bytes_mod_order_wide(input: &[u8; 64]) -> [u8; 32] {
    barrett32::scalar_from_bytes_mod_order_wide(input)
}

#[cfg(any(target_arch = "bpf", target_os = "solana", test))]
mod barrett32 {
    /// Ed25519 group order L as 8 × u32 limbs (little-endian).
    const L: [u32; 8] = [
        0x5cf5d3ed, 0x5812631a, 0xa2f79cd6, 0x14def9de,
        0x00000000, 0x00000000, 0x00000000, 0x10000000,
    ];

    /// Barrett constant μ = floor(2^512 / L) as 9 × u32 limbs (little-endian).
    const MU: [u32; 9] = [
        0x0a2c131b, 0xed9ce5a3, 0x086329a7, 0x2106215d,
        0xffffffeb, 0xffffffff, 0xffffffff, 0xffffffff,
        0x0000000f,
    ];

    /// Multiply a 16-limb number by the 9-limb constant MU, returning
    /// limbs [16..25] of the 25-limb product (i.e. the result >> 512).
    #[inline(always)]
    fn mul_x_mu(x: &[u32; 16]) -> [u32; 9] {
        let mut result = [0u32; 25];

        for i in 0..16 {
            let mut carry = 0u64;
            for j in 0..9 {
                carry += (x[i] as u64) * (MU[j] as u64) + result[i + j] as u64;
                result[i + j] = carry as u32;
                carry >>= 32;
            }
            let mut k = i + 9;
            while carry > 0 && k < 25 {
                carry += result[k] as u64;
                result[k] = carry as u32;
                carry >>= 32;
                k += 1;
            }
        }

        [
            result[16], result[17], result[18], result[19],
            result[20], result[21], result[22], result[23],
            result[24],
        ]
    }

    /// Multiply a 9-limb quotient estimate by the 8-limb constant L,
    /// returning the low 9 limbs (mod 2^288).
    #[inline(always)]
    fn mul_q_l(q: &[u32; 9]) -> [u32; 9] {
        let mut result = [0u32; 9];

        for i in 0..9 {
            let mut carry = 0u64;
            for j in 0..8 {
                if i + j >= 9 {
                    break;
                }
                carry += (q[i] as u64) * (L[j] as u64) + result[i + j] as u64;
                result[i + j] = carry as u32;
                carry >>= 32;
            }
            let mut k = i + 8.min(9 - i);
            while carry > 0 && k < 9 {
                carry += result[k] as u64;
                result[k] = carry as u32;
                carry >>= 32;
                k += 1;
            }
        }

        result
    }

    /// Subtract b from a (9-limb), returning result and whether it underflowed.
    #[inline(always)]
    fn sub9(a: &[u32; 9], b: &[u32; 9]) -> ([u32; 9], bool) {
        let mut result = [0u32; 9];
        let mut borrow = 0u64;

        for i in 0..9 {
            let diff = (a[i] as u64)
                .wrapping_sub(b[i] as u64)
                .wrapping_sub(borrow);
            result[i] = diff as u32;
            borrow = (diff >> 63) & 1;
        }

        (result, borrow != 0)
    }

    /// Returns true if a >= L (a is 9 limbs, L is 8 limbs).
    #[inline(always)]
    fn gte_l(a: &[u32; 9]) -> bool {
        if a[8] != 0 {
            return true;
        }
        for i in (0..8).rev() {
            if a[i] > L[i] {
                return true;
            }
            if a[i] < L[i] {
                return false;
            }
        }
        true
    }

    #[inline(always)]
    pub(super) fn scalar_from_bytes_mod_order_wide(input: &[u8; 64]) -> [u8; 32] {
        // Parse input as 16 × u32 limbs (little-endian).
        let mut x = [0u32; 16];
        for i in 0..16 {
            x[i] = u32::from_le_bytes([
                input[i * 4],
                input[i * 4 + 1],
                input[i * 4 + 2],
                input[i * 4 + 3],
            ]);
        }

        // q_hat = (x * μ) >> 512
        let q_hat = mul_x_mu(&x);

        // r = x - q_hat * L (mod 2^288, using 9 limbs)
        let q_l = mul_q_l(&q_hat);
        let x9 = [x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7], x[8]];
        let (mut r, _) = sub9(&x9, &q_l);

        // At most 2 corrections needed.
        if gte_l(&r) {
            let l9 = [L[0], L[1], L[2], L[3], L[4], L[5], L[6], L[7], 0];
            let (r2, _) = sub9(&r, &l9);
            r = r2;
        }
        if gte_l(&r) {
            let l9 = [L[0], L[1], L[2], L[3], L[4], L[5], L[6], L[7], 0];
            let (r2, _) = sub9(&r, &l9);
            r = r2;
        }

        // Serialize the low 8 limbs as 32 bytes LE.
        let mut out = [0u8; 32];
        for i in 0..8 {
            out[i * 4..i * 4 + 4].copy_from_slice(&r[i].to_le_bytes());
        }
        out
    }
}

#[cfg(test)]
mod raw {
    const L_BYTES: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];

    pub(super) fn scalar_from_canonical_bytes(bytes: [u8; 32]) -> Option<[u8; 32]> {
        if bytes[31] >> 7 != 0 {
            return None;
        }

        for i in (0..32).rev() {
            if bytes[i] < L_BYTES[i] {
                return Some(bytes);
            }
            if bytes[i] > L_BYTES[i] {
                return None;
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::{raw, barrett32};
    use rand::{RngCore, SeedableRng};
    use rand::rngs::{OsRng, StdRng};

    const FUZZ_RANDOM_CASES: u64 = 1_000_000;

    const L_BYTES: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];

    fn xorshift64(mut x: u64) -> u64 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    }

    fn generated_bytes<const N: usize>(seed: u64) -> [u8; N] {
        let mut state = seed | 1;
        let mut out = [0u8; N];
        let mut i = 0;

        while i < N {
            state = xorshift64(state);
            let block = state.to_le_bytes();
            let take = core::cmp::min(8, N - i);
            out[i..i + take].copy_from_slice(&block[..take]);
            i += take;
        }

        out
    }

    fn add_small_le(mut bytes: [u8; 32], value: u8) -> [u8; 32] {
        let mut carry = value as u16;
        for byte in &mut bytes {
            if carry == 0 {
                break;
            }

            let sum = *byte as u16 + carry;
            *byte = sum as u8;
            carry = sum >> 8;
        }
        bytes
    }

    fn sub_small_le(mut bytes: [u8; 32], value: u8) -> [u8; 32] {
        let mut borrow = value as u16;
        for byte in &mut bytes {
            if borrow == 0 {
                break;
            }

            let lhs = *byte as u16;
            if lhs >= borrow {
                *byte = (lhs - borrow) as u8;
                borrow = 0;
            } else {
                *byte = ((lhs + 256) - borrow) as u8;
                borrow = 1;
            }
        }
        bytes
    }

    fn dalek_canonical(bytes: [u8; 32]) -> Option<[u8; 32]> {
        Option::from(curve25519_dalek::scalar::Scalar::from_canonical_bytes(
            bytes,
        ))
        .map(|scalar: curve25519_dalek::scalar::Scalar| scalar.to_bytes())
    }

    fn dalek_wide(bytes: &[u8; 64]) -> [u8; 32] {
        curve25519_dalek::scalar::Scalar::from_bytes_mod_order_wide(bytes).to_bytes()
    }

    #[test]
    fn canonical_known() {
        let cases = [
            [0u8; 32],
            [1u8; 32],
            sub_small_le(L_BYTES, 2),
            sub_small_le(L_BYTES, 1),
            add_small_le(L_BYTES, 1),
            add_small_le(L_BYTES, 2),
            [
                0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
                0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x10,
            ],
            [
                0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
                0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x10,
            ],
            [
                0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
                0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x90,
            ],
        ];

        for bytes in cases {
            let expected = dalek_canonical(bytes);
            assert_eq!(raw::scalar_from_canonical_bytes(bytes), expected);
        }
    }

    #[test]
    fn canonical_many() {
        for seed in 0..1024u64 {
            let bytes = generated_bytes::<32>(0x9e37_79b9_7f4a_7c15 ^ seed);
            assert_eq!(
                raw::scalar_from_canonical_bytes(bytes),
                dalek_canonical(bytes),
                "seed {seed} bytes {bytes:?}"
            );

            let mut high_bit_bytes = bytes;
            high_bit_bytes[31] |= 0x80;
            assert_eq!(
                raw::scalar_from_canonical_bytes(high_bit_bytes),
                dalek_canonical(high_bit_bytes),
                "seed {seed} high-bit bytes {high_bit_bytes:?}"
            );
        }
    }

    #[test]
    fn canonical_l_window() {
        for delta in 0..=255u8 {
            let below = sub_small_le(L_BYTES, delta);
            assert_eq!(
                raw::scalar_from_canonical_bytes(below),
                dalek_canonical(below),
                "below delta {delta} bytes {below:?}"
            );

            let above = add_small_le(L_BYTES, delta);
            assert_eq!(
                raw::scalar_from_canonical_bytes(above),
                dalek_canonical(above),
                "above delta {delta} bytes {above:?}"
            );
        }
    }

    #[test]
    fn reduce_wide_known() {
        let cases = [
            [0u8; 64],
            [0xffu8; 64],
            core::array::from_fn(|i| i as u8),
            core::array::from_fn(|i| (63 - i) as u8),
            core::array::from_fn(|i| i.wrapping_mul(37) as u8),
        ];

        for input in cases {
            let expected = dalek_wide(&input);
            assert_eq!(barrett32::scalar_from_bytes_mod_order_wide(&input), expected);
        }
    }

    #[test]
    fn reduce_wide_many() {
        for seed in 0..512u64 {
            let input = generated_bytes::<64>(0xd1b5_4a32_d192_ed03 ^ seed);
            let reduced = barrett32::scalar_from_bytes_mod_order_wide(&input);
            let expected = dalek_wide(&input);

            assert_eq!(reduced, expected, "seed {seed} input {input:?}");
            assert_eq!(
                raw::scalar_from_canonical_bytes(reduced),
                Some(reduced),
                "seed {seed} reduced {reduced:?}"
            );
        }
    }

    #[test]
    fn reduce_wide_single_bits() {
        for bit in 0..512usize {
            let mut input = [0u8; 64];
            input[bit / 8] = 1u8 << (bit % 8);

            let reduced = barrett32::scalar_from_bytes_mod_order_wide(&input);
            let expected = dalek_wide(&input);

            assert_eq!(reduced, expected, "bit {bit} input {input:?}");
            assert_eq!(
                raw::scalar_from_canonical_bytes(reduced),
                Some(reduced),
                "bit {bit} reduced {reduced:?}"
            );
        }
    }

    #[test]
    #[ignore] // This is a long-running fuzz test
    fn fuzz_random_against_dalek() {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let mut rng = StdRng::from_seed(seed);

        for case in 0..FUZZ_RANDOM_CASES {
            let mut canonical = [0u8; 32];
            rng.fill_bytes(&mut canonical);

            assert_eq!(
                raw::scalar_from_canonical_bytes(canonical),
                dalek_canonical(canonical),
                "seed {seed:?} case {case} canonical {canonical:?}"
            );

            let mut wide = [0u8; 64];
            rng.fill_bytes(&mut wide);

            let expected = dalek_wide(&wide);

            let reduced = barrett32::scalar_from_bytes_mod_order_wide(&wide);
            assert_eq!(reduced, expected, "seed {seed:?} case {case} barrett32 {wide:?}");

            assert_eq!(
                raw::scalar_from_canonical_bytes(reduced),
                Some(reduced),
                "seed {seed:?} case {case} reduced {reduced:?}"
            );
        }
    }
}
