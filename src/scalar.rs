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

/// Write `Scalar::from_bytes_mod_order_wide(input)` into `out`.
///
/// The out-param form lets callers place the reduced bytes directly into a
/// larger buffer (e.g. an MSM scalar array) rather than through a by-value
/// `[u8; 32]` return, which on sBPF tends to add a redundant stack copy.
#[inline(always)]
pub(crate) fn scalar_from_bytes_mod_order_wide_into(input: &[u8; 64], out: &mut [u8; 32]) {
    *out = reduce(input);
}

const BITS: u32 = 28;
const MASK: i64 = (1 << BITS) - 1;
/// c = L - 2^252 in 28-bit limbs, low first.
const C: [i64; 5] = [0xcf5d3ed, 0x12631a5, 0x79cd658, 0xf9dea2f, 0x14de];

/// Limb `i` of the input, 28 bits from bit 28 i, in one unaligned u32 load; limb 18 is the last
/// byte.
#[inline(always)]
fn limb(input: &[u8; 64], i: usize) -> i64 {
    if i == 18 {
        return input[63] as i64;
    }
    let bit = BITS as usize * i;
    // SAFETY: bit / 8 <= 59, so the four bytes are inside the input.
    let word = unsafe { core::ptr::read_unaligned(input.as_ptr().add(bit / 8) as *const u32) };
    ((u32::from_le(word) >> (bit % 8)) as i64) & MASK
}

/// Reduces a 64-byte digest mod L = 2^252 + c the way ref10's `sc_reduce` does, with 28-bit
/// limbs: 252 is nine limbs exactly, so 2^252 ≡ -c folds a limb into the five below it, and a
/// 28 × 28-bit product leaves room in an i64 to accumulate several before a carry. Signed limbs,
/// rounding carries between the fold groups, floor carries at the end, as in ref10.
///
/// Folding limb i subtracts x · 2^(28 (i - 9)) · L, and a carry moves 2^28 · carry to the next
/// limb, so the value is unchanged mod L throughout. After the second rounding chain limbs 0..7 are
/// within ±2^32, limb 8 in [-2^27, 2^27), limb 9 within ±2^13, so the value W has
/// |W - s9 · 2^252| + |s9| · c < 2^252: after the first `fold 9` and floor chain limb 9 is the sign of W1, in
/// {-1, 0}, and the second `fold 9` adds L exactly when W1 < 0. The result is in [0, L), limb 8
/// holding 2^28 when it is in [2^252, L). No intermediate exceeds 2^59, and no branch depends on
/// the data.
#[inline(always)]
fn reduce(input: &[u8; 64]) -> [u8; 32] {
    let mut s: [i64; 19] = core::array::from_fn(|i| limb(input, i));

    macro_rules! fold {
        ($i:expr) => {{
            let x = s[$i];
            s[$i - 9] -= x * C[0];
            s[$i - 8] -= x * C[1];
            s[$i - 7] -= x * C[2];
            s[$i - 6] -= x * C[3];
            s[$i - 5] -= x * C[4];
            s[$i] = 0;
        }};
    }
    macro_rules! carry_round {
        ($($i:expr),*) => {$({
            let carry = (s[$i] + (1 << (BITS - 1))) >> BITS;
            s[$i + 1] += carry;
            s[$i] -= carry << BITS;
        })*};
    }
    macro_rules! carry_floor {
        ($($i:expr),*) => {$({
            let carry = s[$i] >> BITS;
            s[$i + 1] += carry;
            s[$i] -= carry << BITS;
        })*};
    }

    // The top five limbs into 5..13, then 5..13 back to 28 bits; 13 carries into 14.
    fold!(18);
    fold!(17);
    fold!(16);
    fold!(15);
    fold!(14);
    carry_round!(5, 7, 9, 11, 13, 6, 8, 10, 12);

    // 14..9 into 0..8, then 0..8 back to 28 bits: evens, odds, then the top, so limb 8 carries
    // only after its carry-in and sends everything above 2^27 into limb 9.
    fold!(14);
    fold!(13);
    fold!(12);
    fold!(11);
    fold!(10);
    fold!(9);
    carry_round!(0, 2, 4, 6, 1, 3, 5, 7, 8);

    // Limb 9 away with floor carries, twice.
    fold!(9);
    carry_floor!(0, 1, 2, 3, 4, 5, 6, 7, 8);
    fold!(9);
    carry_floor!(0, 1, 2, 3, 4, 5, 6, 7);

    let limb = |i: usize| s[i] as u64;
    let words = [
        limb(0) | limb(1) << 28 | limb(2) << 56,
        limb(2) >> 8 | limb(3) << 20 | limb(4) << 48,
        limb(4) >> 16 | limb(5) << 12 | limb(6) << 40,
        limb(6) >> 24 | limb(7) << 4 | limb(8) << 32,
    ];
    let mut out = [0u8; 32];
    for (i, word) in words.iter().enumerate() {
        out[8 * i..8 * i + 8].copy_from_slice(&word.to_le_bytes());
    }
    out
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
    use super::{raw, reduce};
    use rand::rngs::{OsRng, StdRng};
    use rand::{RngCore, SeedableRng};

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
            assert_eq!(reduce(&input), expected);
        }
    }

    #[test]
    fn reduce_wide_many() {
        for seed in 0..512u64 {
            let input = generated_bytes::<64>(0xd1b5_4a32_d192_ed03 ^ seed);
            let reduced = reduce(&input);
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

            let reduced = reduce(&input);
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

            let reduced = reduce(&wide);
            assert_eq!(
                reduced, expected,
                "seed {seed:?} case {case} ref10_28 {wide:?}"
            );
            assert_eq!(
                raw::scalar_from_canonical_bytes(reduced),
                Some(reduced),
                "seed {seed:?} case {case} reduced {reduced:?}"
            );
        }
    }

    /// Every check on one input: dalek's answer, and canonical.
    fn check_reduce(input: &[u8; 64]) {
        let expected = dalek_wide(input);
        assert_eq!(reduce(input), expected, "{input:?}");
        assert_eq!(raw::scalar_from_canonical_bytes(expected), Some(expected));
    }

    /// `bytes + value`, little-endian, at any width.
    fn add_le<const N: usize>(mut bytes: [u8; N], value: &[u8]) -> [u8; N] {
        let mut carry = 0u16;
        for (i, byte) in bytes.iter_mut().enumerate() {
            let sum = *byte as u16 + *value.get(i).unwrap_or(&0) as u16 + carry;
            *byte = sum as u8;
            carry = sum >> 8;
        }
        bytes
    }

    fn wide(bytes: &[u8]) -> [u8; 64] {
        let mut input = [0u8; 64];
        input[..bytes.len()].copy_from_slice(bytes);
        input
    }

    /// Every carry-heavy neighbourhood: 2^k ± 2 for every k, and L ± 255.
    #[test]
    fn reduce_wide_around_powers_and_l() {
        let mut minus_two = [0xff; 64];
        minus_two[0] = 0xfe;
        for k in 0..512usize {
            let mut power = [0u8; 64];
            power[k / 8] = 1 << (k % 8);
            check_reduce(&power);
            check_reduce(&add_le(power, &[1]));
            check_reduce(&add_le(power, &[2]));
            check_reduce(&add_le(power, &[0xff; 64]));
            check_reduce(&add_le(power, &minus_two));
        }
        for delta in 0..=255u8 {
            check_reduce(&wide(&sub_small_le(L_BYTES, delta)));
            check_reduce(&wide(&add_small_le(L_BYTES, delta)));
        }
    }

    /// Results in [2^252, L), where limb 8 holds 2^28, from the residue itself and from the
    /// residue plus a few multiples of L.
    #[test]
    fn reduce_wide_top_of_the_range() {
        let mut two_252 = [0u8; 32];
        two_252[31] = 0x10;
        let residues = [
            two_252,
            add_small_le(two_252, 1),
            add_small_le(two_252, 255),
            sub_small_le(L_BYTES, 1),
            sub_small_le(L_BYTES, 2),
        ];
        for residue in residues {
            let mut input = wide(&residue);
            for _ in 0..4 {
                check_reduce(&input);
                assert_eq!(reduce(&input), residue);
                input = add_le(input, &L_BYTES);
            }
        }
    }

    #[test]
    fn reduce_wide_1m_against_dalek() {
        for seed in 1..=1_000_000u64 {
            check_reduce(&generated_bytes::<64>(
                seed.wrapping_mul(0x9e37_79b9_7f4a_7c15),
            ));
        }
    }
}
