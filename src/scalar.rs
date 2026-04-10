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

#[cfg(not(target_os = "solana"))]
pub(crate) fn scalar_from_canonical_bytes(bytes: [u8; 32]) -> Option<[u8; 32]> {
    Option::from(curve25519_dalek::scalar::Scalar::from_canonical_bytes(
        bytes,
    ))
    .map(|scalar: curve25519_dalek::scalar::Scalar| scalar.to_bytes())
}

#[cfg(not(target_os = "solana"))]
pub(crate) fn scalar_from_bytes_mod_order_wide(input: &[u8; 64]) -> [u8; 32] {
    curve25519_dalek::scalar::Scalar::from_bytes_mod_order_wide(input).to_bytes()
}

#[cfg(target_os = "solana")]
pub(crate) fn scalar_from_canonical_bytes(bytes: [u8; 32]) -> Option<[u8; 32]> {
    raw::scalar_from_canonical_bytes(bytes)
}

#[cfg(target_os = "solana")]
pub(crate) fn scalar_from_bytes_mod_order_wide(input: &[u8; 64]) -> [u8; 32] {
    raw::scalar_from_bytes_mod_order_wide(input)
}

#[cfg(any(target_os = "solana", test))]
mod raw {
    const L_BYTES: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];

    const L: Scalar52 = Scalar52([
        0x0002631a5cf5d3ed,
        0x000dea2f79cd6581,
        0x000000000014def9,
        0x0000000000000000,
        0x0000100000000000,
    ]);

    const LFACTOR: u64 = 0x51da312547e1b;

    const R: Scalar52 = Scalar52([
        0x000f48bd6721e6ed,
        0x0003bab5ac67e45a,
        0x000fffffeb35e51b,
        0x000fffffffffffff,
        0x00000fffffffffff,
    ]);

    const RR: Scalar52 = Scalar52([
        0x0009d265e952d13b,
        0x000d63c715bea69f,
        0x0005be65cb687604,
        0x0003dceec73d217f,
        0x000009411b7c309a,
    ]);

    #[derive(Clone, Copy)]
    struct Scalar52([u64; 5]);

    const SCALAR52_ZERO: Scalar52 = Scalar52([0, 0, 0, 0, 0]);

    #[inline(always)]
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

    #[inline(always)]
    pub(super) fn scalar_from_bytes_mod_order_wide(input: &[u8; 64]) -> [u8; 32] {
        Scalar52::from_bytes_wide(input).as_bytes()
    }

    #[inline(always)]
    fn m(x: u64, y: u64) -> u128 {
        (x as u128) * (y as u128)
    }

    impl core::ops::Index<usize> for Scalar52 {
        type Output = u64;

        fn index(&self, index: usize) -> &Self::Output {
            &self.0[index]
        }
    }

    impl core::ops::IndexMut<usize> for Scalar52 {
        fn index_mut(&mut self, index: usize) -> &mut Self::Output {
            &mut self.0[index]
        }
    }

    impl Scalar52 {
        #[inline(always)]
        fn from_bytes_wide(bytes: &[u8; 64]) -> Scalar52 {
            let mut words = [0u64; 8];
            for i in 0..8 {
                for j in 0..8 {
                    words[i] |= (bytes[(i * 8) + j] as u64) << (j * 8);
                }
            }

            let mask = (1u64 << 52) - 1;
            let mut lo = SCALAR52_ZERO;
            let mut hi = SCALAR52_ZERO;

            lo[0] = words[0] & mask;
            lo[1] = ((words[0] >> 52) | (words[1] << 12)) & mask;
            lo[2] = ((words[1] >> 40) | (words[2] << 24)) & mask;
            lo[3] = ((words[2] >> 28) | (words[3] << 36)) & mask;
            lo[4] = ((words[3] >> 16) | (words[4] << 48)) & mask;
            hi[0] = (words[4] >> 4) & mask;
            hi[1] = ((words[4] >> 56) | (words[5] << 8)) & mask;
            hi[2] = ((words[5] >> 44) | (words[6] << 20)) & mask;
            hi[3] = ((words[6] >> 32) | (words[7] << 32)) & mask;
            hi[4] = words[7] >> 20;

            lo = Scalar52::montgomery_mul(&lo, &R);
            hi = Scalar52::montgomery_mul(&hi, &RR);

            Scalar52::add(&hi, &lo)
        }

        #[inline(always)]
        fn as_bytes(&self) -> [u8; 32] {
            let mut s = [0u8; 32];

            s[0] = (self.0[0] >> 0) as u8;
            s[1] = (self.0[0] >> 8) as u8;
            s[2] = (self.0[0] >> 16) as u8;
            s[3] = (self.0[0] >> 24) as u8;
            s[4] = (self.0[0] >> 32) as u8;
            s[5] = (self.0[0] >> 40) as u8;
            s[6] = ((self.0[0] >> 48) | (self.0[1] << 4)) as u8;
            s[7] = (self.0[1] >> 4) as u8;
            s[8] = (self.0[1] >> 12) as u8;
            s[9] = (self.0[1] >> 20) as u8;
            s[10] = (self.0[1] >> 28) as u8;
            s[11] = (self.0[1] >> 36) as u8;
            s[12] = (self.0[1] >> 44) as u8;
            s[13] = (self.0[2] >> 0) as u8;
            s[14] = (self.0[2] >> 8) as u8;
            s[15] = (self.0[2] >> 16) as u8;
            s[16] = (self.0[2] >> 24) as u8;
            s[17] = (self.0[2] >> 32) as u8;
            s[18] = (self.0[2] >> 40) as u8;
            s[19] = ((self.0[2] >> 48) | (self.0[3] << 4)) as u8;
            s[20] = (self.0[3] >> 4) as u8;
            s[21] = (self.0[3] >> 12) as u8;
            s[22] = (self.0[3] >> 20) as u8;
            s[23] = (self.0[3] >> 28) as u8;
            s[24] = (self.0[3] >> 36) as u8;
            s[25] = (self.0[3] >> 44) as u8;
            s[26] = (self.0[4] >> 0) as u8;
            s[27] = (self.0[4] >> 8) as u8;
            s[28] = (self.0[4] >> 16) as u8;
            s[29] = (self.0[4] >> 24) as u8;
            s[30] = (self.0[4] >> 32) as u8;
            s[31] = (self.0[4] >> 40) as u8;

            s
        }

        #[inline(always)]
        fn add(a: &Scalar52, b: &Scalar52) -> Scalar52 {
            let mut sum = SCALAR52_ZERO;
            let mask = (1u64 << 52) - 1;
            let mut carry = 0u64;

            for i in 0..5 {
                carry = a[i] + b[i] + (carry >> 52);
                sum[i] = carry & mask;
            }

            Scalar52::sub(&sum, &L)
        }

        #[inline(always)]
        fn sub(a: &Scalar52, b: &Scalar52) -> Scalar52 {
            #[inline(always)]
            fn black_box(value: u64) -> u64 {
                unsafe { core::ptr::read_volatile(&value) }
            }

            let mut difference = SCALAR52_ZERO;
            let mask = (1u64 << 52) - 1;
            let mut borrow = 0u64;

            for i in 0..5 {
                borrow = a[i].wrapping_sub(b[i] + (borrow >> 63));
                difference[i] = borrow & mask;
            }

            let underflow_mask = ((borrow >> 63) ^ 1).wrapping_sub(1);
            let mut carry = 0u64;
            for i in 0..5 {
                carry = (carry >> 52) + difference[i] + (L[i] & black_box(underflow_mask));
                difference[i] = carry & mask;
            }

            difference
        }

        #[inline(always)]
        fn mul_internal(a: &Scalar52, b: &Scalar52) -> [u128; 9] {
            [
                m(a[0], b[0]),
                m(a[0], b[1]) + m(a[1], b[0]),
                m(a[0], b[2]) + m(a[1], b[1]) + m(a[2], b[0]),
                m(a[0], b[3]) + m(a[1], b[2]) + m(a[2], b[1]) + m(a[3], b[0]),
                m(a[0], b[4]) + m(a[1], b[3]) + m(a[2], b[2]) + m(a[3], b[1]) + m(a[4], b[0]),
                m(a[1], b[4]) + m(a[2], b[3]) + m(a[3], b[2]) + m(a[4], b[1]),
                m(a[2], b[4]) + m(a[3], b[3]) + m(a[4], b[2]),
                m(a[3], b[4]) + m(a[4], b[3]),
                m(a[4], b[4]),
            ]
        }

        #[inline(always)]
        fn montgomery_reduce(limbs: &[u128; 9]) -> Scalar52 {
            #[inline(always)]
            fn part1(sum: u128) -> (u128, u64) {
                let p = (sum as u64).wrapping_mul(LFACTOR) & ((1u64 << 52) - 1);
                ((sum + m(p, L[0])) >> 52, p)
            }

            #[inline(always)]
            fn part2(sum: u128) -> (u128, u64) {
                let w = (sum as u64) & ((1u64 << 52) - 1);
                (sum >> 52, w)
            }

            let (carry, n0) = part1(limbs[0]);
            let (carry, n1) = part1(carry + limbs[1] + m(n0, L[1]));
            let (carry, n2) = part1(carry + limbs[2] + m(n0, L[2]) + m(n1, L[1]));
            let (carry, n3) = part1(carry + limbs[3] + m(n1, L[2]) + m(n2, L[1]));
            let (carry, n4) = part1(carry + limbs[4] + m(n0, L[4]) + m(n2, L[2]) + m(n3, L[1]));

            let (carry, r0) = part2(carry + limbs[5] + m(n1, L[4]) + m(n3, L[2]) + m(n4, L[1]));
            let (carry, r1) = part2(carry + limbs[6] + m(n2, L[4]) + m(n4, L[2]));
            let (carry, r2) = part2(carry + limbs[7] + m(n3, L[4]));
            let (carry, r3) = part2(carry + limbs[8] + m(n4, L[4]));
            let r4 = carry as u64;

            Scalar52::sub(&Scalar52([r0, r1, r2, r3, r4]), &L)
        }

        #[inline(always)]
        fn montgomery_mul(a: &Scalar52, b: &Scalar52) -> Scalar52 {
            Scalar52::montgomery_reduce(&Scalar52::mul_internal(a, b))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::raw;

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
            assert_eq!(raw::scalar_from_bytes_mod_order_wide(&input), expected);
        }
    }

    #[test]
    fn reduce_wide_many() {
        for seed in 0..512u64 {
            let input = generated_bytes::<64>(0xd1b5_4a32_d192_ed03 ^ seed);
            let reduced = raw::scalar_from_bytes_mod_order_wide(&input);
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

            let reduced = raw::scalar_from_bytes_mod_order_wide(&input);
            let expected = dalek_wide(&input);

            assert_eq!(reduced, expected, "bit {bit} input {input:?}");
            assert_eq!(
                raw::scalar_from_canonical_bytes(reduced),
                Some(reduced),
                "bit {bit} reduced {reduced:?}"
            );
        }
    }
}
