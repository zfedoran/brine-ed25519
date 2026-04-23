#![no_std]
#![cfg_attr(all(feature = "asm-sha512", target_os = "solana"), feature(asm_experimental_arch))]

mod curve;
pub mod hasher;
mod scalar;

use crate::curve::multiscalar_multiply_edwards;
use crate::hasher::Hasher;
use crate::scalar::scalar_from_bytes_mod_order_wide_into;
pub use solana_address::Address;
use solana_program_error::ProgramError;

pub type Signature = [u8; 64];

/// Negated compressed base point (-G). Identical to G with the sign bit
/// (bit 7 of the last byte) flipped. Used so that the signature check
/// `R == sB - kA` can be rewritten as a single multiscalar multiplication:
/// `msm([s, k], [-G, A]) == -R`.
const NEG_G: [u8; 32] = [
    88, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102,
    102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 230,
];

/// Verify an ed25519 signature over a vectored message using the provided
/// hash implementation.
#[inline(always)]
pub fn verify<H: Hasher>(
    pubkey: &Address,
    sig: &Signature,
    messages: &[&[u8]],
) -> Result<(), ProgramError> {
    // SAFETY: first 32 bytes of [u8; 64] is a valid [u8; 32].
    let sig_r: &[u8; 32] = unsafe { &*(sig.as_ptr() as *const [u8; 32]) };

    let challenge = challenge::<H>(sig_r, pubkey, messages);

    verify_prehashed(pubkey, sig, &challenge)
}

/// Verify an ed25519 signature using a precomputed challenge hash `H(R || A || M)`.
/// This is useful in cases where the challenge hash needs to be computed off-chain
/// or pre-computed on-chain for efficiency reasons.
///
/// # Safety (validation delegated to the MSM syscall)
///
/// The following checks are intentionally omitted because the Solana
/// `sol_curve_multiscalar_mul` syscall already performs them internally
/// (see `agave/curves/curve25519/src/edwards.rs` and `scalar.rs`):
///
/// - **Point decompression / on-curve check** for both `pubkey` and the
///   constant `-G`: the syscall calls `CompressedEdwardsY::decompress()`
///   on every point and returns failure if decompression fails.
/// - **Scalar canonicality** of `s` (the upper half of the signature):
///   the syscall calls `Scalar::from_canonical_bytes()` on every scalar
///   and returns failure if the scalar is non-canonical.
///
/// If any of those checks fail the MSM returns `None`, which we map to
/// `ProgramError::InvalidArgument`.
///
/// **Small-order rejection** *is* performed here (for both `pubkey` and
/// `R`) via a table lookup against the eight torsion points. The MSM
/// syscall does not do this check itself.
#[inline(always)]
#[allow(non_snake_case)]
pub fn verify_prehashed(
    pubkey: &Address,
    sig: &Signature,
    challenge: &[u8; 64],
) -> Result<(), ProgramError> {
    // Split signature into R (first 32 bytes) and s (last 32 bytes).
    // SAFETY: [u8; 64] has the same layout as [[u8; 32]; 2].
    let (sig_r, sig_s): &([u8; 32], [u8; 32]) = unsafe { &*(sig as *const [u8; 64] as *const _) };

    // SAFETY: Address is #[repr(transparent)] over [u8; 32].
    let pubkey_bytes: &[u8; 32] = unsafe { &*(pubkey as *const Address as *const [u8; 32]) };

    // Reject small-order pubkey and R. These would allow forgeries that
    // verify against any message, so we check even though the MSM does not.
    if is_small_order(pubkey_bytes) || is_small_order(sig_r) {
        return Err(ProgramError::InvalidArgument);
    }

    // Build the [[u8; 32]; 2] scalar array in place so that the reduced `k`
    // limbs can be written straight into the MSM input slot instead of
    // materializing through a separate 32-byte stack temporary.
    let mut scalars: [[u8; 32]; 2] = [*sig_s, [0u8; 32]];
    scalar_from_bytes_mod_order_wide_into(challenge, &mut scalars[1]);

    let points = [NEG_G, *pubkey_bytes];

    // msm([s, k], [-G, A]) = s*(-G) + k*A = k*A - s*G = -(s*G - k*A) = -R
    let neg_R =
        multiscalar_multiply_edwards(&scalars, &points).ok_or(ProgramError::InvalidArgument)?;

    // Negate sig_R (flip sign bit) to compare against -R.
    let mut neg_sig_R = *sig_r;
    neg_sig_R[31] ^= 0x80;

    if neg_R == neg_sig_R {
        Ok(())
    } else {
        Err(ProgramError::InvalidArgument)
    }
}

#[inline(always)]
fn challenge<H: Hasher>(sig_r: &[u8; 32], pubkey: &Address, messagev: &[&[u8]]) -> [u8; 64] {
    let mut hasher = H::new();
    hasher.update(sig_r);
    hasher.update(pubkey.as_ref());
    for message in messagev {
        hasher.update(message);
    }
    hasher.finalize()
}

#[cfg(test)]
const G: [u8; 32] = [
    88, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102,
    102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102,
];

/// The eight small-order (torsion) points on Curve25519, in compressed
/// Edwards form. Any point matching one of these is rejected during
/// signature verification.
const EIGHT_TORSION: [[u8; 32]; 8] = [
    [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ],
    [
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67,
        0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac,
        0x03, 0x7a,
    ],
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x80,
    ],
    [
        0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98,
        0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53,
        0xfc, 0x05,
    ],
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    [
        0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98,
        0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53,
        0xfc, 0x85,
    ],
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ],
    [
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67,
        0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac,
        0x03, 0xfa,
    ],
];

/// Determine if this point is of small order by checking against the
/// eight known torsion points (table lookup, no curve syscalls).
#[inline(always)]
fn is_small_order(point: &[u8; 32]) -> bool {
    EIGHT_TORSION.iter().any(|t| *t == *point)
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hasher::{Hasher, Sha512};
    use curve25519_dalek::constants;

    #[test]
    fn test_base_point() {
        let base_point = constants::ED25519_BASEPOINT_POINT;
        let compressed = base_point.compress();
        let bytes = compressed.to_bytes();
        assert_eq!(bytes, G);
    }

    #[test]
    fn test_small_order() {
        // Refer to https://github.com/dalek-cryptography/curve25519-dalek/blob/43a16f03d4c635a8836c23ac07244c116ea3aab8/curve25519-dalek/src/edwards.rs#L1992

        // Base point (has large order)
        assert_eq!(is_small_order(&G), false);

        // Torsion points (have small order)
        for i in 0..8 {
            let torsion_point = constants::EIGHT_TORSION[i];
            let compressed = torsion_point.compress();
            let torsion_point_bytes = compressed.to_bytes();
            assert_eq!(
                torsion_point_bytes, EIGHT_TORSION[i],
                "torsion point {i} mismatch"
            );
            assert_eq!(is_small_order(&torsion_point_bytes), true);
        }
    }

    #[test]
    fn test_hello_world() {
        let pubkey = Address::from([
            73, 73, 170, 112, 75, 235, 154, 81, 203, 8, 44, 245, 233, 18, 204, 136, 162, 9, 233,
            49, 154, 201, 171, 175, 47, 6, 223, 101, 105, 80, 95, 166,
        ]);
        let sig: [u8; 64] = [
            164, 121, 89, 242, 88, 29, 80, 177, 104, 20, 102, 176, 48, 133, 68, 8, 105, 33, 58, 86,
            28, 108, 198, 140, 160, 219, 62, 184, 154, 181, 140, 33, 35, 102, 183, 203, 111, 33,
            55, 170, 180, 138, 92, 196, 185, 201, 122, 167, 15, 112, 9, 228, 226, 112, 111, 10,
            142, 73, 85, 43, 81, 152, 204, 13,
        ];

        assert!(verify::<Sha512>(&pubkey, &sig, &[b"hello world"]).is_ok());
        assert!(verify::<Sha512>(&pubkey, &sig, &[b"not the right message"]).is_err());
    }

    #[test]
    fn test_error_invalid_public_key() {
        let pubkey = Address::from(EIGHT_TORSION[0]);
        let sig: [u8; 64] = [
            164, 121, 89, 242, 88, 29, 80, 177, 104, 20, 102, 176, 48, 133, 68, 8, 105, 33, 58, 86,
            28, 108, 198, 140, 160, 219, 62, 184, 154, 181, 140, 33, 35, 102, 183, 203, 111, 33,
            55, 170, 180, 138, 92, 196, 185, 201, 122, 167, 15, 112, 9, 228, 226, 112, 111, 10,
            142, 73, 85, 43, 81, 152, 204, 13,
        ];

        assert_eq!(
            verify::<Sha512>(&pubkey, &sig, &[b"hello world"]),
            Err(ProgramError::InvalidArgument)
        );
    }

    #[test]
    fn test_error_invalid_signature() {
        let pubkey = Address::from([
            73, 73, 170, 112, 75, 235, 154, 81, 203, 8, 44, 245, 233, 18, 204, 136, 162, 9, 233,
            49, 154, 201, 171, 175, 47, 6, 223, 101, 105, 80, 95, 166,
        ]);
        let sig: [u8; 64] = [
            164, 121, 89, 242, 88, 29, 80, 177, 104, 20, 102, 176, 48, 133, 68, 8, 105, 33, 58, 86,
            28, 108, 198, 140, 160, 219, 62, 184, 154, 181, 140, 33, 35, 102, 183, 203, 111, 33,
            55, 170, 180, 138, 92, 196, 185, 201, 122, 167, 15, 112, 9, 228, 226, 112, 111, 10,
            142, 73, 85, 43, 81, 152, 204, 13,
        ];

        assert_eq!(
            verify::<Sha512>(&pubkey, &sig, &[b"not the right message"]),
            Err(ProgramError::InvalidArgument)
        );
    }

    #[test]
    fn test_hello_worldv() {
        let pubkey = Address::from([
            73, 73, 170, 112, 75, 235, 154, 81, 203, 8, 44, 245, 233, 18, 204, 136, 162, 9, 233,
            49, 154, 201, 171, 175, 47, 6, 223, 101, 105, 80, 95, 166,
        ]);
        let sig: [u8; 64] = [
            164, 121, 89, 242, 88, 29, 80, 177, 104, 20, 102, 176, 48, 133, 68, 8, 105, 33, 58, 86,
            28, 108, 198, 140, 160, 219, 62, 184, 154, 181, 140, 33, 35, 102, 183, 203, 111, 33,
            55, 170, 180, 138, 92, 196, 185, 201, 122, 167, 15, 112, 9, 228, 226, 112, 111, 10,
            142, 73, 85, 43, 81, 152, 204, 13,
        ];

        let messagev: &[&[u8]] = &[b"hello", b" ", b"world"];
        let bad_messagev: &[&[u8]] = &[b"hello", b" ", b"there"];

        assert!(verify::<Sha512>(&pubkey, &sig, messagev).is_ok());
        assert!(verify::<Sha512>(&pubkey, &sig, bad_messagev).is_err());
    }

    #[test]
    fn test_vector_1() {
        let pubkey = Address::from([
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
            0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
            0xf7, 0x07, 0x51, 0x1a,
        ]);

        let sig: [u8; 64] = [
            0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e,
            0x82, 0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65,
            0x22, 0x49, 0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e,
            0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
            0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
        ];

        assert!(verify::<Sha512>(&pubkey, &sig, &[b""]).is_ok());
        assert!(verify::<Sha512>(&pubkey, &sig, &[b"not the right message"]).is_err());
    }

    #[test]
    fn test_vector_2() {
        let pubkey = Address::from([
            0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b,
            0x7e, 0xbc, 0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1,
            0x2a, 0xf4, 0x66, 0x0c,
        ]);

        let sig: [u8; 64] = [
            0x92, 0xa0, 0x09, 0xa9, 0xf0, 0xd4, 0xca, 0xb8, 0x72, 0x0e, 0x82, 0x0b, 0x5f, 0x64,
            0x25, 0x40, 0xa2, 0xb2, 0x7b, 0x54, 0x16, 0x50, 0x3f, 0x8f, 0xb3, 0x76, 0x22, 0x23,
            0xeb, 0xdb, 0x69, 0xda, 0x08, 0x5a, 0xc1, 0xe4, 0x3e, 0x15, 0x99, 0x6e, 0x45, 0x8f,
            0x36, 0x13, 0xd0, 0xf1, 0x1d, 0x8c, 0x38, 0x7b, 0x2e, 0xae, 0xb4, 0x30, 0x2a, 0xee,
            0xb0, 0x0d, 0x29, 0x16, 0x12, 0xbb, 0x0c, 0x00,
        ];

        assert!(verify::<Sha512>(&pubkey, &sig, &[b"r"]).is_ok());
        assert!(verify::<Sha512>(&pubkey, &sig, &[b"not the right message"]).is_err());
    }

    #[test]
    fn test_vector_3() {
        let pubkey = Address::from([
            0xfc, 0x51, 0xcd, 0x8e, 0x62, 0x18, 0xa1, 0xa3, 0x8d, 0xa4, 0x7e, 0xd0, 0x02, 0x30,
            0xf0, 0x58, 0x08, 0x16, 0xed, 0x13, 0xba, 0x33, 0x03, 0xac, 0x5d, 0xeb, 0x91, 0x15,
            0x48, 0x90, 0x80, 0x25,
        ]);

        let sig: [u8; 64] = [
            0x62, 0x91, 0xd6, 0x57, 0xde, 0xec, 0x24, 0x02, 0x48, 0x27, 0xe6, 0x9c, 0x3a, 0xbe,
            0x01, 0xa3, 0x0c, 0xe5, 0x48, 0xa2, 0x84, 0x74, 0x3a, 0x44, 0x5e, 0x36, 0x80, 0xd7,
            0xdb, 0x5a, 0xc3, 0xac, 0x18, 0xff, 0x9b, 0x53, 0x8d, 0x16, 0xf2, 0x90, 0xae, 0x67,
            0xf7, 0x60, 0x98, 0x4d, 0xc6, 0x59, 0x4a, 0x7c, 0x15, 0xe9, 0x71, 0x6e, 0xd2, 0x8d,
            0xc0, 0x27, 0xbe, 0xce, 0xea, 0x1e, 0xc4, 0x0a,
        ];

        let message: &[u8] = &[0xaf, 0x82];

        assert!(verify::<Sha512>(&pubkey, &sig, &[message]).is_ok());
        assert!(verify::<Sha512>(&pubkey, &sig, &[b"not the right message"]).is_err());
    }

    #[test]
    fn test_prehashed() {
        let pubkey = Address::from([
            0xfc, 0x51, 0xcd, 0x8e, 0x62, 0x18, 0xa1, 0xa3, 0x8d, 0xa4, 0x7e, 0xd0, 0x02, 0x30,
            0xf0, 0x58, 0x08, 0x16, 0xed, 0x13, 0xba, 0x33, 0x03, 0xac, 0x5d, 0xeb, 0x91, 0x15,
            0x48, 0x90, 0x80, 0x25,
        ]);

        let sig: [u8; 64] = [
            0x62, 0x91, 0xd6, 0x57, 0xde, 0xec, 0x24, 0x02, 0x48, 0x27, 0xe6, 0x9c, 0x3a, 0xbe,
            0x01, 0xa3, 0x0c, 0xe5, 0x48, 0xa2, 0x84, 0x74, 0x3a, 0x44, 0x5e, 0x36, 0x80, 0xd7,
            0xdb, 0x5a, 0xc3, 0xac, 0x18, 0xff, 0x9b, 0x53, 0x8d, 0x16, 0xf2, 0x90, 0xae, 0x67,
            0xf7, 0x60, 0x98, 0x4d, 0xc6, 0x59, 0x4a, 0x7c, 0x15, 0xe9, 0x71, 0x6e, 0xd2, 0x8d,
            0xc0, 0x27, 0xbe, 0xce, 0xea, 0x1e, 0xc4, 0x0a,
        ];

        let message = &[0xaf, 0x82];
        let challenge = Sha512::hashv(&[sig[..32].as_ref(), pubkey.as_ref(), message.as_ref()]);
        let wrong_challenge = [0u8; 64];

        assert!(verify_prehashed(&pubkey, &sig, &challenge).is_ok());
        assert!(verify_prehashed(&pubkey, &sig, &wrong_challenge).is_err());
    }

    #[test]
    fn test_challenge_hashv() {
        let sig_r: [u8; 32] = [
            164, 121, 89, 242, 88, 29, 80, 177, 104, 20, 102, 176, 48, 133, 68, 8, 105, 33, 58, 86,
            28, 108, 198, 140, 160, 219, 62, 184, 154, 181, 140, 33,
        ];
        let pubkey = Address::from([
            73, 73, 170, 112, 75, 235, 154, 81, 203, 8, 44, 245, 233, 18, 204, 136, 162, 9, 233,
            49, 154, 201, 171, 175, 47, 6, 223, 101, 105, 80, 95, 166,
        ]);
        let messagev: &[&[u8]] = &[b"hello", b" ", b"world"];

        let expected = Sha512::hashv(&[sig_r.as_ref(), pubkey.as_ref(), b"hello", b" ", b"world"]);

        assert_eq!(challenge::<Sha512>(&sig_r, &pubkey, messagev), expected);
    }

}
