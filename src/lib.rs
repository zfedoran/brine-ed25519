#![no_std]
use core::mem::MaybeUninit;

pub mod hasher;
mod curve;
mod scalar;

use crate::curve::{
    multiply_edwards,
    subtract_edwards,
    validate_edwards,
    PodEdwardsPoint,
    PodScalar,
};
use crate::hasher::Hasher;
use crate::scalar::{
    scalar_from_bytes_mod_order_wide, 
    scalar_from_canonical_bytes
};

const ED25519_SIG_LEN:    usize = 64;
const ED25519_PUBKEY_LEN: usize = 32;

pub type Pubkey    = [u8; ED25519_PUBKEY_LEN];
pub type Signature = [u8; ED25519_SIG_LEN];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureError {
    /// The provided public key is not a valid non-small-order Edwards point.
    InvalidPublicKey,
    /// The signature is malformed or does not verify for the provided message.
    InvalidSignature,
}

/// Compressed base point
const G: [u8; 32] = [
    88, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102,
    102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102,
];

/// Verify an ed25519 signature over a vectored message using the provided
/// hash implementation.
#[inline(always)]
pub fn verify<H: Hasher>(
    pubkey: &Pubkey,
    sig: &Signature,
    messages: &[&[u8]],
) -> Result<(), SignatureError> {

    // SAFETY: The length of `sig` is 64 bytes, so slicing the first 32 bytes is always valid.
    let sig_r_bytes: [u8; 32] = sig[..32]
        .try_into()
        .unwrap();

    let sig_r = PodEdwardsPoint(sig_r_bytes);
    let challenge = challenge::<H>(&sig_r, pubkey, messages);

    verify_prehashed(pubkey, sig, &challenge)
}

/// Verify an ed25519 signature using a precomputed challenge hash `H(R || A || M)`.
/// This is useful in cases where the challenge hash needs to be computed off-chain
/// or pre-computed on-chain for efficiency reasons.
#[inline(always)]
#[allow(non_snake_case)]
pub fn verify_prehashed(
    pubkey: &Pubkey,
    sig: &Signature,
    challenge: &[u8; 64],
) -> Result<(), SignatureError> {
    // Normally, we could verify the signature using the Solana SDK or
    // dalek_ed25519, but those are too compute, stack, and heap heavy for the
    // SVM.

    // Refer to https://datatracker.ietf.org/doc/html/rfc8032 for rough outline
    // of the ed25519 signature verification process.

    // Roughly follows the dalek ed25519 crate, but with some changes for the
    // SVM. Refer to
    // https://github.com/dalek-cryptography/curve25519-dalek/blob/0964f800ab2114a862543ca000291a6e3531c203/ed25519-dalek/src/verifying.rs#L401

    let pubkey_point = PodEdwardsPoint(*pubkey);
    let (sig_lower, sig_upper) = split_signature(sig);

    let sig_R = PodEdwardsPoint(sig_lower);
    let sig_s_bytes =
        scalar_from_canonical_bytes(sig_upper).ok_or(SignatureError::InvalidSignature)?;

    validate_pubkey(&pubkey_point)?;
    validate_signature_point(&sig_R)?;

    let k_bytes = scalar_from_bytes_mod_order_wide(challenge);

    let a = PodScalar(k_bytes);
    let b = PodScalar(sig_s_bytes);
    let B = PodEdwardsPoint(G);

    // R = sB - kA

    let sB = multiply_edwards(&b, &B).ok_or(SignatureError::InvalidSignature)?;
    let kA = multiply_edwards(&a, &pubkey_point).ok_or(SignatureError::InvalidPublicKey)?;
    let R = subtract_edwards(&sB, &kA).ok_or(SignatureError::InvalidSignature)?;

    let expected_R = sig_R.0;
    let computed_R = R.0;

    if expected_R == computed_R {
        Ok(())
    } else {
        Err(SignatureError::InvalidSignature)
    }
}

#[inline(always)]
fn validate_pubkey(pubkey: &PodEdwardsPoint) -> Result<(), SignatureError> {
    // Keep the explicit curve check even though decompression in the curve shim
    // already performs it. This preserves a stable error mapping for callers.
    if !validate_edwards(pubkey) || is_small_order(pubkey) {
        Err(SignatureError::InvalidPublicKey)
    } else {
        Ok(())
    }
}

#[inline(always)]
fn validate_signature_point(sig_r: &PodEdwardsPoint) -> Result<(), SignatureError> {
    if !validate_edwards(sig_r) || is_small_order(sig_r) {
        Err(SignatureError::InvalidSignature)
    } else {
        Ok(())
    }
}

#[inline(always)]
fn challenge<H: Hasher>(
    sig_r: &PodEdwardsPoint,
    pubkey: &Pubkey,
    messagev: &[&[u8]],
) -> [u8; 64] {
    let mut hasher = H::new();
    hasher.update(&sig_r.0);
    hasher.update(pubkey);

    for message in messagev {
        hasher.update(message);
    }

    hasher.finalize()
}

/// Split the signature into two 32-byte arrays.
#[inline(always)]
fn split_signature(sig: &[u8; 64]) -> ([u8; 32], [u8; 32]) {
    let mut sig_lower: MaybeUninit<[u8; 32]> = MaybeUninit::uninit();
    let mut sig_upper: MaybeUninit<[u8; 32]> = MaybeUninit::uninit();

    // SAFETY: The length of `sig` is 64 bytes, we're copying 32 bytes into
    // `sig_lower` and `sig_upper` respectively.
    unsafe {
        core::ptr::copy_nonoverlapping(sig.as_ptr(), sig_lower.as_mut_ptr() as *mut u8, 32);

        core::ptr::copy_nonoverlapping(sig.as_ptr().add(32), sig_upper.as_mut_ptr() as *mut u8, 32);

        (sig_lower.assume_init(), sig_upper.assume_init())
    }
}

/// The eight small-order (torsion) points on Curve25519, in compressed
/// Edwards form. Any point matching one of these is rejected during
/// signature verification.
const EIGHT_TORSION: [[u8; 32]; 8] = [
    [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a],
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80],
    [0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05],
    [0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
    [0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x85],
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0xfa],
];

/// Determine if this point is of small order by checking against the
/// eight known torsion points (table lookup, no curve syscalls).
#[inline(always)]
fn is_small_order(point: &PodEdwardsPoint) -> bool {
    EIGHT_TORSION.iter().any(|t| point.0 == *t)
}

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
        let base_point_bytes = G;
        let base_point = PodEdwardsPoint(base_point_bytes);
        assert_eq!(is_small_order(&base_point), false);

        // Torsion points (have small order)
        for i in 0..8 {
            let torsion_point = constants::EIGHT_TORSION[i];
            let compressed = torsion_point.compress();
            let torsion_point_bytes = compressed.to_bytes();
            assert_eq!(torsion_point_bytes, EIGHT_TORSION[i], "torsion point {i} mismatch");
            assert_eq!(is_small_order(&PodEdwardsPoint(torsion_point_bytes)), true);
        }
    }

    #[test]
    fn test_hello_world() {
        let pubkey: [u8; 32] = [
            73, 73, 170, 112, 75, 235, 154, 81, 203, 8, 44, 245, 233, 18, 204, 136, 162, 9, 233,
            49, 154, 201, 171, 175, 47, 6, 223, 101, 105, 80, 95, 166,
        ];
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
        let pubkey = EIGHT_TORSION[0];
        let sig: [u8; 64] = [
            164, 121, 89, 242, 88, 29, 80, 177, 104, 20, 102, 176, 48, 133, 68, 8, 105, 33, 58, 86,
            28, 108, 198, 140, 160, 219, 62, 184, 154, 181, 140, 33, 35, 102, 183, 203, 111, 33,
            55, 170, 180, 138, 92, 196, 185, 201, 122, 167, 15, 112, 9, 228, 226, 112, 111, 10,
            142, 73, 85, 43, 81, 152, 204, 13,
        ];

        assert_eq!(
            verify::<Sha512>(&pubkey, &sig, &[b"hello world"]),
            Err(SignatureError::InvalidPublicKey)
        );
    }

    #[test]
    fn test_error_invalid_signature() {
        let pubkey: [u8; 32] = [
            73, 73, 170, 112, 75, 235, 154, 81, 203, 8, 44, 245, 233, 18, 204, 136, 162, 9, 233,
            49, 154, 201, 171, 175, 47, 6, 223, 101, 105, 80, 95, 166,
        ];
        let sig: [u8; 64] = [
            164, 121, 89, 242, 88, 29, 80, 177, 104, 20, 102, 176, 48, 133, 68, 8, 105, 33, 58, 86,
            28, 108, 198, 140, 160, 219, 62, 184, 154, 181, 140, 33, 35, 102, 183, 203, 111, 33,
            55, 170, 180, 138, 92, 196, 185, 201, 122, 167, 15, 112, 9, 228, 226, 112, 111, 10,
            142, 73, 85, 43, 81, 152, 204, 13,
        ];

        assert_eq!(
            verify::<Sha512>(&pubkey, &sig, &[b"not the right message"]),
            Err(SignatureError::InvalidSignature)
        );
    }

    #[test]
    fn test_hello_worldv() {
        let pubkey: [u8; 32] = [
            73, 73, 170, 112, 75, 235, 154, 81, 203, 8, 44, 245, 233, 18, 204, 136, 162, 9, 233,
            49, 154, 201, 171, 175, 47, 6, 223, 101, 105, 80, 95, 166,
        ];
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
        let pubkey: [u8; 32] = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
            0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
            0xf7, 0x07, 0x51, 0x1a,
        ];

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
        let pubkey: [u8; 32] = [
            0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b,
            0x7e, 0xbc, 0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1,
            0x2a, 0xf4, 0x66, 0x0c,
        ];

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
        let pubkey: [u8; 32] = [
            0xfc, 0x51, 0xcd, 0x8e, 0x62, 0x18, 0xa1, 0xa3, 0x8d, 0xa4, 0x7e, 0xd0, 0x02, 0x30,
            0xf0, 0x58, 0x08, 0x16, 0xed, 0x13, 0xba, 0x33, 0x03, 0xac, 0x5d, 0xeb, 0x91, 0x15,
            0x48, 0x90, 0x80, 0x25,
        ];

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
        let pubkey: [u8; 32] = [
            0xfc, 0x51, 0xcd, 0x8e, 0x62, 0x18, 0xa1, 0xa3, 0x8d, 0xa4, 0x7e, 0xd0, 0x02, 0x30,
            0xf0, 0x58, 0x08, 0x16, 0xed, 0x13, 0xba, 0x33, 0x03, 0xac, 0x5d, 0xeb, 0x91, 0x15,
            0x48, 0x90, 0x80, 0x25,
        ];

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
        let sig_r = PodEdwardsPoint([
            164, 121, 89, 242, 88, 29, 80, 177, 104, 20, 102, 176, 48, 133, 68, 8, 105, 33, 58, 86,
            28, 108, 198, 140, 160, 219, 62, 184, 154, 181, 140, 33,
        ]);
        let pubkey = [
            73, 73, 170, 112, 75, 235, 154, 81, 203, 8, 44, 245, 233, 18, 204, 136, 162, 9, 233,
            49, 154, 201, 171, 175, 47, 6, 223, 101, 105, 80, 95, 166,
        ];
        let messagev: &[&[u8]] = &[b"hello", b" ", b"world"];

        let expected =
            Sha512::hashv(&[sig_r.0.as_ref(), pubkey.as_ref(), b"hello", b" ", b"world"]);

        assert_eq!(
            challenge::<Sha512>(&sig_r, &pubkey, messagev),
            expected
        );
    }
}
