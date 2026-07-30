//! Small curve shim for this crate.
//!
//! This crate is mainly meant to run inside Solana. On `target_arch = "bpf"` or
//! `target_os = "solana"`, the point operations used by signature verification
//! go straight to Solana's native curve syscalls.
//!
//! We still support host builds for tests and off-chain callers, so the same
//! API is backed by `curve25519-dalek` there.

#[cfg(not(any(target_arch = "bpf", target_os = "solana")))]
mod imp {
    use curve25519_dalek::{
        edwards::{CompressedEdwardsY, EdwardsPoint},
        scalar::Scalar,
        traits::Identity,
    };

    #[inline(always)]
    pub(crate) fn multiscalar_multiply_edwards(
        scalars: &[[u8; 32]],
        points: &[[u8; 32]],
    ) -> Option<[u8; 32]> {
        let mut acc = EdwardsPoint::identity();
        for (s, p) in scalars.iter().zip(points.iter()) {
            let scalar = Option::from(Scalar::from_canonical_bytes(*s))?;
            let point = CompressedEdwardsY(*p).decompress()?;
            acc = &acc + &(&scalar * &point);
        }
        Some(acc.compress().to_bytes())
    }
}

#[cfg(any(target_arch = "bpf", target_os = "solana"))]
mod imp {
    use solana_define_syscall::{
        curve_constants::CURVE25519_EDWARDS, definitions::sol_curve_multiscalar_mul,
    };

    #[inline(always)]
    pub(crate) fn multiscalar_multiply_edwards(
        scalars: &[[u8; 32]],
        points: &[[u8; 32]],
    ) -> Option<[u8; 32]> {
        // SAFETY: on success (result == 0) the syscall writes all 32 bytes
        // of the output point, so the MaybeUninit is fully initialised.
        let mut result_point = core::mem::MaybeUninit::<[u8; 32]>::uninit();
        let result = unsafe {
            sol_curve_multiscalar_mul(
                CURVE25519_EDWARDS,
                scalars.as_ptr() as *const u8,
                points.as_ptr() as *const u8,
                points.len() as u64,
                result_point.as_mut_ptr() as *mut u8,
            )
        };

        if result == 0 {
            Some(unsafe { result_point.assume_init() })
        } else {
            None
        }
    }
}

pub(crate) use imp::multiscalar_multiply_edwards;
