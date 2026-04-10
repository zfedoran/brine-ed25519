//! Small curve shim for this crate.
//!
//! This crate is mainly meant to run inside Solana. On `target_os = "solana"`,
//! the point operations used by signature verification go straight to Solana's
//! native curve syscalls.
//!
//! We still support host builds for tests and off-chain callers, so the same
//! API is backed by `curve25519-dalek` there.
//!
//! Keeping that split here avoids pulling in `solana-curve25519` just to wrap a
//! few point operations. We still use `curve25519-dalek` elsewhere in the crate
//! for scalar parsing and reduction.

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(transparent)]
pub(crate) struct PodScalar(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(transparent)]
pub(crate) struct PodEdwardsPoint(pub [u8; 32]);

#[cfg(not(target_os = "solana"))]
mod imp {
    use super::{PodEdwardsPoint, PodScalar};
    use curve25519_dalek::{
        edwards::{CompressedEdwardsY, EdwardsPoint},
        scalar::Scalar,
    };

    #[inline(always)]
    pub(crate) fn validate_edwards(point: &PodEdwardsPoint) -> bool {
        point_from_pod(point).is_some()
    }

    #[inline(always)]
    pub(crate) fn subtract_edwards(
        left_point: &PodEdwardsPoint,
        right_point: &PodEdwardsPoint,
    ) -> Option<PodEdwardsPoint> {
        let left_point = point_from_pod(left_point)?;
        let right_point = point_from_pod(right_point)?;
        let result = &left_point - &right_point;
        Some(pod_from_point(&result))
    }

    #[inline(always)]
    pub(crate) fn multiply_edwards(
        scalar: &PodScalar,
        point: &PodEdwardsPoint,
    ) -> Option<PodEdwardsPoint> {
        let scalar = scalar_from_pod(scalar)?;
        let point = point_from_pod(point)?;
        let result = &scalar * &point;
        Some(pod_from_point(&result))
    }

    #[inline(always)]
    fn point_from_pod(pod: &PodEdwardsPoint) -> Option<EdwardsPoint> {
        CompressedEdwardsY(pod.0).decompress()
    }

    #[inline(always)]
    fn scalar_from_pod(pod: &PodScalar) -> Option<Scalar> {
        Option::from(Scalar::from_canonical_bytes(pod.0))
    }

    #[inline(always)]
    fn pod_from_point(point: &EdwardsPoint) -> PodEdwardsPoint {
        PodEdwardsPoint(point.compress().to_bytes())
    }
}

#[cfg(target_os = "solana")]
mod imp {
    use super::{PodEdwardsPoint, PodScalar};
    use solana_define_syscall::definitions::{sol_curve_group_op, sol_curve_validate_point};

    const CURVE25519_EDWARDS: u64 = 0;
    const SUB: u64 = 1;
    const MUL: u64 = 2;

    #[inline(always)]
    pub(crate) fn validate_edwards(point: &PodEdwardsPoint) -> bool {
        let mut validate_result = 0u8;
        let result = unsafe {
            sol_curve_validate_point(CURVE25519_EDWARDS, point.0.as_ptr(), &mut validate_result)
        };
        result == 0
    }

    #[inline(always)]
    pub(crate) fn subtract_edwards(
        left_point: &PodEdwardsPoint,
        right_point: &PodEdwardsPoint,
    ) -> Option<PodEdwardsPoint> {
        let mut result_point = PodEdwardsPoint([0u8; 32]);
        let result = unsafe {
            sol_curve_group_op(
                CURVE25519_EDWARDS,
                SUB,
                left_point.0.as_ptr(),
                right_point.0.as_ptr(),
                result_point.0.as_mut_ptr(),
            )
        };

        if result == 0 {
            Some(result_point)
        } else {
            None
        }
    }

    #[inline(always)]
    pub(crate) fn multiply_edwards(
        scalar: &PodScalar,
        point: &PodEdwardsPoint,
    ) -> Option<PodEdwardsPoint> {
        let mut result_point = PodEdwardsPoint([0u8; 32]);
        let result = unsafe {
            sol_curve_group_op(
                CURVE25519_EDWARDS,
                MUL,
                scalar.0.as_ptr(),
                point.0.as_ptr(),
                result_point.0.as_mut_ptr(),
            )
        };

        if result == 0 {
            Some(result_point)
        } else {
            None
        }
    }
}

pub(crate) use imp::{multiply_edwards, subtract_edwards, validate_edwards};
