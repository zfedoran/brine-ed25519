//! SHA-512 via the `sol_sha512` syscall (SIMD-0512).
//!
//! Instead of hashing in-program, `update` records a (pointer, length)
//! descriptor per slice and `finalize` hands the whole descriptor array to
//! the runtime in a single syscall, which prices short inputs at
//! `85 + max(10, len/2)` CU per slice instead of thousands of CU for a
//! software compression.
//!
//! Requires the `enable_sha512_syscall` feature gate
//! (`s512oDwgx8hjMnaQjXfqqrZroVj4HvC6TkN3iSSWXCh`) to be active on the
//! target cluster. Programs built with this hasher fail to load on clusters
//! where the gate is inactive (the `sol_sha512` syscall is not registered,
//! whether linked dynamically or via a static syscall number). Enable the
//! `fast-sha512` feature to fall back to in-program hashing on such
//! clusters.
//!
//! This module is only compiled for Solana targets; host builds use the
//! `sha2`-backed [`Sha512`](crate::hasher::Sha512) instead.

use crate::hasher::Hasher;
use solana_define_syscall::definitions::sol_sha512;

/// Maximum number of `update` calls a single hash may record. The verify
/// path uses `2 + messages.len()` slices.
const MAX_SLICES: usize = 16;

/// One syscall input slice: (address, length), matching the runtime's
/// expected `SolBytes` layout. Stored explicitly rather than as `&[u8]`
/// so we do not rely on Rust's unspecified fat-pointer layout.
#[repr(C)]
#[derive(Clone, Copy)]
struct Slice {
    addr: u64,
    len: u64,
}

pub(crate) struct Sha512Syscall {
    slices: [Slice; MAX_SLICES],
    count: usize,
}

impl Hasher for Sha512Syscall {
    #[inline(always)]
    fn new() -> Self {
        Self {
            slices: [Slice { addr: 0, len: 0 }; MAX_SLICES],
            count: 0,
        }
    }

    /// Records the slice; the bytes are not read until `finalize`, so
    /// every slice passed to `update` must remain live until then.
    #[inline(always)]
    fn update(&mut self, bytes: &[u8]) {
        self.slices[self.count] = Slice {
            addr: bytes.as_ptr() as u64,
            len: bytes.len() as u64,
        };
        self.count += 1;
    }

    #[inline(always)]
    fn finalize(self) -> [u8; 64] {
        // SAFETY: the syscall reads `count` descriptors and writes all
        // 64 bytes of the output on return, aborting the VM on any
        // invalid memory access.
        let mut out = core::mem::MaybeUninit::<[u8; 64]>::uninit();
        unsafe {
            sol_sha512(
                self.slices.as_ptr() as *const u8,
                self.count as u64,
                out.as_mut_ptr() as *mut u8,
            );
            out.assume_init()
        }
    }
}
