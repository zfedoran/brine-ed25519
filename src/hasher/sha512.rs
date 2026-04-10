use sha2::{Digest, Sha512 as Sha512Hasher, digest::FixedOutput};

use crate::hasher::Hasher;

pub struct Sha512;

impl Hasher for Sha512 {
    #[inline(always)]
    fn hash(bytes: &[u8]) -> [u8;64] {
        Sha512Hasher::new_with_prefix(bytes).finalize_fixed().into()
    }

    #[inline(always)]
    fn hashv(bytes: &[&[u8]]) -> [u8;64] {
        let mut hasher = Sha512Hasher::new();
        for b in bytes {
            hasher.update(b)
        }
        hasher.finalize_fixed().into()
    }
}