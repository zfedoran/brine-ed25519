use sha2::{Digest, Sha512 as Sha512Hasher};

use crate::hasher::Hasher;

pub struct Sha512(Sha512Hasher);

impl Hasher for Sha512 {
    #[inline(always)]
    fn new() -> Self {
        Self(Sha512Hasher::new())
    }

    #[inline(always)]
    fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    #[inline(always)]
    fn finalize(self) -> [u8; 64] {
        self.0.finalize().into()
    }
}
