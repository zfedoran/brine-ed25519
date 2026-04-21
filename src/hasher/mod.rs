mod sha512;

pub use sha512::Sha512;

#[cfg(feature = "fast-sha512")]
mod fast_sha512;
#[cfg(feature = "fast-sha512")]
pub use fast_sha512::FastSha512;

pub trait Hasher: Sized {
    fn new() -> Self;
    fn update(&mut self, bytes: &[u8]);
    fn finalize(self) -> [u8; 64];

    #[inline(always)]
    fn hash(bytes: &[u8]) -> [u8; 64] {
        let mut hasher = Self::new();
        hasher.update(bytes);
        hasher.finalize()
    }

    #[inline(always)]
    fn hashv(bytesv: &[&[u8]]) -> [u8; 64] {
        let mut hasher = Self::new();
        for bytes in bytesv {
            hasher.update(bytes);
        }
        hasher.finalize()
    }
}
