pub mod sha512;
pub use sha512::*;

pub trait Hasher {
    fn hash(bytes: &[u8]) -> [u8;64];
    fn hashv(bytes: &[&[u8]]) -> [u8;64];
}