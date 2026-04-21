#![cfg_attr(not(test), no_std)]
#![allow(unexpected_cfgs)]

use brine_ed25519::{hasher::Sha512, verify, Address};
use pinocchio::{default_allocator, nostd_panic_handler};

const HELLO_WORLD_PUBKEY: Address = Address::new_from_array([
    73, 73, 170, 112, 75, 235, 154, 81, 203, 8, 44, 245, 233, 18, 204, 136, 162, 9, 233, 49, 154,
    201, 171, 175, 47, 6, 223, 101, 105, 80, 95, 166,
]);

const HELLO_WORLD_SIG: [u8; 64] = [
    164, 121, 89, 242, 88, 29, 80, 177, 104, 20, 102, 176, 48, 133, 68, 8, 105, 33, 58, 86, 28,
    108, 198, 140, 160, 219, 62, 184, 154, 181, 140, 33, 35, 102, 183, 203, 111, 33, 55, 170, 180,
    138, 92, 196, 185, 201, 122, 167, 15, 112, 9, 228, 226, 112, 111, 10, 142, 73, 85, 43, 81, 152,
    204, 13,
];

default_allocator!();
nostd_panic_handler!();

#[unsafe(no_mangle)]
pub unsafe extern "C" fn entrypoint() -> u64 {
    match verify::<Sha512>(&HELLO_WORLD_PUBKEY, &HELLO_WORLD_SIG, &[b"hello world"]) {
        Ok(_) => 0,
        Err(e) => e.into(),
    }
}

#[cfg(test)]
mod tests {
    use mollusk_svm::{result::Check, Mollusk};
    use solana_instruction::Instruction;

    #[test]
    fn test_verify() {
        let mollusk = Mollusk::new(&[0x02; 32].into(), "target/deploy/brine_ed25519_test");

        let result = mollusk.process_and_validate_instruction(
            &Instruction::new_with_bytes([0x02; 32].into(), &[], vec![]),
            &[],
            &[Check::success()],
        );
        println!("verify consumed {} CUs", result.compute_units_consumed);
    }
}
