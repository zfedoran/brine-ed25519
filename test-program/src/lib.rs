#![cfg_attr(not(test), no_std)]
#![allow(unexpected_cfgs)]

use brine_ed25519::{verify, hasher::Sha512};
use pinocchio::{
    default_allocator, nostd_panic_handler, program_entrypoint, 
    AccountView, Address, ProgramResult,
};

const HELLO_WORLD_PUBKEY: [u8; 32] = [
    73, 73, 170, 112, 75, 235, 154, 81, 203, 8, 44, 245, 233, 18, 204, 136, 162, 9, 233, 49, 154,
    201, 171, 175, 47, 6, 223, 101, 105, 80, 95, 166,
];

const HELLO_WORLD_SIG: [u8; 64] = [
    164, 121, 89, 242, 88, 29, 80, 177, 104, 20, 102, 176, 48, 133, 68, 8, 105, 33, 58, 86, 28,
    108, 198, 140, 160, 219, 62, 184, 154, 181, 140, 33, 35, 102, 183, 203, 111, 33, 55, 170, 180,
    138, 92, 196, 185, 201, 122, 167, 15, 112, 9, 228, 226, 112, 111, 10, 142, 73, 85, 43, 81,
    152, 204, 13,
];

default_allocator!();
nostd_panic_handler!();
program_entrypoint!(process_instruction);

fn process_instruction(
    _program_id: &Address,
    _accounts: &mut [AccountView],
    _instruction_data: &[u8],
) -> ProgramResult {
    verify::<Sha512>(&HELLO_WORLD_PUBKEY, &HELLO_WORLD_SIG, &[b"hello world"])
}

#[cfg(test)]
mod tests {
    use mollusk_svm::{Mollusk, result::ProgramResult};
    use solana_instruction::Instruction;

    #[test]
    fn test_verify() {
        let mollusk = Mollusk::new( &[0x02;32].into(), "target/deploy/brine_ed25519_test");

        let result = mollusk.process_instruction(
            &Instruction::new_with_bytes([0x02;32].into(), &[], vec![]),
            &[],
        );

        println!("verify consumed {} CUs", result.compute_units_consumed);
        assert!(matches!(result.program_result, ProgramResult::Success), "{result:?}");
    }
}
