#![allow(unexpected_cfgs)]

use brine_ed25519::{sig_verify, sig_verify_prehashed, sig_verifyv, SignatureError};
use solana_program::{
    account_info::AccountInfo, entrypoint, entrypoint::ProgramResult, program_error::ProgramError,
    pubkey::Pubkey,
};

const MODE_VERIFY:    u8 = 0;
const MODE_VERIFYV:   u8 = 1;
const MODE_PREHASHED: u8 = 2;

const PUBKEY_LEN: usize = 32;
const SIG_LEN:    usize = 64;
const HEADER_LEN: usize = 1 + PUBKEY_LEN + SIG_LEN;
const MAX_MESSAGE_PARTS: usize = 8;

const ERR_INVALID_ARGUMENT:      u32 = 1;
const ERR_INVALID_PUBLIC_KEY:    u32 = 2;
const ERR_INVALID_SIGNATURE:     u32 = 3;
const ERR_INVALID_ACCOUNT_OWNER: u32 = 4;

#[no_mangle]
pub static IDL: &str = "https://github.com/zfedoran/brine-ed25519";

entrypoint!(process_instruction);

fn process_instruction(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    ix: &[u8],
) -> ProgramResult {
    if ix.len() < HEADER_LEN {
        return Err(ProgramError::InvalidInstructionData);
    }

    // You can choose whatever ix format you'd like in your actual program, this is just a
    // convenient way to test multiple verification modes without needing separate instructions

    // The instruction data is expected to be in the following format:
    // [mode (1 byte)] [pubkey (32 bytes)] [signature (64 bytes)] [payload (remaining bytes)]

    let mode = ix[0];
    let pubkey = &ix[1..1 + PUBKEY_LEN];
    let sig = &ix[1 + PUBKEY_LEN..HEADER_LEN];
    let payload = &ix[HEADER_LEN..];

    let result = match mode {

        // Normal signature verification over a single message
        MODE_VERIFY => 
            sig_verify(pubkey, sig, payload),

        // Signature verification over multiple message parts, which avoids 
        // needing to concatenate them into a single buffer
        MODE_VERIFYV => 
            verify_vectored(pubkey, sig, payload),

        // Signature verification where the message has already been hashed by the caller
        // (e.g. for verifying signatures from off-chain where the message is too large 
        // to fit in a single instruction, or to save compute units by avoiding hashing on-chain)
        // Be careful when doing this
        MODE_PREHASHED => 
            sig_verify_prehashed(pubkey, sig, payload),

        _ => Err(SignatureError::InvalidArgument),
    };

    result.map_err(map_signature_error)
}

fn verify_vectored(
    pubkey: &[u8],
    sig: &[u8],
    payload: &[u8]
    ) -> Result<(), SignatureError> {

    let (messagev, part_count) =
        parse_message_parts(payload)
        .map_err(|_| SignatureError::InvalidArgument)?;

    sig_verifyv(pubkey, sig, &messagev[..part_count])
}

fn parse_message_parts<'a>(
    payload: &'a [u8],
) -> Result<([&'a [u8]; MAX_MESSAGE_PARTS], usize), ProgramError> {
    if payload.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    let part_count = payload[0] as usize;
    if part_count == 0 || part_count > MAX_MESSAGE_PARTS {
        return Err(ProgramError::InvalidInstructionData);
    }

    let lengths_len = part_count
        .checked_mul(2)
        .and_then(|len| len.checked_add(1))
        .ok_or(ProgramError::InvalidInstructionData)?;

    if payload.len() < lengths_len {
        return Err(ProgramError::InvalidInstructionData);
    }

    let mut parts = [&[][..]; MAX_MESSAGE_PARTS];
    let mut lengths_offset = 1;
    let mut message_offset = lengths_len;

    for part in parts.iter_mut().take(part_count) {
        let len_bytes: [u8; 2] = payload[lengths_offset..lengths_offset + 2]
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        lengths_offset += 2;

        let len = u16::from_le_bytes(len_bytes) as usize;
        let end = message_offset
            .checked_add(len)
            .ok_or(ProgramError::InvalidInstructionData)?;
        if end > payload.len() {
            return Err(ProgramError::InvalidInstructionData);
        }

        *part = &payload[message_offset..end];
        message_offset = end;
    }

    if message_offset != payload.len() {
        return Err(ProgramError::InvalidInstructionData);
    }

    Ok((parts, part_count))
}

fn map_signature_error(err: SignatureError) -> ProgramError {
    let code = match err {
        SignatureError::InvalidArgument => ERR_INVALID_ARGUMENT,
        SignatureError::InvalidPublicKey => ERR_INVALID_PUBLIC_KEY,
        SignatureError::InvalidSignature => ERR_INVALID_SIGNATURE,
        SignatureError::InvalidAccountOwner => ERR_INVALID_ACCOUNT_OWNER,
    };

    ProgramError::Custom(code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mollusk_svm::{result::ProgramResult, Mollusk};
    use solana_sdk::{instruction::Instruction, pubkey::Pubkey};
    use std::path::Path;

    // We're not asserting specific CU costs here, just that they're within a reasonable range for
    // a single signature verification.

    const VERIFY_CU_LIMIT: u64 = 30_000;
    const VERIFYV_CU_LIMIT: u64 = 30_000;
    const PREHASHED_CU_LIMIT: u64 = 30_000;

    const HELLO_WORLD_PUBKEY: [u8; PUBKEY_LEN] = [
        73, 73, 170, 112, 75, 235, 154, 81, 203, 8, 44, 245, 233, 18, 204, 136, 162, 9, 233, 49,
        154, 201, 171, 175, 47, 6, 223, 101, 105, 80, 95, 166,
    ];

    const HELLO_WORLD_SIG: [u8; SIG_LEN] = [
        164, 121, 89, 242, 88, 29, 80, 177, 104, 20, 102, 176, 48, 133, 68, 8, 105, 33, 58, 86, 28,
        108, 198, 140, 160, 219, 62, 184, 154, 181, 140, 33, 35, 102, 183, 203, 111, 33, 55, 170,
        180, 138, 92, 196, 185, 201, 122, 167, 15, 112, 9, 228, 226, 112, 111, 10, 142, 73, 85, 43,
        81, 152, 204, 13,
    ];

    const PREHASHED_PUBKEY: [u8; PUBKEY_LEN] = [
        0xfc, 0x51, 0xcd, 0x8e, 0x62, 0x18, 0xa1, 0xa3, 0x8d, 0xa4, 0x7e, 0xd0, 0x02, 0x30, 0xf0,
        0x58, 0x08, 0x16, 0xed, 0x13, 0xba, 0x33, 0x03, 0xac, 0x5d, 0xeb, 0x91, 0x15, 0x48, 0x90,
        0x80, 0x25,
    ];

    const PREHASHED_SIG: [u8; SIG_LEN] = [
        0x62, 0x91, 0xd6, 0x57, 0xde, 0xec, 0x24, 0x02, 0x48, 0x27, 0xe6, 0x9c, 0x3a, 0xbe, 0x01,
        0xa3, 0x0c, 0xe5, 0x48, 0xa2, 0x84, 0x74, 0x3a, 0x44, 0x5e, 0x36, 0x80, 0xd7, 0xdb, 0x5a,
        0xc3, 0xac, 0x18, 0xff, 0x9b, 0x53, 0x8d, 0x16, 0xf2, 0x90, 0xae, 0x67, 0xf7, 0x60, 0x98,
        0x4d, 0xc6, 0x59, 0x4a, 0x7c, 0x15, 0xe9, 0x71, 0x6e, 0xd2, 0x8d, 0xc0, 0x27, 0xbe, 0xce,
        0xea, 0x1e, 0xc4, 0x0a,
    ];

    // These run the compiled SBF artifact, so keep them ignored by default.

    #[test]
    #[ignore]
    fn sig_verify_ok() {
        assert_ok("sig_verify", verify_ix(b"hello world"), VERIFY_CU_LIMIT);
    }

    #[test]
    #[ignore]
    fn sig_verify_err() {
        assert_err(verify_ix(b"not the right message"));
    }

    #[test]
    #[ignore]
    fn sig_verifyv_ok() {
        assert_ok(
            "sig_verifyv",
            verifyv_ix(&[b"hello", b" ", b"world"]),
            VERIFYV_CU_LIMIT,
        );
    }

    #[test]
    #[ignore]
    fn sig_verifyv_err() {
        assert_err(verifyv_ix(&[b"hello", b" ", b"there"]));
    }

    #[test]
    #[ignore]
    fn sig_verify_prehashed_ok() {
        assert_ok(
            "sig_verify_prehashed",
            prehashed_ix(&[0xaf, 0x82]),
            PREHASHED_CU_LIMIT,
        );
    }

    #[test]
    #[ignore]
    fn sig_verify_prehashed_err() {
        assert_err(prehashed_ix(&[0xaf, 0x83]));
    }

    fn assert_ok(name: &str, ix: Instruction, limit: u64) {
        let result = process(ix);
        assert!(
            matches!(result.program_result, ProgramResult::Success),
            "{result:?}"
        );
        println!("{name} consumed {} CUs", result.compute_units_consumed);
        assert!(result.compute_units_consumed <= limit, "{result:?}");
    }

    fn assert_err(ix: Instruction) {
        let result = process(ix);
        assert!(is_verify_err(&result), "{result:?}");
    }

    fn is_verify_err(result: &mollusk_svm::result::InstructionResult) -> bool {
        matches!(
            result.program_result,
            ProgramResult::Failure(ProgramError::Custom(ERR_INVALID_ACCOUNT_OWNER))
                | ProgramResult::Failure(ProgramError::Custom(ERR_INVALID_SIGNATURE))
        )
    }

    fn process(instruction: Instruction) -> mollusk_svm::result::InstructionResult {
        assert_program_built();
        Mollusk::new(&program_id(), "target/deploy/brine_ed25519_test")
            .process_instruction(&instruction, &[])
    }

    fn program_id() -> Pubkey {
        Pubkey::new_from_array([7u8; 32])
    }

    fn assert_program_built() {
        assert!(
            Path::new("target/deploy/brine_ed25519_test.so").exists(),
            "missing SBF program artifact; run `cargo build-sbf` from test-program/ first"
        );
    }

    fn verify_ix(message: &[u8]) -> Instruction {
        instruction(MODE_VERIFY, &HELLO_WORLD_PUBKEY, &HELLO_WORLD_SIG, message)
    }

    fn prehashed_ix(digest: &[u8]) -> Instruction {
        instruction(
            MODE_PREHASHED,
            &PREHASHED_PUBKEY,
            &PREHASHED_SIG,
            digest,
        )
    }

    fn verifyv_ix(parts: &[&[u8]]) -> Instruction {
        let mut payload = Vec::with_capacity(
            1 + (parts.len() * 2) + parts.iter().map(|part| part.len()).sum::<usize>(),
        );
        payload.push(parts.len() as u8);
        for part in parts {
            payload.extend_from_slice(&(part.len() as u16).to_le_bytes());
        }
        for part in parts {
            payload.extend_from_slice(part);
        }

        instruction(
            MODE_VERIFYV,
            &HELLO_WORLD_PUBKEY,
            &HELLO_WORLD_SIG,
            &payload,
        )
    }

    fn instruction(
        mode: u8,
        pubkey: &[u8; PUBKEY_LEN],
        sig: &[u8; SIG_LEN],
        payload: &[u8],
    ) -> Instruction {
        let mut ix_data = Vec::with_capacity(HEADER_LEN + payload.len());
        ix_data.push(mode);
        ix_data.extend_from_slice(pubkey);
        ix_data.extend_from_slice(sig);
        ix_data.extend_from_slice(payload);

        Instruction::new_with_bytes(program_id(), &ix_data, vec![])
    }
}
