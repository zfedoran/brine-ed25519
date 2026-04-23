//! # SHA-512 compression in hand-written sBPF inline assembly
#[cfg(any(target_arch = "bpf", target_os = "solana"))]
use crate::hasher::Hasher;

/// Serialize an 8-word SHA-512 state to its 64-byte big-endian digest.
/// Only called by the streaming finalize branch (cold on the ed25519 hot
/// path), so not inlined — keeps code off the hot cache line.
#[cfg(any(target_arch = "bpf", target_os = "solana", test))]
#[inline(never)]
fn state_to_be_bytes(state: &[u64; 8]) -> [u8; 64] {
    let mut out = core::mem::MaybeUninit::<[u8; 64]>::uninit();
    let ptr = out.as_mut_ptr() as *mut u64;
    let mut i = 0;
    while i < 8 {
        // SAFETY: `ptr.add(i)` is in-bounds for the `[u8; 64]` allocation.
        // Unaligned u64 store + byteswap beats 8 byte stores per word on
        // sBPF.
        unsafe { core::ptr::write_unaligned(ptr.add(i), state[i].to_be()) };
        i += 1;
    }
    // SAFETY: all 64 bytes written above.
    unsafe { out.assume_init() }
}

/// Σ1(e) = rotr14(e) ⊕ rotr18(e) ⊕ rotr41(e), computed as
/// `rotr14(e ⊕ rotr4(e) ⊕ rotr27(e))` (rotate composition:
/// `rotr_a(rotr_b(x)) = rotr_{a+b}(x)`). Source in r7 (e-carry from prior
/// round's new_e), result in r1, tmp r2. 16 ops (one fewer than the
/// 3-independent-rotates form, since the outer rotate reuses `u` already
/// in r1 and skips the initial `mov r1, r7`).
#[cfg(any(target_arch = "bpf", target_os = "solana"))]
macro_rules! sig1_r7_to_r1 {
    () => { concat!(
        // r1 = rotr4(r7)
        "mov64 r1, r7\n", "rsh64 r1, 4\n",
        "mov64 r2, r7\n", "lsh64 r2, 60\n", "xor64 r1, r2\n",
        // r1 = e ⊕ rotr4(e)
        "xor64 r1, r7\n",
        // r1 ⊕= rotr27(e)   (composed with the xor above → e ⊕ rotr4 ⊕ rotr27)
        "mov64 r2, r7\n", "rsh64 r2, 27\n", "xor64 r1, r2\n",
        "mov64 r2, r7\n", "lsh64 r2, 37\n", "xor64 r1, r2\n",
        // r1 = rotr14(u) = Σ1
        "mov64 r2, r1\n", "rsh64 r1, 14\n", "lsh64 r2, 50\n", "xor64 r1, r2\n",
    )};
}

/// Σ0(a) = rotr28(a) ⊕ rotr34(a) ⊕ rotr39(a), computed as
/// `rotr28(a ⊕ rotr6(a) ⊕ rotr11(a))` (same composition trick as Σ1).
/// Source in r0, result in r5, tmp r2. 16 ops.
#[cfg(any(target_arch = "bpf", target_os = "solana"))]
macro_rules! sig0_r0_to_r5 {
    () => { concat!(
        // r5 = rotr6(r0)
        "mov64 r5, r0\n", "rsh64 r5, 6\n",
        "mov64 r2, r0\n", "lsh64 r2, 58\n", "xor64 r5, r2\n",
        // r5 = a ⊕ rotr6(a)
        "xor64 r5, r0\n",
        // r5 ⊕= rotr11(a)
        "mov64 r2, r0\n", "rsh64 r2, 11\n", "xor64 r5, r2\n",
        "mov64 r2, r0\n", "lsh64 r2, 53\n", "xor64 r5, r2\n",
        // r5 = rotr28(u) = Σ0
        "mov64 r2, r5\n", "rsh64 r5, 28\n", "lsh64 r2, 36\n", "xor64 r5, r2\n",
    )};
}

/// σ0(x) = rotr1(x) ^ rotr8(x) ^ (x >> 7), computed as
/// `rotr1(x ^ rotr7(x)) ^ shr7(x)`.
///
/// `shr7(x) = x >> 7` is also the high half of `rotr7(x) = (x>>7) | (x<<57)`,
/// so we compute `x >> 7` once (into r3), use it to seed rotr7 construction,
/// and reuse it for the final XOR — saving the redundant `mov+rsh` pair at
/// the end. 12 ops. Uses r0 (src), r1 (dst), r2 (tmp), r3 (shr7 cache).
#[cfg(any(target_arch = "bpf", target_os = "solana"))]
macro_rules! smallsig0_r0_to_r1 {
    () => { concat!(
        // r3 = shr7(x)
        "mov64 r3, r0\n", "rsh64 r3, 7\n",
        // r1 = rotr7(x): start from shr7, XOR in the high shift
        "mov64 r1, r3\n",
        "mov64 r2, r0\n", "lsh64 r2, 57\n", "xor64 r1, r2\n",
        // r1 = x ^ rotr7(x)
        "xor64 r1, r0\n",
        // r1 = rotr1(r1) = rotr1(x) ^ rotr8(x)
        "mov64 r2, r1\n", "lsh64 r2, 63\n", "rsh64 r1, 1\n", "xor64 r1, r2\n",
        // r1 ^= shr7(x) (already in r3)
        "xor64 r1, r3\n",
    )};
}

/// σ1(x) = rotr19(x) ^ rotr61(x) ^ (x >> 6), computed as
/// `rotr19(x ^ rotr42(x)) ^ shr6(x)` (same composition trick as σ0).
/// Source in r0, result in r3, tmp r2. 13 ops.
#[cfg(any(target_arch = "bpf", target_os = "solana"))]
macro_rules! smallsig1_r0_to_r3 {
    () => { concat!(
        // r3 = rotr42(x)
        "mov64 r3, r0\n", "rsh64 r3, 42\n",
        "mov64 r2, r0\n", "lsh64 r2, 22\n", "xor64 r3, r2\n",
        // r3 = x ^ rotr42(x)
        "xor64 r3, r0\n",
        // r3 = rotr19(r3) = rotr19(x) ^ rotr61(x)
        "mov64 r2, r3\n", "lsh64 r2, 45\n", "rsh64 r3, 19\n", "xor64 r3, r2\n",
        // r3 ^= shr6(x)
        "mov64 r2, r0\n", "rsh64 r2, 6\n",  "xor64 r3, r2\n",
    )};
}

/// Ops: 3 loads (f, g, h) + Σ1 (16) + Ch (3) + 4 adds
///      + 3 loads (a, b, c) + Σ0 (16) + Maj (4) + 1 add
///      + 1 load (d) + 2 adds + 2 stores = 56.
///
/// Maj uses the XOR identity `Maj(a,b,c) = a ⊕ ((a⊕b) ∧ (a⊕c))` (FIPS
/// 180-4 §4.1.3's `(x∧y) ⊕ (x∧z) ⊕ (y∧z)` rewritten), matching the same
/// `z ⊕ (x ∧ (y⊕z))` trick already used for Ch just above.
#[cfg(any(target_arch = "bpf", target_os = "solana"))]
macro_rules! round_body_w_in_r5 {
    ($k:literal,
     $a:literal, $b:literal, $c:literal, $d:literal,
     $e:literal, $f:literal, $g:literal, $h:literal,
     $na:literal, $ne:literal) => { concat!(
        // --- T1 = h + Σ1(e) + Ch(e,f,g) + K[i] + W[i] ---
        // e is in r7 (carry); $e slot offset is unused in this expansion.
        "ldxdw r6, [r9 + ", $k, "]\n",
        sig1_r7_to_r1!(),
        "ldxdw r3, [r8 + ", $f, "]\n",
        "ldxdw r0, [r8 + ", $g, "]\n",
        "xor64 r3, r0\n",
        "and64 r3, r7\n",
        "xor64 r3, r0\n",
        "add64 r1, r3\n",
        "ldxdw r3, [r8 + ", $h, "]\n",     // h → r3 (was r7, now holds e)
        "add64 r1, r3\n",
        "add64 r1, r6\n",
        "add64 r1, r5\n",                   // W[i] already in r5

        // --- T2 = Σ0(a) + Maj(a,b,c); new_e; new_a (T1 consumed last) ---
        "ldxdw r0, [r8 + ", $a, "]\n",
        sig0_r0_to_r5!(),                   // r5 = Σ0(a) — W[i] no longer needed
        "ldxdw r3, [r8 + ", $b, "]\n",
        "ldxdw r4, [r8 + ", $c, "]\n",
        // Maj(a,b,c) = a ^ ((a^b) & (a^c)).
        "xor64 r3, r0\n",                   // r3 = a ^ b
        "xor64 r4, r0\n",                   // r4 = a ^ c
        "and64 r3, r4\n",                   // r3 = (a^b) & (a^c)
        "xor64 r3, r0\n",                   // r3 = Maj(a,b,c)
        "add64 r5, r3\n",                   // r5 = T2 = Σ0(a) + Maj
        "ldxdw r7, [r8 + ", $d, "]\n",     // r7 = d (e no longer needed)
        "add64 r7, r1\n",                   // r7 = new_e = d + T1 → carries as next round's e
        "add64 r5, r1\n",                   // r5 = new_a = T2 + T1 (clobbers r1)
        "stxdw [r8 + ", $na, "], r5\n",
        "stxdw [r8 + ", $ne, "], r7\n",
    )};
}

/// Round body for rounds 0..15: loads `W[i]` into `r5` from the pre-populated
/// schedule, then invokes the common body. 1 op of prologue.
#[cfg(any(target_arch = "bpf", target_os = "solana"))]
macro_rules! round_nosched {
    ($k:literal, $wi:literal,
     $a:literal, $b:literal, $c:literal, $d:literal,
     $e:literal, $f:literal, $g:literal, $h:literal,
     $na:literal, $ne:literal) => { concat!(
        "ldxdw r5, [r8 + ", $wi, "]\n",
        round_body_w_in_r5!($k, $a, $b, $c, $d, $e, $f, $g, $h, $na, $ne),
    )};
}

/// Like `round_nosched` but expects `h + K[i]` as a pre-summed 64-bit
/// constant materialised with `lddw`, saving one ldxdw (K[i]) + one ldxdw
/// (h) + one add, replaced by one lddw + one add. `h` isn't passed since
/// it's baked into the HK constant. 2 ops saved per invocation.
///
/// Usable whenever `h_i` is a compile-time constant — on the round-0-folded
/// fast path that's rounds 1, 2, 3 (h_i traces back to g_0, f_0, e_0, all
/// H0 entries). `$hk` must be a template fragment like `"{HK_2}"` matched
/// by a `HK_2 = const ...` asm operand.
#[cfg(any(target_arch = "bpf", target_os = "solana"))]
macro_rules! round_nosched_hk {
    ($hk:literal, $wi:literal,
     $a:literal, $b:literal, $c:literal, $d:literal,
     $e:literal, $f:literal, $g:literal,
     $na:literal, $ne:literal) => { concat!(
        "ldxdw r5, [r8 + ", $wi, "]\n",
        sig1_r7_to_r1!(),
        "ldxdw r3, [r8 + ", $f, "]\n",
        "ldxdw r0, [r8 + ", $g, "]\n",
        "xor64 r3, r0\n",
        "and64 r3, r7\n",
        "xor64 r3, r0\n",
        "add64 r1, r3\n",
        "lddw r6, ", $hk, "\n",
        "add64 r1, r6\n",
        "add64 r1, r5\n",
        "ldxdw r0, [r8 + ", $a, "]\n",
        sig0_r0_to_r5!(),
        "ldxdw r3, [r8 + ", $b, "]\n",
        "ldxdw r4, [r8 + ", $c, "]\n",
        "xor64 r3, r0\n",
        "xor64 r4, r0\n",
        "and64 r3, r4\n",
        "xor64 r3, r0\n",
        "add64 r5, r3\n",
        "ldxdw r7, [r8 + ", $d, "]\n",
        "add64 r7, r1\n",
        "add64 r5, r1\n",
        "stxdw [r8 + ", $na, "], r5\n",
        "stxdw [r8 + ", $ne, "], r7\n",
    )};
}

/// Schedule update (W[i] += σ0(W[i+1]) + W[i+9] + σ1(W[i+14])) leaving the
/// updated `W[i]` in `r5`, then the round body. Schedule: 36 ops.
#[cfg(any(target_arch = "bpf", target_os = "solana"))]
macro_rules! round_sched {
    ($k:literal, $wi:literal, $wip1:literal, $wip9:literal, $wip14:literal,
     $a:literal, $b:literal, $c:literal, $d:literal,
     $e:literal, $f:literal, $g:literal, $h:literal,
     $na:literal, $ne:literal) => { concat!(
        "ldxdw r0, [r8 + ", $wip1, "]\n",
        smallsig0_r0_to_r1!(),
        "ldxdw r0, [r8 + ", $wip14, "]\n",
        smallsig1_r0_to_r3!(),
        "ldxdw r5, [r8 + ", $wi, "]\n",
        "ldxdw r4, [r8 + ", $wip9, "]\n",
        "add64 r5, r1\n",
        "add64 r5, r3\n",
        "add64 r5, r4\n",
        "stxdw [r8 + ", $wi, "], r5\n",
        round_body_w_in_r5!($k, $a, $b, $c, $d, $e, $f, $g, $h, $na, $ne),
    )};
}

/// Rounds 2..79 — used by `compress_initial_h0_asm` after its folded
/// round 1. Rounds 2 and 3 use `round_nosched_hk` because their `h_i`
/// values (H0[5] and H0[4] respectively) are still compile-time constants
/// on the round-0-folded path; from round 4 onward h is W-dependent so we
/// revert to the generic `round_nosched`.
#[cfg(any(target_arch = "bpf", target_os = "solana"))]
macro_rules! rounds_2_through_79 {
    () => { concat!(
        round_nosched_hk!("{HK_2}", "80",  "48", "56", "0",  "8",  "16", "24", "32", "40", "8"),
        round_nosched_hk!("{HK_3}", "88",  "40", "48", "56", "0",  "8",  "16", "24", "32", "0"),
        round_nosched!("32",  "96",  "32", "40", "48", "56", "0",  "8",  "16", "24", "24", "56"),
        round_nosched!("40",  "104", "24", "32", "40", "48", "56", "0",  "8",  "16", "16", "48"),
        round_nosched!("48",  "112", "16", "24", "32", "40", "48", "56", "0",  "8",  "8",  "40"),
        round_nosched!("56",  "120", "8",  "16", "24", "32", "40", "48", "56", "0",  "0",  "32"),
        round_nosched!("64",  "128", "0",  "8",  "16", "24", "32", "40", "48", "56", "56", "24"),
        round_nosched!("72",  "136", "56", "0",  "8",  "16", "24", "32", "40", "48", "48", "16"),
        round_nosched!("80",  "144", "48", "56", "0",  "8",  "16", "24", "32", "40", "40", "8"),
        round_nosched!("88",  "152", "40", "48", "56", "0",  "8",  "16", "24", "32", "32", "0"),
        round_nosched!("96",  "160", "32", "40", "48", "56", "0",  "8",  "16", "24", "24", "56"),
        round_nosched!("104", "168", "24", "32", "40", "48", "56", "0",  "8",  "16", "16", "48"),
        round_nosched!("112", "176", "16", "24", "32", "40", "48", "56", "0",  "8",  "8",  "40"),
        round_nosched!("120", "184", "8",  "16", "24", "32", "40", "48", "56", "0",  "0",  "32"),

        round_sched!("128", "64",  "72",  "136", "176", "0",  "8",  "16", "24", "32", "40", "48", "56", "56", "24"),
        round_sched!("136", "72",  "80",  "144", "184", "56", "0",  "8",  "16", "24", "32", "40", "48", "48", "16"),
        round_sched!("144", "80",  "88",  "152", "64",  "48", "56", "0",  "8",  "16", "24", "32", "40", "40", "8"),
        round_sched!("152", "88",  "96",  "160", "72",  "40", "48", "56", "0",  "8",  "16", "24", "32", "32", "0"),
        round_sched!("160", "96",  "104", "168", "80",  "32", "40", "48", "56", "0",  "8",  "16", "24", "24", "56"),
        round_sched!("168", "104", "112", "176", "88",  "24", "32", "40", "48", "56", "0",  "8",  "16", "16", "48"),
        round_sched!("176", "112", "120", "184", "96",  "16", "24", "32", "40", "48", "56", "0",  "8",  "8",  "40"),
        round_sched!("184", "120", "128", "64",  "104", "8",  "16", "24", "32", "40", "48", "56", "0",  "0",  "32"),
        round_sched!("192", "128", "136", "72",  "112", "0",  "8",  "16", "24", "32", "40", "48", "56", "56", "24"),
        round_sched!("200", "136", "144", "80",  "120", "56", "0",  "8",  "16", "24", "32", "40", "48", "48", "16"),
        round_sched!("208", "144", "152", "88",  "128", "48", "56", "0",  "8",  "16", "24", "32", "40", "40", "8"),
        round_sched!("216", "152", "160", "96",  "136", "40", "48", "56", "0",  "8",  "16", "24", "32", "32", "0"),
        round_sched!("224", "160", "168", "104", "144", "32", "40", "48", "56", "0",  "8",  "16", "24", "24", "56"),
        round_sched!("232", "168", "176", "112", "152", "24", "32", "40", "48", "56", "0",  "8",  "16", "16", "48"),
        round_sched!("240", "176", "184", "120", "160", "16", "24", "32", "40", "48", "56", "0",  "8",  "8",  "40"),
        round_sched!("248", "184", "64",  "128", "168", "8",  "16", "24", "32", "40", "48", "56", "0",  "0",  "32"),
        round_sched!("256", "64",  "72",  "136", "176", "0",  "8",  "16", "24", "32", "40", "48", "56", "56", "24"),
        round_sched!("264", "72",  "80",  "144", "184", "56", "0",  "8",  "16", "24", "32", "40", "48", "48", "16"),
        round_sched!("272", "80",  "88",  "152", "64",  "48", "56", "0",  "8",  "16", "24", "32", "40", "40", "8"),
        round_sched!("280", "88",  "96",  "160", "72",  "40", "48", "56", "0",  "8",  "16", "24", "32", "32", "0"),
        round_sched!("288", "96",  "104", "168", "80",  "32", "40", "48", "56", "0",  "8",  "16", "24", "24", "56"),
        round_sched!("296", "104", "112", "176", "88",  "24", "32", "40", "48", "56", "0",  "8",  "16", "16", "48"),
        round_sched!("304", "112", "120", "184", "96",  "16", "24", "32", "40", "48", "56", "0",  "8",  "8",  "40"),
        round_sched!("312", "120", "128", "64",  "104", "8",  "16", "24", "32", "40", "48", "56", "0",  "0",  "32"),
        round_sched!("320", "128", "136", "72",  "112", "0",  "8",  "16", "24", "32", "40", "48", "56", "56", "24"),
        round_sched!("328", "136", "144", "80",  "120", "56", "0",  "8",  "16", "24", "32", "40", "48", "48", "16"),
        round_sched!("336", "144", "152", "88",  "128", "48", "56", "0",  "8",  "16", "24", "32", "40", "40", "8"),
        round_sched!("344", "152", "160", "96",  "136", "40", "48", "56", "0",  "8",  "16", "24", "32", "32", "0"),
        round_sched!("352", "160", "168", "104", "144", "32", "40", "48", "56", "0",  "8",  "16", "24", "24", "56"),
        round_sched!("360", "168", "176", "112", "152", "24", "32", "40", "48", "56", "0",  "8",  "16", "16", "48"),
        round_sched!("368", "176", "184", "120", "160", "16", "24", "32", "40", "48", "56", "0",  "8",  "8",  "40"),
        round_sched!("376", "184", "64",  "128", "168", "8",  "16", "24", "32", "40", "48", "56", "0",  "0",  "32"),
        round_sched!("384", "64",  "72",  "136", "176", "0",  "8",  "16", "24", "32", "40", "48", "56", "56", "24"),
        round_sched!("392", "72",  "80",  "144", "184", "56", "0",  "8",  "16", "24", "32", "40", "48", "48", "16"),
        round_sched!("400", "80",  "88",  "152", "64",  "48", "56", "0",  "8",  "16", "24", "32", "40", "40", "8"),
        round_sched!("408", "88",  "96",  "160", "72",  "40", "48", "56", "0",  "8",  "16", "24", "32", "32", "0"),
        round_sched!("416", "96",  "104", "168", "80",  "32", "40", "48", "56", "0",  "8",  "16", "24", "24", "56"),
        round_sched!("424", "104", "112", "176", "88",  "24", "32", "40", "48", "56", "0",  "8",  "16", "16", "48"),
        round_sched!("432", "112", "120", "184", "96",  "16", "24", "32", "40", "48", "56", "0",  "8",  "8",  "40"),
        round_sched!("440", "120", "128", "64",  "104", "8",  "16", "24", "32", "40", "48", "56", "0",  "0",  "32"),
        round_sched!("448", "128", "136", "72",  "112", "0",  "8",  "16", "24", "32", "40", "48", "56", "56", "24"),
        round_sched!("456", "136", "144", "80",  "120", "56", "0",  "8",  "16", "24", "32", "40", "48", "48", "16"),
        round_sched!("464", "144", "152", "88",  "128", "48", "56", "0",  "8",  "16", "24", "32", "40", "40", "8"),
        round_sched!("472", "152", "160", "96",  "136", "40", "48", "56", "0",  "8",  "16", "24", "32", "32", "0"),
        round_sched!("480", "160", "168", "104", "144", "32", "40", "48", "56", "0",  "8",  "16", "24", "24", "56"),
        round_sched!("488", "168", "176", "112", "152", "24", "32", "40", "48", "56", "0",  "8",  "16", "16", "48"),
        round_sched!("496", "176", "184", "120", "160", "16", "24", "32", "40", "48", "56", "0",  "8",  "8",  "40"),
        round_sched!("504", "184", "64",  "128", "168", "8",  "16", "24", "32", "40", "48", "56", "0",  "0",  "32"),
        round_sched!("512", "64",  "72",  "136", "176", "0",  "8",  "16", "24", "32", "40", "48", "56", "56", "24"),
        round_sched!("520", "72",  "80",  "144", "184", "56", "0",  "8",  "16", "24", "32", "40", "48", "48", "16"),
        round_sched!("528", "80",  "88",  "152", "64",  "48", "56", "0",  "8",  "16", "24", "32", "40", "40", "8"),
        round_sched!("536", "88",  "96",  "160", "72",  "40", "48", "56", "0",  "8",  "16", "24", "32", "32", "0"),
        round_sched!("544", "96",  "104", "168", "80",  "32", "40", "48", "56", "0",  "8",  "16", "24", "24", "56"),
        round_sched!("552", "104", "112", "176", "88",  "24", "32", "40", "48", "56", "0",  "8",  "16", "16", "48"),
        round_sched!("560", "112", "120", "184", "96",  "16", "24", "32", "40", "48", "56", "0",  "8",  "8",  "40"),
        round_sched!("568", "120", "128", "64",  "104", "8",  "16", "24", "32", "40", "48", "56", "0",  "0",  "32"),
        round_sched!("576", "128", "136", "72",  "112", "0",  "8",  "16", "24", "32", "40", "48", "56", "56", "24"),
        round_sched!("584", "136", "144", "80",  "120", "56", "0",  "8",  "16", "24", "32", "40", "48", "48", "16"),
        round_sched!("592", "144", "152", "88",  "128", "48", "56", "0",  "8",  "16", "24", "32", "40", "40", "8"),
        round_sched!("600", "152", "160", "96",  "136", "40", "48", "56", "0",  "8",  "16", "24", "32", "32", "0"),
        round_sched!("608", "160", "168", "104", "144", "32", "40", "48", "56", "0",  "8",  "16", "24", "24", "56"),
        round_sched!("616", "168", "176", "112", "152", "24", "32", "40", "48", "56", "0",  "8",  "16", "16", "48"),
        round_sched!("624", "176", "184", "120", "160", "16", "24", "32", "40", "48", "56", "0",  "8",  "8",  "40"),
        round_sched!("632", "184", "64",  "128", "168", "8",  "16", "24", "32", "40", "48", "56", "0",  "0",  "32"),
    )};
}

/// Rounds 1..79 of the SHA-512 compression — shared between the full
/// compress (`compress_asm`, which prepends round 0) and the round-0-folded
/// fast path (`compress_initial_h0_asm`, which starts here).
///
/// Rounds 1..15 use `round_nosched` (W schedule already materialized in
/// slots 64..184); rounds 16..79 use `round_sched` (on-the-fly schedule
/// update). Slot arg strings follow the (k_off, wi, a, b, c, d, e, f, g,
/// h, new_a, new_e) rotation from the round body doc above.
#[cfg(any(target_arch = "bpf", target_os = "solana"))]
macro_rules! rounds_1_through_79 {
    () => { concat!(
        // ---- Rounds 1..15: W[i] already loaded, no schedule update. ----
        round_nosched!("8",   "72",  "56", "0",  "8",  "16", "24", "32", "40", "48", "48", "16"),
        round_nosched!("16",  "80",  "48", "56", "0",  "8",  "16", "24", "32", "40", "40", "8"),
        round_nosched!("24",  "88",  "40", "48", "56", "0",  "8",  "16", "24", "32", "32", "0"),
        round_nosched!("32",  "96",  "32", "40", "48", "56", "0",  "8",  "16", "24", "24", "56"),
        round_nosched!("40",  "104", "24", "32", "40", "48", "56", "0",  "8",  "16", "16", "48"),
        round_nosched!("48",  "112", "16", "24", "32", "40", "48", "56", "0",  "8",  "8",  "40"),
        round_nosched!("56",  "120", "8",  "16", "24", "32", "40", "48", "56", "0",  "0",  "32"),
        round_nosched!("64",  "128", "0",  "8",  "16", "24", "32", "40", "48", "56", "56", "24"),
        round_nosched!("72",  "136", "56", "0",  "8",  "16", "24", "32", "40", "48", "48", "16"),
        round_nosched!("80",  "144", "48", "56", "0",  "8",  "16", "24", "32", "40", "40", "8"),
        round_nosched!("88",  "152", "40", "48", "56", "0",  "8",  "16", "24", "32", "32", "0"),
        round_nosched!("96",  "160", "32", "40", "48", "56", "0",  "8",  "16", "24", "24", "56"),
        round_nosched!("104", "168", "24", "32", "40", "48", "56", "0",  "8",  "16", "16", "48"),
        round_nosched!("112", "176", "16", "24", "32", "40", "48", "56", "0",  "8",  "8",  "40"),
        round_nosched!("120", "184", "8",  "16", "24", "32", "40", "48", "56", "0",  "0",  "32"),

        // ---- Rounds 16..79: schedule update + round body. ----
        round_sched!("128", "64",  "72",  "136", "176", "0",  "8",  "16", "24", "32", "40", "48", "56", "56", "24"),
        round_sched!("136", "72",  "80",  "144", "184", "56", "0",  "8",  "16", "24", "32", "40", "48", "48", "16"),
        round_sched!("144", "80",  "88",  "152", "64",  "48", "56", "0",  "8",  "16", "24", "32", "40", "40", "8"),
        round_sched!("152", "88",  "96",  "160", "72",  "40", "48", "56", "0",  "8",  "16", "24", "32", "32", "0"),
        round_sched!("160", "96",  "104", "168", "80",  "32", "40", "48", "56", "0",  "8",  "16", "24", "24", "56"),
        round_sched!("168", "104", "112", "176", "88",  "24", "32", "40", "48", "56", "0",  "8",  "16", "16", "48"),
        round_sched!("176", "112", "120", "184", "96",  "16", "24", "32", "40", "48", "56", "0",  "8",  "8",  "40"),
        round_sched!("184", "120", "128", "64",  "104", "8",  "16", "24", "32", "40", "48", "56", "0",  "0",  "32"),
        round_sched!("192", "128", "136", "72",  "112", "0",  "8",  "16", "24", "32", "40", "48", "56", "56", "24"),
        round_sched!("200", "136", "144", "80",  "120", "56", "0",  "8",  "16", "24", "32", "40", "48", "48", "16"),
        round_sched!("208", "144", "152", "88",  "128", "48", "56", "0",  "8",  "16", "24", "32", "40", "40", "8"),
        round_sched!("216", "152", "160", "96",  "136", "40", "48", "56", "0",  "8",  "16", "24", "32", "32", "0"),
        round_sched!("224", "160", "168", "104", "144", "32", "40", "48", "56", "0",  "8",  "16", "24", "24", "56"),
        round_sched!("232", "168", "176", "112", "152", "24", "32", "40", "48", "56", "0",  "8",  "16", "16", "48"),
        round_sched!("240", "176", "184", "120", "160", "16", "24", "32", "40", "48", "56", "0",  "8",  "8",  "40"),
        round_sched!("248", "184", "64",  "128", "168", "8",  "16", "24", "32", "40", "48", "56", "0",  "0",  "32"),
        round_sched!("256", "64",  "72",  "136", "176", "0",  "8",  "16", "24", "32", "40", "48", "56", "56", "24"),
        round_sched!("264", "72",  "80",  "144", "184", "56", "0",  "8",  "16", "24", "32", "40", "48", "48", "16"),
        round_sched!("272", "80",  "88",  "152", "64",  "48", "56", "0",  "8",  "16", "24", "32", "40", "40", "8"),
        round_sched!("280", "88",  "96",  "160", "72",  "40", "48", "56", "0",  "8",  "16", "24", "32", "32", "0"),
        round_sched!("288", "96",  "104", "168", "80",  "32", "40", "48", "56", "0",  "8",  "16", "24", "24", "56"),
        round_sched!("296", "104", "112", "176", "88",  "24", "32", "40", "48", "56", "0",  "8",  "16", "16", "48"),
        round_sched!("304", "112", "120", "184", "96",  "16", "24", "32", "40", "48", "56", "0",  "8",  "8",  "40"),
        round_sched!("312", "120", "128", "64",  "104", "8",  "16", "24", "32", "40", "48", "56", "0",  "0",  "32"),
        round_sched!("320", "128", "136", "72",  "112", "0",  "8",  "16", "24", "32", "40", "48", "56", "56", "24"),
        round_sched!("328", "136", "144", "80",  "120", "56", "0",  "8",  "16", "24", "32", "40", "48", "48", "16"),
        round_sched!("336", "144", "152", "88",  "128", "48", "56", "0",  "8",  "16", "24", "32", "40", "40", "8"),
        round_sched!("344", "152", "160", "96",  "136", "40", "48", "56", "0",  "8",  "16", "24", "32", "32", "0"),
        round_sched!("352", "160", "168", "104", "144", "32", "40", "48", "56", "0",  "8",  "16", "24", "24", "56"),
        round_sched!("360", "168", "176", "112", "152", "24", "32", "40", "48", "56", "0",  "8",  "16", "16", "48"),
        round_sched!("368", "176", "184", "120", "160", "16", "24", "32", "40", "48", "56", "0",  "8",  "8",  "40"),
        round_sched!("376", "184", "64",  "128", "168", "8",  "16", "24", "32", "40", "48", "56", "0",  "0",  "32"),
        round_sched!("384", "64",  "72",  "136", "176", "0",  "8",  "16", "24", "32", "40", "48", "56", "56", "24"),
        round_sched!("392", "72",  "80",  "144", "184", "56", "0",  "8",  "16", "24", "32", "40", "48", "48", "16"),
        round_sched!("400", "80",  "88",  "152", "64",  "48", "56", "0",  "8",  "16", "24", "32", "40", "40", "8"),
        round_sched!("408", "88",  "96",  "160", "72",  "40", "48", "56", "0",  "8",  "16", "24", "32", "32", "0"),
        round_sched!("416", "96",  "104", "168", "80",  "32", "40", "48", "56", "0",  "8",  "16", "24", "24", "56"),
        round_sched!("424", "104", "112", "176", "88",  "24", "32", "40", "48", "56", "0",  "8",  "16", "16", "48"),
        round_sched!("432", "112", "120", "184", "96",  "16", "24", "32", "40", "48", "56", "0",  "8",  "8",  "40"),
        round_sched!("440", "120", "128", "64",  "104", "8",  "16", "24", "32", "40", "48", "56", "0",  "0",  "32"),
        round_sched!("448", "128", "136", "72",  "112", "0",  "8",  "16", "24", "32", "40", "48", "56", "56", "24"),
        round_sched!("456", "136", "144", "80",  "120", "56", "0",  "8",  "16", "24", "32", "40", "48", "48", "16"),
        round_sched!("464", "144", "152", "88",  "128", "48", "56", "0",  "8",  "16", "24", "32", "40", "40", "8"),
        round_sched!("472", "152", "160", "96",  "136", "40", "48", "56", "0",  "8",  "16", "24", "32", "32", "0"),
        round_sched!("480", "160", "168", "104", "144", "32", "40", "48", "56", "0",  "8",  "16", "24", "24", "56"),
        round_sched!("488", "168", "176", "112", "152", "24", "32", "40", "48", "56", "0",  "8",  "16", "16", "48"),
        round_sched!("496", "176", "184", "120", "160", "16", "24", "32", "40", "48", "56", "0",  "8",  "8",  "40"),
        round_sched!("504", "184", "64",  "128", "168", "8",  "16", "24", "32", "40", "48", "56", "0",  "0",  "32"),
        round_sched!("512", "64",  "72",  "136", "176", "0",  "8",  "16", "24", "32", "40", "48", "56", "56", "24"),
        round_sched!("520", "72",  "80",  "144", "184", "56", "0",  "8",  "16", "24", "32", "40", "48", "48", "16"),
        round_sched!("528", "80",  "88",  "152", "64",  "48", "56", "0",  "8",  "16", "24", "32", "40", "40", "8"),
        round_sched!("536", "88",  "96",  "160", "72",  "40", "48", "56", "0",  "8",  "16", "24", "32", "32", "0"),
        round_sched!("544", "96",  "104", "168", "80",  "32", "40", "48", "56", "0",  "8",  "16", "24", "24", "56"),
        round_sched!("552", "104", "112", "176", "88",  "24", "32", "40", "48", "56", "0",  "8",  "16", "16", "48"),
        round_sched!("560", "112", "120", "184", "96",  "16", "24", "32", "40", "48", "56", "0",  "8",  "8",  "40"),
        round_sched!("568", "120", "128", "64",  "104", "8",  "16", "24", "32", "40", "48", "56", "0",  "0",  "32"),
        round_sched!("576", "128", "136", "72",  "112", "0",  "8",  "16", "24", "32", "40", "48", "56", "56", "24"),
        round_sched!("584", "136", "144", "80",  "120", "56", "0",  "8",  "16", "24", "32", "40", "48", "48", "16"),
        round_sched!("592", "144", "152", "88",  "128", "48", "56", "0",  "8",  "16", "24", "32", "40", "40", "8"),
        round_sched!("600", "152", "160", "96",  "136", "40", "48", "56", "0",  "8",  "16", "24", "32", "32", "0"),
        round_sched!("608", "160", "168", "104", "144", "32", "40", "48", "56", "0",  "8",  "16", "24", "24", "56"),
        round_sched!("616", "168", "176", "112", "152", "24", "32", "40", "48", "56", "0",  "8",  "16", "16", "48"),
        round_sched!("624", "176", "184", "120", "160", "16", "24", "32", "40", "48", "56", "0",  "8",  "8",  "40"),
        round_sched!("632", "184", "64",  "128", "168", "8",  "16", "24", "32", "40", "48", "56", "0",  "0",  "32"),
    )};
}

/// Hand-written sBPF inline-asm SHA-512 compression function.
#[cfg(any(target_arch = "bpf", target_os = "solana"))]
#[inline(never)]
fn compress_asm(state: &mut [u64; 8], block: &[u8; 128]) {
    // 8 state working slots + 16 W slots. Skip the initial zero-fill —
    // every slot is written below before the asm reads it.
    //
    // W slots on the stack. Byte offsets from `r8` (locals base):
    //   state[0..8] → 0,  8, 16, 24, 32, 40, 48, 56
    //   W[0..16]    → 64, 72, 80, ..., 184
    // W[i mod 16] lives at `64 + (i mod 16) * 8`.
    let mut locals: core::mem::MaybeUninit<[u64; 24]> = core::mem::MaybeUninit::uninit();
    let locals_ptr = locals.as_mut_ptr() as *mut u64;
    let block_ptr = block.as_ptr() as *const u64;

    // SAFETY:
    // - `locals_ptr` points at a valid `[u64; 24]` stack allocation. The
    //   two loops below write each of its 24 slots (state[0..8] then the
    //   16 big-endian block words), so `assume_init` is sound.
    // - `read_unaligned::<u64>` on `block_ptr.add(i)` for `i < 16` stays
    //   within the 128-byte `block`; sBPF permits unaligned loads.
    // - The `core::arch::asm!` block consumes `locals` / `K` by pointer
    //   and conforms to the register clobber list.
    unsafe {
        let mut k = 0;
        while k < 8 {
            locals_ptr.add(k).write(state[k]);
            k += 1;
        }

        // One unaligned u64 load + bswap per word instead of 8 byte loads.
        let mut i = 0;
        while i < 16 {
            let word = u64::from_be(core::ptr::read_unaligned(block_ptr.add(i)));
            locals_ptr.add(8 + i).write(word);
            i += 1;
        }

        let mut locals = locals.assume_init();

        core::arch::asm!(
            concat!(
                // Pre-load e_0 into r7 so round 0 can pick it up via the
                // same e-carry path as rounds 1..79 (sig1 sources from r7).
                // Costs 1 op; saves 1 ldxdw per round across 80 rounds.
                "ldxdw r7, [r8 + 32]\n",
                // Round 0: W[0] already loaded, no schedule update.
                round_nosched!("0", "64", "0", "8", "16", "24", "32", "40", "48", "56", "56", "24"),
                rounds_1_through_79!(),
            ),
            in("r8") locals.as_mut_ptr(),
            in("r9") K.as_ptr(),
            out("r0") _, out("r1") _, out("r2") _, out("r3") _,
            out("r4") _, out("r5") _, out("r6") _, out("r7") _,
            options(nostack),
        );

        state[0] = state[0].wrapping_add(locals[0]);
        state[1] = state[1].wrapping_add(locals[1]);
        state[2] = state[2].wrapping_add(locals[2]);
        state[3] = state[3].wrapping_add(locals[3]);
        state[4] = state[4].wrapping_add(locals[4]);
        state[5] = state[5].wrapping_add(locals[5]);
        state[6] = state[6].wrapping_add(locals[6]);
        state[7] = state[7].wrapping_add(locals[7]);
    }
}

/// Specialized compress for the hashv single-block fast path where the
/// initial state is the standard IVs (H0). Folds round 0 in Rust (its
/// inputs modulo W[0] are all compile-time constants) and starts the asm
/// at round 1, saving the round-0 body (~60 ops) and the e-carry preload.
/// Returns the 64-byte big-endian digest directly, fusing the `H0[i] +
/// locals[i]` final-add with the big-endian byte emission so LLVM can't
/// split them across a function boundary.
#[cfg(any(target_arch = "bpf", target_os = "solana"))]
#[inline(always)]
fn compress_initial_h0_asm(block: &[u8; 128]) -> [u8; 64] {
    let mut locals: core::mem::MaybeUninit<[u64; 24]> = core::mem::MaybeUninit::uninit();
    let locals_ptr = locals.as_mut_ptr() as *mut u64;
    let block_ptr = block.as_ptr() as *const u64;

    // SAFETY:
    // - Unaligned u64 loads from `block_ptr.add(0..16)` stay within the
    //   128-byte `block`; sBPF permits unaligned access.
    // - The two write blocks initialise every slot of `locals` before
    //   `assume_init`: post-round-0 state in slots 0..8 (laid out to
    //   match the round-0 rotation: new_a → 7, new_e → 3, others inherit
    //   from H0), then W[0..16] in slots 8..24.
    // - `asm!` consumes `locals` and `K` by pointer and conforms to the
    //   register clobber list.
    unsafe {
        let w0 = u64::from_be(core::ptr::read_unaligned(block_ptr));
        let new_a_0 = NEW_A_0_BASE.wrapping_add(w0);
        let new_e_0 = NEW_E_0_BASE.wrapping_add(w0);

        locals_ptr.add(0).write(H0[0]);
        locals_ptr.add(1).write(H0[1]);
        locals_ptr.add(2).write(H0[2]);
        locals_ptr.add(3).write(new_e_0);
        locals_ptr.add(4).write(H0[4]);
        locals_ptr.add(5).write(H0[5]);
        locals_ptr.add(6).write(H0[6]);
        locals_ptr.add(7).write(new_a_0);

        locals_ptr.add(8).write(w0);
        let mut i = 1;
        while i < 16 {
            let word = u64::from_be(core::ptr::read_unaligned(block_ptr.add(i)));
            locals_ptr.add(8 + i).write(word);
            i += 1;
        }

        let mut locals = locals.assume_init();

        core::arch::asm!(
            // Round 0 is pre-folded in Rust; r7 starts holding new_e_0 via
            // `inout` below.
            //
            // Round 1 constants (all `H0`-derived, thus compile-time known)
            // replace stack/K-table loads with `lddw` immediates:
            //   f_1 ^ g_1  → FG_XOR_1       (for Ch)
            //   g_1         → G_1            (for Ch final xor)
            //   h_1 + K[1] → HK_1           (pre-summed, 1 load + 1 add
            //                                 replaces 2 loads + 2 adds)
            //   b_1 & c_1  → BC_AND_1       (for Maj base)
            //   b_1 | c_1  → BC_OR_1        (for Maj body)
            //
            // Maj folds to `BC_AND_1 | (a & BC_OR_1)` when both b and c are
            // compile-time constants (equivalent to the general XOR form
            // but saves 2 ops since we don't need to build `a⊕b` and `a⊕c`).
            //
            // --- Folded round 1 (k=8, W[1] at slot 72) ---
            "ldxdw r5, [r8 + 72]\n",
            sig1_r7_to_r1!(),
            "lddw r3, {FG_XOR_1}\n",
            "and64 r3, r7\n",
            "lddw r0, {G_1}\n",
            "xor64 r3, r0\n",
            "add64 r1, r3\n",
            "lddw r6, {HK_1}\n",
            "add64 r1, r6\n",
            "add64 r1, r5\n",
            "ldxdw r0, [r8 + 56]\n",
            sig0_r0_to_r5!(),
            "lddw r3, {BC_OR_1}\n",
            "and64 r3, r0\n",
            "lddw r2, {BC_AND_1}\n",
            "or64 r3, r2\n",
            "add64 r5, r3\n",
            "ldxdw r7, [r8 + 16]\n",
            "add64 r7, r1\n",
            "add64 r5, r1\n",
            "stxdw [r8 + 48], r5\n",
            "stxdw [r8 + 16], r7\n",
            // --- Rounds 2..79 (normal body) ---
            rounds_2_through_79!(),
            FG_XOR_1 = const (H0[4] ^ H0[5]),
            G_1 = const H0[5],
            HK_1 = const H0[6].wrapping_add(K[1]),
            BC_OR_1 = const (H0[0] | H0[1]),
            BC_AND_1 = const (H0[0] & H0[1]),
            HK_2 = const H0[5].wrapping_add(K[2]),
            HK_3 = const H0[4].wrapping_add(K[3]),
            in("r8") locals.as_mut_ptr(),
            in("r9") K.as_ptr(),
            inout("r7") new_e_0 => _,
            out("r0") _, out("r1") _, out("r2") _, out("r3") _,
            out("r4") _, out("r5") _, out("r6") _,
            options(nostack),
        );

        let mut out = core::mem::MaybeUninit::<[u8; 64]>::uninit();
        let out_ptr = out.as_mut_ptr() as *mut u64;
        let mut i = 0;
        while i < 8 {
            // SAFETY: `out_ptr.add(i)` is in-bounds for [u8; 64];
            // write_unaligned accepts any alignment. Fused fold of
            // `H0[i] + locals[i]` and big-endian byte emission into one
            // pass — no intermediate `[u64; 8]` materialised.
            core::ptr::write_unaligned(
                out_ptr.add(i),
                H0[i].wrapping_add(locals[i]).to_be(),
            );
            i += 1;
        }
        out.assume_init()
    }
}

/// SHA-512 initial hash values (FIPS 180-4 §5.3.5).
#[cfg(any(target_arch = "bpf", target_os = "solana", test))]
const H0: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];

/// SHA-512 round constants (FIPS 180-4 §4.2.3).
#[cfg(any(target_arch = "bpf", target_os = "solana", test))]
const K: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

// --- Round-0 constant folding for the single-block fast path. ------------
//
// When the compress input state is the standard IVs (H0), every term feeding
// round 0 except W[0] is fixed at compile time. The running state after
// round 0 is therefore:
//
//   a = NEW_A_0_BASE + W[0]
//   e = NEW_E_0_BASE + W[0]
//   b, c, d, f, g, h = H0[0], H0[1], H0[2], H0[4], H0[5], H0[6]
//
// The BPF fast path pre-populates this state in `locals` and skips round 0
// entirely — saving the round-0 body (~60 ops) and the initial e-carry load.

#[cfg(any(target_arch = "bpf", target_os = "solana", test))]
const fn sigma0_c(x: u64) -> u64 {
    x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
}

#[cfg(any(target_arch = "bpf", target_os = "solana", test))]
const fn sigma1_c(x: u64) -> u64 {
    x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
}

#[cfg(any(target_arch = "bpf", target_os = "solana", test))]
const fn ch_c(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (!x & z)
}

#[cfg(any(target_arch = "bpf", target_os = "solana", test))]
const fn maj_c(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (x & z) ^ (y & z)
}

/// T1 at round 0 with initial state = H0, before adding W[0]:
///   T1_0 = H0[7] + Σ1(H0[4]) + Ch(H0[4],H0[5],H0[6]) + K[0] + W[0]
#[cfg(any(target_arch = "bpf", target_os = "solana", test))]
const T1_0_BASE: u64 = H0[7]
    .wrapping_add(sigma1_c(H0[4]))
    .wrapping_add(ch_c(H0[4], H0[5], H0[6]))
    .wrapping_add(K[0]);

/// T2 at round 0 (pure constant):
///   T2_0 = Σ0(H0[0]) + Maj(H0[0],H0[1],H0[2])
#[cfg(any(target_arch = "bpf", target_os = "solana", test))]
const T2_0: u64 = sigma0_c(H0[0]).wrapping_add(maj_c(H0[0], H0[1], H0[2]));

/// Post-round-0 `a` base: new_a_0 = NEW_A_0_BASE + W[0].
#[cfg(any(target_arch = "bpf", target_os = "solana", test))]
const NEW_A_0_BASE: u64 = T1_0_BASE.wrapping_add(T2_0);

/// Post-round-0 `e` base: new_e_0 = NEW_E_0_BASE + W[0].
#[cfg(any(target_arch = "bpf", target_os = "solana", test))]
const NEW_E_0_BASE: u64 = H0[3].wrapping_add(T1_0_BASE);

// Host builds can't use the sBPF inline asm, so `AsmSha512` aliases the
// safe `Sha512` wrapper. The solana target defines its own streaming driver
// below.
#[cfg(not(any(target_arch = "bpf", target_os = "solana")))]
pub use super::Sha512 as AsmSha512;

/// Minimal streaming driver around the sBPF asm `compress`.
#[cfg(any(target_arch = "bpf", target_os = "solana"))]
pub struct AsmSha512 {
    /// Bytes currently in `buf`. Hot-read on every `update` call.
    buf_len: usize,
    /// Running state once streaming has started. `None` while we can still
    /// stay on the single-block fast path, so `update` avoids touching
    /// `state`/`total` entirely on the ed25519 hot path.
    state: Option<[u64; 8]>,
    /// Total bytes absorbed so far. Only meaningful once `state` is `Some`;
    /// until then the total equals `buf_len`.
    total: u64,
    /// Partial block buffer. In single-block mode this holds the entire
    /// message so far (≤111 bytes). After overflow it holds the current
    /// block-aligned tail (0..128 bytes). Placed last because the whole
    /// 128-byte region is only touched at finalize time.
    buf: [u8; 128],
}

#[cfg(any(target_arch = "bpf", target_os = "solana"))]
impl Hasher for AsmSha512 {
    #[inline(always)]
    fn new() -> Self {
        Self { buf: [0u8; 128], buf_len: 0, state: None, total: 0 }
    }

    #[inline(always)]
    fn update(&mut self, bytes: &[u8]) {
        // Fast path: stay single-block until we cross the 111-byte ceiling
        // that lets finalize fit 0x80 + length in the same block. Ed25519's
        // hot path (R ‖ A ‖ short message) stays here, and we skip the
        // `total` bookkeeping entirely since total == buf_len here.
        if self.state.is_none() && self.buf_len + bytes.len() <= 111 {
            self.buf[self.buf_len..self.buf_len + bytes.len()].copy_from_slice(bytes);
            self.buf_len += bytes.len();
            return;
        }
        // Streaming path — cold on the ed25519 hot path.
        streaming_update(self, bytes);

        #[cold]
        #[inline(never)]
        fn streaming_update(this: &mut AsmSha512, mut bytes: &[u8]) {
            if this.state.is_none() {
                this.state = Some(H0);
                this.total = this.buf_len as u64;
            }
            this.total = this.total.wrapping_add(bytes.len() as u64);
            let state = this.state.as_mut().unwrap();
            while !bytes.is_empty() {
                let take = (128 - this.buf_len).min(bytes.len());
                this.buf[this.buf_len..this.buf_len + take].copy_from_slice(&bytes[..take]);
                this.buf_len += take;
                bytes = &bytes[take..];
                if this.buf_len == 128 {
                    compress_asm(state, &this.buf);
                    this.buf_len = 0;
                }
            }
        }
    }

    #[inline(never)]
    fn finalize(mut self) -> [u8; 64] {
        if let Some(mut state) = self.state {
            return streaming_finalize(&mut self.buf, self.buf_len, self.total, &mut state);
        }

        // Single-block mode: total == buf_len < 112, so 0x80 and the
        // length fit in one block. Pad in place (trailing bytes are
        // zero from `new`) and run the round-0-folded compress.
        self.buf[self.buf_len] = 0x80;
        let bit_len = (self.buf_len as u64).wrapping_mul(8);
        // SAFETY: writing into buf[120..128], in bounds.
        unsafe {
            core::ptr::write_unaligned(
                self.buf.as_mut_ptr().add(120) as *mut u64,
                bit_len.to_be(),
            );
        }
        return compress_initial_h0_asm(&self.buf);

        // Streaming finalize is the long-message path; ed25519 verify
        // stays on the fast path above. Marked cold so LLVM biases code
        // layout toward the fast-path return.
        #[cold]
        #[inline(never)]
        fn streaming_finalize(
            buf: &mut [u8; 128],
            buf_len: usize,
            total: u64,
            state: &mut [u64; 8],
        ) -> [u8; 64] {
            let total_bits = total.wrapping_mul(8);
            buf[buf_len] = 0x80;
            let tail_start = buf_len + 1;
            if tail_start > 112 {
                buf[tail_start..].fill(0);
                compress_asm(state, buf);
                buf[..112].fill(0);
            } else {
                buf[tail_start..112].fill(0);
            }
            buf[112..120].fill(0);
            // SAFETY: writing into buf[120..128], in bounds.
            unsafe {
                core::ptr::write_unaligned(
                    buf.as_mut_ptr().add(120) as *mut u64,
                    total_bits.to_be(),
                );
            }
            compress_asm(state, buf);
            state_to_be_bytes(state)
        }
    }
}

#[cfg(test)]
mod tests {
    //! Host-side validation for the round-0 folding math.
    //!
    //! The BPF inline-asm compress is not reachable from `cargo test` — the
    //! host backend uses `sha2`. These tests instead validate the *algebra*
    //! behind `compress_initial_h0_asm`: a pure-Rust reference compress,
    //! a pure-Rust version of the round-0 fold, and cross-checks against
    //! `sha2::Sha512`. If the fold math is correct here and the BPF asm
    //! mirrors it faithfully, the on-chain path is correct.
    use super::*;
    use sha2::Digest;

    fn w_schedule(block: &[u8; 128]) -> [u64; 80] {
        let mut w = [0u64; 80];
        let mut i = 0;
        while i < 16 {
            let o = i * 8;
            w[i] = u64::from_be_bytes([
                block[o], block[o + 1], block[o + 2], block[o + 3],
                block[o + 4], block[o + 5], block[o + 6], block[o + 7],
            ]);
            i += 1;
        }
        let mut i = 16;
        while i < 80 {
            let x15 = w[i - 15];
            let x2 = w[i - 2];
            let s0 = x15.rotate_right(1) ^ x15.rotate_right(8) ^ (x15 >> 7);
            let s1 = x2.rotate_right(19) ^ x2.rotate_right(61) ^ (x2 >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
            i += 1;
        }
        w
    }

    /// Textbook FIPS 180-4 compress. No optimization tricks — the point
    /// is to be obviously correct so it can validate the fold.
    fn ref_compress(state: &mut [u64; 8], block: &[u8; 128]) {
        let w = w_schedule(block);
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (
            state[0], state[1], state[2], state[3],
            state[4], state[5], state[6], state[7],
        );
        for i in 0..80 {
            let t1 = h
                .wrapping_add(sigma1_c(e))
                .wrapping_add(ch_c(e, f, g))
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let t2 = sigma0_c(a).wrapping_add(maj_c(a, b, c));
            h = g; g = f; f = e;
            e = d.wrapping_add(t1);
            d = c; c = b; b = a;
            a = t1.wrapping_add(t2);
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    /// Rust version of the round-0 folded compress. Pre-computes the
    /// post-round-0 running state from the compile-time bases, then runs
    /// rounds 1..80. The final add uses the *original* IVs (H0), not the
    /// post-round-0 values — this mirrors what the BPF asm does.
    fn ref_compress_initial_h0(block: &[u8; 128]) -> [u64; 8] {
        let w = w_schedule(block);
        let new_a_0 = NEW_A_0_BASE.wrapping_add(w[0]);
        let new_e_0 = NEW_E_0_BASE.wrapping_add(w[0]);
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (
            new_a_0, H0[0], H0[1], H0[2],
            new_e_0, H0[4], H0[5], H0[6],
        );
        for i in 1..80 {
            let t1 = h
                .wrapping_add(sigma1_c(e))
                .wrapping_add(ch_c(e, f, g))
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let t2 = sigma0_c(a).wrapping_add(maj_c(a, b, c));
            h = g; g = f; f = e;
            e = d.wrapping_add(t1);
            d = c; c = b; b = a;
            a = t1.wrapping_add(t2);
        }
        [
            H0[0].wrapping_add(a),
            H0[1].wrapping_add(b),
            H0[2].wrapping_add(c),
            H0[3].wrapping_add(d),
            H0[4].wrapping_add(e),
            H0[5].wrapping_add(f),
            H0[6].wrapping_add(g),
            H0[7].wrapping_add(h),
        ]
    }

    fn pad_single_block(msg: &[u8]) -> [u8; 128] {
        assert!(msg.len() <= 111);
        let mut block = [0u8; 128];
        block[..msg.len()].copy_from_slice(msg);
        block[msg.len()] = 0x80;
        let bit_len = (msg.len() as u64).wrapping_mul(8);
        block[120..128].copy_from_slice(&bit_len.to_be_bytes());
        block
    }

    #[test]
    fn ref_compress_matches_sha2_single_block() {
        let mut buf = [0u8; 111];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i * 31 + 7) as u8;
        }
        for &n in &[0usize, 1, 31, 55, 56, 75, 111] {
            let msg = &buf[..n];
            let block = pad_single_block(msg);
            let mut state = H0;
            ref_compress(&mut state, &block);
            let got = super::state_to_be_bytes(&state);
            let expected: [u8; 64] = sha2::Sha512::digest(msg).into();
            assert_eq!(got, expected, "ref_compress mismatch at len {n}");
        }
    }

    #[test]
    fn fold_matches_unfolded_on_arbitrary_blocks() {
        for seed in 0u64..128 {
            let mut block = [0u8; 128];
            let mut j = 0usize;
            while j < 128 {
                block[j] = (seed.wrapping_mul(2654435761).wrapping_add(j as u64) as u8) ^ 0x5a;
                j += 1;
            }
            let mut unfolded = H0;
            ref_compress(&mut unfolded, &block);
            let folded = ref_compress_initial_h0(&block);
            assert_eq!(unfolded, folded, "fold mismatch for seed {seed}");
        }
    }

    #[test]
    fn fold_matches_sha2_single_block() {
        let mut buf = [0u8; 111];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i * 17 + 3) as u8;
        }
        for &n in &[0usize, 1, 7, 8, 31, 32, 55, 56, 75, 111] {
            let msg = &buf[..n];
            let block = pad_single_block(msg);
            let state = ref_compress_initial_h0(&block);
            let got = super::state_to_be_bytes(&state);
            let expected: [u8; 64] = sha2::Sha512::digest(msg).into();
            assert_eq!(got, expected, "fold mismatch at len {n}");
        }
    }

    /// Pins the precomputed bases so an accidental edit to H0/K/the const
    /// fn helpers trips a test instead of silently breaking the fold.
    #[test]
    fn round_0_bases_are_stable() {
        assert_eq!(NEW_E_0_BASE, H0[3].wrapping_add(T1_0_BASE));
        assert_eq!(NEW_A_0_BASE, T1_0_BASE.wrapping_add(T2_0));
        let block = [0u8; 128];
        let mut full = H0;
        ref_compress(&mut full, &block);
        let folded = ref_compress_initial_h0(&block);
        assert_eq!(full, folded);
    }
}

