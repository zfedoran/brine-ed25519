//! # SHA-512 compression in hand-written sBPF inline assembly
use crate::hasher::Hasher;

/// sBPF-only dispatch into the inline-asm SHA-512 compression function.
#[cfg(any(target_arch = "bpf", target_os = "solana"))]
#[inline(always)]
pub(crate) fn compress(state: &mut [u64; 8], block: &[u8; 128]) {
    compress_asm(state, block);
}

/// Serialize an 8-word SHA-512 state to its 64-byte big-endian digest.
#[cfg(any(target_arch = "bpf", target_os = "solana", test))]
#[inline(always)]
pub(crate) fn state_to_be_bytes(state: &[u64; 8]) -> [u8; 64] {
    let mut out = core::mem::MaybeUninit::<[u8; 64]>::uninit();
    let ptr = out.as_mut_ptr() as *mut [u8; 8];
    let mut i = 0;
    while i < 8 {
        // SAFETY: `ptr.add(i)` is within the `[u8; 64]` allocation for
        // `i in 0..8`, and `[u8; 8]` is `repr(transparent)` over 8 bytes.
        unsafe { ptr.add(i).write(state[i].to_be_bytes()); }
        i += 1;
    }
    // SAFETY: all 64 bytes written above.
    unsafe { out.assume_init() }
}

/// Σ1(e) into `r1` using `r7` as source (e-carry from prior round's
/// new_e), `r2` as temp. 17 ops.
#[cfg(any(target_arch = "bpf", target_os = "solana"))]
macro_rules! sig1_r7_to_r1 {
    () => { concat!(
        "mov64 r1, r7\n", "rsh64 r1, 14\n",
        "mov64 r2, r7\n", "lsh64 r2, 50\n", "xor64 r1, r2\n",
        "mov64 r2, r7\n", "rsh64 r2, 18\n", "xor64 r1, r2\n",
        "mov64 r2, r7\n", "lsh64 r2, 46\n", "xor64 r1, r2\n",
        "mov64 r2, r7\n", "rsh64 r2, 41\n", "xor64 r1, r2\n",
        "mov64 r2, r7\n", "lsh64 r2, 23\n", "xor64 r1, r2\n",
    )};
}

/// Σ0(a) into `r5` using `r0` as source, `r2` as temp. 17 ops.
#[cfg(any(target_arch = "bpf", target_os = "solana"))]
macro_rules! sig0_r0_to_r5 {
    () => { concat!(
        "mov64 r5, r0\n", "rsh64 r5, 28\n",
        "mov64 r2, r0\n", "lsh64 r2, 36\n", "xor64 r5, r2\n",
        "mov64 r2, r0\n", "rsh64 r2, 34\n", "xor64 r5, r2\n",
        "mov64 r2, r0\n", "lsh64 r2, 30\n", "xor64 r5, r2\n",
        "mov64 r2, r0\n", "rsh64 r2, 39\n", "xor64 r5, r2\n",
        "mov64 r2, r0\n", "lsh64 r2, 25\n", "xor64 r5, r2\n",
    )};
}

/// σ0(x) = rotr1(x) ^ rotr8(x) ^ (x >> 7). Source in r0, result in r1, tmp r2. 14 ops.
#[cfg(any(target_arch = "bpf", target_os = "solana"))]
macro_rules! smallsig0_r0_to_r1 {
    () => { concat!(
        "mov64 r1, r0\n", "rsh64 r1, 1\n",
        "mov64 r2, r0\n", "lsh64 r2, 63\n", "xor64 r1, r2\n",
        "mov64 r2, r0\n", "rsh64 r2, 8\n",  "xor64 r1, r2\n",
        "mov64 r2, r0\n", "lsh64 r2, 56\n", "xor64 r1, r2\n",
        "mov64 r2, r0\n", "rsh64 r2, 7\n",  "xor64 r1, r2\n",
    )};
}

/// σ1(x) = rotr19(x) ^ rotr61(x) ^ (x >> 6). Source in r0, result in r3, tmp r2. 14 ops.
#[cfg(any(target_arch = "bpf", target_os = "solana"))]
macro_rules! smallsig1_r0_to_r3 {
    () => { concat!(
        "mov64 r3, r0\n", "rsh64 r3, 19\n",
        "mov64 r2, r0\n", "lsh64 r2, 45\n", "xor64 r3, r2\n",
        "mov64 r2, r0\n", "rsh64 r2, 61\n", "xor64 r3, r2\n",
        "mov64 r2, r0\n", "lsh64 r2, 3\n",  "xor64 r3, r2\n",
        "mov64 r2, r0\n", "rsh64 r2, 6\n",  "xor64 r3, r2\n",
    )};
}

/// Ops: 3 loads (f, g, h) + Σ1 (17) + Ch (3) + 4 adds
///      + 3 loads (a, b, c) + Σ0 (17) + Maj (5) + 1 add
///      + 1 load (d) + 2 adds + 2 stores = 59.
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
        "mov64 r7, r0\n",                   // r7 = a (e no longer needed)
        "or64 r7, r3\n",
        "and64 r7, r4\n",
        "and64 r3, r0\n",
        "or64 r7, r3\n",
        "add64 r5, r7\n",                   // r5 = T2
        "ldxdw r7, [r8 + ", $d, "]\n",
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

/// Hand-written sBPF inline-asm SHA-512 compression function.
#[cfg(any(target_arch = "bpf", target_os = "solana"))]
#[inline(never)]
fn compress_asm(state: &mut [u64; 8], block: &[u8; 128]) {
    // 8 state working slots + 16 W slots. Skip the initial zero-fill —
    // every slot is written before the asm block reads it.
    let mut locals: core::mem::MaybeUninit<[u64; 24]> = core::mem::MaybeUninit::uninit();
    let locals_ptr = locals.as_mut_ptr() as *mut u64;

    // SAFETY: `locals_ptr` points at a valid `[u64; 24]` stack allocation.
    // We touch each of the 24 slots before the asm reads them: slots 0..8
    // from `state`, slots 8..24 from the big-endian block load below.
    unsafe {
        let mut k = 0;
        while k < 8 {
            locals_ptr.add(k).write(state[k]);
            k += 1;
        }

        let mut i = 0;
        while i < 16 {
            let o = i * 8;
            let word = u64::from_be_bytes([
                block[o],     block[o + 1], block[o + 2], block[o + 3],
                block[o + 4], block[o + 5], block[o + 6], block[o + 7],
            ]);
            locals_ptr.add(8 + i).write(word);
            i += 1;
        }
    }

    // All 24 slots have been written above; safe to commit the array.
    // SAFETY: each slot of `locals` was written exactly once by the loops
    // above — state[0..8] and the 16 big-endian block words.
    let mut locals = unsafe { locals.assume_init() };

    // W slots on the stack. Byte offsets from `r8` (locals base):
    //   state[0..8] → 0,  8, 16, 24, 32, 40, 48, 56
    //   W[0..16]    → 64, 72, 80, ..., 184
    // W[i mod 16] lives at `64 + (i mod 16) * 8`.

    unsafe {
        core::arch::asm!(
            concat!(
                // Pre-load e_0 into r7 so round 0 can pick it up via the
                // same e-carry path as rounds 1..79 (sig1 sources from r7).
                // Costs 1 op; saves 1 ldxdw per round across 80 rounds.
                "ldxdw r7, [r8 + 32]\n",
                // ---- Rounds 0..16: W[i] already loaded, no schedule update. ----
                // Args: (k_off, wi, a, b, c, d, e, f, g, h, new_a, new_e)
                round_nosched!("0",   "64",  "0",  "8",  "16", "24", "32", "40", "48", "56", "56", "24"),
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

                // ---- Rounds 16..80: schedule update + round body. ----
                // Args: (k, wi, wi+1, wi+9, wi+14, a, b, c, d, e, f, g, h, new_a, new_e)
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
            ),
            in("r8") locals.as_mut_ptr(),
            in("r9") K.as_ptr(),
            out("r0") _, out("r1") _, out("r2") _, out("r3") _,
            out("r4") _, out("r5") _, out("r6") _, out("r7") _,
            options(nostack),
        );
    }

    state[0] = state[0].wrapping_add(locals[0]);
    state[1] = state[1].wrapping_add(locals[1]);
    state[2] = state[2].wrapping_add(locals[2]);
    state[3] = state[3].wrapping_add(locals[3]);
    state[4] = state[4].wrapping_add(locals[4]);
    state[5] = state[5].wrapping_add(locals[5]);
    state[6] = state[6].wrapping_add(locals[6]);
    state[7] = state[7].wrapping_add(locals[7]);
}

/// Specialized compress for the hashv single-block fast path where the
/// initial state is the standard IVs (H0). Folds round 0 in Rust (its
/// inputs modulo W[0] are all compile-time constants) and starts the asm
/// at round 1, saving the round-0 body (~60 ops) and the e-carry preload.
#[cfg(any(target_arch = "bpf", target_os = "solana"))]
#[inline(never)]
fn compress_initial_h0_asm(block: &[u8; 128]) -> [u64; 8] {
    let mut locals: core::mem::MaybeUninit<[u64; 24]> = core::mem::MaybeUninit::uninit();
    let locals_ptr = locals.as_mut_ptr() as *mut u64;

    let w0 = u64::from_be_bytes([
        block[0], block[1], block[2], block[3],
        block[4], block[5], block[6], block[7],
    ]);
    let new_a_0 = NEW_A_0_BASE.wrapping_add(w0);
    let new_e_0 = NEW_E_0_BASE.wrapping_add(w0);

    // SAFETY: every slot of `locals` is written exactly once below before
    // `assume_init` commits the array. Post-round-0 state laid out to
    // match the round-0 slot rotation (na → slot 56, ne → slot 24, others
    // inherit from H0) so rounds 1..79 see the same memory shape as
    // `compress_asm` after its round 0 stores.
    unsafe {
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
            let o = i * 8;
            let word = u64::from_be_bytes([
                block[o],     block[o + 1], block[o + 2], block[o + 3],
                block[o + 4], block[o + 5], block[o + 6], block[o + 7],
            ]);
            locals_ptr.add(8 + i).write(word);
            i += 1;
        }
    }

    let mut locals = unsafe { locals.assume_init() };

    unsafe {
        core::arch::asm!(
            concat!(
                // Round 0 pre-folded in Rust; r7 starts holding new_e_0
                // via `inout` below, so the first asm round is round 1.
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
            ),
            in("r8") locals.as_mut_ptr(),
            in("r9") K.as_ptr(),
            inout("r7") new_e_0 => _,
            out("r0") _, out("r1") _, out("r2") _, out("r3") _,
            out("r4") _, out("r5") _, out("r6") _,
            options(nostack),
        );
    }

    [
        H0[0].wrapping_add(locals[0]),
        H0[1].wrapping_add(locals[1]),
        H0[2].wrapping_add(locals[2]),
        H0[3].wrapping_add(locals[3]),
        H0[4].wrapping_add(locals[4]),
        H0[5].wrapping_add(locals[5]),
        H0[6].wrapping_add(locals[6]),
        H0[7].wrapping_add(locals[7]),
    ]
}

/// SHA-512 initial hash values (FIPS 180-4 §5.3.5).
#[cfg(any(target_arch = "bpf", target_os = "solana", test))]
pub(crate) const H0: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];

/// SHA-512 round constants (FIPS 180-4 §4.2.3).
#[cfg(any(target_arch = "bpf", target_os = "solana", test))]
pub(crate) const K: [u64; 80] = [
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
#[inline(always)]
const fn sigma0_c(x: u64) -> u64 {
    x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
}

#[cfg(any(target_arch = "bpf", target_os = "solana", test))]
#[inline(always)]
const fn sigma1_c(x: u64) -> u64 {
    x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
}

#[cfg(any(target_arch = "bpf", target_os = "solana", test))]
#[inline(always)]
const fn ch_c(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (!x & z)
}

#[cfg(any(target_arch = "bpf", target_os = "solana", test))]
#[inline(always)]
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

// Public `Sha512` streaming hasher.
//
// On the host, use sha2's own streaming hasher (native compiles can't use
// the sBPF inline asm anyway). On sBPF, stream into the hand-written
// `compress` via a minimal buffered driver.
#[cfg(not(any(target_arch = "bpf", target_os = "solana")))]
mod backend {
    use sha2::{Digest, Sha512 as Sha512Hasher};

    pub struct Sha512(Sha512Hasher);

    impl Sha512 {
        #[inline(always)]
        pub fn new() -> Self { Self(Sha512Hasher::new()) }
        #[inline(always)]
        pub fn update(&mut self, bytes: &[u8]) { self.0.update(bytes) }
        #[inline(always)]
        pub fn finalize(self) -> [u8; 64] { self.0.finalize().into() }
    }
}

#[cfg(any(target_arch = "bpf", target_os = "solana"))]
mod backend {
    use super::{compress, H0};

    /// A minimal streaming driver around `compress`. Only state is the 8-word
    /// chaining value, the 128-byte buffer, and a u64 total-byte counter.
    /// `buf_len` is derived as `total & 127`, saving a struct field and the
    /// arithmetic to keep two counters in sync.
    pub struct Sha512 {
        state: [u64; 8],
        buf: [u8; 128],
        /// Total bytes absorbed so far (low 64 bits of the 128-bit length).
        total: u64,
    }

    impl Sha512 {
        #[inline(always)]
        pub fn new() -> Self {
            Self { state: H0, buf: [0u8; 128], total: 0 }
        }

        #[inline(always)]
        pub fn update(&mut self, bytes: &[u8]) {
            let len = bytes.len();
            let buf_len = (self.total & 127) as usize;
            self.total = self.total.wrapping_add(len as u64);

            let mut off = 0usize;

            if buf_len != 0 {
                let need = 128 - buf_len;
                if len < need {
                    copy_bytes(&mut self.buf[buf_len..], bytes, len);
                    return;
                }
                copy_bytes(&mut self.buf[buf_len..], bytes, need);
                compress(&mut self.state, &self.buf);
                off = need;
            }

            while len - off >= 128 {
                // SAFETY: `bytes.as_ptr().add(off)` points at a valid 128-byte
                // run (checked by the loop condition); layout of `[u8; 128]`
                // is identical to 128 consecutive bytes.
                let block: &[u8; 128] = unsafe {
                    &*(bytes.as_ptr().add(off) as *const [u8; 128])
                };
                compress(&mut self.state, block);
                off += 128;
            }

            let rem = len - off;
            if rem != 0 {
                copy_bytes(&mut self.buf, &bytes[off..], rem);
            }
        }

        #[inline(always)]
        pub fn finalize(mut self) -> [u8; 64] {
            let total_bits = self.total.wrapping_mul(8);
            let mut buf_len = (self.total & 127) as usize;

            self.buf[buf_len] = 0x80;
            buf_len += 1;

            if buf_len > 112 {
                // No room for the length field in this block: pad zeros,
                // compress, use a fresh block for the length.
                zero_tail(&mut self.buf, buf_len);
                compress(&mut self.state, &self.buf);
                zero_range(&mut self.buf, 0, 112);
            } else {
                zero_range(&mut self.buf, buf_len, 112);
            }

            // 128-bit big-endian length; top 64 bits always zero for messages
            // under 2^64 bytes.
            self.buf[112..120].fill(0);
            self.buf[120..128].copy_from_slice(&total_bits.to_be_bytes());

            compress(&mut self.state, &self.buf);

            super::state_to_be_bytes(&self.state)
        }
    }

    /// Delegate to `copy_from_slice`, which LLVM's BPF backend lowers to
    /// the VM-provided `sol_memcpy_` builtin. Cheaper than a byte loop for
    /// any copy over ~5 bytes.
    #[inline(always)]
    fn copy_bytes(dst: &mut [u8], src: &[u8], n: usize) {
        dst[..n].copy_from_slice(&src[..n]);
    }

    /// Zero `buf[start..end]`. Lowers to `sol_memset_`.
    #[inline(always)]
    fn zero_range(buf: &mut [u8; 128], start: usize, end: usize) {
        buf[start..end].fill(0);
    }

    /// Zero `buf[start..128]`. Lowers to `sol_memset_`.
    #[inline(always)]
    fn zero_tail(buf: &mut [u8; 128], start: usize) {
        buf[start..].fill(0);
    }
}

pub struct Sha512(backend::Sha512);

impl Hasher for Sha512 {
    #[inline(always)]
    fn new() -> Self {
        Self(backend::Sha512::new())
    }

    #[inline(always)]
    fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    #[inline(always)]
    fn finalize(self) -> [u8; 64] {
        self.0.finalize()
    }

    /// Single-block fast path: if the combined input fits in one padded
    /// SHA-512 block (≤111 bytes), skip the streaming state machine and
    /// build the block directly. Kept even though `challenge` calls
    /// `new`/`update`/`finalize` instead of `hashv` — empirically removing
    /// it shifts LLVM's inlining choices and costs ~60 CU on verify.
    #[cfg(any(target_arch = "bpf", target_os = "solana"))]
    #[inline(always)]
    fn hashv(bytesv: &[&[u8]]) -> [u8; 64] {
        let mut total = 0usize;
        let mut i = 0;
        while i < bytesv.len() {
            total += bytesv[i].len();
            i += 1;
        }

        if total <= 111 {
            let mut block = [0u8; 128];
            let mut off = 0usize;
            let mut ci = 0;
            while ci < bytesv.len() {
                let s = bytesv[ci];
                // SAFETY: `off + s.len() <= total <= 111 < 128`.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        s.as_ptr(),
                        block.as_mut_ptr().add(off),
                        s.len(),
                    );
                }
                off += s.len();
                ci += 1;
            }

            block[off] = 0x80;
            let bits = (total as u64).wrapping_mul(8).to_be_bytes();
            // SAFETY: block is 128 bytes, writing 8 at offset 120.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    bits.as_ptr(),
                    block.as_mut_ptr().add(120),
                    8,
                );
            }

            let state = compress_initial_h0_asm(&block);

            state_to_be_bytes(&state)
        } else {
            let mut hasher = Self::new();
            let mut j = 0;
            while j < bytesv.len() {
                hasher.update(bytesv[j]);
                j += 1;
            }
            hasher.finalize()
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

