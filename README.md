# brine-ed25519

[license-image]: https://img.shields.io/badge/license-MIT-blue.svg?style=flat
![license][license-image]
[![crates.io](https://img.shields.io/crates/v/brine-ed25519.svg?style=flat)](https://crates.io/crates/brine-ed25519)

A fast, low-overhead, Ed25519 signature verification library for the Solana SVM.

## ⚡ Performance

| Operation | Feature flag  | CU (Approx.) | Notes |
|-----------|---------------|--------------|-------|
| `verify`        | default       |       ~4,759 | challenge hash via `sol_sha512` syscall |
| `verify`        | `fast-sha512` |      ~12,243 | in-program SHA-512, works on any cluster |
| `verify_strict` | default       |       ~4,844 | challenge hash via `sol_sha512` syscall |
| `verify_strict` | `fast-sha512` |      ~12,344 | in-program SHA-512, works on any cluster |

These values are measured inside the Solana SVM via `test-program/` and depend on the message size.
Almost the entire difference is the cost of hashing `H(R || A || M)` in-program versus
one vectored syscall (85 CU base + ~max(10, len/2) CU per slice).

Strict point validation accounts for about 50 CU.

---

## Features

- Verifies Ed25519 signatures **within the program**, at run-time
- Fully supports dynamically generated messages
- No extra lamports required

Signature verification roughly follows [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032)

---

## Quick Start

```rust
use brine_ed25519::*;

let pubkey: [u8; 32] = [...];
let sig: [u8; 64] = [...];

// Single message
verify(&pubkey, &sig, &[b"hello world"])?;

// Vectored message
verify(&pubkey, &sig, &[b"hello", b" ", b"world"])?;

// Prehashed challenge (precomputed H(R || A || M))
verify_prehashed(&pubkey, &sig, &challenge)?;
```

Custom hash implementations are supported via the `Hasher` trait and
`verify_with_hasher::<H>`.

Each function also has a strict variation: `verify_strict`,
`verify_with_hasher_strict`, and `verify_prehashed_strict`. Their point checks
match Solana's ed25519 precompile. See [Point validation](#point-validation) for
the tradeoff.

For clusters or SVM runtimes where the `sol_sha512` syscall is not available,
opt into in-program hashing (enabling this anywhere in the dependency tree opts
the whole program out of the syscall):

```toml
brine-ed25519 = { version = "0.9", features = ["fast-sha512"] }
```

Since 0.9.1, syscall linkage follows the toolchain: dynamic on the default
arch, static syscall numbers under `cargo build-sbf --arch v3` (SBPF v3).

---

## Which version should I use?

| Version | Default hash path | Use when |
|---------|-------------------|----------|
| **0.9.x** | `sol_sha512` syscall ([SIMD-0512](https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0512-sha512-syscall.md)) | The `enable_sha512_syscall` feature gate is active on your target cluster (devnet and testnet today; mainnet-beta pending) |
| **0.8.x** | In-program SHA-512, syscall opt-in via `sha512-syscall` feature | You deploy to mainnet-beta before SIMD-0512 activates |

> [!WARNING]
> 0.9.x uses the `sol_sha512` syscall **by default**. The syscall is gated by
> `enable_sha512_syscall` (`s512oDwgx8hjMnaQjXfqqrZroVj4HvC6TkN3iSSWXCh`),
> currently **active on devnet and testnet, but not yet on mainnet-beta**. A
> program built with the syscall path **will fail to deploy/load** on any
> cluster where the gate is inactive (unresolved `sol_sha512` symbol at ELF
> verification). For mainnet today, pin `0.8.x`, or build 0.9.x with the
> `fast-sha512` feature. Once the gate is active on mainnet, 0.9.x is the
> intended end state of this crate.

---

### Migrating from 0.8.x

`verify::<Sha512>(...)` / `verify::<FastSha512>(...)` / `verify::<Sha512Syscall>(...)`
are replaced by a single non-generic `verify(...)`, which picks the syscall on-chain
and `sha2` on host builds. The generic form lives on as `verify_with_hasher::<H>(...)`.

Feature names are unchanged, so existing `Cargo.toml` entries keep resolving:
`fast-sha512` now means "hash in-program instead of using the syscall" (the safe
choice for clusters without SIMD-0512), and `sha512-syscall` is a no-op since the
syscall is the default.

---

## But why?

**Q:** Why not use the native Ed25519 program?

**A:** Solana does provide a [Ed25519 pre-compile](https://github.com/solana-labs/solana/blob/master/sdk/src/ed25519_instruction.rs) program for signature verification, but it comes with several downsides:

- Charges an extra **5000 lamports per signature**
- Consumes additional transaction data
- Requires the `instruction_sysvar` to be passed into your program
- Only verifies signatures on data hardcoded into the transaction
- Cannot be used with dynamically generated data inside your program
- Has [cumbersome devex](https://github.com/solana-labs/solana/blob/7700cb3128c1f19820de67b81aa45d18f73d2ac0/sdk/src/ed25519_instruction.rs#L23-L29)

This crate, **brine-ed25519**, solves all of that.

---

## Security

### Point validation

`verify_strict` matches Solana's ed25519 precompile by rejecting small-order
public keys and `R` values, including their alternate encodings. This uses the
dalek crate to run `verify_strict` internally within dalek.

The non-strict functions omit this check and save about 50 CU. Use them when the
public key is trusted or has already been validated.

Note, `verify_strict` hardens downstream code that treats a signature as
unique, or checks only that a valid signature exists without binding it to the
expected signer. Neither is a safe design: a signer can vary the nonce to
produce different valid signatures, and verification must always identify the
intended public key.

If your protocol relies on either assumption, `verify_strict` is not the fix!
Your architecture is already unsafe. Strict verification only closes the
small-order edge case.

### Audits and review

The implementation was pulled from [code-vm](https://github.com/code-payments/code-vm) (MIT-licensed), which was written and maintained by the author of this crate. 

- Reviewed as part of the [code-vm](https://github.com/code-payments/code-vm) audit by [OtterSec](https://osec.io)  
- Peer reviewed by [@stegaBOB](https://github.com/stegaBOB) and [@deanmlittle](https://github.com/deanmlittle)
- Many CU optimizations by [@deanmlittle](https://github.com/deanmlittle)
- Small optimizations by [@crypt0miester](https://github.com/crypt0miester)

Big thanks to all reviewers for helpful suggestions and CU reductions!

> [!NOTE]
> This crate has had multiple rounds of optimizations since the audits above. If you prefer the to use the audited version, use v0.2.0 or lower, but note that the CU is more than double. 

---

## Contributing

Contributions are welcome! Please open issues or PRs on the GitHub repo.
