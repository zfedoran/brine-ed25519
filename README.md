# brine-ed25519

[license-image]: https://img.shields.io/badge/license-MIT-blue.svg?style=flat
![license][license-image]
[![crates.io](https://img.shields.io/crates/v/brine-ed25519.svg?style=flat)](https://crates.io/crates/brine-ed25519)

A fast, low-overhead, Ed25519 signature verification library for the Solana SVM.

## ⚡ Performance

| Operation | Feature flag  | CU (Approx.) | Notes |
|-----------|---------------|--------------|-------|
| `verify`        | default       |       ~3,824 | challenge hash via `sol_sha512` syscall |
| `verify`        | `fast-sha512` |      ~11,350 | in-program SHA-512, works on any cluster |
| `verify_strict` | default       |       ~3,877 | challenge hash via `sol_sha512` syscall |
| `verify_strict` | `fast-sha512` |      ~11,393 | in-program SHA-512, works on any cluster |

These values are measured inside the Solana SVM via `test-program/`, using the
same direct-constant method as earlier releases with the 11-byte message
`hello world`. CU usage depends on the message size.
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
`verify_with_hasher_strict`, and `verify_prehashed_strict`. These add
small-order rejection matching Solana's ed25519 precompile. See
[Point validation](#point-validation) for the tradeoff.

For clusters or SVM runtimes where the `sol_sha512` syscall is not available,
opt into in-program hashing (enabling this anywhere in the dependency tree opts
the whole program out of the syscall):

```toml
brine-ed25519 = { version = "0.10", features = ["fast-sha512"] }
```

Syscall linkage follows the toolchain: dynamic on the default
arch, static syscall numbers under `cargo build-sbf --arch v3` (SBPF v3).

---

## Cluster compatibility

> [!WARNING]
> This crate uses the `sol_sha512` syscall **by default**. The syscall is gated by
> `enable_sha512_syscall` (`s512oDwgx8hjMnaQjXfqqrZroVj4HvC6TkN3iSSWXCh`),
> currently **active on devnet and testnet, but not yet on mainnet-beta**. A
> program built with the syscall path **will fail to deploy/load** on any
> cluster where the gate is inactive (unresolved `sol_sha512` symbol at ELF
> verification). For mainnet today, enable the `fast-sha512` feature.

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

All verification functions enforce RFC 8032 point-encoding rules: the encoded
`y` coordinate must be less than `p = 2^255 - 19`, and `x = 0` cannot carry a
set sign bit. Point decompression and on-curve validation are performed by the
curve implementation.

`verify_strict` additionally matches Solana's ed25519 precompile by rejecting
the eight canonical small-order public keys and `R` values. The non-strict
functions use the cofactorless verification equation permitted by RFC 8032 and
save about 50 CU by omitting this additional policy check.

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
