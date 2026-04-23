# brine-ed25519

[license-image]: https://img.shields.io/badge/license-MIT-blue.svg?style=flat
![license][license-image]
[![crates.io](https://img.shields.io/crates/v/brine-ed25519.svg?style=flat)](https://crates.io/crates/brine-ed25519)

A fast, low-overhead, Ed25519 signature verification library for the Solana SVM.

---

## ⚡ Performance

| Operation               | Feature flag  | CU (Approx.) | Improvement |
|-------------------------|---------------|--------------|-------------|
| `verify::<Sha512>`      | default       |      ~12,549 | baseline    |
| `verify::<FastSha512>`  | `fast-sha512` |      ~12,252 | -297 CU (~2.4%) |
| `verify::<AsmSha512>`   | `asm-sha512`  |      ~11,578 | -971 CU (~7.7%) |

These values are measured inside the Solana SVM via `test-program/` and depend on the message size.
`FastSha512` is available behind the `fast-sha512` feature flag.
`AsmSha512` is available behind the `asm-sha512` feature flag (sBPF inline assembly; Solana target only).

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
use brine_ed25519::hasher::Sha512;

let pubkey: [u8; 32] = [...];
let sig: [u8; 64] = [...];

// Single message
verify::<Sha512>(&pubkey, &sig, &[b"hello world"])?;

// Vectored message
verify::<Sha512>(&pubkey, &sig, &[b"hello", b" ", b"world"])?;

// Prehashed challenge (precomputed H(R || A || M))
verify_prehashed(&pubkey, &sig, &challenge)?;
```

Custom hash implementations are supported via the `Hasher` trait.

To opt into the faster SHA-512 path:

```toml
brine-ed25519 = { version = "0.6", features = ["fast-sha512"] }
```

```rust
use brine_ed25519::hasher::FastSha512;

verify::<FastSha512>(&pubkey, &sig, &[b"hello world"])?;
```

---

## But why?

**Q:** Why not use the native Ed25519 program?

**A:** Solana does provide a [Ed25519 pre-compile](https://github.com/solana-labs/solana/blob/master/sdk/src/ed25519_instruction.rs) program for signature verification—but it comes with several downsides:

- Charges an extra **5000 lamports per signature**
- Consumes additional transaction data
- Requires the `instruction_sysvar` to be passed into your program
- Only verifies signatures on data hardcoded into the transaction
- Cannot be used with dynamically generated data inside your program
- Has [cumbersome devex](https://github.com/solana-labs/solana/blob/7700cb3128c1f19820de67b81aa45d18f73d2ac0/sdk/src/ed25519_instruction.rs#L23-L29)

This crate, **brine-ed25519**, solves all of that.

---

## Security

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
