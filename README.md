# brine-ed25519

[license-image]: https://img.shields.io/badge/license-MIT-blue.svg?style=flat
![license][license-image]
[![crates.io](https://img.shields.io/crates/v/brine-ed25519.svg?style=flat)](https://crates.io/crates/brine-ed25519)

![image](https://github.com/user-attachments/assets/cc354cf3-b82d-40c6-8c9a-9902fae146f0)


A fast, low-overhead, Ed25519 signature verification library for the Solana SVM.

---

**Why brine-ed25519?**

Solana provides an Ed25519 pre-compile program for signature verification—but it comes with several downsides:

- ❌ Requires the `instruction_sysvar` to be passed into your program  
- ❌ Charges **5000 lamports per signature**  
- ❌ Only verifies signatures on data hardcoded into the transaction  
- ❌ Cannot be used with dynamically generated data inside your program  

**brine-ed25519** solves all of that:

- ✅ Verifies Ed25519 signatures **within the program**  
- ✅ Fully supports dynamically generated messages  
- ✅ Uses the low-level `curve25519_syscalls` for fast native operations  
- ✅ Costs **~ 30,000 compute units**  
- ✅ No extra lamports required  
- ✅ Built for use in Solana smart contracts (`#![no_std]` compatible)  

---

## Example: Verifying a Signature

```rust
use brine_ed25519::sig_verify;

let pubkey: [u8; 32] = [...];
let sig: [u8; 64] = [...];
let message = b"hello world";

sig_verify(&pubkey, &sig, message)?;
```

Returns `Ok(())` if valid, or `Err(SignatureError)` if the signature is invalid.

---

## Performance

| Function     | CU Used (approx) |
|--------------|------------------|
| `sig_verify` | ~30,000          |

Measured on-chain using `solana_program::log::sol_log_compute_units()`.

---

## Features

- Uses `curve25519_syscalls`  
- Drops in easily to any Solana smart contract  
- Verifies dynamically created payloads  

Signature verification roughly follows [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032), with adaptations from:

---

## 📦 Usage

Add to your `Cargo.toml`:

```toml
brine-ed25519 = "0.1.0"
```

---

## Tests

Includes test vectors from RFC 8032, as well as custom positive/negative test cases.

Run locally with:

```bash
cargo test
```

---

## Audit and Peer Reviews

This implementation is pulled from [code-vm](https://github.com/code-payments/code-vm) (MIT-licensed), which was written and maintained by the author of this crate.

- ✅ Reviewed as part of the [code-vm](https://github.com/code-payments/code-vm) audit by [OtterSec](https://osec.io)  
- ✅ Peer reviewed by [@stegaBOB](https://github.com/stegaBOB) and [@deanmlittle](https://github.com/deanmlittle)  

Big thanks to both reviewers for helpful suggestions and CU reductions!

---

## Why “brine-ed25519”?

“Brine” evokes salt water — a precise solution. The name reflects a design focused on _precision_, _fluidity_, and _minimal bloat_ — ideal for constrained environments.

---

## License

Licensed under the MIT License.
