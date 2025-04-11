# brine-ed25519

[license-image]: https://img.shields.io/badge/license-MIT-blue.svg?style=flat
![license][license-image]
[![crates.io](https://img.shields.io/crates/v/brine-ed25519.svg?style=flat)](https://crates.io/crates/brine-ed25519)

![image](https://github.com/user-attachments/assets/cc354cf3-b82d-40c6-8c9a-9902fae146f0)


A fast, low-overhead, Ed25519 signature verification library for the Solana SVM.

---

## ⚡ Performance

| Operation    | CU (Approx.) |
|--------------|--------------|
| `sig_verify` |      ~30,000 |

These value was measured inside the Solana SVM (via test programs), it depends on the size of the data (32 bytes in this case).

---

## ✨ Features

- Verifies Ed25519 signatures **within the program**, at run-time
- Fully supports dynamically generated messages
- No extra lamports required

Signature verification roughly follows [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032)

---

## 🧱 Use Cases

- Signed content or metadata validation
- Meta-transactions & gasless relays
- Custom auth with off-chain signatures
- Cross-chain validator proof verification
- Oracle data integrity checks
- Decentralized identity & DID claims

---

## 🚀 Quick Start

```rust
use brine_ed25519::sig_verify;

let pubkey: [u8; 32] = [...];
let sig: [u8; 64] = [...];
let message = b"hello world";

sig_verify(&pubkey, &sig, message)?;
```

Returns `Ok(())` if valid, or `Err(SignatureError)` if the signature is invalid.

---

## 🧠 But why?

**Q:** Why not use the native Ed25519 program?

**A:** Solana does provide a [Ed25519 pre-compile](https://github.com/solana-labs/solana/blob/master/sdk/src/ed25519_instruction.rs) program for signature verification—but it comes with several downsides:

- Charges an extra **5000 lamports per signature**
- Requires the `instruction_sysvar` to be passed into your program
- Only verifies signatures on data hardcoded into the transaction
- Cannot be used with dynamically generated data inside your program
- Has [cumbersome devex](https://github.com/solana-labs/solana/blob/7700cb3128c1f19820de67b81aa45d18f73d2ac0/sdk/src/ed25519_instruction.rs#L23-L29)

This crate, **brine-ed25519**, solves all of that.

---

## 🔐 Security

This implementation is pulled from [code-vm](https://github.com/code-payments/code-vm) (MIT-licensed), which was written and maintained by the author of this crate.

- ✅ Reviewed as part of the [code-vm](https://github.com/code-payments/code-vm) audit by [OtterSec](https://osec.io)  
- ✅ Peer reviewed by [@stegaBOB](https://github.com/stegaBOB) and [@deanmlittle](https://github.com/deanmlittle)  

Big thanks to both reviewers for helpful suggestions and CU reductions!

---

## 🙌 Contributing

Contributions are welcome! Please open issues or PRs on the GitHub repo.
