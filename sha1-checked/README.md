# RustCrypto: SHA-1 Checked

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

Pure Rust implementation of the [SHA-1] cryptographic hash algorithm with collision detection.

## 🚨 Warning: Cryptographically Broken! 🚨

The SHA-1 hash function should be considered cryptographically broken and
unsuitable for further use in any security critical capacity, as it is
[practically vulnerable to chosen-prefix collisions][1].

But, this crate provides the detection [algorithm] pioneered by git, to detect hash collisions when they
occur and prevent them. The [paper] has more details on how this works.

## Performance

This implementation is slower than plain SHA-1, since it does extra work per block to detect collisions.
Measured against this crate's own benchmarks, at throughput relative to plain, undetected SHA-1 on the same backend:

| architecture | scalar | hardware-accelerated |
|--------------|--------|----------------------|
| `aarch64`    |    64% |                  63% |
| `x86_64`     |    55% |                  38% |

Where the CPU's SHA-1 instructions are available, most blocks run through them, falling back to scalar
compression only when a potential collision is flagged. On `aarch64` this keeps detection roughly the same
fraction of plain SHA-1's speed as without hardware acceleration. On `x86_64`, `sha1`'s own hardware backend
speeds up by more than `sha1-checked`'s fixed per-block bookkeeping does, so the gap widens.

## Examples

### One-shot API

```rust
use hex_literal::hex;
use sha1_checked::Sha1;

let result = Sha1::try_digest(b"hello world");
assert_eq!(result.hash().as_ref(), hex!("2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"));
assert!(!result.has_collision());
```

### Incremental API

```rust
use hex_literal::hex;
use sha1_checked::{Sha1, Digest};

let mut hasher = Sha1::new();
hasher.update(b"hello world");
let result = hasher.try_finalize();

assert_eq!(result.hash().as_ref(), hex!("2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"));
assert!(!result.has_collision());
```

See the [`digest`] crate docs for additional examples.

## License

The crate is licensed under either of:

* [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
* [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/sha1-checked.svg
[crate-link]: https://crates.io/crates/sha1-checked
[docs-image]: https://docs.rs/sha1-checked/badge.svg
[docs-link]: https://docs.rs/sha1-checked/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260041-hashes
[build-image]: https://github.com/RustCrypto/hashes/actions/workflows/sha1-checked.yml/badge.svg?branch=master
[build-link]: https://github.com/RustCrypto/hashes/actions/workflows/sha1-checked.yml?query=branch:master

[//]: # (general links)

[SHA-1]: https://en.wikipedia.org/wiki/SHA-1
[1]: https://sha-mbles.github.io/
[`digest`]: https://docs.rs/digest
[algorithm]: https://github.com/cr-marcstevens/sha1collisiondetection
[paper]: https://marc-stevens.nl/research/papers/C13-S.pdf
