# Schnorr-sig

This crate provides an implementation of a modified version of the Schnorr signature protocol, for efficient verification in a STARK AIR program.
The underlying curve is a custom curve, Cheetah, based on a sextic extension of the the Prime Field Fp with p = 2<sup>64</sup> - 2<sup>32</sup> + 1, and curve equation E(Fp): y<sup>2</sup> = x<sup>3</sup> + x + B, with
B = `u + 395`
where

- `u^6 - 7 = 0` is the polynomial defining the sextic extension Fp6 over Fp.
and implemented [here](https://github.com/ToposWare/cheetah).

- This implementation may not rely on the Rust standard library by relying on the `alloc` crate instead.

**WARNING:** This is an ongoing, prototype implementation subject to changes. In particular, it has not been audited and may contain bugs and security flaws. This implementation is NOT ready for production use.

## Features

- `serialize` (on by default): Enables Serde serialization
- `std` (on by default): Enables the Rust standard library

## Description

See :

- [here](https://en.wikipedia.org/wiki/Schnorr_signature) for an introduction to Schnorr signatures,
- [here](https://github.com/ToposWare/cheetah) for the implementation of the underlying fields and elliptic curve,
- [here](https://github.com/ToposWare/hash) for the implementation of the internal Rescue hash function.

## License

Licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
