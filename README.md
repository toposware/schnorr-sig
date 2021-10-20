# Schnorr-sig

This crate provides an ongoing implementation of a modified version of the Schnorr signature protocol, for efficient verification in a STARK AIR program.
The underlying curve is currently the one originally discovered by STARKWARE, based on the Prime Field Fp with p = 2<sup>251</sup> + 17(2<sup>192</sup>) + 1, and curve equation E(Fp): y<sup>2</sup> = x<sup>3</sup> + x + B, with 
B = `0x6f21413efbe40de150e596d72f7a8c5609ad26c15c915c1f4cdfcb99cee9e89`,
and implemented [here](https://github.com/ToposWare/stark-curve).

* This implementation does not require the Rust standard library

## Description

See :
- [here](https://en.wikipedia.org/wiki/Schnorr_signature) for an introduction to Schnorr signatures,
- [here](https://github.com/ToposWare/stark-curve) for the implementation of the underlying fields and elliptic curve,
- [here](https://github.com/ToposWare/hash) for the implementation of the internal Rescue hash function.