# Schnorr-sig

This crate provides an ongoing implementation of a modified version of the Schnorr signature protocol, for efficient verification in a STARK AIR program.
The underlying curve is a custom curve, Cheetah, based on a sextic extension of the the Prime Field Fp with p = 2<sup>62</sup> + 2<sup>56</sup> + 2<sup>55</sup> + 1, and curve equation E(Fp): y<sup>2</sup> = x<sup>3</sup> + x + B, with
B = `(1200866201009650596 * u + 1935817186716799185) * v^2 + (3999205700308519553 * u + 3518137720867787056) * v + 2508413708960025374 * u + 1526905369741321712`
where
- `u^2 - 2u - 2 = 0` is the polynomial defining the quadratic extension Fp2 over Fp,
- `v^3 + v + 1 = 0` is the polynomial defining the cubic extension Fp6 over Fp2.
and implemented [here](https://github.com/ToposWare/cheetah).

* This implementation does not require the Rust standard library

## Features

* `serialize` (on by default): Enables Serde serialization

## Description

See :
- [here](https://en.wikipedia.org/wiki/Schnorr_signature) for an introduction to Schnorr signatures,
- [here](https://github.com/ToposWare/cheetah) for the implementation of the underlying fields and elliptic curve,
- [here](https://github.com/ToposWare/hash) for the implementation of the internal Rescue hash function.

## License

Licensed under
 * TBD
