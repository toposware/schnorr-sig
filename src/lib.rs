// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! This crate provides an implementation of a custom Schnorr
//! signature with internal Rescue hash on a 63-bit field.

//! # Usage
//!
//! To generate a new random key pair, consisting of a secret scalar
//! (private key) and an associated curve point in projective coordinate
//! (public key), do as the following:
//!
//! ```rust
//! use schnorr_sig::KeyPair;
//! use rand_core::OsRng;
//!
//! let mut rng = OsRng;
//! let new_key_pair = KeyPair::new(&mut rng);
//! ```
//!
//! To sign a `message` seen as an array of `Fp` values, with a given
//! private key `skey` and given source of randomness `rng`, either call the `sign`
//! method from the `Signature` struct or from the private key directly, as shown
//! in the following examples:
//!
//! ```rust
//! use cheetah::Fp;
//! use schnorr_sig::PrivateKey;
//! use schnorr_sig::Signature;
//! use rand_core::OsRng;
//!
//! let mut rng = OsRng;
//! let message = [Fp::one(); 42];
//! let skey = PrivateKey::new(&mut rng);
//!
//! let signature = Signature::sign(&message, &skey, &mut rng);
//! ```
//!
//! ```rust
//! use cheetah::Fp;
//! use schnorr_sig::PrivateKey;
//! use rand_core::OsRng;
//!
//! let mut rng = OsRng;
//! let message = [Fp::one(); 42];
//! let skey = PrivateKey::new(&mut rng);
//!
//! let signature = skey.sign(&message, &mut rng);
//! ```
//!
//! The Schnorr signatures of this library hash the public key associated
//! to the signing key. For a faster signing process, one can call either
//! the `sign_with_provided_pkey` or `sign_with_keypair` methods, or the
//! `sign` method from the `KeyPair` struct, as shown below:
//!
//! ```rust
//! use cheetah::Fp;
//! use schnorr_sig::PrivateKey;
//! use schnorr_sig::PublicKey;
//! use schnorr_sig::Signature;
//! use rand_core::OsRng;
//!
//! let mut rng = OsRng;
//! let message = [Fp::one(); 42];
//! let skey = PrivateKey::new(&mut rng);
//! let pkey = PublicKey::from_private_key(&skey);
//!
//! let signature = Signature::sign_with_provided_pkey(&message, &skey, &pkey, &mut rng);
//! ```
//!
//! ```rust
//! use cheetah::Fp;
//! use schnorr_sig::KeyPair;
//! use schnorr_sig::Signature;
//! use rand_core::OsRng;
//!
//! let mut rng = OsRng;
//! let message = [Fp::one(); 42];
//! let keypair = KeyPair::new(&mut rng);
//!
//! let signature = Signature::sign_with_keypair(&message, &keypair, &mut rng);
//! ```
//!
//! ```rust
//! use cheetah::Fp;
//! use schnorr_sig::KeyPair;
//! use rand_core::OsRng;
//!
//! let mut rng = OsRng;
//! let message = [Fp::one(); 42];
//! let keypair = KeyPair::new(&mut rng);
//!
//! let signature = keypair.sign(&message, &mut rng);
//! ```
//!
//! To verify a signature against a given `message`, with a provided
//! public key `pkey`, you can call the verify method from the `signature`
//! directly, as shown in the following example:
//!
//! ```rust
//! use cheetah::Fp;
//! use schnorr_sig::PrivateKey;
//! use schnorr_sig::PublicKey;
//! use schnorr_sig::Signature;
//! use rand_core::OsRng;
//!
//! let mut rng = OsRng;
//! let message = [Fp::one(); 42];
//! let skey = PrivateKey::new(&mut rng);
//! let pkey = PublicKey::from_private_key(&skey);
//!
//! let signature = skey.sign(&message, &mut rng);
//!
//! assert!(signature.verify(&message, &pkey).is_ok());
//! ```
//!
//! You can also verify a signature directly from the
//! `verify_signature` method implemented for the
//! `PublicKey` and `KeyPair` types:
//!
//! ```rust
//! use cheetah::Fp;
//! use schnorr_sig::KeyPair;
//! use rand_core::OsRng;
//!
//! let mut rng = OsRng;
//! let message = [Fp::one(); 42];
//! let keypair = KeyPair::new(&mut rng);
//! let pkey = keypair.public_key;
//!
//! let signature = keypair.sign(&message, &mut rng);
//!
//! assert!(keypair.verify_signature(&signature, &message).is_ok());
//! assert!(pkey.verify_signature(&signature, &message).is_ok());
//! ```
//!
//! The `KeyedSignature` struct can also be used to attach the identity
//! of the signer (its `PublicKey`) to a produced signature. The
//! `KeyedSignature` struct shares the same signing methods than the
//! `Signature` struct, and can be verified like this:
//!
//! ```rust
//! use cheetah::Fp;
//! use schnorr_sig::KeyPair;
//! use schnorr_sig::KeyedSignature;
//! use rand_core::OsRng;
//!
//! let mut rng = OsRng;
//! let message = [Fp::one(); 42];
//! let keypair = KeyPair::new(&mut rng);
//!
//! let keyed_signature = KeyedSignature::sign_with_keypair(&message, &keypair, &mut rng);
//!
//! assert!(keypair.verify_signature(&keyed_signature.signature, &message).is_ok());
//! assert!(keyed_signature.verify(&message).is_ok());
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_debug_implementations)]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![no_std]

#[cfg(test)]
#[macro_use]
extern crate std;

mod error;

/// The private key module.
mod private;

/// The public key module.
mod public;

/// The key pair module.
mod keypair;

/// The key derivation module.
mod derivation;

/// The Schnorr signature module.
mod signature;

pub use private::PrivateKey;
pub use public::PublicKey;

pub use keypair::KeyPair;

pub use derivation::{ChainCode, ExtendedPrivateKey, ExtendedPublicKey, CHAIN_CODE_LENGTH};

pub use signature::{KeyedSignature, Signature};
