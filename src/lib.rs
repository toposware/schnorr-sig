//! This crate provides an implementation of a custom Schnorr
//! signature with internal Rescue hash on a 252-bit field.

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
//! To sign a `message` seen as an array of `FieldElement` values, with a given
//! private key `skey` and given source of randomness `rng`, either call the sign
//! method from the `Signature` struct or from the private key directly, as shown
//! in the following examples:
//!
//! ```rust
//! use stark_curve::FieldElement;
//! use schnorr_sig::PrivateKey;
//! use schnorr_sig::Signature;
//! use rand_core::OsRng;
//!
//! let mut rng = OsRng;
//! let message = [FieldElement::one(); 42];
//! let skey = PrivateKey::new(&mut rng);
//!
//! let signature = Signature::sign(&message, &skey, &mut rng);
//! ```
//!
//! ```rust
//! use stark_curve::FieldElement;
//! use schnorr_sig::PrivateKey;
//! use rand_core::OsRng;
//!
//! let mut rng = OsRng;
//! let message = [FieldElement::one(); 42];
//! let skey = PrivateKey::new(&mut rng);
//!
//! let signature = skey.sign(&message, &mut rng);
//! ```
//!
//! To verify a signature against a given `message`, with a provided
//! public key `pkey`, you can call the verify method from the `signature`
//! directly, as shown in the following example:
//!
//! ```rust
//! use stark_curve::FieldElement;
//! use schnorr_sig::PrivateKey;
//! use schnorr_sig::PublicKey;
//! use rand_core::OsRng;
//!
//! let mut rng = OsRng;
//! let message = [FieldElement::one(); 42];
//! let skey = PrivateKey::new(&mut rng);
//! let pkey = PublicKey::from_private_key(skey);
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
//!
//! ```rust
//! use stark_curve::FieldElement;
//! use schnorr_sig::KeyPair;
//! use rand_core::OsRng;
//!
//! let mut rng = OsRng;
//! let message = [FieldElement::one(); 42];
//! let key_pair = KeyPair::new(&mut rng);
//!
//! let signature = key_pair.sign(&message, &mut rng);
//!
//! assert!(key_pair.verify_signature(&signature, &message).is_ok());
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(broken_intra_doc_links)]
#![deny(missing_debug_implementations)]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

mod error;

/// The private key module.
pub mod private;

/// The public key module.
pub mod public;

/// The key pair module.
pub mod keypair;

/// The Schnorr signature module.
pub mod signature;

pub use private::PrivateKey;
pub use public::PublicKey;

pub use keypair::KeyPair;

pub use signature::Signature;
