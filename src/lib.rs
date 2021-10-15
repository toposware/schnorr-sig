//! This crate provides an implementation of a custom Schnorr
//! signature with internal Rescue hash on a 252-bit field.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(broken_intra_doc_links)]
#![deny(missing_debug_implementations)]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

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
