//! This module provides a `KeyPair` struct
//! combining a `PrivateKey` and an associated `PublicKey`.

use super::{PrivateKey, PublicKey, Signature};

use rand_core::{CryptoRng, RngCore};
use stark_curve::FieldElement;
use subtle::{Choice, CtOption};

/// A KeyPair
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyPair {
    /// A private key
    pub private_key: PrivateKey,
    /// A public key
    pub public_key: PublicKey,
}

impl KeyPair {
    /// Generates a new random key pair
    pub fn new(mut rng: impl CryptoRng + RngCore) -> Self {
        let private_key = PrivateKey::new(&mut rng);
        let public_key = PublicKey::from_private_key(private_key);

        KeyPair {
            private_key,
            public_key,
        }
    }

    /// Generates a new key pair from a provided private key.
    ///
    /// If the source or generation method of the private key
    /// is unknown, it is preferable to use the `KeyPair:new`
    /// method instead.
    pub fn from_private_key(private_key: PrivateKey) -> Self {
        let public_key = PublicKey::from_private_key(private_key);

        KeyPair {
            private_key,
            public_key,
        }
    }

    /// Converts this key pair to an array of bytes
    ///
    /// To ensure consistency between the private key and public key
    /// during reconstruction without extra checks, KeyPair serialization
    /// only serializes the private_key part, and reconstructs the public
    /// key when deserializing.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.private_key.to_bytes()
    }

    /// Constructs a key pair from an array of bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> CtOption<Self> {
        PrivateKey::from_bytes(bytes).and_then(|private_key| {
            let public_key = PublicKey::from_private_key(private_key);
            CtOption::new(
                KeyPair {
                    private_key,
                    public_key,
                },
                Choice::from(1u8),
            )
        })
    }

    /// Verifies a signature against a message and this key pair
    pub fn verify_signature(self, signature: Signature, message: &[FieldElement]) -> bool {
        signature.verify(message, self.public_key)
    }
}
