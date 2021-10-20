//! This module provides a `KeyPair` struct
//! combining a `PrivateKey` and an associated `PublicKey`.

use super::error::SignatureError;
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

    /// Computes a Schnorr signature
    pub fn sign(&self, message: &[FieldElement], mut rng: impl CryptoRng + RngCore) -> Signature {
        Signature::sign(message, &self.private_key, &mut rng)
    }

    /// Verifies a signature against a message and this key pair
    pub fn verify_signature(
        self,
        signature: &Signature,
        message: &[FieldElement],
    ) -> Result<(), SignatureError> {
        signature.verify(message, &self.public_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;
    use stark_curve::Scalar;

    #[test]
    fn test_signature() {
        let mut rng = OsRng;
        let mut message = [FieldElement::zero(); 6];
        for message_chunk in message.iter_mut().skip(2) {
            *message_chunk = FieldElement::random(&mut rng);
        }

        let skey = PrivateKey::new(OsRng);
        let key_pair = KeyPair::from_private_key(skey);

        let signature = key_pair.sign(&message, &mut rng);
        assert!(key_pair.verify_signature(&signature, &message).is_ok());
    }

    #[test]
    fn test_encoding() {
        assert_eq!(
            KeyPair::from_private_key(PrivateKey::from_scalar(Scalar::zero())).to_bytes(),
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0
            ]
        );

        assert_eq!(
            KeyPair::from_private_key(PrivateKey::from_scalar(Scalar::one())).to_bytes(),
            [
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0
            ]
        );

        // Test random key pairs encoding
        let mut rng = OsRng;

        for _ in 0..100 {
            let key_pair = KeyPair::new(&mut rng);
            let bytes = key_pair.to_bytes();

            assert_eq!(key_pair, KeyPair::from_bytes(&bytes).unwrap());
        }
    }
}
