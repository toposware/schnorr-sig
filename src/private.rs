//! This module provides a `PrivateKey` wrapping
//! struct around a `Scalar` element.

use super::Signature;

use rand_core::{CryptoRng, RngCore};
use stark_curve::{FieldElement, Scalar};
use subtle::{Choice, ConditionallySelectable, CtOption};

/// A private key
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PrivateKey(pub(crate) Scalar);

impl ConditionallySelectable for PrivateKey {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        PrivateKey(Scalar::conditional_select(&a.0, &b.0, choice))
    }
}

impl PrivateKey {
    /// Generates a new random private key
    pub fn new(mut rng: impl CryptoRng + RngCore) -> Self {
        let secret_scalar = Scalar::random(&mut rng);

        PrivateKey(secret_scalar)
    }

    /// Generates a new private key from a provided scalar.
    ///
    /// If the source or generation method of the scalar is
    /// unknown, it is preferable to use the `PrivateKey:new`
    /// method instead.
    pub fn from_scalar(scalar: Scalar) -> Self {
        PrivateKey(scalar)
    }

    /// Converts this private key to an array of bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Constructs a private key from an array of bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> CtOption<Self> {
        Scalar::from_bytes(bytes).and_then(|s| CtOption::new(PrivateKey(s), Choice::from(1u8)))
    }

    /// Computes a Schnorr signature
    pub fn sign(&self, message: &[FieldElement], mut rng: impl CryptoRng + RngCore) -> Signature {
        Signature::sign(message, self, &mut rng)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    use crate::PublicKey;

    #[test]
    fn test_signature() {
        let mut rng = OsRng;
        let mut message = [FieldElement::zero(); 6];
        for message_chunk in message.iter_mut().skip(2) {
            *message_chunk = FieldElement::random(&mut rng);
        }

        let skey = PrivateKey::new(OsRng);
        let pkey = PublicKey::from_private_key(skey);

        let signature = skey.sign(&message, &mut rng);
        assert!(signature.verify(&message, &pkey).is_ok());
    }

    #[test]
    fn test_encoding() {
        assert_eq!(
            PrivateKey::from_scalar(Scalar::zero()).to_bytes(),
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0
            ]
        );

        assert_eq!(
            PrivateKey::from_scalar(Scalar::one()).to_bytes(),
            [
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0
            ]
        );

        // Test random keys encoding
        let mut rng = OsRng;

        for _ in 0..100 {
            let key = PrivateKey::new(&mut rng);
            let bytes = key.to_bytes();

            assert_eq!(key, PrivateKey::from_bytes(&bytes).unwrap());
        }

        // Test invalid encoding
        let bytes = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff,
        ];
        let recovered_key = PrivateKey::from_bytes(&bytes);
        assert!(bool::from(recovered_key.is_none()))
    }
}
