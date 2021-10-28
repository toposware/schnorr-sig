//! This module provides a `PrivateKey` wrapping
//! struct around a `Scalar` element.

use super::Signature;

use rand_core::{CryptoRng, RngCore};
use stark_curve::group::ff::Field;
use stark_curve::{FieldElement, Scalar};
use subtle::{Choice, ConditionallySelectable, CtOption};

#[cfg(feature = "serialize")]
use serde::{Deserialize, Serialize};

/// A private key
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serialize", derive(Deserialize, Serialize))]
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
        for message_chunk in message.iter_mut() {
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

    #[test]
    #[cfg(feature = "serialize")]
    fn test_serde() {
        let mut rng = OsRng;
        let skey = PrivateKey::new(&mut rng);
        let encoded = bincode::serialize(&skey).unwrap();
        let parsed: PrivateKey = bincode::deserialize(&encoded).unwrap();
        assert_eq!(parsed, skey);

        // Check that the encoding is 32 bytes exactly
        assert_eq!(encoded.len(), 32);

        // Check that the encoding itself matches the usual one
        assert_eq!(skey, bincode::deserialize(&skey.to_bytes()).unwrap());

        // Check that invalid encodings fail
        let skey = PrivateKey::new(&mut rng);
        let mut encoded = bincode::serialize(&skey).unwrap();
        encoded[31] = 127;
        assert!(bincode::deserialize::<PrivateKey>(&encoded).is_err());

        let encoded = bincode::serialize(&skey).unwrap();
        assert!(bincode::deserialize::<PrivateKey>(&encoded[0..31]).is_err());
    }
}
