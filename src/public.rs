//! This module provides a `PublicKey` wrapping
//! struct around a `ProjectivePoint` element.

use super::error::SignatureError;
use super::{PrivateKey, Signature};

use stark_curve::{FieldElement, ProjectivePoint};
use subtle::CtOption;

#[cfg(feature = "serialize")]
use serde::{Deserialize, Serialize};

/// A private key
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serialize", derive(Deserialize, Serialize))]
pub struct PublicKey(pub(crate) ProjectivePoint);

impl PublicKey {
    /// Computes a public key from a provided private key
    pub fn from_private_key(sk: PrivateKey) -> Self {
        let pkey = ProjectivePoint::generator() * sk.0;

        PublicKey(pkey)
    }

    /// Converts this public key to an array of bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_compressed()
    }

    /// Constructs a public key from an array of bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> CtOption<Self> {
        ProjectivePoint::from_compressed(bytes).map(PublicKey)
    }

    /// Verifies a signature against a message and this public key
    pub fn verify_signature(
        self,
        signature: &Signature,
        message: &[FieldElement],
    ) -> Result<(), SignatureError> {
        signature.verify(message, &self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;
    use stark_curve::group::ff::Field;
    use stark_curve::Scalar;

    #[test]
    fn test_signature() {
        let mut rng = OsRng;
        let mut message = [FieldElement::zero(); 6];
        for message_chunk in message.iter_mut() {
            *message_chunk = FieldElement::random(&mut rng);
        }

        let skey = PrivateKey::new(OsRng);
        let pkey = PublicKey::from_private_key(skey);

        let signature = Signature::sign(&message, &skey, &mut rng);
        assert!(pkey.verify_signature(&signature, &message).is_ok());
    }

    #[test]
    fn test_encoding() {
        assert_eq!(
            PublicKey::from_private_key(PrivateKey::from_scalar(Scalar::zero())).to_bytes(),
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 192
            ]
        );

        // Test random keys encoding
        let mut rng = OsRng;

        for _ in 0..100 {
            let key = PrivateKey::new(&mut rng);
            let bytes = key.to_bytes();

            assert_eq!(key, PrivateKey::from_bytes(&bytes).unwrap());
        }
    }

    #[test]
    #[cfg(feature = "serialize")]
    fn test_serde() {
        let mut rng = OsRng;
        let pkey = PublicKey::from_private_key(PrivateKey::new(&mut rng));
        let encoded = bincode::serialize(&pkey).unwrap();
        let parsed: PublicKey = bincode::deserialize(&encoded).unwrap();
        assert_eq!(parsed, pkey);

        // Check that the encoding is 32 bytes exactly
        assert_eq!(encoded.len(), 32);

        // Check that the encoding itself matches the usual one
        assert_eq!(pkey, bincode::deserialize(&pkey.to_bytes()).unwrap());

        // Check that invalid encodings fail
        let pkey = PublicKey::from_private_key(PrivateKey::new(&mut rng));
        let mut encoded = bincode::serialize(&pkey).unwrap();
        encoded[31] = 127;
        assert!(bincode::deserialize::<PublicKey>(&encoded).is_err());

        let encoded = bincode::serialize(&pkey).unwrap();
        assert!(bincode::deserialize::<PublicKey>(&encoded[0..31]).is_err());
    }
}
