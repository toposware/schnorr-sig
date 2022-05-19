// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! This module provides a `PublicKey` wrapping
//! struct around an `AffinePoint` element.

use super::error::SignatureError;
use super::{PrivateKey, Signature};

use cheetah::{AffinePoint, CompressedPoint, Fp, BASEPOINT_TABLE};
use subtle::{Choice, ConditionallySelectable, CtOption};

#[cfg(feature = "serialize")]
use serde::{Deserialize, Serialize};

/// A private key
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serialize", derive(Deserialize, Serialize))]
pub struct PublicKey(pub(crate) AffinePoint);

impl ConditionallySelectable for PublicKey {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        PublicKey(AffinePoint::conditional_select(&a.0, &b.0, choice))
    }
}

impl PublicKey {
    /// Computes a public key from a provided private key
    pub fn from_private_key(sk: &PrivateKey) -> Self {
        let pkey = &BASEPOINT_TABLE * sk.0;

        PublicKey(pkey.into())
    }

    /// Converts this public key to an array of bytes
    pub fn to_bytes(&self) -> [u8; 49] {
        self.0.to_compressed().to_bytes()
    }

    /// Constructs a public key from an array of bytes
    pub fn from_bytes(bytes: &[u8; 49]) -> CtOption<Self> {
        AffinePoint::from_compressed(&CompressedPoint::from_bytes(bytes)).map(PublicKey)
    }

    /// Verifies a signature against a message and this public key
    pub fn verify_signature(
        self,
        signature: &Signature,
        message: &[Fp],
    ) -> Result<(), SignatureError> {
        signature.verify(message, &self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cheetah::Scalar;
    use rand_core::OsRng;

    #[test]
    fn test_conditional_selection() {
        let a = PublicKey(AffinePoint::identity());
        let b = PublicKey(AffinePoint::generator());

        assert_eq!(
            ConditionallySelectable::conditional_select(&a, &b, Choice::from(0u8)),
            a
        );
        assert_eq!(
            ConditionallySelectable::conditional_select(&a, &b, Choice::from(1u8)),
            b
        );
    }

    #[test]
    fn test_signature() {
        let mut rng = OsRng;

        let mut message = [Fp::zero(); 42];
        for message_chunk in message.iter_mut() {
            *message_chunk = Fp::random(&mut rng);
        }

        let skey = PrivateKey::new(&mut rng);
        let pkey = PublicKey::from_private_key(&skey);

        let signature = Signature::sign(&message, &skey, &mut rng);
        assert!(pkey.verify_signature(&signature, &message).is_ok());
    }

    #[test]
    fn test_encoding() {
        assert_eq!(
            PublicKey::from_private_key(&PrivateKey::from_scalar(Scalar::zero())).to_bytes(),
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128
            ]
        );

        // Test random keys encoding
        let mut rng = OsRng;

        for _ in 0..100 {
            let key = PrivateKey::new(&mut rng);
            let bytes = key.to_bytes();

            assert_eq!(key, PrivateKey::from_bytes(&bytes).unwrap());
        }

        // Test invalid encodings
        let bytes = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let recovered_key = PublicKey::from_bytes(&bytes);
        assert!(bool::from(recovered_key.is_none()));

        let bytes = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ];
        let recovered_key = PublicKey::from_bytes(&bytes);
        assert!(bool::from(recovered_key.is_none()));
    }

    #[test]
    #[cfg(feature = "serialize")]
    fn test_serde() {
        let mut rng = OsRng;
        let pkey = PublicKey::from_private_key(&PrivateKey::new(&mut rng));
        let encoded = bincode::serialize(&pkey).unwrap();
        let parsed: PublicKey = bincode::deserialize(&encoded).unwrap();
        assert_eq!(parsed, pkey);

        // Check that the encoding is 49 bytes exactly
        assert_eq!(encoded.len(), 49);

        // Check that the encoding itself matches the usual one
        assert_eq!(pkey, bincode::deserialize(&pkey.to_bytes()).unwrap());

        // Check that invalid encodings fail
        let pkey = PublicKey::from_private_key(&PrivateKey::new(&mut rng));
        let mut encoded = bincode::serialize(&pkey).unwrap();
        encoded[48] = 255;
        assert!(bincode::deserialize::<PublicKey>(&encoded).is_err());

        let encoded = bincode::serialize(&pkey).unwrap();
        assert!(bincode::deserialize::<PublicKey>(&encoded[0..48]).is_err());
    }
}
