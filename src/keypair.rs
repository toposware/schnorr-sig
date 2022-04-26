// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! This module provides a `KeyPair` struct
//! combining a `PrivateKey` and an associated `PublicKey`.

use super::error::SignatureError;
use super::{KeyedSignature, PrivateKey, PublicKey, Signature};

use cheetah::Fp;
use rand_core::{CryptoRng, RngCore};
use subtle::{Choice, CtOption};

#[cfg(feature = "serialize")]
use serde::de::Visitor;
#[cfg(feature = "serialize")]
use serde::{self, Deserialize, Deserializer, Serialize, Serializer};

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
        let public_key = PublicKey::from_private_key(&private_key);

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
        let public_key = PublicKey::from_private_key(&private_key);

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
            let public_key = PublicKey::from_private_key(&private_key);
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
    pub fn sign(&self, message: &[Fp], mut rng: impl CryptoRng + RngCore) -> Signature {
        Signature::sign_with_keypair(message, self, &mut rng)
    }

    /// Computes a Schnorr signature binded to its associated public key.
    pub fn sign_and_bind_pkey(
        &self,
        message: &[Fp],
        mut rng: impl CryptoRng + RngCore,
    ) -> KeyedSignature {
        KeyedSignature::sign_with_keypair(message, self, &mut rng)
    }

    /// Verifies a signature against a message and this key pair
    pub fn verify_signature(
        self,
        signature: &Signature,
        message: &[Fp],
    ) -> Result<(), SignatureError> {
        signature.verify(message, &self.public_key)
    }
}

// Serde Serialize and Deserialize traits are not directly derived
// as we would end up with a serialization twice larger than the
// byte encoding, which skips the public_key component and reconstructs
// it when decoding.
#[cfg(feature = "serialize")]
impl Serialize for KeyPair {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeTuple;
        let mut tup = serializer.serialize_tuple(32)?;
        for byte in self.to_bytes().iter() {
            tup.serialize_element(byte)?;
        }
        tup.end()
    }
}

#[cfg(feature = "serialize")]
impl<'de> Deserialize<'de> for KeyPair {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct KeyPairVisitor;

        impl<'de> Visitor<'de> for KeyPairVisitor {
            type Value = KeyPair;

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("a valid field element")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<KeyPair, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut bytes = [0u8; 32];
                for (i, byte) in bytes.iter_mut().enumerate() {
                    *byte = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &"expected 32 bytes"))?;
                }
                let scalar = KeyPair::from_bytes(&bytes);
                if bool::from(scalar.is_none()) {
                    Err(serde::de::Error::custom("decompression failed"))
                } else {
                    Ok(scalar.unwrap())
                }
            }
        }

        deserializer.deserialize_tuple(32, KeyPairVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cheetah::Scalar;
    use rand_core::OsRng;

    #[test]
    fn test_signature() {
        let mut rng = OsRng;

        let mut message = [Fp::zero(); 42];
        for message_chunk in message.iter_mut() {
            *message_chunk = Fp::random(&mut rng);
        }

        let skey = PrivateKey::new(&mut rng);
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

    #[test]
    #[cfg(feature = "serialize")]
    fn test_serde() {
        let mut rng = OsRng;
        let key_pair = KeyPair::from_private_key(PrivateKey::new(&mut rng));
        let encoded = bincode::serialize(&key_pair).unwrap();
        let parsed: KeyPair = bincode::deserialize(&encoded).unwrap();
        assert_eq!(parsed, key_pair);

        // Check that the encoding is 32 bytes exactly
        assert_eq!(encoded.len(), 32);

        // Check that the encoding itself matches the usual one
        assert_eq!(
            key_pair,
            bincode::deserialize(&key_pair.to_bytes()).unwrap()
        );

        // Check that invalid encodings fail
        let key_pair = KeyPair::from_private_key(PrivateKey::new(&mut rng));
        let mut encoded = bincode::serialize(&key_pair).unwrap();
        encoded[31] = 127;
        assert!(bincode::deserialize::<KeyPair>(&encoded).is_err());

        let encoded = bincode::serialize(&key_pair).unwrap();
        assert!(bincode::deserialize::<KeyPair>(&encoded[0..31]).is_err());
    }
}
