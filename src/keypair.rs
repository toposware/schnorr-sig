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
use super::KEY_PAIR_LENGTH;
use super::{KeyedSignature, PrivateKey, PublicKey, Signature};

use rand_core::{CryptoRng, RngCore};
use subtle::{Choice, CtOption};

#[cfg(feature = "serialize")]
use serde::de::Visitor;
#[cfg(feature = "serialize")]
use serde::{self, Deserialize, Deserializer, Serialize, Serializer};

impl From<&PrivateKey> for KeyPair {
    /// Creates a key pair from a private key reference.
    ///
    /// If the source or generation method of the private key
    /// is unknown, it is preferable to use the `KeyPair:new`
    /// method instead.
    fn from(private_key: &PrivateKey) -> KeyPair {
        KeyPair {
            private_key: *private_key,
            public_key: private_key.into(),
        }
    }
}

impl From<PrivateKey> for KeyPair {
    /// Creates a key pair from a private key.
    ///
    /// If the source or generation method of the private key
    /// is unknown, it is preferable to use the `KeyPair:new`
    /// method instead.
    fn from(private_key: PrivateKey) -> KeyPair {
        (&private_key).into()
    }
}

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
        let public_key = PublicKey::from(&private_key);

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
    pub fn to_bytes(&self) -> [u8; KEY_PAIR_LENGTH] {
        self.private_key.to_bytes()
    }

    /// Constructs a key pair from an array of bytes
    pub fn from_bytes(bytes: &[u8; KEY_PAIR_LENGTH]) -> CtOption<Self> {
        PrivateKey::from_bytes(bytes).and_then(|private_key| {
            let public_key = PublicKey::from(&private_key);
            CtOption::new(
                KeyPair {
                    private_key,
                    public_key,
                },
                Choice::from(1u8),
            )
        })
    }

    /// Constructs a key pair from a 64 bytes seed.
    pub fn from_seed(seed: &[u8; 64]) -> CtOption<Self> {
        PrivateKey::from_seed(seed).and_then(|private_key| {
            let public_key = PublicKey::from(&private_key);
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
    pub fn sign(&self, message: &[u8], mut rng: impl CryptoRng + RngCore) -> Signature {
        Signature::sign_with_keypair(message, self, &mut rng)
    }

    /// Computes a Schnorr signature binded to its associated public key.
    pub fn sign_and_bind_pkey(
        &self,
        message: &[u8],
        mut rng: impl CryptoRng + RngCore,
    ) -> KeyedSignature {
        KeyedSignature::sign_with_keypair(message, self, &mut rng)
    }

    /// Verifies a signature against a message and this key pair
    pub fn verify_signature(
        self,
        signature: &Signature,
        message: &[u8],
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
        let mut tup = serializer.serialize_tuple(KEY_PAIR_LENGTH)?;
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
                let mut bytes = [0u8; KEY_PAIR_LENGTH];
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

        deserializer.deserialize_tuple(KEY_PAIR_LENGTH, KeyPairVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cheetah::Scalar;
    use rand_core::OsRng;

    #[test]
    fn test_from_private_key() {
        let mut rng = OsRng;

        for _ in 0..100 {
            let skey = PrivateKey::new(&mut rng);
            let keypair = KeyPair {
                private_key: skey,
                public_key: PublicKey::from(&skey),
            };

            assert_eq!(keypair, KeyPair::from(skey));
            assert_eq!(keypair, KeyPair::from(&skey));
        }
    }

    #[test]
    fn test_signature() {
        let mut rng = OsRng;

        let mut message = [0u8; 160];
        rng.fill_bytes(&mut message);

        let skey = PrivateKey::new(&mut rng);
        let key_pair = KeyPair::from(skey);

        let signature = key_pair.sign(&message, &mut rng);
        assert!(key_pair.verify_signature(&signature, &message).is_ok());

        let keyed_signature = key_pair.sign_and_bind_pkey(&message, &mut rng);
        assert!(keyed_signature.verify(&message).is_ok());
    }

    #[test]
    fn test_encoding() {
        assert_eq!(
            KeyPair::from(PrivateKey::from_scalar(Scalar::zero())).to_bytes(),
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0
            ]
        );

        assert_eq!(
            KeyPair::from(PrivateKey::from_scalar(Scalar::one())).to_bytes(),
            [
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0
            ]
        );

        // Test random key pairs encodings
        let mut rng = OsRng;

        for _ in 0..100 {
            let key_pair = KeyPair::new(&mut rng);
            let bytes = key_pair.to_bytes();
            assert_eq!(bytes.len(), KEY_PAIR_LENGTH);

            assert_eq!(key_pair, KeyPair::from_bytes(&bytes).unwrap());
        }

        // Test invalid encodings
        let bytes = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        let recovered_key = KeyPair::from_bytes(&bytes);
        assert!(bool::from(recovered_key.is_none()));

        let bytes = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff,
        ];
        let recovered_key = KeyPair::from_bytes(&bytes);
        assert!(bool::from(recovered_key.is_none()));
    }

    #[test]
    fn test_from_seed() {
        let mut rng = OsRng;

        for _ in 0..100 {
            let key = KeyPair::new(&mut rng);
            let bytes = key.to_bytes();
            let mut seed = [0u8; 64];
            seed[0..32].copy_from_slice(&bytes);

            assert_eq!(key, KeyPair::from_seed(&seed).unwrap());
        }

        let invalid_seed = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0,
        ];
        let recovered_key = KeyPair::from_seed(&invalid_seed);
        assert!(bool::from(recovered_key.is_none()));
    }

    #[test]
    #[cfg(feature = "serialize")]
    fn test_serde() {
        let mut rng = OsRng;
        let key_pair = KeyPair::from(PrivateKey::new(&mut rng));
        let encoded = bincode::serialize(&key_pair).unwrap();
        let parsed: KeyPair = bincode::deserialize(&encoded).unwrap();
        assert_eq!(parsed, key_pair);

        // Check that the encoding is KEY_PAIR_LENGTH (32) bytes exactly
        assert_eq!(encoded.len(), KEY_PAIR_LENGTH);

        // Check that the encoding itself matches the usual one
        assert_eq!(
            key_pair,
            bincode::deserialize(&key_pair.to_bytes()).unwrap()
        );

        // Check that invalid encodings fail
        let key_pair = KeyPair::from(PrivateKey::new(&mut rng));
        let mut encoded = bincode::serialize(&key_pair).unwrap();
        encoded[KEY_PAIR_LENGTH - 1] = 127;
        assert!(bincode::deserialize::<KeyPair>(&encoded).is_err());

        assert_eq!(
            format!("{:?}", bincode::deserialize::<KeyPair>(&encoded)),
            "Err(Custom(\"decompression failed\"))"
        );

        let encoded = bincode::serialize(&key_pair).unwrap();
        assert!(bincode::deserialize::<KeyPair>(&encoded[0..KEY_PAIR_LENGTH - 1]).is_err());

        assert_eq!(
            format!(
                "{:?}",
                bincode::deserialize::<KeyPair>(&encoded[0..KEY_PAIR_LENGTH - 1])
            ),
            "Err(Io(Kind(UnexpectedEof)))"
        );
    }
}
