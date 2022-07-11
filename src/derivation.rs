// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! This module provides an implementation of "hierarchical deterministic
//! key derivation" (HDKD) for Schnorr signatures on the Cheetah curve.

use super::{PrivateKey, PublicKey};
use super::{
    CHAIN_CODE_LENGTH, EXTENDED_PRIVATE_KEY_LENGTH, EXTENDED_PUBLIC_KEY_LENGTH, PRIVATE_KEY_LENGTH,
    PRIVATE_KEY_SEED_LENGTH, PUBLIC_KEY_LENGTH,
};

use cheetah::Scalar;
use cheetah::BASEPOINT_TABLE;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use subtle::{Choice, ConditionallySelectable, CtOption};

#[cfg(feature = "serialize")]
use serde::{Deserialize, Serialize};

type HmacSha512 = Hmac<Sha512>;

/// BIP32 like chain codes, providing large entropy when deriving keys.
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serialize", derive(Deserialize, Serialize))]
pub struct ChainCode(pub [u8; CHAIN_CODE_LENGTH]);

impl ConditionallySelectable for ChainCode {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut bytes = [0u8; CHAIN_CODE_LENGTH];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::conditional_select(&a.0[i], &b.0[i], choice);
        }

        ChainCode(bytes)
    }
}

/// A wraper combining a derivable private key and a chain code.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serialize", derive(Deserialize, Serialize))]
pub struct ExtendedPrivateKey {
    /// A private key
    pub key: PrivateKey,
    /// A chain code
    pub chaincode: ChainCode,
}

impl ConditionallySelectable for ExtendedPrivateKey {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        ExtendedPrivateKey {
            key: PrivateKey::conditional_select(&a.key, &b.key, choice),
            chaincode: ChainCode::conditional_select(&a.chaincode, &b.chaincode, choice),
        }
    }
}

impl ExtendedPrivateKey {
    /// Generates a master extended spending key from a provided seed.
    pub fn generate_master_key(seed: &[u8; PRIVATE_KEY_SEED_LENGTH]) -> CtOption<Self> {
        let mut mac = HmacSha512::new_from_slice("Cheetah - Master extended key seed".as_bytes())
            .expect("This instantiation should not fail.");
        mac.update(seed);

        let result = mac.finalize();
        let bytes = result.into_bytes();

        let mut array = [0u8; PRIVATE_KEY_LENGTH];
        array.copy_from_slice(&bytes[..PRIVATE_KEY_LENGTH]);
        let key = PrivateKey(Scalar::from_bytes_non_canonical(&array));

        array.copy_from_slice(&bytes[PRIVATE_KEY_LENGTH..]);
        let chaincode = ChainCode(array);

        CtOption::new(ExtendedPrivateKey { key, chaincode }, !(key.0.is_zero()))
    }

    /// Derives a private child (either normal or hardened) from the current extended
    /// private key with the provided index `i`.
    /// The index, written in little-endian, can represent either a hardened or
    /// non-hardened child.
    pub fn derive_private(&self, i: &[u8; 4]) -> CtOption<Self> {
        ConditionallySelectable::conditional_select(
            &self.derive_hardened_private(i),
            &self.derive_normal_private(i),
            Choice::from(((i[3] & 0b1000_0000) == 0) as u8),
        )
    }

    /// Derives a hardened private child from the current extended private key
    /// with the provided index `i`.
    /// The index, written in little-endian, must represent an integer greater
    /// than 2^31.
    fn derive_hardened_private(&self, i: &[u8; 4]) -> CtOption<Self> {
        let mut key_array = [0u8; PUBLIC_KEY_LENGTH];
        key_array[PUBLIC_KEY_LENGTH - PRIVATE_KEY_LENGTH..].copy_from_slice(&self.key.to_bytes());
        let mut mac = HmacSha512::new_from_slice(&self.chaincode.0)
            .expect("HMAC should take a 32-bytes long chaincode.");
        mac.update(&key_array);
        mac.update(i);

        let result = mac.finalize();
        let bytes = result.into_bytes();

        let mut array = [0u8; PRIVATE_KEY_LENGTH];
        array.copy_from_slice(&bytes[..PRIVATE_KEY_LENGTH]);
        let key = PrivateKey(Scalar::from_bytes_non_canonical(&array) + self.key.0);

        array.copy_from_slice(&bytes[PRIVATE_KEY_LENGTH..]);
        let chaincode = ChainCode(array);

        CtOption::new(
            ExtendedPrivateKey { key, chaincode },
            !(key.0.is_zero())
                // Make sure that i ≥ 2^31 (i.e. that we derive a hardened child)
                & Choice::from(((i[3] & 0b1000_0000) != 0) as u8),
        )
    }

    /// Derives a non-hardened private child from the current extended private key
    /// with the provided index `i`.
    /// The index, written in little-endian, must represent an integer strictly
    /// smaller than 2^31.
    fn derive_normal_private(&self, i: &[u8; 4]) -> CtOption<Self> {
        let public_key_bytes = PublicKey::from(&self.key).to_bytes();

        let mut mac = HmacSha512::new_from_slice(&self.chaincode.0)
            .expect("HMAC should take a 32-bytes long chaincode.");
        mac.update(&public_key_bytes);
        mac.update(i);

        let result = mac.finalize();
        let bytes = result.into_bytes();

        let mut array = [0u8; PRIVATE_KEY_LENGTH];
        array.copy_from_slice(&bytes[..PRIVATE_KEY_LENGTH]);
        let key = PrivateKey(Scalar::from_bytes_non_canonical(&array) + self.key.0);

        array.copy_from_slice(&bytes[PRIVATE_KEY_LENGTH..]);
        let chaincode = ChainCode(array);

        CtOption::new(
            ExtendedPrivateKey { key, chaincode },
            !(key.0.is_zero())
                // Make sure that i < 2^31 (i.e. that we derive a non-hardened child)
                & Choice::from(((i[3] & 0b1000_0000) == 0) as u8),
        )
    }

    /// Derives a public child from the current extended private key with the
    /// provided index `i`.
    /// The index, written in little-endian, can represent either a hardened or
    /// non-hardened child.
    pub fn derive_public(&self, i: &[u8; 4]) -> CtOption<ExtendedPublicKey> {
        let derived_private_key = self.derive_private(i);
        let extended_private_key = derived_private_key.unwrap_or(ExtendedPrivateKey {
            key: PrivateKey(Scalar::zero()),
            chaincode: ChainCode([0u8; CHAIN_CODE_LENGTH]),
        });

        CtOption::new(
            ExtendedPublicKey {
                key: PublicKey::from(&extended_private_key.key),
                chaincode: extended_private_key.chaincode,
            },
            derived_private_key.is_some(),
        )
    }

    /// Converts this extended private key to an array of bytes
    pub fn to_bytes(&self) -> [u8; EXTENDED_PRIVATE_KEY_LENGTH] {
        let mut bytes = [0u8; EXTENDED_PRIVATE_KEY_LENGTH];
        bytes[0..PRIVATE_KEY_LENGTH].copy_from_slice(&self.key.to_bytes());
        bytes[PRIVATE_KEY_LENGTH..].copy_from_slice(&self.chaincode.0);

        bytes
    }

    /// Constructs an extended private key from an array of bytes
    pub fn from_bytes(bytes: &[u8; EXTENDED_PRIVATE_KEY_LENGTH]) -> CtOption<Self> {
        let mut array = [0u8; PRIVATE_KEY_LENGTH];
        array.copy_from_slice(&bytes[0..PRIVATE_KEY_LENGTH]);
        PrivateKey::from_bytes(&array).and_then(|key| {
            array.copy_from_slice(&bytes[PRIVATE_KEY_LENGTH..]);

            CtOption::new(
                ExtendedPrivateKey {
                    key,
                    chaincode: ChainCode(array),
                },
                !key.0.is_zero(),
            )
        })
    }
}

/// A wraper combining a derivable public key and a chain code.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serialize", derive(Deserialize, Serialize))]
pub struct ExtendedPublicKey {
    /// A public key
    pub key: PublicKey,
    /// A chain code
    pub chaincode: ChainCode,
}

impl ConditionallySelectable for ExtendedPublicKey {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        ExtendedPublicKey {
            key: PublicKey::conditional_select(&a.key, &b.key, choice),
            chaincode: ChainCode::conditional_select(&a.chaincode, &b.chaincode, choice),
        }
    }
}

impl ExtendedPublicKey {
    /// Computes the extended public key from a provided extended private key
    pub fn from_extended_private_key(extended_private_key: &ExtendedPrivateKey) -> Self {
        ExtendedPublicKey {
            key: PublicKey::from(&extended_private_key.key),
            chaincode: extended_private_key.chaincode,
        }
    }

    /// Derives a non-hardened public child from the current extended public key
    /// with the provided index `i`.
    /// The index, written in little-endian, must represent an integer strictly
    /// smaller than 2^31.
    pub fn derive_normal_public(&self, i: &[u8; 4]) -> CtOption<Self> {
        let public_key_bytes = self.key.to_bytes();

        let mut mac = HmacSha512::new_from_slice(&self.chaincode.0)
            .expect("HMAC should take a 32-bytes long chaincode.");
        mac.update(&public_key_bytes);
        mac.update(i);

        let result = mac.finalize();
        let bytes = result.into_bytes();

        let mut array = [0u8; PRIVATE_KEY_LENGTH];
        array.copy_from_slice(&bytes[..PRIVATE_KEY_LENGTH]);
        let point = &BASEPOINT_TABLE * Scalar::from_bytes_non_canonical(&array);
        let key = PublicKey((point + self.key.0).into());

        array.copy_from_slice(&bytes[PRIVATE_KEY_LENGTH..]);
        let chaincode = ChainCode(array);

        CtOption::new(
            ExtendedPublicKey { key, chaincode },
            !(point.is_identity())
                // Make sure that i < 2^31 (i.e. that we derive a non-hardened child)
                & Choice::from(((i[3] & 0b1000_0000) == 0) as u8),
        )
    }

    /// Converts this extended public key to an array of bytes
    pub fn to_bytes(&self) -> [u8; EXTENDED_PUBLIC_KEY_LENGTH] {
        let mut bytes = [0u8; EXTENDED_PUBLIC_KEY_LENGTH];
        bytes[0..PUBLIC_KEY_LENGTH].copy_from_slice(&self.key.to_bytes());
        bytes[PUBLIC_KEY_LENGTH..].copy_from_slice(&self.chaincode.0);

        bytes
    }

    /// Constructs an extended public key from an array of bytes
    pub fn from_bytes(bytes: &[u8; EXTENDED_PUBLIC_KEY_LENGTH]) -> CtOption<Self> {
        let mut key_array = [0u8; PUBLIC_KEY_LENGTH];
        key_array.copy_from_slice(&bytes[0..PUBLIC_KEY_LENGTH]);
        PublicKey::from_bytes(&key_array).and_then(|key| {
            let mut array = [0u8; CHAIN_CODE_LENGTH];
            array.copy_from_slice(&bytes[PUBLIC_KEY_LENGTH..]);

            CtOption::new(
                ExtendedPublicKey {
                    key,
                    chaincode: ChainCode(array),
                },
                !key.0.is_identity(),
            )
        })
    }
}

impl PrivateKey {
    /// Derives a private child (either normal or hardened) from the provided private key,
    /// chaincode and index `i`. This should not panic.
    pub fn derive_private(&self, chaincode: ChainCode, i: &[u8; 4]) -> (Self, ChainCode) {
        let xsk = ExtendedPrivateKey {
            key: *self,
            chaincode,
        };

        let child = xsk.derive_private(i).unwrap();

        (child.key, child.chaincode)
    }
}

impl PublicKey {
    /// Derives a non-hardened public child from the provided public key,
    /// chaincode and index `i`.
    /// This will panic if the provided index `i` corresponds to a hardened child.
    pub fn derive_public(&self, chaincode: ChainCode, i: &[u8; 4]) -> (Self, ChainCode) {
        let xsk = ExtendedPublicKey {
            key: *self,
            chaincode,
        };

        let child = xsk.derive_normal_public(i).unwrap();

        (child.key, child.chaincode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cheetah::Scalar;
    use rand_core::OsRng;
    use rand_core::RngCore;

    #[test]
    fn test_extended_private_key_conditional_selection() {
        let a_skey = PrivateKey(Scalar::one());
        let a_chaincode = ChainCode([1u8; CHAIN_CODE_LENGTH]);
        let b_skey = PrivateKey(Scalar::from(42u8));
        let b_chaincode = ChainCode([42u8; CHAIN_CODE_LENGTH]);

        let a_ext_skey = ExtendedPrivateKey {
            key: a_skey,
            chaincode: a_chaincode,
        };

        let b_ext_skey = ExtendedPrivateKey {
            key: b_skey,
            chaincode: b_chaincode,
        };

        assert_eq!(
            ConditionallySelectable::conditional_select(
                &a_ext_skey,
                &b_ext_skey,
                Choice::from(0u8)
            ),
            a_ext_skey
        );
        assert_eq!(
            ConditionallySelectable::conditional_select(
                &a_ext_skey,
                &b_ext_skey,
                Choice::from(1u8)
            ),
            b_ext_skey
        );
    }

    #[test]
    fn test_extended_public_key_conditional_selection() {
        let a_skey = PrivateKey(Scalar::one());
        let a_chaincode = ChainCode([1u8; CHAIN_CODE_LENGTH]);
        let b_skey = PrivateKey(Scalar::from(42u8));
        let b_chaincode = ChainCode([42u8; CHAIN_CODE_LENGTH]);

        let a_ext_skey = ExtendedPrivateKey {
            key: a_skey,
            chaincode: a_chaincode,
        };

        let b_ext_skey = ExtendedPrivateKey {
            key: b_skey,
            chaincode: b_chaincode,
        };

        let a_ext_pkey = ExtendedPublicKey::from_extended_private_key(&a_ext_skey);
        let b_ext_pkey = ExtendedPublicKey::from_extended_private_key(&b_ext_skey);

        assert_eq!(
            ConditionallySelectable::conditional_select(
                &a_ext_pkey,
                &b_ext_pkey,
                Choice::from(0u8)
            ),
            a_ext_pkey
        );
        assert_eq!(
            ConditionallySelectable::conditional_select(
                &a_ext_pkey,
                &b_ext_pkey,
                Choice::from(1u8)
            ),
            b_ext_pkey
        );
    }

    #[test]
    fn test_derive() {
        let mut rng = OsRng;
        let mut seed = [0u8; PRIVATE_KEY_SEED_LENGTH];
        rng.fill_bytes(&mut seed);

        let skey = ExtendedPrivateKey::generate_master_key(&seed).unwrap();
        let pkey = ExtendedPublicKey::from_extended_private_key(&skey);

        let mut i = [0u8; 4];
        for _ in 0..100 {
            rng.fill_bytes(&mut i);
            // We ensure that children are non-hardened to be able to derive
            // public children from the extended public key.
            i[3] &= 0b0111_1111;
            let skey_child_private = skey.derive_private(&i).unwrap();
            let skey_child_public = skey.derive_public(&i).unwrap();
            let pkey_child_public = pkey.derive_normal_public(&i).unwrap();

            assert_eq!(
                ExtendedPublicKey::from_extended_private_key(&skey_child_private),
                skey_child_public
            );
            assert_eq!(pkey_child_public, skey_child_public);
        }

        // Derivation of a hardened child should fail for invalid chaincodes
        {
            let i = [0xff, 0xff, 0xff, 0x7f]; // 2^31 - 1
            let skey_child_private = skey.derive_hardened_private(&i);
            assert!(bool::from(skey_child_private.is_none()));
        }

        // Derivation of a non-hardened child should fail for invalid chaincodes
        {
            let i = [0x00, 0x00, 0x00, 0x80]; // 2^31
            let skey_child_private = skey.derive_normal_private(&i);
            assert!(bool::from(skey_child_private.is_none()));
        }

        // Derivation of a hardened child from a public key should fail
        {
            let i = [0x00, 0x00, 0x00, 0x80]; // 2^31
            let pkey_child_public = pkey.derive_normal_public(&i);
            assert!(bool::from(pkey_child_public.is_none()));
        }
    }

    #[test]
    fn test_extended_private_key_encoding() {
        assert_eq!(
            ExtendedPrivateKey {
                key: PrivateKey::from_scalar(Scalar::one()),
                chaincode: ChainCode([1u8; CHAIN_CODE_LENGTH])
            }
            .to_bytes(),
            [
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1,
            ]
        );

        // Test random keys encodings
        let mut rng = OsRng;

        let mut chaincode = [0u8; CHAIN_CODE_LENGTH];
        for _ in 0..100 {
            rng.fill_bytes(&mut chaincode);
            let key = ExtendedPrivateKey {
                key: PrivateKey::new(&mut rng),
                chaincode: ChainCode(chaincode),
            };
            let bytes = key.to_bytes();
            assert_eq!(bytes.len(), EXTENDED_PRIVATE_KEY_LENGTH);

            assert_eq!(key, ExtendedPrivateKey::from_bytes(&bytes).unwrap());
        }

        // Test invalid encodings
        let bytes = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0,
        ];
        let recovered_key = ExtendedPrivateKey::from_bytes(&bytes);
        assert!(bool::from(recovered_key.is_none()));

        let bytes = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let recovered_key = ExtendedPrivateKey::from_bytes(&bytes);
        assert!(bool::from(recovered_key.is_none()));
    }

    #[test]
    fn test_extended_public_key_encoding() {
        assert_eq!(
            ExtendedPublicKey {
                key: PublicKey::from(&PrivateKey::from_scalar(Scalar::zero())),
                chaincode: ChainCode([1u8; CHAIN_CODE_LENGTH])
            }
            .to_bytes(),
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            ]
        );

        // Test random keys encodings
        let mut rng = OsRng;

        let mut chaincode = [0u8; CHAIN_CODE_LENGTH];
        for _ in 0..100 {
            rng.fill_bytes(&mut chaincode);
            let key = ExtendedPublicKey {
                key: PublicKey::from(&PrivateKey::new(&mut rng)),
                chaincode: ChainCode(chaincode),
            };
            let bytes = key.to_bytes();
            assert_eq!(bytes.len(), EXTENDED_PUBLIC_KEY_LENGTH);

            assert_eq!(key, ExtendedPublicKey::from_bytes(&bytes).unwrap());
        }

        // Test invalid encodings
        let bytes = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let recovered_key = ExtendedPublicKey::from_bytes(&bytes);
        assert!(bool::from(recovered_key.is_none()));

        let bytes = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let recovered_key = ExtendedPublicKey::from_bytes(&bytes);
        assert!(bool::from(recovered_key.is_none()));
    }

    #[test]
    #[cfg(feature = "serialize")]
    fn test_extended_private_key_serde() {
        let mut rng = OsRng;
        let skey = PrivateKey::new(&mut rng);
        let chaincode = ChainCode([1u8; CHAIN_CODE_LENGTH]);

        let ext_skey = ExtendedPrivateKey {
            key: skey,
            chaincode,
        };

        let mut encoded = bincode::serialize(&ext_skey).unwrap();
        let parsed: ExtendedPrivateKey = bincode::deserialize(&encoded).unwrap();
        assert_eq!(parsed, ext_skey);

        // Check that the encoding is EXTENDED_PRIVATE_KEY_LENGTH (64) bytes exactly
        assert_eq!(encoded.len(), EXTENDED_PRIVATE_KEY_LENGTH);

        // Check that the encoding itself matches the usual one
        assert_eq!(
            ext_skey,
            bincode::deserialize(&ext_skey.to_bytes()).unwrap()
        );

        // Check that invalid encodings fail
        encoded[31] = 255;
        assert!(bincode::deserialize::<ExtendedPrivateKey>(&encoded).is_err());

        let encoded = bincode::serialize(&ext_skey).unwrap();
        assert!(bincode::deserialize::<ExtendedPrivateKey>(&encoded[0..63]).is_err());
    }

    #[test]
    #[cfg(feature = "serialize")]
    fn test_extended_public_key_serde() {
        let mut rng = OsRng;
        let skey = PrivateKey::new(&mut rng);
        let chaincode = ChainCode([1u8; CHAIN_CODE_LENGTH]);

        let ext_skey = ExtendedPrivateKey {
            key: skey,
            chaincode,
        };

        let ext_pkey = ExtendedPublicKey::from_extended_private_key(&ext_skey);

        let mut encoded = bincode::serialize(&ext_pkey).unwrap();
        let parsed: ExtendedPublicKey = bincode::deserialize(&encoded).unwrap();
        assert_eq!(parsed, ext_pkey);

        // Check that the encoding is EXTENDED_PUBLIC_KEY_LENGTH (81) bytes exactly
        assert_eq!(encoded.len(), EXTENDED_PUBLIC_KEY_LENGTH);

        // Check that the encoding itself matches the usual one
        assert_eq!(
            ext_skey,
            bincode::deserialize(&ext_skey.to_bytes()).unwrap()
        );

        // Check that invalid encodings fail
        encoded[48] = 255;
        assert!(bincode::deserialize::<ExtendedPublicKey>(&encoded).is_err());

        let encoded = bincode::serialize(&ext_pkey).unwrap();
        assert!(bincode::deserialize::<ExtendedPublicKey>(&encoded[0..80]).is_err());
    }
}
