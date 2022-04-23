// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! This module provides a Signature struct implementing
//! Schnorr signing and verification.

use super::error::SignatureError;
use super::{KeyPair, PrivateKey, PublicKey};

use bitvec::{order::Lsb0, view::AsBits};
use cheetah::BASEPOINT_TABLE;
use cheetah::{AffinePoint, Fp, Fp6, Scalar};
use hash::{
    rescue_64_8_4::RescueHash,
    traits::{Digest, Hasher},
};
use rand_core::{CryptoRng, RngCore};
use subtle::{Choice, CtOption};

#[cfg(feature = "serialize")]
use serde::{Deserialize, Serialize};

/// A Schnorr signature not attached to its message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serialize", derive(Deserialize, Serialize))]
pub struct Signature {
    /// The affine coordinate of the random point generated during signing
    pub x: Fp6,
    /// The exponent from the random scalar, the private key
    /// and the output of the hash seen as a `Scalar` element
    pub e: Scalar,
}

impl Signature {
    /// Computes a Schnorr signature. This requires to compute the `PublicKey` from
    /// the provided `PrivateKey` internally. For a faster signing, one should prefer
    /// to use `Signature::sign_with_provided_pkey` or `Signature::sign_with_keypair`.
    pub fn sign(message: &[Fp], skey: &PrivateKey, mut rng: impl CryptoRng + RngCore) -> Self {
        let r = Scalar::random(&mut rng);
        let r_point = AffinePoint::from(&BASEPOINT_TABLE * r);

        let h = hash_message(
            &r_point.get_x(),
            &PublicKey::from_private_key(skey),
            message,
        );
        let h_bits = h.as_bits::<Lsb0>();

        // Reconstruct a scalar from the binary sequence of h
        let h_scalar = Scalar::from_bits(h_bits);

        let e = r - skey.0 * h_scalar;
        Signature {
            x: r_point.get_x(),
            e,
        }
    }

    /// Computes a Schnorr signature with a provided `PublicKey` for faster signing.
    /// This method does not check that the provided `skey` and `pkey` are matching.
    /// In particular, the resulting signature will be invalid if they don't match.
    pub fn sign_with_provided_pkey(
        message: &[Fp],
        skey: &PrivateKey,
        pkey: &PublicKey,
        mut rng: impl CryptoRng + RngCore,
    ) -> Self {
        let r = Scalar::random(&mut rng);
        let r_point = AffinePoint::from(&BASEPOINT_TABLE * r);

        let h = hash_message(&r_point.get_x(), pkey, message);
        let h_bits = h.as_bits::<Lsb0>();

        // Reconstruct a scalar from the binary sequence of h
        let h_scalar = Scalar::from_bits(h_bits);

        let e = r - skey.0 * h_scalar;
        Signature {
            x: r_point.get_x(),
            e,
        }
    }

    /// Computes a Schnorr signature with a provided `PublicKey` for faster signing.
    /// This method does not check that the provided `skey` and `pkey` are matching.
    /// In particular, the resulting signature will be invalid if they don't match.
    pub fn sign_with_keypair(
        message: &[Fp],
        keypair: &KeyPair,
        mut rng: impl CryptoRng + RngCore,
    ) -> Self {
        let r = Scalar::random(&mut rng);
        let r_point = AffinePoint::from(&BASEPOINT_TABLE * r);

        let h = hash_message(&r_point.get_x(), &keypair.public_key, message);
        let h_bits = h.as_bits::<Lsb0>();

        // Reconstruct a scalar from the binary sequence of h
        let h_scalar = Scalar::from_bits(h_bits);

        let e = r - keypair.private_key.0 * h_scalar;
        Signature {
            x: r_point.get_x(),
            e,
        }
    }

    /// Verifies a Schnorr signature
    pub fn verify(self, message: &[Fp], pkey: &PublicKey) -> Result<(), SignatureError> {
        let h = hash_message(&self.x, pkey, message);
        let h_bits = h.as_bits::<Lsb0>();

        // Reconstruct a scalar from the binary sequence of h
        let h_scalar = Scalar::from_bits_vartime(h_bits);

        // Leverage faster scalar multiplication through
        // Straus-Shamir's trick with hardcoded base point table.
        let r = AffinePoint::from(
            pkey.0
                .multiply_double_with_basepoint_vartime(&h_scalar.to_bytes(), &self.e.to_bytes()),
        );

        if r.get_x() == self.x {
            Ok(())
        } else {
            Err(SignatureError::InvalidSignature)
        }
    }

    /// Converts this signature to an array of bytes
    pub fn to_bytes(&self) -> [u8; 80] {
        let mut output = [0u8; 80];
        output[0..48].copy_from_slice(&self.x.to_bytes());
        output[48..80].copy_from_slice(&self.e.to_bytes());

        output
    }

    /// Constructs a signature from an array of bytes
    pub fn from_bytes(bytes: &[u8; 80]) -> CtOption<Self> {
        let mut array = [0u8; 48];
        array.copy_from_slice(&bytes[0..48]);
        let x = Fp6::from_bytes(&array);

        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes[48..80]);
        let e = Scalar::from_bytes(&array);

        x.and_then(|x| e.and_then(|e| CtOption::new(Signature { x, e }, Choice::from(1u8))))
    }
}

pub(crate) fn hash_message(point_coordinate: &Fp6, pkey: &PublicKey, message: &[Fp]) -> [u8; 32] {
    let mut data = <[Fp; 6] as From<&Fp6>>::from(point_coordinate).to_vec();
    data.extend_from_slice(&<[Fp; 6] as From<Fp6>>::from(pkey.0.get_x()));
    // Instead of serializing the public key and storing information of the y-coordinate into the
    // empty bits of the x-coordinate, we hash the lowest coefficient of y along with the x array.
    data.push(<[Fp; 6] as From<Fp6>>::from(pkey.0.get_y())[0]);
    data.extend_from_slice(message);

    let h = RescueHash::hash_field(&data);

    h.as_bytes()
}

#[cfg(test)]
mod test {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_signature() {
        let mut rng = OsRng;

        let mut message = [Fp::zero(); 42];
        for message_chunk in message.iter_mut() {
            *message_chunk = Fp::random(&mut rng);
        }

        let keypair = KeyPair::new(&mut rng);
        let skey = keypair.private_key;
        let pkey = keypair.public_key;

        let signature = Signature::sign(&message, &skey, &mut rng);
        assert!(signature.verify(&message, &pkey).is_ok());

        let signature = Signature::sign_with_provided_pkey(&message, &skey, &pkey, &mut rng);
        assert!(pkey.verify_signature(&signature, &message).is_ok());

        let signature = Signature::sign_with_keypair(&message, &keypair, &mut rng);
        assert!(keypair.verify_signature(&signature, &message).is_ok());
    }

    #[test]
    fn test_invalid_signature() {
        let mut rng = OsRng;

        let mut message = [Fp::zero(); 42];
        for message_chunk in message.iter_mut() {
            *message_chunk = Fp::random(&mut rng);
        }

        let skey = PrivateKey::new(&mut rng);
        let pkey = PublicKey::from_private_key(&skey);

        let signature = Signature::sign(&message, &skey, &mut rng);

        {
            let mut wrong_message = message;
            wrong_message[4] = Fp::zero();
            assert!(signature.verify(&wrong_message, &pkey).is_err());
        }

        {
            let wrong_signature_1 = Signature {
                x: Fp6::zero(),
                e: signature.e,
            };
            assert!(wrong_signature_1.verify(&message, &pkey).is_err());
        }

        {
            let wrong_signature_2 = Signature {
                x: signature.x,
                e: Scalar::zero(),
            };
            assert!(wrong_signature_2.verify(&message, &pkey).is_err());
        }
    }

    #[test]
    fn test_encoding() {
        assert_eq!(
            Signature {
                x: Fp6::one(),
                e: Scalar::zero(),
            }
            .to_bytes(),
            [
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );

        assert_eq!(
            Signature {
                x: Fp6::zero(),
                e: Scalar::one(),
            }
            .to_bytes(),
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );

        // Test random keys encoding
        let mut rng = OsRng;

        for _ in 0..100 {
            let sig = Signature {
                x: Fp6::random(&mut rng),
                e: Scalar::random(&mut rng),
            };
            let bytes = sig.to_bytes();

            assert_eq!(sig, Signature::from_bytes(&bytes).unwrap());
        }

        // Test invalid encoding
        let bytes = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ];
        let recovered_sig = Signature::from_bytes(&bytes);
        assert!(bool::from(recovered_sig.is_none()))
    }

    #[test]
    #[cfg(feature = "serialize")]
    fn test_serde() {
        let mut rng = OsRng;

        let mut message = [Fp::zero(); 42];
        for message_chunk in message.iter_mut() {
            *message_chunk = Fp::random(&mut rng);
        }

        let skey = PrivateKey::new(&mut rng);

        let signature = Signature::sign(&message, &skey, &mut rng);
        let encoded = bincode::serialize(&signature).unwrap();
        let parsed: Signature = bincode::deserialize(&encoded).unwrap();
        assert_eq!(parsed, signature);

        // Check that the encoding is 80 bytes exactly
        assert_eq!(encoded.len(), 80);

        // Check that the encoding itself matches the usual one
        assert_eq!(
            signature,
            bincode::deserialize(&signature.to_bytes()).unwrap()
        );

        // Check that invalid encodings fail
        let signature = Signature::sign(&message, &skey, OsRng);
        let mut encoded = bincode::serialize(&signature).unwrap();
        encoded[79] = 127;
        assert!(bincode::deserialize::<Signature>(&encoded).is_err());

        let encoded = bincode::serialize(&signature).unwrap();
        assert!(bincode::deserialize::<Signature>(&encoded[0..79]).is_err());
    }
}
