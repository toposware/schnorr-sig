//! This module provides a Signature struct implementing
//! Schnorr signing and verification.

use super::error::SignatureError;
use super::{PrivateKey, PublicKey};

use bitvec::{order::Lsb0, view::AsBits};
use hash::{
    rescue::{digest::RescueDigest, hasher::RescueHash},
    traits::Hasher,
};
use rand_core::{CryptoRng, RngCore};
use stark_curve::{AffinePoint, FieldElement, Scalar};

/// A Schnorr signature not attached to its message.
// TODO: should we include the signed message as part
// of the Struct, or have it in a wrapping struct?
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Signature {
    /// The affine coordinate of the random point generated during signing
    pub x: FieldElement,
    /// The exponent from the random scalar, the private key
    /// and the output of the hash seen as a `Scalar` element
    pub e: Scalar,
}

impl Signature {
    /// Computes a Schnorr signature
    pub fn sign(
        message: &[FieldElement],
        skey: PrivateKey,
        mut rng: impl CryptoRng + RngCore,
    ) -> Self {
        let r = Scalar::random(&mut rng);
        let r_point = AffinePoint::from(AffinePoint::generator() * r);

        let h = hash_message([r_point.get_x(), FieldElement::zero()], message);
        let h_bytes = h[0].to_bytes();
        let h_bits = h_bytes.as_bits::<Lsb0>();

        // Reconstruct a scalar from the binary sequence of h
        let h_scalar = Scalar::from_bits_vartime(h_bits);

        let e = r - skey.0 * h_scalar;
        Signature {
            x: r_point.get_x(),
            e,
        }
    }

    /// Verifies a Schnorr signature
    pub fn verify(self, message: &[FieldElement], pkey: PublicKey) -> Result<(), SignatureError> {
        let e_point = AffinePoint::generator() * self.e;
        let pkey: AffinePoint = pkey.0.into();

        let h = hash_message([self.x, FieldElement::zero()], message);
        let h_bytes = h[0].to_bytes();
        let h_bits = h_bytes.as_bits::<Lsb0>();

        // Reconstruct a scalar from the binary sequence of h
        let h_scalar = Scalar::from_bits_vartime(h_bits);

        let h_pubkey_point = pkey * h_scalar;

        let r_point = AffinePoint::from(e_point + h_pubkey_point);

        if r_point.get_x() == self.x {
            Ok(())
        } else {
            Err(SignatureError::InvalidSignature)
        }
    }
}

fn hash_message(input: [FieldElement; 2], message: &[FieldElement]) -> [FieldElement; 2] {
    let mut h = RescueHash::digest(&input);
    let mut chunk = [FieldElement::zero(), FieldElement::zero()];

    for message_chunk in message.chunks(2) {
        chunk.copy_from_slice(message_chunk);
        let digest = RescueDigest::new(chunk);
        h = RescueHash::merge(&[h, digest]);
    }

    h.as_elements()
}

#[cfg(test)]
mod test {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_signature() {
        let mut message = [FieldElement::zero(); 6];
        for message_chunk in message.iter_mut().skip(2) {
            *message_chunk = FieldElement::random(OsRng);
        }

        let skey = PrivateKey::new(OsRng);
        let pkey = PublicKey::from_private_key(skey);

        let signature = Signature::sign(&message, skey, OsRng);
        assert!(signature.verify(&message, pkey).is_ok());
    }

    #[test]
    fn test_invalid_signature() {
        let mut message = [FieldElement::zero(); 6];
        for message_chunk in message.iter_mut().skip(2) {
            *message_chunk = FieldElement::random(OsRng);
        }

        let skey = PrivateKey::new(OsRng);
        let pkey = PublicKey::from_private_key(skey);

        let signature = Signature::sign(&message, skey, OsRng);

        {
            let mut wrong_message = message;
            wrong_message[4] = FieldElement::zero();
            assert!(signature.verify(&wrong_message, pkey).is_err());
        }

        {
            let wrong_signature_1 = Signature {
                x: FieldElement::zero(),
                e: signature.e,
            };
            assert!(wrong_signature_1.verify(&message, pkey).is_err());
        }

        {
            let wrong_signature_2 = Signature {
                x: signature.x,
                e: Scalar::zero(),
            };
            assert!(wrong_signature_2.verify(&message, pkey).is_err());
        }
    }
}
