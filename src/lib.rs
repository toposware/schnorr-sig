//! This crate provides an implementation of a custom Schnorr
//! signature with internal Rescue hash on a 252-bit field.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(broken_intra_doc_links)]
#![deny(missing_debug_implementations)]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

use bitvec::{order::Lsb0, view::AsBits};
use hash::{
    rescue::{digest::RescueDigest, hasher::RescueHash},
    traits::Hasher,
};
use rand_core::{CryptoRng, RngCore};
use stark_curve::{AffinePoint, FieldElement, Scalar};

/// Computes a Schnorr signature
pub fn sign(
    message: [FieldElement; 6],
    skey: Scalar,
    mut rng: impl CryptoRng + RngCore,
) -> (FieldElement, Scalar) {
    let r = Scalar::random(&mut rng);
    let r_point = AffinePoint::from(AffinePoint::generator() * r);

    let h = hash_message([r_point.get_x(), FieldElement::zero()], message);
    let h_bytes = h[0].to_bytes();
    let h_bits = h_bytes.as_bits::<Lsb0>();

    // Reconstruct a scalar from the binary sequence of h
    let h_scalar = Scalar::from_bits_vartime(h_bits);

    let s = r - skey * h_scalar;
    (r_point.get_x(), s)
}

/// Verifies a Schnorr signature
pub fn verify_signature(message: [FieldElement; 6], signature: (FieldElement, Scalar)) -> bool {
    let s_point = AffinePoint::generator() * signature.1;
    // Should we keep this implied, or provide the pkey and ensure it is hashed with the message?
    let pkey = AffinePoint::from_raw_coordinates([message[0], message[1]]);
    assert!(bool::from(pkey.is_on_curve()));

    let h = hash_message([signature.0, FieldElement::zero()], message);
    let h_bytes = h[0].to_bytes();
    let h_bits = h_bytes.as_bits::<Lsb0>();

    // Reconstruct a scalar from the binary sequence of h
    let h_scalar = Scalar::from_bits_vartime(h_bits);

    let h_pubkey_point = pkey * h_scalar;

    let r_point = AffinePoint::from(s_point + h_pubkey_point);

    r_point.get_x() == signature.0
}

fn hash_message(input: [FieldElement; 2], message: [FieldElement; 6]) -> [FieldElement; 2] {
    let mut h = RescueHash::digest(&input);
    let mut message_chunk = RescueDigest::new([message[0], message[1]]);

    h = RescueHash::merge(&[h, message_chunk]);
    message_chunk = RescueDigest::new([message[2], message[3]]);
    h = RescueHash::merge(&[h, message_chunk]);
    message_chunk = RescueDigest::new([message[4], message[5]]);
    h = RescueHash::merge(&[h, message_chunk]);

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

        let skey = Scalar::random(OsRng);
        let pkey = AffinePoint::from(AffinePoint::generator() * skey);
        message[0] = pkey.get_x();
        message[1] = pkey.get_y();

        let signature = sign(message, skey, OsRng);
        assert!(verify_signature(message, signature));
    }

    #[test]
    fn test_invalid_signature() {
        let mut message = [FieldElement::zero(); 6];
        for message_chunk in message.iter_mut().skip(2) {
            *message_chunk = FieldElement::random(OsRng);
        }

        let skey = Scalar::random(OsRng);
        let pkey = AffinePoint::from(AffinePoint::generator() * skey);
        message[0] = pkey.get_x();
        message[1] = pkey.get_y();

        let signature = sign(message, skey, OsRng);

        {
            let mut wrong_message = message;
            wrong_message[4] = FieldElement::zero();
            assert!(!verify_signature(wrong_message, signature));
        }

        {
            let wrong_signature_1 = (FieldElement::zero(), signature.1);
            assert!(!verify_signature(message, wrong_signature_1));
        }

        {
            let wrong_signature_2 = (signature.0, Scalar::zero());
            assert!(!verify_signature(message, wrong_signature_2));
        }
    }
}
