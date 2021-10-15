// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

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
