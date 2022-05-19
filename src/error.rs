// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use core::fmt::{Display, Formatter, Result};

/// Custom error type during signature operations
#[derive(Debug, PartialEq)]
pub enum SignatureError {
    /// Invalid public key
    InvalidPublicKey,
    /// Invalid signature
    InvalidSignature,
}

impl Display for SignatureError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self {
            Self::InvalidPublicKey => {
                write!(f, "The public key is not an element of the prime subgroup.",)
            }
            Self::InvalidSignature => {
                write!(f, "The signature is invalid or was incorrectly computed.",)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{PrivateKey, PublicKey};
    use cheetah::{AffinePoint, Fp, Fp6};
    use rand_core::OsRng;

    #[test]
    fn test_debug() {
        let mut rng = OsRng;

        let skey = PrivateKey::new(&mut rng);
        let pkey = PublicKey::from(&skey);
        let signature = skey.sign(&[Fp::zero()], &mut rng);

        let wrong_pkey = PublicKey(AffinePoint::from_raw_coordinates([
            Fp6::from_raw_unchecked([
                0x9bfcd3244afcb637,
                0x39005e478830b187,
                0x7046f1c03b42c6cc,
                0xb5eeac99193711e5,
                0x7fd272e724307b98,
                0xcc371dd6dd5d8625,
            ]),
            Fp6::from_raw_unchecked([
                0x9d03fdc216dfaae8,
                0xbf4ade2a7665d9b8,
                0xf08b022d5b3262b7,
                0x2eaf583a3cf15c6f,
                0xa92531e4b1338285,
                0x5b8157814141a7a7,
            ]),
        ]));

        assert_eq!(
            format!("{:?}", signature.verify(&[Fp::zero()], &wrong_pkey)),
            "Err(InvalidPublicKey)"
        );
        assert_eq!(
            format!("{:?}", signature.verify(&[Fp::one()], &pkey)),
            "Err(InvalidSignature)"
        );

        assert_eq!(
            format!(
                "{}",
                signature.verify(&[Fp::zero()], &wrong_pkey).unwrap_err()
            ),
            "The public key is not an element of the prime subgroup."
        );
        assert_eq!(
            format!("{}", signature.verify(&[Fp::one()], &pkey).unwrap_err()),
            "The signature is invalid or was incorrectly computed."
        );
    }
}
