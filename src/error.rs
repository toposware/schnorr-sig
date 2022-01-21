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
    /// Invalid signature
    InvalidSignature,
}

impl Display for SignatureError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self {
            Self::InvalidSignature => {
                write!(f, "The signature is invalid or was incorrectly computed.",)
            }
        }
    }
}
