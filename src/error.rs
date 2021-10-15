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
