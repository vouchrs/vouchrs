//! `WebAuthn` error types for `VouchRS`
//!
//! This module defines custom error types for `WebAuthn` operations.

use std::fmt;

/// `WebAuthn` errors that can occur during operations
#[derive(Debug)]
pub enum WebAuthnError {
    /// Configuration error (e.g., invalid settings)
    ConfigurationError(String),

    /// Verification failed (e.g., challenge, signature, or origin)
    VerificationFailed(String),

    /// Data encoding/parsing error
    EncodingError(String),

    /// Operation not supported
    NotSupported(String),

    /// Other internal error
    InternalError(String),
}

impl fmt::Display for WebAuthnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WebAuthnError::ConfigurationError(msg) => write!(f, "Configuration error: {msg}"),
            WebAuthnError::VerificationFailed(msg) => write!(f, "Verification failed: {msg}"),
            WebAuthnError::EncodingError(msg) => write!(f, "Encoding error: {msg}"),
            WebAuthnError::NotSupported(msg) => write!(f, "Not supported: {msg}"),
            WebAuthnError::InternalError(msg) => write!(f, "Internal error: {msg}"),
        }
    }
}

impl std::error::Error for WebAuthnError {}
