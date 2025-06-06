//! `WebAuthn` implementation
//!
//! This module provides core `WebAuthn` functionality independent of any specific
//! application logic or session management. It implements the W3C `WebAuthn` specification
//! using standard cryptography libraries.

mod attestation;
mod cbor;
mod crypto;
mod errors;
mod service;
mod settings;
mod types;

// Re-exports for public use
pub use errors::WebAuthnError;
pub use service::{generate_user_handle, WebAuthnService};
pub use settings::WebAuthnSettings;
pub use types::*;
