//! `WebAuthn` passkey implementation for `VouchRS`
//!
//! This module provides a custom implementation of the `WebAuthn` standard
//! specifically designed for `VouchRS`'s stateless architecture.

mod cbor;
mod errors;
mod handlers;
mod settings;
mod types;
mod webauthn;

pub use errors::WebAuthnError;
pub use handlers::*;
pub use settings::PasskeySettings;
pub use types::*;
pub use webauthn::generate_user_handle;
pub use webauthn::WebAuthnService;
