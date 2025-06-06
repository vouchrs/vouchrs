//! Passkey functionality for application integration
//!
//! This module provides passkey functionality by integrating the `WebAuthn`
//! implementation with application session management.

// Core settings
mod settings;
pub use settings::PasskeySettings;

// Handlers
mod handlers;
pub use handlers::*;

// Session management
mod session;
pub use session::*;

// Re-export types from WebAuthn module
pub use crate::webauthn::{
    generate_user_handle, AuthenticationResult, Credential, WebAuthnError, WebAuthnService,
};
