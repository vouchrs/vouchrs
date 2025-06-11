//! Passkey functionality for application integration
//!
//! This module provides passkey functionality by integrating the `WebAuthn`
//! implementation with application session management.

// Core settings
mod settings;
pub use settings::PasskeySettings;

// Service layer
mod service;
pub use service::*;

// User store for stateless operations
mod user_store;
pub use user_store::PasskeyUserData;
