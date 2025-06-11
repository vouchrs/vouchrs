#![warn(clippy::pedantic)]
#![warn(clippy::cargo)]
#![deny(warnings)]
#![allow(clippy::multiple_crate_versions)]

//! Vouchrs - A modern `OAuth2` authentication service
//!
//! This crate provides a complete `OAuth2` authentication solution with support for
//! multiple providers and session management.

/// Version of the vouchrs application
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod handlers;
pub mod models;
pub mod oauth;
pub mod passkey;
pub mod session;
pub mod settings;
pub mod utils;

/// Re-export commonly used items
pub use handlers::{
    health, oauth_callback, oauth_debug, oauth_sign_in, oauth_sign_out, oauth_userinfo,
};
pub use models::VouchrsSession;
pub use oauth::OAuthConfig;
pub use oauth::{
    check_and_refresh_tokens, fetch_discovery_document, fetch_jwks, JwtValidationError,
    JwtValidator, OAuthAuthenticationService, OAuthAuthenticationServiceImpl, OAuthCallback,
    OAuthState, OidcDiscoveryDocument,
};
pub use session::SessionManager;
pub use session::{get_state_from_callback, PasskeySessionBuilder, PasskeySessionData};
pub use settings::VouchrsSettings;
