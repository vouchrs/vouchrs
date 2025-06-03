#![warn(clippy::pedantic)]
#![warn(clippy::cargo)]
#![deny(warnings)]
#![allow(clippy::multiple_crate_versions)]

/// Version of the vouchrs application
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod handlers;
pub mod models;
pub mod oauth;
pub mod session;
pub mod session_builder;
pub mod session_validation;
pub mod settings;
pub mod utils;

/// Re-export commonly used items
pub use handlers::{
    health, oauth_callback, oauth_debug, oauth_sign_in, oauth_sign_out,
    oauth_userinfo,
};
pub use models::VouchrsSession;
pub use oauth::OAuthConfig;
pub use session::SessionManager;
pub use settings::VouchrsSettings;
