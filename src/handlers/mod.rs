// HTTP request handlers
pub mod debug;
pub mod oauth;
pub mod passkey;
pub mod proxy_upstream;
pub mod static_files;

// Re-export the main handler functions
pub use debug::{oauth_debug, oauth_userinfo};
pub use oauth::{oauth_callback, oauth_sign_in, oauth_sign_out};
pub use passkey::{complete_authentication, complete_registration, start_authentication, start_registration, RegistrationRequest};
pub use proxy_upstream::proxy_upstream;
pub use static_files::{health, initialize_static_files, serve_static};
