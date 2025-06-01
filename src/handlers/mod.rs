// HTTP request handlers for OAuth proxy
pub mod auth;
pub mod callback;
pub mod debug;
pub mod static_files;
pub mod proxy_upstream;

#[cfg(test)]
mod tests;

// Re-export the main handler functions
pub use auth::{oauth_sign_in, oauth_sign_out};
pub use callback::oauth_callback;
pub use debug::{oauth_debug, oauth_userinfo};
pub use static_files::{health, serve_static};
pub use proxy_upstream::proxy_upstream;
