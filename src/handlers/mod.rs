// HTTP request handlers for OAuth proxy
pub mod auth;
pub mod callback;
pub mod debug;
pub mod proxy_upstream;
pub mod static_files;

#[cfg(test)]
mod tests;

// Re-export the main handler functions
pub use auth::{oauth_sign_in, oauth_sign_out};
pub use callback::oauth_callback;
pub use debug::{oauth_debug, oauth_userinfo};
pub use proxy_upstream::proxy_upstream;
pub use static_files::{health, initialize_static_files, serve_static};
