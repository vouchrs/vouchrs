// HTTP request handlers for OAuth proxy
pub mod auth;
pub mod callback;
pub mod debug;
pub mod static_files;
pub mod proxy_upstream;

#[cfg(test)]
mod tests;

// Re-export the main handler functions
pub use auth::{jwt_oauth_sign_in, jwt_oauth_sign_out};
pub use callback::jwt_oauth_callback;
pub use debug::{jwt_oauth_debug, jwt_oauth_userinfo};
pub use static_files::{health, serve_static};
pub use proxy_upstream::proxy_upstream;
