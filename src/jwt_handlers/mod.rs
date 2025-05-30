// JWT-based handlers for stateless OAuth proxy
pub mod auth;
pub mod callback;
pub mod debug;
pub mod helpers;
pub mod types;
pub mod session_builder;

#[cfg(test)]
mod tests;

// Re-export the main handler functions
pub use auth::{jwt_oauth_sign_in, jwt_oauth_sign_out};
pub use callback::jwt_oauth_callback;
pub use debug::{jwt_oauth_debug, jwt_oauth_userinfo};
pub use types::{OAuthCallback, SignInQuery};
