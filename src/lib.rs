pub mod api_proxy;
pub mod handlers;
pub mod models;
pub mod oauth;
pub mod session;
pub mod session_builder;
pub mod settings;
pub mod utils;

// Re-export commonly used items
pub use api_proxy::proxy_generic_api;
pub use handlers::{
    health, jwt_oauth_callback, jwt_oauth_debug, jwt_oauth_sign_in, jwt_oauth_sign_out,
    jwt_oauth_userinfo,
};
pub use models::VouchrsSession;
pub use oauth::OAuthConfig;
pub use session::SessionManager;
pub use settings::VouchrsSettings;
