// Common types used across JWT handlers
use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub struct OAuthCallback {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub user: Option<serde_json::Value>, // Apple sends user info in form POST on first login
}

#[derive(Deserialize)]
pub struct SignInQuery {
    pub provider: Option<String>,
    pub redirect_url: Option<String>,
}
