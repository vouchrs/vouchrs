// Common types used across handlers
use serde::Deserialize;

#[derive(Deserialize)]
pub struct SignInQuery {
    pub provider: Option<String>,
    pub redirect_url: Option<String>,
}
