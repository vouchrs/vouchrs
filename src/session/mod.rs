//! Session Management Module
//!
//! This module provides comprehensive session management functionality for Vouchrs,
//! including session creation, validation, encryption, and security features.
//!
//! # Modules
//!
//! - [`manager`] - Core session manager for encrypted session handling
//! - [`validation`] - Session validation and security checking
//! - [`cookie`] - Cookie management utilities
//! - [`utils`] - Session utility functions
//! - [`passkey`] - Passkey-specific session handling
//! - [`auth_results`] - Authentication result structures for module separation
//! - [`token_processor`] - OAuth token processing (moved from oauth module)

pub mod auth_results;
pub mod cookie;
pub mod manager;
pub mod passkey;
pub mod utils;
pub mod validation;

// Re-export commonly used items for convenience
pub use cookie::{CookieFactory, CookieOptions, COOKIE_NAME, OAUTH_STATE_COOKIE, USER_COOKIE_NAME};
pub use manager::{SessionError, SessionManager};
pub use passkey::{PasskeySessionBuilder, PasskeySessionData};
pub use utils::{create_error_response, extract_client_info, get_state_from_callback};
pub use validation::{calculate_client_context_hash, validate_client_context};

// Re-export auth result types
pub use auth_results::{OauthResult, PasskeyResult};
