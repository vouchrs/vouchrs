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
//! - [`oauth`] - OAuth-specific session utilities and logic
//! - [`passkey`] - Passkey-specific session handling
//! - [`auth_results`] - Authentication result structures for module separation
//! - [`token_processor`] - OAuth token processing (moved from oauth module)

pub mod cookie;
pub mod manager;
pub mod oauth;
pub mod passkey;
pub mod utils;
pub mod validation;

// Re-export commonly used items for convenience
pub use cookie::{CookieFactory, CookieOptions, COOKIE_NAME, OAUTH_STATE_COOKIE, USER_COOKIE_NAME};
pub use manager::{SessionError, SessionManager};
pub use oauth::{
    create_minimal_oauth_result, create_oauth_session, extract_oauth_provider_info,
    reconstruct_session_from_oauth_result, validate_oauth_refresh_requirements,
    validate_oauth_result_for_session,
};
pub use passkey::{
    convert_passkey_session_data, create_minimal_passkey_result,
    create_passkey_session_from_result, extract_passkey_auth_info,
    validate_passkey_result_for_session, PasskeySessionBuilder, PasskeySessionData,
};
pub use utils::{create_error_response, extract_client_info, get_state_from_callback};
pub use validation::{
    calculate_client_context_hash, create_session_fingerprint, is_session_expired,
    is_session_time_expired, needs_token_refresh, validate_client_context,
    validate_client_context_only, validate_ip_binding, validate_session_fingerprint,
    validate_session_security, validate_session_security_advanced, validate_user_agent_fingerprint,
};
