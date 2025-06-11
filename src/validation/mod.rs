//! Validation Module
//!
//! This module provides comprehensive validation functionality for Vouchrs,
//! including specialized validators for different authentication methods and
//! common validation utilities.
//!
//! # Modules
//!
//! - [`core`] - Core validation utilities and helper functions
//! - [`passkey`] - Passkey-specific validation (registration, authentication)
//! - [`oauth_callback`] - OAuth callback validation and data extraction
//! - [`redirect`] - Redirect URL validation and security checks
//!
//! # Organization
//!
//! The validation module is organized by concern:
//! - **Core utilities**: Reusable validation functions and macros
//! - **Domain-specific validators**: Focused validators for specific authentication flows
//! - **Security validators**: URL and data safety validation
//!
//! # Usage
//!
//! ```ignore
//! // For passkey validation
//! use crate::validation::PasskeyValidator;
//!
//! // For OAuth callback validation
//! use crate::validation::CallbackValidator;
//!
//! // For redirect validation
//! use crate::validation::validate_post_auth_redirect;
//!
//! // For general field extraction
//! use crate::validation::extract_required_field;
//! ```

pub mod core;
pub mod oauth_callback;
pub mod passkey;
pub mod redirect;

// Re-export commonly used items for convenience

// Core validation utilities
pub use core::{
    decode_and_parse_jwt_part, extract_and_decode_user_data, extract_audiences_from_claim,
    extract_credential_response, extract_name_from_claims, extract_optional_field,
    extract_required_field, extract_required_string, extract_state,
};

// Re-export the macro from crate root since it's macro_export
pub use crate::validate_all_required;

// Passkey validation
pub use passkey::{PasskeyValidator, RegistrationRequestValidator};

// OAuth callback validation
pub use oauth_callback::{CallbackDataExtractor, CallbackValidator};

// Redirect validation
pub use redirect::validate_post_auth_redirect;
