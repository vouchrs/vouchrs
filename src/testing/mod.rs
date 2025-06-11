//! Unified testing utilities for Vouchrs
//!
//! This module consolidates all test helpers, fixtures, and utilities into a single,
//! well-organized location to eliminate duplication and improve test maintainability.
//!
//! ## Organization
//!
//! - [`fixtures`] - Pre-built test data (sessions, users, settings)
//! - [`builders`] - Fluent builders for creating test objects
//! - [`requests`] - HTTP request builders for testing handlers
//! - [`assertions`] - Custom assertion helpers for common patterns
//! - [`mock`] - Mock objects and fake implementations
//!
//! ## Usage
//!
//! ```rust
//! use vouchrs::testing::{fixtures::TestFixtures, builders::TestSessionBuilder};
//!
//! // Example: Testing with OAuth session
//! fn test_oauth_session() {
//!     let session = TestFixtures::oauth_session();
//!     let manager = TestFixtures::session_manager();
//!
//!     // Test with the session...
//! }
//!
//! // Example: Testing with custom session
//! fn test_custom_session() {
//!     let session = TestSessionBuilder::new()
//!         .with_provider("github")
//!         .expires_in_hours(2)
//!         .build();
//!
//!     // Test with custom session...
//! }
//! ```

pub mod assertions;
pub mod builders;
pub mod fixtures;
pub mod mock;
pub mod requests;

// Re-export commonly used items for convenience
pub use assertions::*;
pub use builders::*;
pub use fixtures::TestFixtures;
pub use requests::RequestBuilder;

/// Common test constants
pub mod constants {
    /// Default test email address
    pub const TEST_EMAIL: &str = "test@example.com";

    /// Default test user name
    pub const TEST_USER_NAME: &str = "Test User";

    /// Default test provider ID
    pub const TEST_PROVIDER_ID: &str = "123456789";

    /// Default test client IP
    pub const TEST_CLIENT_IP: &str = "192.168.1.1";

    /// Default test user agent string
    pub const TEST_USER_AGENT: &str =
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36";

    /// Default test platform
    pub const TEST_PLATFORM: &str = "macOS";

    /// Default test language
    pub const TEST_LANGUAGE: &str = "en-US";

    /// Test OAuth providers
    pub const OAUTH_PROVIDERS: &[&str] = &["google", "github", "apple"];

    /// Test JWT signing key for HMAC (256 bits)
    pub const TEST_JWT_KEY: &[u8] = b"test_key_32_bytes_long_for_test_";
}
