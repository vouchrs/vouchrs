//! Authentication module for service factory and common authentication traits
//!
//! This module provides the service factory for creating configured authentication
//! services, common authentication traits, and advanced dependency injection patterns.

pub mod dependency_injection;
pub mod factory;
pub mod traits;

pub use dependency_injection::{ServiceConfigBuilder, ServiceContainer};
pub use factory::{AuthenticationConfig, AuthenticationServiceFactory};
pub use traits::{
    AuthenticationService, OAuthAuthenticationService, PasskeyAuthenticationService, SessionService,
};
