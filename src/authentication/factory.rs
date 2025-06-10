//! Service factory for creating configured authentication services
//!
//! This module provides the factory pattern for creating `SessionManager` instances
//! with the appropriate authentication services based on configuration.

use crate::oauth::OAuthAuthenticationServiceImpl;
use crate::passkey::PasskeyAuthenticationServiceImpl;
use crate::session::SessionManager;
use crate::settings::VouchrsSettings;
use std::sync::Arc;

/// Configuration for creating authentication services
#[derive(Debug, Clone)]
pub struct AuthenticationConfig {
    pub encryption_key: Vec<u8>,
    pub cookie_secure: bool,
    pub session_duration_hours: u64,
    pub session_expiration_hours: u64,
    pub session_refresh_hours: u64,
}

impl AuthenticationConfig {
    /// Create authentication configuration from settings
    #[must_use]
    pub fn from_settings(settings: &VouchrsSettings) -> Self {
        Self {
            encryption_key: settings.session.session_secret.as_bytes().to_vec(),
            cookie_secure: settings.cookies.secure,
            session_duration_hours: settings.session.session_duration_hours,
            session_expiration_hours: settings.session.session_expiration_hours,
            session_refresh_hours: settings.session.session_refresh_hours,
        }
    }
}

/// Factory for creating authentication services with dependency injection
pub struct AuthenticationServiceFactory;

impl AuthenticationServiceFactory {
    /// Create a fully configured `SessionManager` with all authentication services
    ///
    /// This is the main factory method that creates a complete authentication system
    /// by analyzing the configuration and conditionally adding appropriate services.
    ///
    /// # Arguments
    /// * `settings` - The application settings containing authentication configuration
    /// * `config` - Authentication configuration parameters
    ///
    /// # Returns
    /// A configured `SessionManager` with appropriate authentication services
    #[must_use]
    pub fn create_complete_session_manager(
        settings: &VouchrsSettings,
        config: &AuthenticationConfig,
    ) -> SessionManager {
        log::info!("🏭 Starting authentication service factory...");

        let mut session_manager = SessionManager::new(
            &config.encryption_key,
            config.cookie_secure,
            config.session_duration_hours,
            config.session_expiration_hours,
            config.session_refresh_hours,
        );

        // Add authentication services based on configuration
        session_manager = Self::add_oauth_service(session_manager, settings);
        session_manager = Self::add_passkey_service(session_manager, settings);

        log::info!("🏭 Authentication service factory completed successfully");
        session_manager
    }

    /// Add OAuth authentication service if enabled providers exist
    fn add_oauth_service(
        mut session_manager: SessionManager,
        settings: &VouchrsSettings,
    ) -> SessionManager {
        let enabled_providers = settings.get_enabled_providers();
        if enabled_providers.is_empty() {
            log::info!("⚠️  OAuth authentication is disabled - no enabled providers");
        } else {
            let oauth_service = Arc::new(OAuthAuthenticationServiceImpl::new(settings.clone()));
            session_manager = session_manager.with_oauth_service(oauth_service);
            log::info!(
                "✅ OAuth authentication service configured with {} providers",
                enabled_providers.len()
            );

            // Log enabled provider details
            for provider in &enabled_providers {
                log::info!(
                    "   └─ {} ({})",
                    provider.display_name.as_deref().unwrap_or(&provider.name),
                    provider.name
                );
            }
        }
        session_manager
    }

    /// Add Passkey authentication service if enabled
    fn add_passkey_service(
        mut session_manager: SessionManager,
        settings: &VouchrsSettings,
    ) -> SessionManager {
        if settings.passkeys.enabled {
            let passkey_service = Arc::new(PasskeyAuthenticationServiceImpl::new(settings.clone()));
            session_manager = session_manager.with_passkey_service(passkey_service);
            log::info!("✅ Passkey authentication service configured");
            log::info!("   └─ Relying party: {}", settings.passkeys.rp_name);
        } else {
            log::info!("⚠️  Passkey authentication is disabled");
        }
        session_manager
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_helpers::create_test_settings;

    #[test]
    fn test_create_session_manager_with_services() {
        let settings = create_test_settings();
        let config = AuthenticationConfig::from_settings(&settings);

        let session_manager =
            AuthenticationServiceFactory::create_complete_session_manager(&settings, &config);

        // SessionManager should be created successfully
        // The specific services availability depends on the test settings configuration
        assert!(session_manager.encryption_key().len() == 32);
        assert!(!session_manager.cookie_secure());
    }

    #[test]
    fn test_authentication_config_from_settings() {
        let settings = create_test_settings();
        let config = AuthenticationConfig::from_settings(&settings);

        assert!(config.encryption_key.len() >= 32);
        assert!(!config.cookie_secure);
        assert!(config.session_duration_hours > 0);
        assert!(config.session_expiration_hours > 0);
    }

    #[test]
    fn test_session_manager_builder_pattern() {
        let settings = create_test_settings();

        // Test basic SessionManager creation
        let base_manager = SessionManager::new(
            b"test_key_12345678901234567890123456789012",
            false,
            24,
            24,
            0,
        );

        // Test that builder pattern methods exist and can be chained
        let oauth_service = Arc::new(OAuthAuthenticationServiceImpl::new(settings.clone()));
        let passkey_service = Arc::new(PasskeyAuthenticationServiceImpl::new(settings.clone()));

        let configured_manager = base_manager
            .with_oauth_service(oauth_service)
            .with_passkey_service(passkey_service);

        // Verify the manager is properly configured
        assert!(configured_manager.encryption_key().len() == 32);
    }
}
