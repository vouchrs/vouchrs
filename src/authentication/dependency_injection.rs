//! Dependency injection configuration for authentication services
//!
//! This module provides advanced dependency injection patterns for configuring
//! authentication services with fine-grained control over service initialization.

use crate::oauth::OAuthAuthenticationServiceImpl;
use crate::passkey::PasskeyAuthenticationServiceImpl;
use crate::session::SessionManager;
use crate::settings::VouchrsSettings;
use std::sync::Arc;

/// Service configuration builder for dependency injection
#[derive(Clone, Default)]
pub struct ServiceConfigBuilder {
    oauth_enabled: Option<bool>,
    passkey_enabled: Option<bool>,
    custom_oauth_service: Option<Arc<OAuthAuthenticationServiceImpl>>,
    custom_passkey_service: Option<Arc<PasskeyAuthenticationServiceImpl>>,
}

impl ServiceConfigBuilder {
    /// Create a new service configuration builder
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable or disable OAuth service
    #[must_use]
    pub fn with_oauth_enabled(mut self, enabled: bool) -> Self {
        self.oauth_enabled = Some(enabled);
        self
    }

    /// Enable or disable Passkey service
    #[must_use]
    pub fn with_passkey_enabled(mut self, enabled: bool) -> Self {
        self.passkey_enabled = Some(enabled);
        self
    }

    /// Use a custom OAuth service implementation
    #[must_use]
    pub fn with_custom_oauth_service(
        mut self,
        service: Arc<OAuthAuthenticationServiceImpl>,
    ) -> Self {
        self.custom_oauth_service = Some(service);
        self
    }

    /// Use a custom Passkey service implementation
    #[must_use]
    pub fn with_custom_passkey_service(
        mut self,
        service: Arc<PasskeyAuthenticationServiceImpl>,
    ) -> Self {
        self.custom_passkey_service = Some(service);
        self
    }

    /// Build the service configuration and apply it to a `SessionManager`
    #[must_use]
    pub fn configure_session_manager(
        self,
        mut session_manager: SessionManager,
        settings: &VouchrsSettings,
    ) -> SessionManager {
        log::info!("🔧 Configuring session manager with custom service configuration...");

        // Configure OAuth service
        if self.should_enable_oauth(settings) {
            let oauth_service = if let Some(custom_service) = &self.custom_oauth_service {
                custom_service.clone()
            } else {
                Arc::new(OAuthAuthenticationServiceImpl::new(settings.clone()))
            };
            session_manager = session_manager.with_oauth_service(oauth_service);
            log::info!("✅ OAuth service configured via dependency injection");
        } else {
            log::info!("⚠️  OAuth service disabled via dependency injection");
        }

        // Configure Passkey service
        if self.should_enable_passkey(settings) {
            let passkey_service = self.custom_passkey_service.clone().unwrap_or_else(|| {
                Arc::new(PasskeyAuthenticationServiceImpl::new(settings.clone()))
            });
            session_manager = session_manager.with_passkey_service(passkey_service);
            log::info!("✅ Passkey service configured via dependency injection");
        } else {
            log::info!("⚠️  Passkey service disabled via dependency injection");
        }

        log::info!("🔧 Session manager configuration completed");
        session_manager
    }

    /// Determine if OAuth should be enabled based on override or settings
    fn should_enable_oauth(&self, settings: &VouchrsSettings) -> bool {
        self.oauth_enabled
            .unwrap_or_else(|| !settings.get_enabled_providers().is_empty())
    }

    /// Determine if Passkey should be enabled based on override or settings
    fn should_enable_passkey(&self, settings: &VouchrsSettings) -> bool {
        self.passkey_enabled.unwrap_or(settings.passkeys.enabled)
    }
}

/// Application service container for centralized dependency management
#[derive(Clone)]
pub struct ServiceContainer {
    pub session_manager: SessionManager,
    pub settings: VouchrsSettings,
}

impl ServiceContainer {
    /// Create a new service container with default configuration
    #[must_use]
    pub fn new(settings: VouchrsSettings) -> Self {
        use super::factory::{AuthenticationConfig, AuthenticationServiceFactory};

        let auth_config = AuthenticationConfig::from_settings(&settings);
        let session_manager =
            AuthenticationServiceFactory::create_complete_session_manager(&settings, &auth_config);

        Self {
            session_manager,
            settings,
        }
    }

    /// Create a service container with custom service configuration
    #[must_use]
    pub fn with_custom_services(
        settings: VouchrsSettings,
        service_builder: ServiceConfigBuilder,
    ) -> Self {
        use super::factory::AuthenticationConfig;

        let auth_config = AuthenticationConfig::from_settings(&settings);
        let base_session_manager = SessionManager::new(
            &auth_config.encryption_key,
            auth_config.cookie_secure,
            auth_config.session_duration_hours,
            auth_config.session_expiration_hours,
            auth_config.session_refresh_hours,
        );

        let session_manager =
            service_builder.configure_session_manager(base_session_manager, &settings);

        Self {
            session_manager,
            settings,
        }
    }

    /// Get the session manager
    #[must_use]
    pub const fn session_manager(&self) -> &SessionManager {
        &self.session_manager
    }

    /// Get the settings
    #[must_use]
    pub const fn settings(&self) -> &VouchrsSettings {
        &self.settings
    }

    /// Check if OAuth is available
    #[must_use]
    pub fn is_oauth_available(&self) -> bool {
        self.session_manager.has_oauth_service()
    }

    /// Check if Passkey is available
    #[must_use]
    pub fn is_passkey_available(&self) -> bool {
        self.session_manager.has_passkey_service()
    }

    /// Get a summary of available authentication methods
    #[must_use]
    pub fn get_auth_methods_summary(&self) -> String {
        let mut methods = Vec::new();

        if self.is_oauth_available() {
            let provider_count = self.settings.get_enabled_providers().len();
            methods.push(format!("OAuth ({provider_count} providers)"));
        }

        if self.is_passkey_available() {
            methods.push("Passkey".to_string());
        }

        if methods.is_empty() {
            "No authentication methods available".to_string()
        } else {
            methods.join(", ")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_helpers::create_test_settings;

    #[test]
    fn test_service_config_builder() {
        let settings = create_test_settings();
        let auth_config = super::super::factory::AuthenticationConfig::from_settings(&settings);

        let base_manager = SessionManager::new(
            &auth_config.encryption_key,
            auth_config.cookie_secure,
            auth_config.session_duration_hours,
            auth_config.session_expiration_hours,
            auth_config.session_refresh_hours,
        );

        let config_builder = ServiceConfigBuilder::new()
            .with_oauth_enabled(true)
            .with_passkey_enabled(false);

        let configured_manager = config_builder.configure_session_manager(base_manager, &settings);

        // Verify the manager was configured
        assert!(configured_manager.encryption_key().len() == 32);
    }

    #[test]
    fn test_service_container() {
        let settings = create_test_settings();
        let container = ServiceContainer::new(settings);

        // Verify container is properly initialized
        assert!(container.session_manager().encryption_key().len() == 32);

        let summary = container.get_auth_methods_summary();
        assert!(!summary.is_empty());
    }

    #[test]
    fn test_service_container_with_custom_services() {
        let settings = create_test_settings();

        let service_builder = ServiceConfigBuilder::new()
            .with_oauth_enabled(false)
            .with_passkey_enabled(true);

        let container = ServiceContainer::with_custom_services(settings, service_builder);

        // Verify container is properly initialized
        assert!(container.session_manager().encryption_key().len() == 32);
    }
}
