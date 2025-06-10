#![warn(clippy::pedantic)]
#![warn(clippy::cargo)]
#![deny(warnings)]
#![allow(clippy::multiple_crate_versions)]

use actix_cors::Cors;
use actix_web::{middleware::Logger, web, App, HttpRequest, HttpResponse, HttpServer, Result};
use vouchrs::{
    authentication::{AuthenticationConfig, AuthenticationServiceFactory},
    handlers::{
        health, initialize_static_files, oauth_callback, oauth_debug, oauth_sign_in,
        oauth_sign_out, oauth_userinfo, proxy_upstream, serve_static,
    },
    oauth::OAuthConfig,
    session::SessionManager,
    settings::VouchrsSettings,
};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load configuration from Settings.toml and environment variables
    // This also loads .env file and initializes the logger
    let settings = VouchrsSettings::load()
        .map_err(|e| std::io::Error::other(format!("Failed to load settings: {e}")))?;

    // Initialize OAuth configuration with config-driven providers
    let mut oauth_config = OAuthConfig::new();
    oauth_config
        .initialize_from_settings(&settings)
        .await
        .map_err(|e| std::io::Error::other(format!("Failed to initialize OAuth providers: {e}")))?;

    // Initialize static files from templates
    initialize_static_files(&settings)
        .map_err(|e| std::io::Error::other(format!("Failed to initialize static files: {e}")))?;

    println!("✓ Using stateless sessions with encrypted cookies");
    start_server(oauth_config, settings).await
}

/// Start the server with stateless sessions
///
/// # Errors
///
/// Returns an error if:
/// - Server binding fails
/// - Server fails to start
async fn start_server(oauth_config: OAuthConfig, settings: VouchrsSettings) -> std::io::Result<()> {
    let bind_address = settings.get_bind_address();
    print_startup_info(&bind_address, "Stateless", &settings);

    // Initialize session manager with authentication services using factory
    let auth_config = AuthenticationConfig::from_settings(&settings);
    let session_manager =
        AuthenticationServiceFactory::create_complete_session_manager(&settings, &auth_config);

    // Configure CORS for SPAs
    let cors_origins = settings.get_cors_origins();

    HttpServer::new(move || {
        let cors_origins = cors_origins.clone();
        let cors = Cors::default()
            .allowed_origin_fn(move |origin, _| {
                cors_origins
                    .iter()
                    .any(|allowed| allowed == origin.to_str().unwrap_or(""))
            })
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE", "OPTIONS"])
            .allowed_headers(vec!["Authorization", "Content-Type", "Accept"])
            .supports_credentials()
            .max_age(3600);

        App::new()
            .app_data(web::Data::new(oauth_config.clone()))
            .app_data(web::Data::new(settings.clone()))
            .app_data(web::Data::new(session_manager.clone()))
            .wrap(cors)
            .wrap(Logger::default())
            .configure(configure_services)
    })
    .bind(&bind_address)?
    .run()
    .await
}

// Passkey wrapper handlers to match actix-web signatures
async fn passkey_start_registration(
    req: HttpRequest,
    data: web::Json<vouchrs::handlers::passkey::RegistrationRequest>,
    settings: web::Data<VouchrsSettings>,
) -> Result<HttpResponse> {
    use vouchrs::handlers::start_registration;
    start_registration(&req, &data, &settings)
}

async fn passkey_complete_registration(
    req: HttpRequest,
    data: web::Json<serde_json::Value>,
    session_manager: web::Data<SessionManager>,
) -> Result<HttpResponse> {
    use vouchrs::handlers::complete_registration;
    complete_registration(&req, &data, &session_manager)
}

async fn passkey_start_authentication(
    req: HttpRequest,
    data: web::Json<serde_json::Value>,
    settings: web::Data<VouchrsSettings>,
) -> Result<HttpResponse> {
    use vouchrs::handlers::start_authentication;
    start_authentication(&req, &data, &settings)
}

async fn passkey_complete_authentication(
    req: HttpRequest,
    data: web::Json<serde_json::Value>,
    session_manager: web::Data<SessionManager>,
) -> Result<HttpResponse> {
    use vouchrs::handlers::complete_authentication;
    complete_authentication(&req, &data, &session_manager)
}

fn configure_services(cfg: &mut web::ServiceConfig) {
    cfg
        // OAuth2 endpoints
        .route("/oauth2/sign_in", web::get().to(oauth_sign_in))
        .route("/oauth2/sign_out", web::get().to(oauth_sign_out))
        .route("/oauth2/sign_out", web::post().to(oauth_sign_out))
        .route("/oauth2/callback", web::get().to(oauth_callback))
        .route("/oauth2/callback", web::post().to(oauth_callback))
        .route("/oauth2/debug", web::get().to(oauth_debug))
        .route("/oauth2/userinfo", web::get().to(oauth_userinfo))
        // Passkey endpoints
        .route(
            "/oauth2/passkey/register/start",
            web::post().to(passkey_start_registration),
        )
        .route(
            "/oauth2/passkey/register/complete",
            web::post().to(passkey_complete_registration),
        )
        .route(
            "/oauth2/passkey/auth/start",
            web::post().to(passkey_start_authentication),
        )
        .route(
            "/oauth2/passkey/auth/complete",
            web::post().to(passkey_complete_authentication),
        )
        // Static files endpoint
        .route("/oauth2/static/{filename:.*}", web::get().to(serve_static))
        // Health endpoint
        .route("/ping", web::get().to(health))
        // Catch-all proxy for any other path - provider determined from session
        .default_service(
            web::route()
                .guard(actix_web::guard::fn_guard(|req| {
                    let path = req.head().uri.path();
                    !path.starts_with("/oauth2") && !path.starts_with("/ping")
                }))
                .to(proxy_upstream),
        );
}

fn print_startup_info(bind_address: &str, session_backend: &str, settings: &VouchrsSettings) {
    println!("Starting Vouchrs OIDC Reverse Proxy on http://{bind_address}");
    println!("Session Backend: {session_backend}");
    println!();
    println!("OAuth2 endpoints:");
    println!("  GET  /oauth2/sign_in  - Login/logout page");
    println!("  GET|POST /oauth2/sign_out - Clear session");
    println!("  GET|POST /oauth2/callback - OAuth callback (POST for Apple form_post)");
    println!();
    println!("OAuth callback URL for identity providers:");
    println!(
        "  {}/oauth2/callback",
        settings.application.redirect_base_url
    );
    println!();
    if session_backend == "Stateless" {
        println!("Sidecar Proxy endpoints (with automatic OAuth token injection):");
        println!("  ALL {{any path}}                   - Proxy to upstream service as-is");
        println!("                                    (except /oauth2/* and /health)");
        println!(
            "                                    Upstream URL: {}",
            settings.proxy.upstream_url
        );
        println!();
    }
    println!("System endpoints:");
    println!("  GET  /ping            - Health check");
    println!("  GET  /oauth2/static/* - Static files (HTML, CSS, JS, images)");
    println!(
        "  Static files folder: {}",
        settings.static_files.assets_folder
    );
}
